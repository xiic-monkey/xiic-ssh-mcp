use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::app_core::DesktopCore;
use crate::approval::LocalApprovalClient;
use crate::models::{
    ApprovalMode, ApprovalOperationMetadata, CreateSessionResult, DownloadFileArgs,
    DownloadFileResult, ExecuteCommandArgs, ExecuteCommandResult, OperationContext,
    PendingToolCall, RuleDecision, ToolCall, UploadFileArgs, UploadFileResult, WhitelistMode,
};
use crate::whitelist::WhitelistChecker;

const DEFAULT_PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "xiic-ssh-mcp";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MessageFraming {
    Newline,
    ContentLength,
}

#[derive(Debug)]
struct IncomingMessage {
    payload: Value,
    framing: MessageFraming,
}

enum DispatchResult {
    Respond(Value),
    NoResponse,
    NeedsApproval {
        flow: ApprovalFlow,
        pending: PendingToolCall,
    },
}

enum ApprovalFlow {
    Elicitation(Value),
    Local,
}

pub struct McpServer {
    core: Arc<DesktopCore>,
    whitelist_mode: WhitelistMode,
    approval_mode: ApprovalMode,
    client_supports_elicitation: bool,
    checker: WhitelistChecker,
    local_approval: LocalApprovalClient,
}

impl McpServer {
    pub fn new(
        core: Arc<DesktopCore>,
        whitelist_mode: WhitelistMode,
        approval_mode: ApprovalMode,
        approval_endpoint: Option<String>,
    ) -> Self {
        let checker = core.create_whitelist_checker();
        Self {
            core,
            whitelist_mode,
            approval_mode,
            client_supports_elicitation: false,
            checker,
            local_approval: LocalApprovalClient::new(approval_endpoint),
        }
    }

    pub fn run(&mut self) -> Result<()> {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut reader = BufReader::new(stdin.lock());
        let mut writer = stdout.lock();
        let mut response_framing = None;

        eprintln!("[xiic-ssh-mcp] MCP server starting, waiting for messages...");

        loop {
            let message = match read_message(&mut reader)? {
                Some(msg) => msg,
                None => break,
            };

            let framing = *response_framing.get_or_insert(message.framing);
            let method = message
                .payload
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let id_str = message
                .payload
                .get("id")
                .map(|v| v.to_string())
                .unwrap_or_else(|| "notification".to_string());
            eprintln!("[xiic-ssh-mcp] Received: method={}, id={}", method, id_str);

            match self.dispatch(message.payload)? {
                DispatchResult::Respond(response) => {
                    write_message(&mut writer, &response, framing)?;
                    eprintln!(
                        "[xiic-ssh-mcp] Sent response for method={}, id={}",
                        method, id_str
                    );
                }
                DispatchResult::NoResponse => {
                    eprintln!("[xiic-ssh-mcp] No response needed for method={}", method);
                }
                DispatchResult::NeedsApproval { flow, pending } => {
                    let accepted = match flow {
                        ApprovalFlow::Elicitation(elicitation) => self
                            .request_elicitation_approval(
                                &mut reader,
                                &mut writer,
                                framing,
                                &pending,
                                elicitation,
                            )?,
                        ApprovalFlow::Local => {
                            eprintln!(
                                "[xiic-ssh-mcp] Requesting local approval for tool='{}'",
                                pending.tool_call.name
                            );
                            self.local_approval.request(&pending.approval)?
                        }
                    };

                    if accepted {
                        eprintln!(
                            "[xiic-ssh-mcp] Approval accepted for tool='{}'",
                            pending.tool_call.name
                        );
                        self.checker.cache_approval(&pending.operation);
                        let exec_result = self.execute_tool(&pending.tool_call)?;
                        let response = success_response(pending.id, exec_result);
                        write_message(&mut writer, &response, framing)?;
                    } else {
                        eprintln!(
                            "[xiic-ssh-mcp] Approval declined for tool='{}'",
                            pending.tool_call.name
                        );
                        let response = error_response(
                            pending.id,
                            -32000,
                            "operation declined by user".to_string(),
                        );
                        write_message(&mut writer, &response, framing)?;
                    }
                }
            }
        }

        eprintln!("[xiic-ssh-mcp] MCP server shutting down (stdin closed)");
        Ok(())
    }

    fn dispatch(&mut self, message: Value) -> Result<DispatchResult> {
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("incoming JSON-RPC message is missing method"))?;

        let id = message.get("id").cloned();
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

        if id.is_none() {
            self.handle_notification(method, params)?;
            return Ok(DispatchResult::NoResponse);
        }

        let id = id.expect("checked is_some");
        let response = match method {
            "initialize" => match self.handle_initialize(params) {
                Ok(result) => success_response(id, result),
                Err(err) => error_response(id, -32602, err.to_string()),
            },
            "ping" => success_response(id, json!({})),
            "tools/list" => success_response(id, self.handle_tools_list()),
            "tools/call" => match self.handle_tool_call(params, id.clone()) {
                Ok(result) => {
                    return Ok(result);
                }
                Err(err) => success_response(id, tool_error(err.to_string())),
            },
            _ => error_response(id, -32601, format!("method '{}' not found", method)),
        };

        Ok(DispatchResult::Respond(response))
    }

    fn handle_notification(&self, method: &str, _params: Value) -> Result<()> {
        match method {
            "notifications/initialized" => Ok(()),
            "notifications/cancelled" => Ok(()),
            _ => Ok(()),
        }
    }

    fn handle_initialize(&mut self, params: Value) -> Result<Value> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct InitializeParams {
            protocol_version: Option<String>,
            capabilities: Option<Value>,
        }

        let params: InitializeParams =
            serde_json::from_value(params).context("invalid initialize params")?;
        self.client_supports_elicitation = has_elicitation_capability(params.capabilities.as_ref());

        Ok(json!({
            "protocolVersion": params.protocol_version.unwrap_or_else(|| DEFAULT_PROTOCOL_VERSION.to_string()),
            "capabilities": {
                "tools": {
                    "listChanged": false
                }
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION
            },
            "instructions": "Manage SSH sessions stored by the local Xiic SSH Manager desktop app. Operations not in the whitelist require approval."
        }))
    }

    fn handle_tools_list(&self) -> Value {
        json!({
            "tools": [
                {
                    "name": "list_servers",
                    "description": "List all configured SSH server instances.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                },
                {
                    "name": "create_session",
                    "description": "Create an SSH session for a configured instance_id.",
                    "inputSchema": {
                    "type": "object",
                    "properties": {
                        "instance_id": {
                            "type": "string"
                        }
                    },
                    "required": ["instance_id"],
                        "additionalProperties": false
                    }
                },
                {
                    "name": "execute_command",
                    "description": "Execute a non-interactive shell command in an existing SSH session.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "session_id": { "type": "string" },
                            "command": { "type": "string" },
                            "command_description": { "type": "string" },
                            "timeout_secs": { "type": "integer", "minimum": 1 }
                        },
                        "required": ["session_id", "command", "command_description"],
                        "additionalProperties": false
                    }
                },
                {
                    "name": "upload_file",
                    "description": "Upload inline content to a remote file over SFTP.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "session_id": { "type": "string" },
                            "remote_path": { "type": "string" },
                            "content": { "type": "string" },
                            "encoding": { "type": "string", "enum": ["utf8", "base64"] },
                            "overwrite": { "type": "boolean" }
                        },
                        "required": ["session_id", "remote_path", "content"],
                        "additionalProperties": false
                    }
                },
                {
                    "name": "download_file",
                    "description": "Download a remote file over SFTP and return its contents.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "session_id": { "type": "string" },
                            "remote_path": { "type": "string" },
                            "encoding": { "type": "string", "enum": ["utf8", "base64"] }
                        },
                        "required": ["session_id", "remote_path"],
                        "additionalProperties": false
                    }
                }
            ]
        })
    }

    fn handle_tool_call(&self, params: Value, id: Value) -> Result<DispatchResult> {
        let tool_call: ToolCall =
            serde_json::from_value(params).context("invalid tools/call params")?;

        if self.whitelist_mode == WhitelistMode::Off {
            let result = self.execute_tool(&tool_call)?;
            return Ok(DispatchResult::Respond(success_response(id, result)));
        }

        let ctx = self.build_context(&tool_call)?;

        match self.checker.check(&ctx)? {
            RuleDecision::Allow => {
                eprintln!(
                    "[xiic-ssh-mcp] Whitelist ALLOW for tool='{}' cmd='{}'",
                    ctx.tool_name,
                    ctx.command.as_deref().unwrap_or("-"),
                );
                let result = self.execute_tool(&tool_call)?;
                Ok(DispatchResult::Respond(success_response(id, result)))
            }
            RuleDecision::Deny(reason) => {
                eprintln!(
                    "[xiic-ssh-mcp] Whitelist DENY for tool='{}': {}",
                    ctx.tool_name, reason
                );
                Ok(DispatchResult::Respond(error_response(id, -32001, reason)))
            }
            RuleDecision::NeedsElicitation => {
                let elicitation_id = Uuid::new_v4().to_string();
                let details = json!({
                    "tool_name": ctx.tool_name,
                    "command": ctx.command,
                    "command_description": ctx.command_description,
                    "remote_path": ctx.remote_path,
                    "instance_id": ctx.instance_id,
                });
                let elicitation = json!({
                    "jsonrpc": "2.0",
                    "id": elicitation_id,
                    "method": "elicitation/create",
                    "params": {
                        "message": format!(
                            "SSH operation '{}' requires approval.",
                            ctx.tool_name
                        ),
                        "requestId": Uuid::new_v4().to_string(),
                        "details": details,
                    }
                });

                let approval = ApprovalOperationMetadata::from(&ctx);
                let pending = PendingToolCall {
                    id,
                    tool_call,
                    operation: ctx,
                    approval,
                };

                let flow = if self.should_use_elicitation() {
                    ApprovalFlow::Elicitation(elicitation)
                } else {
                    ApprovalFlow::Local
                };

                Ok(DispatchResult::NeedsApproval { flow, pending })
            }
        }
    }

    fn should_use_elicitation(&self) -> bool {
        should_use_elicitation_mode(self.approval_mode, self.client_supports_elicitation)
    }

    fn request_elicitation_approval<R, W>(
        &self,
        reader: &mut BufReader<R>,
        writer: &mut W,
        framing: MessageFraming,
        pending: &PendingToolCall,
        elicitation: Value,
    ) -> Result<bool>
    where
        R: Read,
        W: Write,
    {
        eprintln!(
            "[xiic-ssh-mcp] Sending elicitation for tool='{}'",
            pending.tool_call.name
        );
        write_message(writer, &elicitation, framing)?;

        let elicitation_response = read_message(reader)?
            .ok_or_else(|| anyhow!("stdin closed while waiting for elicitation response"))?;

        let result = elicitation_response
            .payload
            .get("result")
            .and_then(|r| r.get("action"))
            .and_then(|a| a.as_str());

        Ok(matches!(result, Some("accept")))
    }

    fn build_context(&self, tool_call: &ToolCall) -> Result<OperationContext> {
        match tool_call.name.as_str() {
            "list_servers" => Ok(OperationContext {
                tool_name: "list_servers".into(),
                command: None,
                command_description: None,
                remote_path: None,
                instance_id: None,
            }),
            "create_session" => {
                #[derive(Deserialize)]
                struct Args {
                    instance_id: String,
                }
                let args: Args = deserialize_args(tool_call.arguments.clone())?;
                Ok(OperationContext {
                    tool_name: "create_session".into(),
                    command: None,
                    command_description: None,
                    remote_path: None,
                    instance_id: Some(args.instance_id),
                })
            }
            "execute_command" => {
                let args: ExecuteCommandArgs = deserialize_args(tool_call.arguments.clone())?;
                let command_description = args.command_description.trim().to_string();
                if command_description.is_empty() {
                    bail!("command_description cannot be empty");
                }
                let instance_id = self.lookup_session_instance(&args.session_id)?;
                Ok(OperationContext {
                    tool_name: "execute_command".into(),
                    command: Some(args.command),
                    command_description: Some(command_description),
                    remote_path: None,
                    instance_id: Some(instance_id),
                })
            }
            "upload_file" => {
                let args: UploadFileArgs = deserialize_args(tool_call.arguments.clone())?;
                let instance_id = self.lookup_session_instance(&args.session_id)?;
                Ok(OperationContext {
                    tool_name: "upload_file".into(),
                    command: None,
                    command_description: None,
                    remote_path: Some(args.remote_path),
                    instance_id: Some(instance_id),
                })
            }
            "download_file" => {
                let args: DownloadFileArgs = deserialize_args(tool_call.arguments.clone())?;
                let instance_id = self.lookup_session_instance(&args.session_id)?;
                Ok(OperationContext {
                    tool_name: "download_file".into(),
                    command: None,
                    command_description: None,
                    remote_path: Some(args.remote_path),
                    instance_id: Some(instance_id),
                })
            }
            _ => bail!("unknown tool '{}'", tool_call.name),
        }
    }

    fn lookup_session_instance(&self, session_id: &str) -> Result<String> {
        self.core.get_session_instance_id(session_id)
    }

    fn execute_tool(&self, tool_call: &ToolCall) -> Result<Value> {
        match tool_call.name.as_str() {
            "list_servers" => {
                let result = self.core.list_servers()?;
                tool_success(result)
            }
            "create_session" => {
                #[derive(Deserialize)]
                struct Args {
                    instance_id: String,
                }
                let args: Args = deserialize_args(tool_call.arguments.clone())?;
                let result = self.core.create_session(&args.instance_id)?;
                tool_success(result)
            }
            "execute_command" => {
                let args: ExecuteCommandArgs = deserialize_args(tool_call.arguments.clone())?;
                let result = self.core.execute_command(args)?;
                tool_success(result)
            }
            "upload_file" => {
                let args: UploadFileArgs = deserialize_args(tool_call.arguments.clone())?;
                let result = self.core.upload_file(args)?;
                tool_success(result)
            }
            "download_file" => {
                let args: DownloadFileArgs = deserialize_args(tool_call.arguments.clone())?;
                let result = self.core.download_file(args)?;
                tool_success(result)
            }
            _ => bail!("unknown tool '{}'", tool_call.name),
        }
    }
}

fn has_elicitation_capability(capabilities: Option<&Value>) -> bool {
    capabilities
        .and_then(|capabilities| capabilities.get("elicitation"))
        .is_some()
}

fn should_use_elicitation_mode(mode: ApprovalMode, client_supports_elicitation: bool) -> bool {
    match mode {
        ApprovalMode::Elicitation => true,
        ApprovalMode::Local => false,
        ApprovalMode::Auto => client_supports_elicitation,
    }
}

fn deserialize_args<T>(value: Value) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value).context("invalid tool arguments")
}

fn read_message<R>(reader: &mut BufReader<R>) -> Result<Option<IncomingMessage>>
where
    R: Read,
{
    let mut content_length = None;
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader
            .read_line(&mut line)
            .context("failed to read MCP message")?;
        if bytes_read == 0 {
            return Ok(None);
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            let value = serde_json::from_str(trimmed)
                .context("failed to parse newline-delimited MCP JSON-RPC message")?;
            return Ok(Some(IncomingMessage {
                payload: value,
                framing: MessageFraming::Newline,
            }));
        }

        if let Some((name, value)) = trimmed.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            let parsed = value
                .trim()
                .parse::<usize>()
                .context("invalid Content-Length header")?;
            content_length = Some(parsed);
            break;
        }

        if trimmed.split_once(':').is_some() {
            break;
        }

        bail!("invalid MCP message start");
    }

    loop {
        line.clear();
        let bytes_read = reader
            .read_line(&mut line)
            .context("failed to read MCP header")?;
        if bytes_read == 0 {
            bail!("unexpected EOF while reading MCP headers");
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }

        if let Some((name, value)) = trimmed.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            let parsed = value
                .trim()
                .parse::<usize>()
                .context("invalid Content-Length header")?;
            content_length = Some(parsed);
        }
    }

    let content_length = content_length.ok_or_else(|| anyhow!("missing Content-Length header"))?;
    let mut body = vec![0; content_length];
    reader
        .read_exact(&mut body)
        .context("failed to read MCP message body")?;

    let value =
        serde_json::from_slice(&body).context("failed to parse MCP JSON-RPC message body")?;
    Ok(Some(IncomingMessage {
        payload: value,
        framing: MessageFraming::ContentLength,
    }))
}

fn write_message<W>(writer: &mut W, payload: &Value, framing: MessageFraming) -> Result<()>
where
    W: Write,
{
    let body = serde_json::to_vec(payload).context("failed to serialize MCP response")?;
    match framing {
        MessageFraming::Newline => {
            writer
                .write_all(&body)
                .context("failed to write MCP response body")?;
            writer
                .write_all(b"\n")
                .context("failed to write MCP response newline")?;
        }
        MessageFraming::ContentLength => {
            write!(writer, "Content-Length: {}\r\n\r\n", body.len())
                .context("failed to write MCP response header")?;
            writer
                .write_all(&body)
                .context("failed to write MCP response body")?;
        }
    }
    writer.flush().context("failed to flush MCP response")?;
    Ok(())
}

fn success_response(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn error_response(id: Value, code: i64, message: String) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

fn tool_success<T>(payload: T) -> Result<Value>
where
    T: serde::Serialize,
{
    let structured = serde_json::to_value(payload).context("failed to serialize tool result")?;
    let text = serde_json::to_string_pretty(&structured).context("failed to format tool result")?;
    Ok(json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "structuredContent": structured
    }))
}

fn tool_error(message: String) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": message
            }
        ],
        "structuredContent": {
            "error": message
        },
        "isError": true
    })
}

#[allow(dead_code)]
fn _type_assertions(
    create: CreateSessionResult,
    exec: ExecuteCommandResult,
    upload: UploadFileResult,
    download: DownloadFileResult,
) {
    let _ = (create, exec, upload, download);
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};
    use std::path::PathBuf;
    use std::sync::Arc;

    use serde_json::json;

    use crate::app_core::{DEFAULT_KEYRING_SERVICE, DesktopCore};
    use crate::models::{ApprovalMode, WhitelistMode};

    use super::{
        McpServer, MessageFraming, has_elicitation_capability, read_message,
        should_use_elicitation_mode, write_message,
    };

    fn initialize_payload() -> serde_json::Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test",
                    "version": "0.0.0"
                }
            }
        })
    }

    #[test]
    fn reads_newline_delimited_message() {
        let input = format!("{}\n", initialize_payload());
        let mut reader = BufReader::new(Cursor::new(input.into_bytes()));

        let message = read_message(&mut reader).unwrap().unwrap();

        assert_eq!(message.framing, MessageFraming::Newline);
        assert_eq!(message.payload["method"], "initialize");
    }

    #[test]
    fn reads_content_length_message() {
        let body = initialize_payload().to_string();
        let input = format!("Content-Length: {}\r\n\r\n{}", body.len(), body);
        let mut reader = BufReader::new(Cursor::new(input.into_bytes()));

        let message = read_message(&mut reader).unwrap().unwrap();

        assert_eq!(message.framing, MessageFraming::ContentLength);
        assert_eq!(message.payload["method"], "initialize");
    }

    #[test]
    fn writes_newline_delimited_response() {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {}
        });
        let mut output = Vec::new();

        write_message(&mut output, &payload, MessageFraming::Newline).unwrap();

        assert!(output.ends_with(b"\n"));
        assert!(!output.starts_with(b"Content-Length:"));
        let parsed: serde_json::Value =
            serde_json::from_slice(output.strip_suffix(b"\n").unwrap()).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn writes_content_length_response() {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {}
        });
        let mut output = Vec::new();

        write_message(&mut output, &payload, MessageFraming::ContentLength).unwrap();

        let output = String::from_utf8(output).unwrap();
        let (header, body) = output.split_once("\r\n\r\n").unwrap();
        let length = header
            .strip_prefix("Content-Length: ")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        assert_eq!(length, body.len());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body).unwrap(),
            payload
        );
    }

    #[test]
    fn detects_elicitation_capability() {
        let capabilities = json!({
            "roots": {},
            "elicitation": {}
        });

        assert!(has_elicitation_capability(Some(&capabilities)));
        assert!(!has_elicitation_capability(Some(&json!({ "roots": {} }))));
        assert!(!has_elicitation_capability(None));
    }

    #[test]
    fn approval_mode_selects_expected_flow() {
        assert!(should_use_elicitation_mode(ApprovalMode::Auto, true));
        assert!(!should_use_elicitation_mode(ApprovalMode::Auto, false));
        assert!(should_use_elicitation_mode(
            ApprovalMode::Elicitation,
            false
        ));
        assert!(!should_use_elicitation_mode(ApprovalMode::Local, true));
    }

    #[test]
    fn execute_command_schema_requires_command_description() {
        let server = test_server();
        let tools = server.handle_tools_list();
        let execute = tools["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "execute_command")
            .unwrap();

        assert_eq!(
            execute["inputSchema"]["properties"]["command_description"]["type"],
            "string"
        );
        assert!(
            execute["inputSchema"]["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "command_description")
        );
    }

    #[test]
    fn build_context_rejects_empty_command_description() {
        let server = test_server();
        let err = server
            .build_context(&crate::models::ToolCall {
                name: "execute_command".into(),
                arguments: json!({
                    "session_id": "session-1",
                    "command": "uname -a",
                    "command_description": "   "
                }),
            })
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("command_description cannot be empty")
        );
    }

    fn test_server() -> McpServer {
        let db_path = PathBuf::from(format!(
            "/private/tmp/xiic-ssh-mcp-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let core = Arc::new(
            DesktopCore::new(db_path.clone(), DEFAULT_KEYRING_SERVICE)
                .expect("test core should initialize"),
        );
        let server = McpServer::new(core, WhitelistMode::Strict, ApprovalMode::Auto, None);
        let _ = std::fs::remove_file(db_path);
        server
    }
}
