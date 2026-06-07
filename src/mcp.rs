use std::collections::VecDeque;
use std::io::{self, BufReader, Read, Write};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::app_core::DesktopCore;
use crate::approval::LocalApprovalClient;
use crate::mcp_protocol::{IncomingMessage, MessageFraming, read_message, write_message};
use crate::models::{
    ApprovalMode, ApprovalOperationMetadata, CloseSessionArgs, CreateSessionResult,
    DownloadFileArgs, DownloadFileResult, DownloadToLocalArgs, DownloadToLocalResult,
    ExecuteCommandArgs, ExecuteCommandResult, OperationContext, PendingToolCall, RequestContext,
    RuleDecision, SudoCommandArgs, ToolCall, UploadFileArgs, UploadFileResult, UploadLocalFileArgs,
    UploadLocalFileResult, WhitelistMode,
};
use crate::whitelist::WhitelistChecker;

const DEFAULT_PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "xiic-ssh-mcp";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

enum DispatchResult {
    Respond(Value),
    NeedsApproval {
        flow: ApprovalFlow,
        pending: Box<PendingToolCall>,
    },
}

#[derive(Debug)]
enum ApprovalFlow {
    Elicitation { request_id: Value, request: Value },
    Local,
}

pub struct McpServer {
    core: Arc<DesktopCore>,
    whitelist_mode: WhitelistMode,
    approval_mode: ApprovalMode,
    client_supports_elicitation: bool,
    pending_messages: VecDeque<IncomingMessage>,
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
            pending_messages: VecDeque::new(),
            checker,
            local_approval: LocalApprovalClient::new(approval_endpoint),
        }
    }

    /// 预启动审批桌面 App，避免首次审批请求的冷启动延迟。
    pub fn pre_launch(&self) {
        self.local_approval.pre_launch();
    }

    pub fn run(&mut self, request_context: RequestContext) -> Result<()> {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut reader = BufReader::new(stdin.lock());
        let mut writer = stdout.lock();
        let mut response_framing = None;

        eprintln!("[xiic-ssh-mcp] MCP server starting, waiting for messages...");

        loop {
            let message = match self.next_message(&mut reader)? {
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

            self.dispatch_with_context(
                request_context.clone(),
                message.payload,
                framing,
                &mut reader,
                &mut writer,
            )?;
            eprintln!(
                "[xiic-ssh-mcp] Sent/handled response for method={}, id={}",
                method, id_str
            );
        }

        eprintln!("[xiic-ssh-mcp] MCP server shutting down (stdin closed)");
        Ok(())
    }

    pub fn dispatch_with_context<R, W>(
        &mut self,
        request_context: RequestContext,
        message: Value,
        framing: MessageFraming,
        reader: &mut BufReader<R>,
        writer: &mut W,
    ) -> Result<()>
    where
        R: Read,
        W: Write,
    {
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("incoming JSON-RPC message is missing method"))?;

        let id = message.get("id").cloned();
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

        if id.is_none() {
            self.handle_notification(method, params)?;
            return Ok(());
        }

        let id = id.expect("checked is_some");
        let result = match method {
            "initialize" => match self.handle_initialize(params) {
                Ok(result) => DispatchResult::Respond(success_response(id, result)),
                Err(err) => DispatchResult::Respond(error_response(id, -32602, err.to_string())),
            },
            "ping" => DispatchResult::Respond(success_response(id, json!({}))),
            "resources/list" => DispatchResult::Respond(success_response(
                id,
                json!({
                    "resources": []
                }),
            )),
            "tools/list" => DispatchResult::Respond(success_response(id, self.handle_tools_list())),
            "tools/call" => {
                match self.handle_tool_call(request_context.clone(), params, id.clone()) {
                    Ok(result) => result,
                    Err(err) => {
                        DispatchResult::Respond(success_response(id, tool_error(err.to_string())))
                    }
                }
            }
            _ => DispatchResult::Respond(error_response(
                id,
                -32601,
                format!("method '{}' not found", method),
            )),
        };

        match result {
            DispatchResult::Respond(response) => {
                write_message(writer, &response, framing)?;
            }
            DispatchResult::NeedsApproval { flow, pending } => {
                let accepted = match flow {
                    ApprovalFlow::Elicitation {
                        request_id,
                        request,
                    } => self.request_elicitation_approval(
                        reader, writer, framing, &pending, request_id, request,
                    )?,
                    ApprovalFlow::Local => self.local_approval.request(&pending.approval)?,
                };

                if accepted {
                    self.checker.cache_approval(&pending.operation);
                    let exec_result = self.execute_tool(&pending.context, &pending.tool_call)?;
                    let response = success_response(pending.id, exec_result);
                    write_message(writer, &response, framing)?;
                } else {
                    let response = error_response(
                        pending.id,
                        -32000,
                        "operation declined by user".to_string(),
                    );
                    write_message(writer, &response, framing)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn next_message<R>(
        &mut self,
        reader: &mut BufReader<R>,
    ) -> Result<Option<IncomingMessage>>
    where
        R: Read,
    {
        if let Some(message) = self.pending_messages.pop_front() {
            return Ok(Some(message));
        }

        read_message(reader)
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
                            "timeout_secs": { "type": "integer", "minimum": 1 }
                        },
                        "required": ["session_id", "command"],
                        "additionalProperties": false
                    }
                },
                {
                    "name": "upload_file",
                    "description": "Upload a local file to a remote path over SFTP.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "session_id": { "type": "string" },
                            "local_path": { "type": "string" },
                            "remote_path": { "type": "string" },
                            "overwrite": { "type": "boolean" }
                        },
                        "required": ["session_id", "local_path", "remote_path"],
                        "additionalProperties": false
                    }
                },
                {
                    "name": "download_file",
                    "description": "Download a remote file over SFTP to a local path.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "session_id": { "type": "string" },
                            "remote_path": { "type": "string" },
                            "local_path": { "type": "string" }
                        },
                        "required": ["session_id", "remote_path"],
                        "additionalProperties": false
                    }
                },
                {
                    "name": "upload_local_file",
                    "description": "Upload a local file to a remote path over SFTP.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "session_id": { "type": "string" },
                            "local_path": { "type": "string" },
                            "remote_path": { "type": "string" },
                            "overwrite": { "type": "boolean" }
                        },
                        "required": ["session_id", "local_path", "remote_path"],
                        "additionalProperties": false
                    }
                },
                {
                    "name": "download_to_local",
                    "description": "Download a remote file over SFTP to a local file path.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "session_id": { "type": "string" },
                            "remote_path": { "type": "string" },
                            "local_path": { "type": "string" },
                            "overwrite": { "type": "boolean" }
                        },
                        "required": ["session_id", "remote_path", "local_path"],
                        "additionalProperties": false
                    }
                },
                {
                    "name": "close_session",
                    "description": "Close an active SSH session.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "session_id": { "type": "string" }
                        },
                        "required": ["session_id"],
                        "additionalProperties": false
                    }
                },
                {
                    "name": "sudo",
                    "description": "Execute a command with sudo privileges using a system password dialog.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "session_id": { "type": "string" },
                            "command": { "type": "string" },
                            "timeout_secs": { "type": "integer", "minimum": 1 }
                        },
                        "required": ["session_id", "command"],
                        "additionalProperties": false
                    }
                }
            ]
        })
    }

    fn handle_tool_call(
        &self,
        request_context: RequestContext,
        params: Value,
        id: Value,
    ) -> Result<DispatchResult> {
        let tool_call: ToolCall =
            serde_json::from_value(params).context("invalid tools/call params")?;

        if self.whitelist_mode == WhitelistMode::Off {
            let result = self.execute_tool(&request_context, &tool_call)?;
            return Ok(DispatchResult::Respond(success_response(id, result)));
        }

        let ctx = self.build_context(&tool_call)?;

        let check_result = self.checker.check(&ctx)?;
        match check_result {
            RuleDecision::Allow => {
                eprintln!(
                    "[xiic-ssh-mcp] Whitelist ALLOW for tool='{}' cmd='{}'",
                    ctx.tool_name,
                    ctx.command.as_deref().unwrap_or("-"),
                );
                let result = self.execute_tool(&request_context, &tool_call)?;
                Ok(DispatchResult::Respond(success_response(id, result)))
            }
            RuleDecision::Deny(reason) => {
                eprintln!(
                    "[xiic-ssh-mcp] Whitelist DENY for tool='{}': {}",
                    ctx.tool_name, reason
                );
                Ok(DispatchResult::Respond(error_response(id, -32001, reason)))
            }
            RuleDecision::NeedsApproval => {
                let flow = match self.approval_flow_for(&ctx) {
                    Ok(flow) => flow,
                    Err(err) => {
                        return Ok(DispatchResult::Respond(error_response(
                            id,
                            -32002,
                            err.to_string(),
                        )));
                    }
                };
                let approval = ApprovalOperationMetadata::from(&ctx);
                let pending = Box::new(PendingToolCall {
                    id,
                    tool_call,
                    operation: ctx,
                    approval,
                    context: request_context,
                });

                Ok(DispatchResult::NeedsApproval { flow, pending })
            }
        }
    }

    fn approval_flow_for(&self, ctx: &OperationContext) -> Result<ApprovalFlow> {
        match self.approval_mode {
            ApprovalMode::Local => Ok(ApprovalFlow::Local),
            ApprovalMode::Auto => {
                if crate::settings::load_settings().use_system_approval
                    || !self.client_supports_elicitation
                {
                    Ok(ApprovalFlow::Local)
                } else {
                    Ok(self.build_elicitation_flow(ctx))
                }
            }
            ApprovalMode::Elicitation => {
                if self.client_supports_elicitation {
                    Ok(self.build_elicitation_flow(ctx))
                } else {
                    bail!(
                        "approval mode 'elicitation' requires a client that advertises the MCP elicitation capability"
                    )
                }
            }
        }
    }

    fn build_elicitation_flow(&self, ctx: &OperationContext) -> ApprovalFlow {
        let request_id = Value::String(Uuid::new_v4().to_string());
        let details = json!({
            "tool_name": ctx.tool_name,
            "command": ctx.command,
            "remote_path": ctx.remote_path,
            "local_path": ctx.local_path,
            "instance_id": ctx.instance_id,
        });
        let request = json!({
            "jsonrpc": "2.0",
            "id": request_id,
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

        ApprovalFlow::Elicitation {
            request_id,
            request,
        }
    }

    fn request_elicitation_approval<R, W>(
        &mut self,
        reader: &mut BufReader<R>,
        writer: &mut W,
        framing: MessageFraming,
        pending: &PendingToolCall,
        request_id: Value,
        request: Value,
    ) -> Result<bool>
    where
        R: Read,
        W: Write,
    {
        eprintln!(
            "[xiic-ssh-mcp] Sending elicitation for tool='{}'",
            pending.tool_call.name
        );
        write_message(writer, &request, framing)?;

        loop {
            let message = read_message(reader)?
                .ok_or_else(|| anyhow!("stdin closed while waiting for elicitation response"))?;

            if message.payload.get("id") == Some(&request_id) {
                if message.payload.get("error").is_some() {
                    return Ok(false);
                }

                let result = message
                    .payload
                    .get("result")
                    .and_then(|result| result.get("action"))
                    .and_then(Value::as_str);
                return Ok(matches!(result, Some("accept")));
            }

            if let Some(method) = message.payload.get("method").and_then(Value::as_str) {
                if message.payload.get("id").is_none() {
                    let params = message
                        .payload
                        .get("params")
                        .cloned()
                        .unwrap_or_else(|| json!({}));
                    self.handle_notification(method, params)?;
                    continue;
                }

                if method == "ping" {
                    if let Some(id) = message.payload.get("id").cloned() {
                        write_message(writer, &success_response(id, json!({})), message.framing)?;
                    }
                    continue;
                }
            }

            self.pending_messages.push_back(message);
        }
    }

    fn build_context(&self, tool_call: &ToolCall) -> Result<OperationContext> {
        match tool_call.name.as_str() {
            "list_servers" => Ok(OperationContext {
                tool_name: "list_servers".into(),
                command: None,
                remote_path: None,
                local_path: None,
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
                    remote_path: None,
                    local_path: None,
                    instance_id: Some(args.instance_id),
                })
            }
            "execute_command" => {
                let args: ExecuteCommandArgs = deserialize_args(tool_call.arguments.clone())?;
                let instance_id = self.lookup_session_instance(&args.session_id)?;
                Ok(OperationContext {
                    tool_name: "execute_command".into(),
                    command: Some(args.command),
                    remote_path: None,
                    local_path: None,
                    instance_id: Some(instance_id),
                })
            }
            "upload_file" => {
                let args: UploadFileArgs = deserialize_args(tool_call.arguments.clone())?;
                let instance_id = self.lookup_session_instance(&args.session_id)?;
                Ok(OperationContext {
                    tool_name: "upload_file".into(),
                    command: None,
                    remote_path: Some(args.remote_path),
                    local_path: Some(args.local_path),
                    instance_id: Some(instance_id),
                })
            }
            "download_file" => {
                let args: DownloadFileArgs = deserialize_args(tool_call.arguments.clone())?;
                let instance_id = self.lookup_session_instance(&args.session_id)?;
                Ok(OperationContext {
                    tool_name: "download_file".into(),
                    command: None,
                    remote_path: Some(args.remote_path),
                    local_path: args.local_path,
                    instance_id: Some(instance_id),
                })
            }
            "upload_local_file" => {
                let args: UploadLocalFileArgs = deserialize_args(tool_call.arguments.clone())?;
                let instance_id = self.lookup_session_instance(&args.session_id)?;
                Ok(OperationContext {
                    tool_name: "upload_local_file".into(),
                    command: None,
                    remote_path: Some(args.remote_path),
                    local_path: Some(args.local_path),
                    instance_id: Some(instance_id),
                })
            }
            "download_to_local" => {
                let args: DownloadToLocalArgs = deserialize_args(tool_call.arguments.clone())?;
                let instance_id = self.lookup_session_instance(&args.session_id)?;
                Ok(OperationContext {
                    tool_name: "download_to_local".into(),
                    command: None,
                    remote_path: Some(args.remote_path),
                    local_path: Some(args.local_path),
                    instance_id: Some(instance_id),
                })
            }
            "close_session" => {
                let args: CloseSessionArgs = deserialize_args(tool_call.arguments.clone())?;
                let instance_id = self.lookup_session_instance(&args.session_id)?;
                Ok(OperationContext {
                    tool_name: "close_session".into(),
                    command: None,
                    remote_path: None,
                    local_path: None,
                    instance_id: Some(instance_id),
                })
            }
            "sudo" => {
                let args: SudoCommandArgs = deserialize_args(tool_call.arguments.clone())?;
                let instance_id = self.lookup_session_instance(&args.session_id)?;
                Ok(OperationContext {
                    tool_name: "sudo".into(),
                    command: Some(format!("sudo {}", args.command)),
                    remote_path: None,
                    local_path: None,
                    instance_id: Some(instance_id),
                })
            }
            _ => bail!("unknown tool '{}'", tool_call.name),
        }
    }

    fn lookup_session_instance(&self, session_id: &str) -> Result<String> {
        self.core.get_session_instance_id(session_id)
    }

    fn execute_tool(
        &self,
        request_context: &RequestContext,
        tool_call: &ToolCall,
    ) -> Result<Value> {
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
                let result = self
                    .core
                    .create_session(request_context, &args.instance_id)?;
                tool_success(result)
            }
            "execute_command" => {
                let args: ExecuteCommandArgs = deserialize_args(tool_call.arguments.clone())?;
                let result = self.core.execute_command(request_context, args)?;
                tool_success(result)
            }
            "upload_file" => {
                let args: UploadFileArgs = deserialize_args(tool_call.arguments.clone())?;
                let result = self.core.upload_file(request_context, args)?;
                tool_success(result)
            }
            "download_file" => {
                let args: DownloadFileArgs = deserialize_args(tool_call.arguments.clone())?;
                let result = self.core.download_file(request_context, args)?;
                tool_success(result)
            }
            "upload_local_file" => {
                let args: UploadLocalFileArgs = deserialize_args(tool_call.arguments.clone())?;
                let result = self.core.upload_local_file(request_context, args)?;
                tool_success(result)
            }
            "download_to_local" => {
                let args: DownloadToLocalArgs = deserialize_args(tool_call.arguments.clone())?;
                let result = self.core.download_to_local(request_context, args)?;
                tool_success(result)
            }
            "close_session" => {
                let args: CloseSessionArgs = deserialize_args(tool_call.arguments.clone())?;
                let result = self.core.close_session(request_context, &args.session_id)?;
                tool_success(result)
            }
            "sudo" => {
                let args: SudoCommandArgs = deserialize_args(tool_call.arguments.clone())?;
                let result = self.core.sudo_command(request_context, args)?;
                tool_success(result)
            }
            _ => bail!("unknown tool '{}'", tool_call.name),
        }
    }
}

fn deserialize_args<T>(value: Value) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value).context("invalid tool arguments")
}

fn has_elicitation_capability(capabilities: Option<&Value>) -> bool {
    capabilities
        .and_then(|capabilities| capabilities.get("elicitation"))
        .is_some()
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
    upload_local: UploadLocalFileResult,
    download_local: DownloadToLocalResult,
    close: crate::models::CloseSessionResult,
) {
    let _ = (
        create,
        exec,
        upload,
        download,
        upload_local,
        download_local,
        close,
    );
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};
    use std::path::PathBuf;
    use std::sync::Arc;

    use serde_json::json;

    use crate::app_core::{DEFAULT_KEYRING_SERVICE, DesktopCore};
    use crate::models::{ApprovalMode, RequestContext, WhitelistMode};

    use super::{McpServer, MessageFraming, deserialize_args, read_message, write_message};

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
    fn resources_list_returns_empty_resources() {
        let mut server = test_server();
        let mut reader = BufReader::new(Cursor::new(Vec::<u8>::new()));
        let mut output = Vec::new();
        server
            .dispatch_with_context(
                test_context(),
                json!({
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "resources/list",
                    "params": {}
                }),
                MessageFraming::Newline,
                &mut reader,
                &mut output,
            )
            .unwrap();

        let parsed: serde_json::Value =
            serde_json::from_slice(output.strip_suffix(b"\n").unwrap()).unwrap();
        assert_eq!(parsed["id"], 7);
        assert_eq!(parsed["result"]["resources"], json!([]));
    }

    #[test]
    fn execute_command_schema_does_not_require_command_description() {
        let server = test_server();
        let tools = server.handle_tools_list();
        let execute = tools["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "execute_command")
            .unwrap();

        assert!(
            execute["inputSchema"]["properties"]
                .get("command_description")
                .is_none()
        );
    }

    #[test]
    fn execute_command_args_deserialize_without_command_description() {
        let args: crate::models::ExecuteCommandArgs = deserialize_args(json!({
            "session_id": "session-1",
            "command": "uname -a"
        }))
        .unwrap();

        assert_eq!(args.session_id, "session-1");
        assert_eq!(args.command, "uname -a");
    }

    #[test]
    fn forced_elicitation_requires_client_capability() {
        let server = test_server_with_mode(ApprovalMode::Elicitation);
        let err = server
            .approval_flow_for(&crate::models::OperationContext {
                tool_name: "execute_command".to_string(),
                command: Some("uname -a".to_string()),
                remote_path: None,
                local_path: None,
                instance_id: Some("dev-server".to_string()),
            })
            .unwrap_err();

        assert!(err.to_string().contains("elicitation"));
    }

    #[test]
    fn elicitation_wait_matches_response_id_and_preserves_other_messages() {
        let mut server = test_server_with_mode(ApprovalMode::Elicitation);
        let mut init_reader = BufReader::new(Cursor::new(Vec::<u8>::new()));
        let mut init_output = Vec::new();
        server
            .dispatch_with_context(
                test_context(),
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "elicitation": {}
                        }
                    }
                }),
                MessageFraming::Newline,
                &mut init_reader,
                &mut init_output,
            )
            .unwrap();

        let queued_tool_response = json!({
            "jsonrpc": "2.0",
            "id": 999,
            "result": {}
        });
        let ping = json!({
            "jsonrpc": "2.0",
            "id": 100,
            "method": "ping",
            "params": {}
        });
        let accept = json!({
            "jsonrpc": "2.0",
            "id": "elicitation-id",
            "result": {
                "action": "accept"
            }
        });
        let mut reader = BufReader::new(Cursor::new(format!(
            "{}\n{}\n{}\n",
            queued_tool_response, ping, accept
        )));
        let mut output = Vec::new();
        let pending = test_pending_tool_call();

        let accepted = server
            .request_elicitation_approval(
                &mut reader,
                &mut output,
                MessageFraming::Newline,
                &pending,
                json!("elicitation-id"),
                json!({
                    "jsonrpc": "2.0",
                    "id": "elicitation-id",
                    "method": "elicitation/create",
                    "params": {}
                }),
            )
            .unwrap();

        assert!(accepted);

        let mut output_reader = BufReader::new(Cursor::new(output));
        let elicitation_request = read_message(&mut output_reader).unwrap().unwrap();
        assert_eq!(elicitation_request.payload["method"], "elicitation/create");
        let ping_response = read_message(&mut output_reader).unwrap().unwrap();
        assert_eq!(ping_response.payload["id"], 100);
        assert!(read_message(&mut output_reader).unwrap().is_none());

        let queued = server.next_message(&mut reader).unwrap().unwrap();
        assert_eq!(queued.payload, queued_tool_response);
    }

    fn test_server() -> McpServer {
        test_server_with_mode(ApprovalMode::Auto)
    }

    fn test_server_with_mode(approval_mode: ApprovalMode) -> McpServer {
        let db_path = PathBuf::from(format!(
            "/private/tmp/xiic-ssh-mcp-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let core = Arc::new(
            DesktopCore::new(db_path.clone(), DEFAULT_KEYRING_SERVICE)
                .expect("test core should initialize"),
        );
        let server = McpServer::new(core, WhitelistMode::Strict, approval_mode, None);
        let _ = std::fs::remove_file(db_path);
        server
    }

    fn test_pending_tool_call() -> crate::models::PendingToolCall {
        let tool_call = crate::models::ToolCall {
            name: "create_session".to_string(),
            arguments: json!({
                "instance_id": "dev-server"
            }),
        };
        let operation = crate::models::OperationContext {
            tool_name: "create_session".to_string(),
            command: None,
            remote_path: None,
            local_path: None,
            instance_id: Some("dev-server".to_string()),
        };
        crate::models::PendingToolCall {
            id: json!(7),
            tool_call,
            approval: crate::models::ApprovalOperationMetadata::from(&operation),
            operation,
            context: test_context(),
        }
    }

    fn test_context() -> RequestContext {
        RequestContext {
            client_id: "test-client".to_string(),
            client_session_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}
