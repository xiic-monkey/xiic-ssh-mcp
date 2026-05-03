use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::app_core::DesktopCore;
use crate::models::{
    CreateSessionResult, DownloadFileArgs, DownloadFileResult, ExecuteCommandArgs,
    ExecuteCommandResult, UploadFileArgs, UploadFileResult,
};

const DEFAULT_PROTOCOL_VERSION: &str = "2025-03-26";
const SERVER_NAME: &str = "xiic-ssh-mcp";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct McpServer {
    core: Arc<DesktopCore>,
    protocol_version: String,
}

impl McpServer {
    pub fn new(core: Arc<DesktopCore>) -> Self {
        Self {
            core,
            protocol_version: DEFAULT_PROTOCOL_VERSION.to_string(),
        }
    }

    pub fn run(&mut self) -> Result<()> {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut reader = BufReader::new(stdin.lock());
        let mut writer = stdout.lock();

        while let Some(message) = read_message(&mut reader)? {
            if let Some(response) = self.handle_message(message)? {
                write_message(&mut writer, &response)?;
            }
        }

        Ok(())
    }

    fn handle_message(&mut self, message: Value) -> Result<Option<Value>> {
        let method = message
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("incoming JSON-RPC message is missing method"))?;

        let id = message.get("id").cloned();
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

        if id.is_none() {
            self.handle_notification(method, params)?;
            return Ok(None);
        }

        let id = id.expect("checked is_some");
        let response = match method {
            "initialize" => match self.handle_initialize(params) {
                Ok(result) => success_response(id, result),
                Err(err) => error_response(id, -32602, err.to_string()),
            },
            "ping" => success_response(id, json!({})),
            "tools/list" => success_response(id, self.handle_tools_list()),
            "tools/call" => match self.handle_tool_call(params) {
                Ok(result) => success_response(id, result),
                Err(err) => success_response(id, tool_error(err.to_string())),
            },
            _ => error_response(id, -32601, format!("method '{}' not found", method)),
        };

        Ok(Some(response))
    }

    fn handle_notification(&mut self, method: &str, _params: Value) -> Result<()> {
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
        }

        let params: InitializeParams =
            serde_json::from_value(params).context("invalid initialize params")?;
        if let Some(protocol_version) = params.protocol_version {
            self.protocol_version = protocol_version;
        }

        Ok(json!({
            "protocolVersion": self.protocol_version,
            "capabilities": {
                "tools": {
                    "listChanged": false
                }
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION
            },
            "instructions": "Manage SSH sessions stored by the local Xiic SSH Manager desktop app."
        }))
    }

    fn handle_tools_list(&self) -> Value {
        json!({
            "tools": [
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

    fn handle_tool_call(&mut self, params: Value) -> Result<Value> {
        #[derive(Deserialize)]
        struct ToolCall {
            name: String,
            #[serde(default)]
            arguments: Value,
        }

        let tool_call: ToolCall =
            serde_json::from_value(params).context("invalid tools/call params")?;

        match tool_call.name.as_str() {
            "create_session" => {
                #[derive(Deserialize)]
                struct Args {
                    instance_id: String,
                }

                let args: Args = deserialize_args(tool_call.arguments)?;
                let result = self.core.create_session(&args.instance_id)?;
                Ok(tool_success(result)?)
            }
            "execute_command" => {
                let args: ExecuteCommandArgs = deserialize_args(tool_call.arguments)?;
                let result = self.core.execute_command(args)?;
                Ok(tool_success(result)?)
            }
            "upload_file" => {
                let args: UploadFileArgs = deserialize_args(tool_call.arguments)?;
                let result = self.core.upload_file(args)?;
                Ok(tool_success(result)?)
            }
            "download_file" => {
                let args: DownloadFileArgs = deserialize_args(tool_call.arguments)?;
                let result = self.core.download_file(args)?;
                Ok(tool_success(result)?)
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

fn read_message<R>(reader: &mut BufReader<R>) -> Result<Option<Value>>
where
    R: Read,
{
    let mut content_length = None;
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader
            .read_line(&mut line)
            .context("failed to read MCP header")?;
        if bytes_read == 0 {
            return Ok(None);
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
    Ok(Some(value))
}

fn write_message<W>(writer: &mut W, payload: &Value) -> Result<()>
where
    W: Write,
{
    let body = serde_json::to_vec(payload).context("failed to serialize MCP response")?;
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())
        .context("failed to write MCP response header")?;
    writer
        .write_all(&body)
        .context("failed to write MCP response body")?;
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
