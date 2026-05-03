use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use async_stream::stream;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::app_core::DesktopCore;
use crate::models::{DownloadFileArgs, ExecuteCommandArgs, UploadFileArgs};

const DEFAULT_PROTOCOL_VERSION: &str = "2025-03-26";
const SERVER_NAME: &str = "xiic-ssh-manager";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone)]
pub struct McpServiceState {
    core: Arc<DesktopCore>,
    sse_sessions: Arc<Mutex<HashMap<String, broadcast::Sender<String>>>>,
}

impl McpServiceState {
    pub fn new(core: Arc<DesktopCore>) -> Self {
        Self {
            core,
            sse_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

pub async fn run_mcp_service(core: Arc<DesktopCore>, bind_address: SocketAddr) -> Result<()> {
    let state = McpServiceState::new(core);
    let app = Router::new()
        .route("/health", get(health))
        .route("/mcp", post(http_mcp))
        .route("/sse", get(sse_connect))
        .route("/sse/message", post(sse_message))
        .with_state(state);

    let listener = TcpListener::bind(bind_address)
        .await
        .with_context(|| format!("failed to bind MCP service at {}", bind_address))?;

    axum::serve(listener, app)
        .await
        .context("MCP service exited unexpectedly")
}

async fn health() -> impl IntoResponse {
    Json(json!({ "ok": true }))
}

async fn http_mcp(
    State(state): State<McpServiceState>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    match handle_json_rpc(&state.core, payload).await {
        Ok(Some(response)) => Json(response).into_response(),
        Ok(None) => Json(json!({ "accepted": true })).into_response(),
        Err(err) => Json(error_response(json!(null), -32603, err.to_string())).into_response(),
    }
}

async fn sse_connect(
    State(state): State<McpServiceState>,
) -> Sse<impl futures_core::Stream<Item = Result<Event, Infallible>>> {
    let session_id = Uuid::new_v4().to_string();
    let (sender, mut receiver) = broadcast::channel::<String>(64);
    state
        .sse_sessions
        .lock()
        .expect("sse session lock poisoned")
        .insert(session_id.clone(), sender);

    let endpoint = format!("/sse/message?session_id={session_id}");
    let sessions = state.sse_sessions.clone();
    let stream = stream! {
        yield Ok(Event::default().event("endpoint").data(endpoint));
        while let Ok(message) = receiver.recv().await {
            yield Ok(Event::default().event("message").data(message));
        }
        let _ = sessions.lock().map(|mut sessions| sessions.remove(&session_id));
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[derive(Deserialize)]
struct SseQuery {
    session_id: String,
}

async fn sse_message(
    State(state): State<McpServiceState>,
    Query(query): Query<SseQuery>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let sender = {
        let sessions = state.sse_sessions.lock().expect("sse session lock poisoned");
        sessions.get(&query.session_id).cloned()
    };

    let Some(sender) = sender else {
        return Json(json!({ "error": "unknown SSE session" })).into_response();
    };

    match handle_json_rpc(&state.core, payload).await {
        Ok(Some(response)) => match serde_json::to_string(&response) {
            Ok(message) => {
                let _ = sender.send(message);
                Json(json!({ "accepted": true })).into_response()
            }
            Err(err) => Json(json!({ "error": err.to_string() })).into_response(),
        },
        Ok(None) => Json(json!({ "accepted": true })).into_response(),
        Err(err) => Json(json!({ "error": err.to_string() })).into_response(),
    }
}

async fn handle_json_rpc(core: &Arc<DesktopCore>, message: Value) -> Result<Option<Value>> {
    let method = message
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("incoming JSON-RPC message is missing method"))?;
    let id = message.get("id").cloned();
    let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

    if id.is_none() {
        handle_notification(method, params)?;
        return Ok(None);
    }

    let id = id.expect("checked is_some");
    let response = match method {
        "initialize" => match handle_initialize(params) {
            Ok(result) => success_response(id, result),
            Err(err) => error_response(id, -32602, err.to_string()),
        },
        "ping" => success_response(id, json!({})),
        "tools/list" => success_response(id, tools_list()),
        "tools/call" => match handle_tool_call(core, params) {
            Ok(result) => success_response(id, result),
            Err(err) => success_response(id, tool_error(err.to_string())),
        },
        _ => error_response(id, -32601, format!("method '{}' not found", method)),
    };

    Ok(Some(response))
}

fn handle_notification(method: &str, _params: Value) -> Result<()> {
    match method {
        "notifications/initialized" | "notifications/cancelled" => Ok(()),
        _ => Ok(()),
    }
}

fn handle_initialize(params: Value) -> Result<Value> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct InitializeParams {
        protocol_version: Option<String>,
    }

    let params: InitializeParams =
        serde_json::from_value(params).context("invalid initialize params")?;

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
        "instructions": "Local desktop SSH connection manager with MCP tools for create_session, execute_command, upload_file, and download_file."
    }))
}

fn tools_list() -> Value {
    json!({
        "tools": [
            {
                "name": "create_session",
                "description": "Create an SSH session for a saved instance_id.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "instance_id": { "type": "string" }
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

fn handle_tool_call(core: &Arc<DesktopCore>, params: Value) -> Result<Value> {
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

            let args: Args = serde_json::from_value(tool_call.arguments)
                .context("invalid create_session arguments")?;
            tool_success(core.create_session(&args.instance_id)?)
        }
        "execute_command" => {
            let args: ExecuteCommandArgs =
                serde_json::from_value(tool_call.arguments).context("invalid execute_command arguments")?;
            tool_success(core.execute_command(args)?)
        }
        "upload_file" => {
            let args: UploadFileArgs =
                serde_json::from_value(tool_call.arguments).context("invalid upload_file arguments")?;
            tool_success(core.upload_file(args)?)
        }
        "download_file" => {
            let args: DownloadFileArgs =
                serde_json::from_value(tool_call.arguments).context("invalid download_file arguments")?;
            tool_success(core.download_file(args)?)
        }
        _ => bail!("unknown tool '{}'", tool_call.name),
    }
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
