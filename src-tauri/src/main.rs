#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tauri::{Emitter, Manager, State};
use xiic_ssh_mcp::app_core::{DEFAULT_KEYRING_SERVICE, DesktopCore};
use xiic_ssh_mcp::models::{
    ApprovalRequest, ApprovalResponse, InstanceDraft, InstanceSummary, McpConfigBundle,
    OperationLogEntry, TestConnectionResult,
};

type ApprovalWaiters = Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>>>;

struct DesktopState {
    core: Arc<DesktopCore>,
    mcp_config: McpConfigBundle,
    approval_waiters: ApprovalWaiters,
}

#[tauri::command]
fn list_instances(state: State<'_, DesktopState>) -> Result<Vec<InstanceSummary>, String> {
    state.core.list_instances().map_err(|err| err.to_string())
}

#[tauri::command]
fn save_instance(
    state: State<'_, DesktopState>,
    draft: InstanceDraft,
) -> Result<InstanceSummary, String> {
    state.core.save_instance(draft).map_err(|err| err.to_string())
}

#[tauri::command]
fn delete_instance(state: State<'_, DesktopState>, instance_id: String) -> Result<(), String> {
    state
        .core
        .delete_instance(&instance_id)
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn test_connection(
    state: State<'_, DesktopState>,
    draft: InstanceDraft,
) -> Result<TestConnectionResult, String> {
    state
        .core
        .test_connection(draft)
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn get_operation_logs(
    state: State<'_, DesktopState>,
    limit: Option<u64>,
) -> Result<Vec<OperationLogEntry>, String> {
    state
        .core
        .get_operation_logs(limit)
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn get_operation_logs_since(
    state: State<'_, DesktopState>,
    since_id: i64,
    limit: Option<u64>,
) -> Result<Vec<OperationLogEntry>, String> {
    state
        .core
        .get_operation_logs_since(since_id, limit.unwrap_or(200))
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn get_mcp_configs(state: State<'_, DesktopState>) -> Result<McpConfigBundle, String> {
    Ok(state.mcp_config.clone())
}

#[tauri::command]
fn resolve_approval(
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    request_id: String,
    accepted: bool,
) -> Result<(), String> {
    let sender = state
        .approval_waiters
        .lock()
        .map_err(|_| "approval waiters lock poisoned".to_string())?
        .remove(&request_id);

    if let Some(sender) = sender {
        let _ = sender.send(accepted);
    }

    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_always_on_top(false);
    }

    Ok(())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let (core, db_path, notify_socket_path) = build_core(app.handle().clone())?;
            let helper_path = resolve_stdio_helper_path(std::env::current_exe()?);
            let notify_socket_str = notify_socket_path.to_string_lossy().to_string();
            let mcp_config = core.mcp_config_bundle(
                &helper_path.to_string_lossy(),
                &db_path.to_string_lossy(),
                DEFAULT_KEYRING_SERVICE,
                Some(&notify_socket_str),
            )?;

            let notify_socket = notify_socket_path.clone();
            let app_handle = app.handle().clone();
            let approval_waiters: ApprovalWaiters = Arc::new(Mutex::new(HashMap::new()));
            let listener_waiters = approval_waiters.clone();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()?;
            std::thread::spawn(move || {
                rt.block_on(async move {
                    let listener = match tokio::net::UnixListener::bind(&notify_socket) {
                        Ok(l) => l,
                        Err(e) => {
                            eprintln!("[xiic-ssh] failed to bind notify socket: {e}");
                            return;
                        }
                    };
                    loop {
                        match listener.accept().await {
                            Ok((stream, _)) => {
                                let app = app_handle.clone();
                                let waiters = listener_waiters.clone();
                                tokio::spawn(async move {
                                    if let Err(err) = handle_notify_socket(app, waiters, stream).await {
                                        eprintln!("[xiic-ssh] notify socket request failed: {err}");
                                    }
                                });
                            }
                            Err(e) => {
                                eprintln!("[xiic-ssh] notify socket error: {e}");
                                break;
                            }
                        }
                    }
                });
            });

            app.manage(DesktopState {
                core,
                mcp_config,
                approval_waiters,
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_instances,
            save_instance,
            delete_instance,
            test_connection,
            get_operation_logs,
            get_operation_logs_since,
            get_mcp_configs,
            resolve_approval
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

async fn handle_notify_socket(
    app: tauri::AppHandle,
    waiters: ApprovalWaiters,
    mut stream: tokio::net::UnixStream,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await?;
    let text = String::from_utf8_lossy(&buffer);
    let trimmed = text.trim();

    if !trimmed.starts_with('{') {
        let _ = app.emit("log-updated", ());
        return Ok(());
    }

    let request: ApprovalRequest = serde_json::from_str(trimmed)?;
    if request.kind != "approval_request" {
        let _ = app.emit("log-updated", ());
        return Ok(());
    }

    let (tx, rx) = tokio::sync::oneshot::channel();
    waiters
        .lock()
        .map_err(|_| anyhow::anyhow!("approval waiters lock poisoned"))?
        .insert(request.request_id.clone(), tx);

    focus_main_window(&app);
    app.emit("approval-requested", request.clone())?;

    let accepted = rx.await.unwrap_or(false);
    let response = ApprovalResponse {
        kind: "approval_response".to_string(),
        request_id: request.request_id,
        accepted,
    };
    let payload = serde_json::to_vec(&response)?;
    stream.write_all(&payload).await?;
    stream.write_all(b"\n").await?;
    stream.shutdown().await?;
    Ok(())
}

fn focus_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_always_on_top(true);
        let _ = window.set_focus();
    }
}

fn build_core(app: tauri::AppHandle) -> anyhow::Result<(Arc<DesktopCore>, PathBuf, PathBuf)> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    std::fs::create_dir_all(&data_dir)?;

    let notify_socket = data_dir.join("notify.sock");
    let _ = std::fs::remove_file(&notify_socket);

    let database_path: PathBuf = data_dir.join("instances.sqlite3");
    let core = DesktopCore::new_with_socket(
        database_path.clone(),
        DEFAULT_KEYRING_SERVICE,
        Some(notify_socket.clone()),
    )?;
    Ok((Arc::new(core), database_path, notify_socket))
}

fn resolve_stdio_helper_path(current_exe: PathBuf) -> PathBuf {
    let helper_name = helper_binary_name();
    let sibling = current_exe.with_file_name(helper_name);
    if sibling.exists() {
        return sibling;
    }

    let Some(profile_dir) = current_exe.parent() else {
        return sibling;
    };
    let Some(profile_name) = profile_dir.file_name() else {
        return sibling;
    };
    let Some(repo_root) = current_exe.ancestors().nth(4) else {
        return sibling;
    };

    let dev_helper = repo_root.join("target").join(profile_name).join(helper_name);
    if dev_helper.exists() {
        return dev_helper;
    }

    sibling
}

fn helper_binary_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "xiic-ssh-mcp.exe"
    }

    #[cfg(not(target_os = "windows"))]
    {
        "xiic-ssh-mcp"
    }
}
