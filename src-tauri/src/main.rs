#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};

use anyhow::Context;
use tauri::{Emitter, Manager, State};
use xiic_ssh_mcp::app_core::{DEFAULT_KEYRING_SERVICE, DesktopCore};
use xiic_ssh_mcp::approval::ApprovalQueue;
use xiic_ssh_mcp::local_ipc::{
    LOG_NOTIFICATION_PAYLOAD, default_approval_endpoint, default_notify_endpoint,
    remove_stale_endpoint,
};
use xiic_ssh_mcp::models::{
    ApprovalRequest, InstanceDraft, InstanceSummary, McpConfigBundle, OperationLogEntry,
    TestConnectionResult,
};

type ApprovalState = Arc<Mutex<ApprovalQueue>>;

struct DesktopState {
    core: Arc<DesktopCore>,
    mcp_config: McpConfigBundle,
    approvals: ApprovalState,
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
fn get_active_approval(
    state: State<'_, DesktopState>,
) -> Result<Option<xiic_ssh_mcp::models::ApprovalRequestedEvent>, String> {
    let approvals = state
        .approvals
        .lock()
        .map_err(|_| "approval queue lock poisoned".to_string())?;
    Ok(approvals.current_event())
}

#[tauri::command]
fn resolve_approval(
    app: tauri::AppHandle,
    state: State<'_, DesktopState>,
    request_id: String,
    accepted: bool,
) -> Result<(), String> {
    let (resolved, next_event) = {
        let mut approvals = state
            .approvals
            .lock()
            .map_err(|_| "approval queue lock poisoned".to_string())?;
        approvals
            .resolve(&request_id, accepted)
            .map_err(|err| err.to_string())?
    };

    emit_to_approval_window(&app, "approval-resolved", resolved).map_err(|err| err.to_string())?;

    if let Some(next_event) = next_event {
        focus_approval_window(&app);
        emit_to_approval_window(&app, "approval-requested", next_event)
            .map_err(|err| err.to_string())?;
    } else if let Some(window) = app.get_webview_window("approval") {
        let _ = window.set_always_on_top(false);
        let _ = window.hide();
    }

    Ok(())
}

fn main() {
    let approvals: ApprovalState = Arc::new(Mutex::new(ApprovalQueue::new()));
    let approvals_for_setup = approvals.clone();
    let approvals_for_exit = approvals.clone();
    let approval_only = std::env::args().any(|arg| arg == "--approval-only");

    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(move |app| {
            let (core, db_path, notify_endpoint, approval_endpoint) =
                build_core(app.handle().clone())?;
            let helper_path = resolve_stdio_helper_path(std::env::current_exe()?);
            let mcp_config = core.mcp_config_bundle(
                &helper_path.to_string_lossy(),
                &db_path.to_string_lossy(),
                DEFAULT_KEYRING_SERVICE,
                Some(&notify_endpoint),
                Some(&approval_endpoint),
            )?;

            start_notify_listener(app.handle().clone(), notify_endpoint.clone());
            start_approval_listener(
                app.handle().clone(),
                approvals_for_setup.clone(),
                approval_endpoint.clone(),
            );

            app.manage(DesktopState {
                core,
                mcp_config,
                approvals: approvals_for_setup.clone(),
            });

            if !approval_only {
                show_main_window(app.handle());
            }

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
            get_active_approval,
            resolve_approval
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(move |_app, event| {
            if matches!(event, tauri::RunEvent::Exit | tauri::RunEvent::ExitRequested { .. })
                && let Ok(mut approvals) = approvals_for_exit.lock()
            {
                approvals.reject_all();
            }
        });
}

fn build_core(
    app: tauri::AppHandle,
) -> anyhow::Result<(Arc<DesktopCore>, PathBuf, String, String)> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    std::fs::create_dir_all(&data_dir)?;

    let notify_endpoint = default_notify_endpoint(&data_dir);
    let approval_endpoint = default_approval_endpoint(&data_dir);
    remove_stale_endpoint(&notify_endpoint);
    remove_stale_endpoint(&approval_endpoint);

    let database_path: PathBuf = data_dir.join("instances.sqlite3");
    let core = DesktopCore::new_with_socket(
        database_path.clone(),
        DEFAULT_KEYRING_SERVICE,
        Some(notify_endpoint.clone()),
    )?;
    Ok((
        Arc::new(core),
        database_path,
        notify_endpoint,
        approval_endpoint,
    ))
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn focus_approval_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("approval") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_always_on_top(true);
        let _ = window.set_focus();
    }
}

fn emit_to_approval_window<S: serde::Serialize + Clone>(
    app: &tauri::AppHandle,
    event: &str,
    payload: S,
) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window("approval") {
        window.emit(event, payload)?;
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn start_notify_listener(app: tauri::AppHandle, endpoint: String) {
    std::thread::spawn(move || {
        use std::os::unix::net::UnixListener;

        let listener = match UnixListener::bind(&endpoint) {
            Ok(listener) => listener,
            Err(err) => {
                eprintln!("[xiic-ssh] failed to bind notify endpoint: {err}");
                return;
            }
        };

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let app = app.clone();
                    std::thread::spawn(move || {
                        if let Err(err) = handle_notify_stream(app, stream) {
                            eprintln!("[xiic-ssh] notify request failed: {err}");
                        }
                    });
                }
                Err(err) => {
                    eprintln!("[xiic-ssh] notify listener error: {err}");
                    break;
                }
            }
        }
    });
}

#[cfg(not(target_os = "windows"))]
fn start_approval_listener(app: tauri::AppHandle, approvals: ApprovalState, endpoint: String) {
    std::thread::spawn(move || {
        use std::os::unix::net::UnixListener;

        let listener = match UnixListener::bind(&endpoint) {
            Ok(listener) => listener,
            Err(err) => {
                eprintln!("[xiic-ssh] failed to bind approval endpoint: {err}");
                if let Ok(mut queue) = approvals.lock() {
                    queue.reject_all();
                }
                return;
            }
        };

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let app = app.clone();
                    let approvals = approvals.clone();
                    std::thread::spawn(move || {
                        if let Err(err) = handle_approval_stream(app, approvals, stream) {
                            eprintln!("[xiic-ssh] approval request failed: {err}");
                        }
                    });
                }
                Err(err) => {
                    eprintln!("[xiic-ssh] approval listener error: {err}");
                    if let Ok(mut queue) = approvals.lock() {
                        queue.reject_all();
                    }
                    break;
                }
            }
        }
    });
}

#[cfg(target_os = "windows")]
fn start_notify_listener(app: tauri::AppHandle, endpoint: String) {
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_io()
            .enable_time()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                eprintln!("[xiic-ssh] failed to create notify runtime: {err}");
                return;
            }
        };

        runtime.block_on(async move {
            if let Err(err) = run_windows_notify_listener(app, endpoint).await {
                eprintln!("[xiic-ssh] notify listener error: {err}");
            }
        });
    });
}

#[cfg(target_os = "windows")]
fn start_approval_listener(app: tauri::AppHandle, approvals: ApprovalState, endpoint: String) {
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_io()
            .enable_time()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                eprintln!("[xiic-ssh] failed to create approval runtime: {err}");
                if let Ok(mut queue) = approvals.lock() {
                    queue.reject_all();
                }
                return;
            }
        };

        runtime.block_on(async move {
            if let Err(err) = run_windows_approval_listener(app, approvals.clone(), endpoint).await
            {
                eprintln!("[xiic-ssh] approval listener error: {err}");
                if let Ok(mut queue) = approvals.lock() {
                    queue.reject_all();
                }
            }
        });
    });
}

#[cfg(not(target_os = "windows"))]
fn handle_notify_stream<S>(app: tauri::AppHandle, stream: S) -> anyhow::Result<()>
where
    S: std::io::Read,
{
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    let _ = reader.read_line(&mut line)?;
    if line.trim().is_empty() || line.trim() == LOG_NOTIFICATION_PAYLOAD {
        let _ = app.emit("log-updated", ());
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn handle_approval_stream<S>(
    app: tauri::AppHandle,
    approvals: ApprovalState,
    mut stream: S,
) -> anyhow::Result<()>
where
    S: std::io::Read + Write,
{
    let request = read_approval_request(&mut stream)?;
    let (tx, rx) = mpsc::sync_channel(1);
    let enqueue = {
        let mut queue = approvals
            .lock()
            .map_err(|_| anyhow::anyhow!("approval queue lock poisoned"))?;
        queue.enqueue(request.clone(), tx)
    };

    if enqueue.activated {
        focus_approval_window(&app);
    }
    emit_to_approval_window(&app, "approval-requested", enqueue.event)?;

    let accepted = rx.recv().unwrap_or(false);
    write_approval_response(&mut stream, &request, accepted)?;
    Ok(())
}

#[cfg(target_os = "windows")]
async fn run_windows_notify_listener(
    app: tauri::AppHandle,
    endpoint: String,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut first_instance = true;
    loop {
        let mut options = ServerOptions::new();
        if first_instance {
            options.first_pipe_instance(true);
        }
        let server = options.create(&endpoint)?;
        first_instance = false;
        server.connect().await?;

        let app = app.clone();
        tokio::spawn(async move {
            let mut line = String::new();
            let mut reader = BufReader::new(server);
            if reader.read_line(&mut line).await.is_ok()
                && (line.trim().is_empty() || line.trim() == LOG_NOTIFICATION_PAYLOAD)
            {
                let _ = app.emit("log-updated", ());
            }
        });
    }
}

#[cfg(target_os = "windows")]
async fn run_windows_approval_listener(
    app: tauri::AppHandle,
    approvals: ApprovalState,
    endpoint: String,
) -> anyhow::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut first_instance = true;
    loop {
        let mut options = ServerOptions::new();
        if first_instance {
            options.first_pipe_instance(true);
        }
        let server = options.create(&endpoint)?;
        first_instance = false;
        server.connect().await?;

        let app = app.clone();
        let approvals = approvals.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_windows_approval_pipe(app, approvals, server).await {
                eprintln!("[xiic-ssh] approval request failed: {err}");
            }
        });
    }
}

#[cfg(target_os = "windows")]
async fn handle_windows_approval_pipe(
    app: tauri::AppHandle,
    approvals: ApprovalState,
    mut server: tokio::net::windows::named_pipe::NamedPipeServer,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let request = {
        let mut line = String::new();
        let mut reader = BufReader::new(&mut server);
        reader.read_line(&mut line).await?;
        serde_json::from_str::<ApprovalRequest>(line.trim())
            .context("failed to decode approval request")?
    };

    let (tx, rx) = mpsc::sync_channel(1);
    let enqueue = {
        let mut queue = approvals
            .lock()
            .map_err(|_| anyhow::anyhow!("approval queue lock poisoned"))?;
        queue.enqueue(request.clone(), tx)
    };

    if enqueue.activated {
        focus_approval_window(&app);
    }
    emit_to_approval_window(&app, "approval-requested", enqueue.event)?;

    let accepted = rx.recv().unwrap_or(false);
    let payload = serde_json::to_string(&approval_response(&request, accepted))?;
    server.write_all(payload.as_bytes()).await?;
    server.write_all(b"\n").await?;
    server.flush().await?;
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn read_approval_request<S>(stream: &mut S) -> anyhow::Result<ApprovalRequest>
where
    S: std::io::Read,
{
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut line)?;
    serde_json::from_str(line.trim()).context("failed to decode approval request")
}

#[cfg(not(target_os = "windows"))]
fn write_approval_response<S>(
    stream: &mut S,
    request: &ApprovalRequest,
    accepted: bool,
) -> anyhow::Result<()>
where
    S: Write,
{
    let payload = serde_json::to_string(&approval_response(request, accepted))?;
    stream.write_all(payload.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

fn approval_response(request: &ApprovalRequest, accepted: bool) -> serde_json::Value {
    serde_json::json!({
        "kind": "approval_response",
        "request_id": request.request_id,
        "accepted": accepted
    })
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
