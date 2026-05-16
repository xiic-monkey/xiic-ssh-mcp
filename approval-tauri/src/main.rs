#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{BufRead, BufReader, Write};
use std::sync::{Arc, Mutex, mpsc};

use anyhow::Context;
use tauri::{Emitter, Manager, State};
use xiic_ssh_mcp::approval::ApprovalQueue;
use xiic_ssh_mcp::local_ipc::{
    APPROVAL_HEALTH_CHECK_KIND, APPROVAL_HEALTH_OK_KIND, approval_server_healthy,
    default_approval_endpoint, remove_stale_endpoint,
};
use xiic_ssh_mcp::models::{ApprovalRequest, ApprovalRequestedEvent};
use xiic_ssh_mcp::paths::shared_app_data_dir;
use xiic_ssh_mcp::single_instance::SingleInstanceGuard;

type ApprovalState = Arc<Mutex<ApprovalQueue>>;

struct AppState {
    approvals: ApprovalState,
    _instance_lock: SingleInstanceGuard,
}

#[tauri::command]
fn get_active_approval(
    state: State<'_, AppState>,
) -> Result<Option<ApprovalRequestedEvent>, String> {
    let approvals = state
        .approvals
        .lock()
        .map_err(|_| "approval queue lock poisoned".to_string())?;
    Ok(approvals.current_event())
}

#[tauri::command]
fn resolve_approval(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
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

    tauri::Builder::default()
        .setup(move |app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let endpoint = approval_endpoint()?;
            let data_dir = shared_app_data_dir()?;
            let instance_lock =
                match SingleInstanceGuard::acquire(&data_dir.join("approval.lock"), || {
                    approval_server_healthy(&endpoint)
                })? {
                    Some(lock) => lock,
                    None => std::process::exit(0),
                };

            remove_stale_endpoint(&endpoint);

            start_approval_listener(app.handle().clone(), approvals_for_setup.clone(), endpoint);

            app.manage(AppState {
                approvals: approvals_for_setup.clone(),
                _instance_lock: instance_lock,
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_active_approval,
            resolve_approval
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(move |_app, event| {
            if matches!(
                event,
                tauri::RunEvent::Exit | tauri::RunEvent::ExitRequested { .. }
            ) && let Ok(mut approvals) = approvals_for_exit.lock()
            {
                approvals.reject_all();
            }
        });
}

fn approval_endpoint() -> anyhow::Result<String> {
    let data_dir = shared_app_data_dir()?;
    std::fs::create_dir_all(&data_dir)?;
    Ok(default_approval_endpoint(&data_dir))
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

        eprintln!("[xiic-ssh] approval listener ready at {endpoint}");

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
fn handle_approval_stream<S>(
    app: tauri::AppHandle,
    approvals: ApprovalState,
    mut stream: S,
) -> anyhow::Result<()>
where
    S: std::io::Read + Write,
{
    let raw = read_raw_request(&mut stream)?;

    // 先检查 kind 字段，避免将非 ApprovalRequest 格式的消息强制转换失败
    let kind: String = serde_json::from_str::<serde_json::Value>(&raw)
        .ok()
        .and_then(|v| v.get("kind").and_then(|k| k.as_str().map(String::from)))
        .unwrap_or_default();

    if kind == APPROVAL_HEALTH_CHECK_KIND {
        stream.write_all(
            serde_json::json!({
                "kind": APPROVAL_HEALTH_OK_KIND
            })
            .to_string()
            .as_bytes(),
        )?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        return Ok(());
    }

    let request: ApprovalRequest =
        serde_json::from_str(&raw).context("failed to decode approval request")?;

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

#[cfg(not(target_os = "windows"))]
fn read_raw_request<S>(stream: &mut S) -> anyhow::Result<String>
where
    S: std::io::Read,
{
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut line)?;
    Ok(line.trim().to_string())
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

    let raw = {
        let mut line = String::new();
        let mut reader = BufReader::new(&mut server);
        reader.read_line(&mut line).await?;
        line.trim().to_string()
    };

    let kind: String = serde_json::from_str::<serde_json::Value>(&raw)
        .ok()
        .and_then(|v| v.get("kind").and_then(|k| k.as_str().map(String::from)))
        .unwrap_or_default();

    if kind == APPROVAL_HEALTH_CHECK_KIND {
        let payload = serde_json::json!({
            "kind": APPROVAL_HEALTH_OK_KIND
        })
        .to_string();
        server.write_all(payload.as_bytes()).await?;
        server.write_all(b"\n").await?;
        server.flush().await?;
        return Ok(());
    }

    let request: ApprovalRequest =
        serde_json::from_str(&raw).context("failed to decode approval request")?;

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
        "accepted": accepted,
    })
}
