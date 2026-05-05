#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::Arc;

use tauri::{Emitter, Manager, State};
use xiic_ssh_mcp::app_core::{DEFAULT_KEYRING_SERVICE, DesktopCore};
use xiic_ssh_mcp::local_ipc::{LOG_NOTIFICATION_PAYLOAD, default_approval_endpoint, default_notify_endpoint, remove_stale_endpoint};
use xiic_ssh_mcp::models::{
    InstanceDraft, InstanceSummary, McpConfigBundle, OperationLogEntry, TestConnectionResult,
};
use xiic_ssh_mcp::paths::shared_app_data_dir;

struct DesktopState {
    core: Arc<DesktopCore>,
    mcp_config: McpConfigBundle,
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
fn get_settings() -> Result<xiic_ssh_mcp::settings::AppSettings, String> {
    Ok(xiic_ssh_mcp::settings::load_settings())
}

#[tauri::command]
fn save_settings(settings: xiic_ssh_mcp::settings::AppSettings) -> Result<(), String> {
    xiic_ssh_mcp::settings::save_settings(&settings).map_err(|err| err.to_string())
}

/// 重启 MCP 服务器：杀死残留进程 + 清理 stale socket 文件。
/// IDE 检测到 MCP 进程退出后会自动重新拉起。
#[tauri::command]
fn restart_mcp() -> Result<String, String> {
    eprintln!("[xiic-ssh] 用户触发了 MCP 重启");

    // 1. 清理残留的 MCP 子进程
    kill_mcp_processes();

    // 2. 清理 stale socket 文件
    let data_dir = xiic_ssh_mcp::paths::shared_app_data_dir().map_err(|e| e.to_string())?;
    let notify = default_notify_endpoint(&data_dir);
    let approval = default_approval_endpoint(&data_dir);
    remove_stale_endpoint(&notify);
    remove_stale_endpoint(&approval);

    eprintln!("[xiic-ssh] MCP 重启完成，IDE 将在几秒后自动重连");
    Ok("MCP 服务器已重启，IDE 将在几秒后自动重新连接。".to_string())
}

/// 杀死所有 `xiic-ssh-mcp` 进程（排除当前进程）。
#[cfg(unix)]
fn kill_mcp_processes() {
    let current_pid = std::process::id();
    let output = match std::process::Command::new("pgrep")
        .args(["-f", "xiic-ssh-mcp"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return,
    };
    if !output.status.success() {
        return;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let pid: u32 = match line.trim().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if pid != current_pid {
            let _ = std::process::Command::new("kill")
                .args([&pid.to_string()])
                .status();
            eprintln!("[xiic-ssh] 已杀掉 MCP 进程 (pid={pid})");
        }
    }
}

#[cfg(windows)]
fn kill_mcp_processes() {
    let output = match std::process::Command::new("taskkill")
        .args(["/F", "/IM", "xiic-ssh-mcp.exe"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return,
    };
    if output.status.success() {
        eprintln!("[xiic-ssh] 已 Windows 上杀掉 MCP 进程");
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(move |app| {
            let (core, db_path, notify_endpoint, approval_endpoint) = build_core()?;
            let helper_path = resolve_stdio_helper_path(std::env::current_exe()?);
            let mcp_config = core.mcp_config_bundle(
                &helper_path.to_string_lossy(),
                &db_path.to_string_lossy(),
                DEFAULT_KEYRING_SERVICE,
                Some(&notify_endpoint),
                Some(&approval_endpoint),
            )?;

            start_notify_listener(app.handle().clone(), notify_endpoint);

            app.manage(DesktopState { core, mcp_config });
            show_main_window(app.handle());
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
            get_settings,
            save_settings,
            restart_mcp
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_, _| {});
}

fn build_core() -> anyhow::Result<(Arc<DesktopCore>, PathBuf, String, String)> {
    let data_dir = shared_app_data_dir()?;
    std::fs::create_dir_all(&data_dir)?;

    let notify_endpoint = default_notify_endpoint(&data_dir);
    let approval_endpoint = default_approval_endpoint(&data_dir);
    remove_stale_endpoint(&notify_endpoint);
    remove_stale_endpoint(&approval_endpoint);

    let database_path = data_dir.join("instances.sqlite3");
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

fn resolve_stdio_helper_path(current_exe: PathBuf) -> PathBuf {
    let helper_name = if cfg!(target_os = "windows") {
        "xiic-ssh-mcp.exe"
    } else {
        "xiic-ssh-mcp"
    };

    if let Some(parent) = current_exe.parent() {
        let sibling = parent.join(helper_name);
        if sibling.exists() {
            return sibling;
        }
    }

    current_exe
}
