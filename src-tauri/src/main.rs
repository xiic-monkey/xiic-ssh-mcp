#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tauri::{Emitter, Manager, State};
use xiic_ssh_mcp::app_core::{DEFAULT_KEYRING_SERVICE, DesktopCore};
use xiic_ssh_mcp::local_ipc::{
    LOG_NOTIFICATION_PAYLOAD, NOTIFY_HEALTH_CHECK_KIND, NOTIFY_HEALTH_OK_KIND,
    default_approval_endpoint, default_notify_endpoint, notify_server_healthy,
    remove_stale_endpoint,
};
use xiic_ssh_mcp::models::{
    InstanceDraft, InstanceSummary, McpConfigBundle, McpConfigRequest, OperationLogEntry,
    TestConnectionResult,
};
use xiic_ssh_mcp::paths::shared_app_data_dir;
use xiic_ssh_mcp::single_instance::SingleInstanceGuard;

struct DesktopState {
    core: Arc<DesktopCore>,
    mcp_config: McpConfigBundle,
    _instance_lock: SingleInstanceGuard,
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
    state
        .core
        .save_instance(draft)
        .map_err(|err| err.to_string())
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

/// 杀死所有 MCP 子进程（xiic-ssh-mcp 和 xiic-ssh-approval），排除当前 Tauri 进程。
/// 使用 `pgrep -x` 匹配进程名（精确），避免误杀 Vite 等非目标进程。
#[cfg(unix)]
fn kill_mcp_processes() {
    let current_pid = std::process::id();
    for name in &["xiic-ssh-mcp", "xiic-ssh-approval"] {
        let output = match std::process::Command::new("pgrep")
            .args(["-x", name])
            .output()
        {
            Ok(o) => o,
            Err(_) => continue,
        };
        if !output.status.success() {
            continue;
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
                eprintln!("[xiic-ssh] 已杀掉 MCP 进程 {name} (pid={pid})");
            }
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
            let data_dir = shared_app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            let notify_endpoint = default_notify_endpoint(&data_dir);
            let instance_lock =
                match SingleInstanceGuard::acquire(&data_dir.join("manager.lock"), || {
                    notify_server_healthy(&notify_endpoint)
                })? {
                    Some(lock) => lock,
                    None => std::process::exit(0),
                };

            let (core, db_path, notify_endpoint, approval_endpoint) = build_core()?;
            let current_exe = std::env::current_exe()?;
            let helper_resolution = resolve_stdio_helper_path(app.handle(), &current_exe);
            let command_path = helper_resolution.path.to_string_lossy();
            let db_path = db_path.to_string_lossy();
            let mcp_config = core.mcp_config_bundle(McpConfigRequest {
                command_path: &command_path,
                db_path: &db_path,
                keyring_service: DEFAULT_KEYRING_SERVICE,
                notify_endpoint: Some(&notify_endpoint),
                approval_endpoint: Some(&approval_endpoint),
                helper_found: helper_resolution.found,
                helper_warning: helper_resolution.warning,
            })?;

            start_notify_listener(app.handle().clone(), notify_endpoint);

            app.manage(DesktopState {
                core,
                mcp_config,
                _instance_lock: instance_lock,
            });
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
    S: std::io::Read + std::io::Write,
{
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    let _ = reader.read_line(&mut line)?;
    let trimmed = line.trim();
    if trimmed == LOG_NOTIFICATION_PAYLOAD || trimmed.is_empty() {
        let _ = app.emit("log-updated", ());
        return Ok(());
    }

    if trimmed == NOTIFY_HEALTH_CHECK_KIND {
        std::io::Write::write_all(
            reader.get_mut(),
            serde_json::json!({
                "kind": NOTIFY_HEALTH_OK_KIND
            })
            .to_string()
            .as_bytes(),
        )?;
        std::io::Write::write_all(reader.get_mut(), b"\n")?;
        std::io::Write::flush(reader.get_mut())?;
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
            if reader.read_line(&mut line).await.is_ok() {
                let trimmed = line.trim();
                if trimmed == LOG_NOTIFICATION_PAYLOAD || trimmed.is_empty() {
                    let _ = app.emit("log-updated", ());
                } else if trimmed == NOTIFY_HEALTH_CHECK_KIND {
                    use tokio::io::AsyncWriteExt;

                    let payload = serde_json::json!({
                        "kind": NOTIFY_HEALTH_OK_KIND
                    })
                    .to_string();
                    let server = reader.into_inner();
                    let mut server = server;
                    let _ = server.write_all(payload.as_bytes()).await;
                    let _ = server.write_all(b"\n").await;
                    let _ = server.flush().await;
                }
            }
        });
    }
}

struct HelperResolution {
    path: PathBuf,
    found: bool,
    warning: Option<String>,
}

fn resolve_stdio_helper_path(app: &tauri::AppHandle, current_exe: &Path) -> HelperResolution {
    let helper_name = if cfg!(target_os = "windows") {
        "xiic-ssh-mcp.exe"
    } else {
        "xiic-ssh-mcp"
    };

    if let Some(found) = find_helper_path(app, current_exe, helper_name) {
        return HelperResolution {
            path: found,
            found: true,
            warning: None,
        };
    }

    HelperResolution {
        path: current_exe.to_path_buf(),
        found: false,
        warning: Some(format!(
            "未找到 MCP helper `{helper_name}`。当前展示的 command 是桌面主程序路径，仅用于提示发布包缺少 helper，不能直接作为 MCP server 配置使用。"
        )),
    }
}

fn find_helper_path(
    app: &tauri::AppHandle,
    current_exe: &Path,
    helper_name: &str,
) -> Option<PathBuf> {
    if let Some(parent) = current_exe.parent() {
        let sibling = parent.join(helper_name);
        if sibling.exists() {
            ensure_executable(&sibling);
            return Some(sibling);
        }
    }

    if let Ok(resource_dir) = app.path().resource_dir() {
        let bundled = resource_dir.join("binaries").join(helper_name);
        if bundled.exists() {
            ensure_executable(&bundled);
            return Some(bundled);
        }
    }

    None
}

#[cfg(unix)]
fn ensure_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    if let Ok(metadata) = std::fs::metadata(path) {
        let mut permissions = metadata.permissions();
        let mode = permissions.mode();
        if mode & 0o111 == 0 {
            permissions.set_mode(mode | 0o755);
            let _ = std::fs::set_permissions(path, permissions);
        }
    }
}

#[cfg(not(unix))]
fn ensure_executable(_path: &Path) {}
