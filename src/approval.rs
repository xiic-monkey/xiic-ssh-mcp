use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use uuid::Uuid;

use crate::models::{ApprovalRequest, ApprovalResponse, OperationContext};

#[derive(Debug, Clone)]
pub struct LocalApproval {
    notify_socket: Option<PathBuf>,
}

impl LocalApproval {
    pub fn new(notify_socket: Option<PathBuf>) -> Self {
        Self { notify_socket }
    }

    pub fn request(&self, operation: &OperationContext) -> Result<bool> {
        let request = ApprovalRequest {
            kind: "approval_request".to_string(),
            request_id: Uuid::new_v4().to_string(),
            message: approval_message(operation),
            operation: operation.clone(),
        };

        if let Some(socket_path) = &self.notify_socket {
            if let Ok(accepted) = request_via_app(socket_path, &request) {
                return Ok(accepted);
            }

            let _ = launch_desktop_app();
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                thread::sleep(Duration::from_millis(150));
                if let Ok(accepted) = request_via_app(socket_path, &request) {
                    return Ok(accepted);
                }
            }
        }

        request_via_native_dialog(&request)
    }
}

fn approval_message(operation: &OperationContext) -> String {
    match operation.tool_name.as_str() {
        "execute_command" => format!(
            "是否允许在连接 '{}' 上执行命令？\n\n{}",
            operation.instance_id.as_deref().unwrap_or("-"),
            operation.command.as_deref().unwrap_or("-"),
        ),
        "upload_file" => format!(
            "是否允许上传文件到连接 '{}'？\n\n{}",
            operation.instance_id.as_deref().unwrap_or("-"),
            operation.remote_path.as_deref().unwrap_or("-"),
        ),
        "download_file" => format!(
            "是否允许从连接 '{}' 下载文件？\n\n{}",
            operation.instance_id.as_deref().unwrap_or("-"),
            operation.remote_path.as_deref().unwrap_or("-"),
        ),
        _ => format!("是否允许执行 SSH 操作 '{}'？", operation.tool_name),
    }
}

#[cfg(unix)]
fn request_via_app(socket_path: &Path, request: &ApprovalRequest) -> Result<bool> {
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path).with_context(|| {
        format!(
            "failed to connect approval socket '{}'",
            socket_path.display()
        )
    })?;
    let payload = serde_json::to_string(request).context("failed to encode approval request")?;
    stream
        .write_all(payload.as_bytes())
        .context("failed to write approval request")?;
    stream
        .write_all(b"\n")
        .context("failed to finish approval request")?;
    let _ = stream.shutdown(Shutdown::Write);

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .context("failed to read approval response")?;
    let response: ApprovalResponse =
        serde_json::from_str(response.trim()).context("failed to decode approval response")?;

    if response.kind != "approval_response" || response.request_id != request.request_id {
        bail!("approval response does not match request");
    }

    Ok(response.accepted)
}

#[cfg(not(unix))]
fn request_via_app(_socket_path: &Path, _request: &ApprovalRequest) -> Result<bool> {
    bail!("desktop approval socket is not available on this platform")
}

fn launch_desktop_app() -> Result<()> {
    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;
    let desktop = resolve_desktop_binary(&current_exe)
        .ok_or_else(|| anyhow!("xiic-ssh-manager-desktop binary was not found"))?;
    Command::new(desktop)
        .spawn()
        .context("failed to launch xiic-ssh-manager-desktop")?;
    Ok(())
}

fn resolve_desktop_binary(current_exe: &Path) -> Option<PathBuf> {
    let desktop_name = desktop_binary_name();
    let sibling = current_exe.with_file_name(desktop_name);
    if sibling.exists() {
        return Some(sibling);
    }

    let repo_root = current_exe.ancestors().nth(3)?;
    let profile_name = current_exe.parent()?.file_name()?;
    let dev_desktop = repo_root
        .join("src-tauri")
        .join("target")
        .join(profile_name)
        .join(desktop_name);
    if dev_desktop.exists() {
        return Some(dev_desktop);
    }

    None
}

fn desktop_binary_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "xiic-ssh-manager-desktop.exe"
    }

    #[cfg(not(target_os = "windows"))]
    {
        "xiic-ssh-manager-desktop"
    }
}

#[cfg(target_os = "macos")]
fn request_via_native_dialog(request: &ApprovalRequest) -> Result<bool> {
    let script = format!(
        "display dialog {} buttons {{\"拒绝\", \"允许执行\"}} default button \"允许执行\" cancel button \"拒绝\" with title \"Xiic SSH 审批\" with icon caution",
        osascript_string(&request.message)
    );
    let status = Command::new("osascript")
        .args(["-e", &script])
        .status()
        .context("failed to show macOS approval dialog")?;
    Ok(status.success())
}

#[cfg(target_os = "windows")]
fn request_via_native_dialog(request: &ApprovalRequest) -> Result<bool> {
    let script = format!(
        "Add-Type -AssemblyName PresentationFramework; $r=[System.Windows.MessageBox]::Show({}, 'Xiic SSH 审批', 'YesNo', 'Warning', 'Yes', 'ServiceNotification'); if ($r -eq 'Yes') {{ exit 0 }} else {{ exit 1 }}",
        powershell_string(&request.message)
    );
    let status = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .status()
        .context("failed to show Windows approval dialog")?;
    Ok(status.success())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn request_via_native_dialog(request: &ApprovalRequest) -> Result<bool> {
    if command_exists("zenity") {
        let status = Command::new("zenity")
            .args([
                "--question",
                "--title",
                "Xiic SSH 审批",
                "--text",
                &request.message,
            ])
            .status()
            .context("failed to show zenity approval dialog")?;
        return Ok(status.success());
    }

    if command_exists("kdialog") {
        let status = Command::new("kdialog")
            .args(["--title", "Xiic SSH 审批", "--yesno", &request.message])
            .status()
            .context("failed to show kdialog approval dialog")?;
        return Ok(status.success());
    }

    bail!("无法完成本地审批：桌面 App 不可用，且未找到系统原生弹窗工具")
}

#[cfg(not(any(unix, target_os = "windows")))]
fn request_via_native_dialog(_request: &ApprovalRequest) -> Result<bool> {
    bail!("无法完成本地审批：当前平台没有可用的系统原生弹窗实现")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn command_exists(command: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {command} >/dev/null 2>&1")])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn osascript_string(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(target_os = "windows")]
fn powershell_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::models::{ApprovalRequest, ApprovalResponse, OperationContext};

    use super::{approval_message, resolve_desktop_binary};

    #[test]
    fn formats_command_approval_message() {
        let ctx = OperationContext {
            tool_name: "execute_command".into(),
            command: Some("rm -rf /tmp/demo".into()),
            remote_path: None,
            instance_id: Some("dev".into()),
        };

        let message = approval_message(&ctx);

        assert!(message.contains("dev"));
        assert!(message.contains("rm -rf /tmp/demo"));
    }

    #[test]
    fn missing_desktop_binary_returns_none() {
        let path = PathBuf::from("/tmp/xiic-ssh-mcp-test/target/debug/xiic-ssh-mcp");

        assert!(resolve_desktop_binary(&path).is_none());
    }

    #[cfg(unix)]
    fn round_trip_app_approval(accepted: bool) -> Option<bool> {
        use std::io::ErrorKind;
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        use std::thread;

        let socket_path = PathBuf::from(format!("/private/tmp/xsa-{}.sock", uuid::Uuid::new_v4()));
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => return None,
            Err(err) => panic!("failed to bind test socket: {err}"),
        };
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            stream.read_to_string(&mut request).unwrap();
            let request: ApprovalRequest = serde_json::from_str(request.trim()).unwrap();
            let response = ApprovalResponse {
                kind: "approval_response".to_string(),
                request_id: request.request_id,
                accepted,
            };
            stream
                .write_all(serde_json::to_string(&response).unwrap().as_bytes())
                .unwrap();
        });

        let request = ApprovalRequest {
            kind: "approval_request".to_string(),
            request_id: uuid::Uuid::new_v4().to_string(),
            message: "approve?".into(),
            operation: OperationContext {
                tool_name: "execute_command".into(),
                command: Some("whoami".into()),
                remote_path: None,
                instance_id: Some("dev".into()),
            },
        };

        let result = super::request_via_app(&socket_path, &request).unwrap();
        handle.join().unwrap();
        let _ = std::fs::remove_file(socket_path);
        Some(result)
    }

    #[cfg(unix)]
    #[test]
    fn app_ipc_accepts_approval() {
        if let Some(result) = round_trip_app_approval(true) {
            assert!(result);
        }
    }

    #[cfg(unix)]
    #[test]
    fn app_ipc_declines_approval() {
        if let Some(result) = round_trip_app_approval(false) {
            assert!(!result);
        }
    }
}
