use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::SyncSender;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use uuid::Uuid;

use crate::local_ipc::send_request;
use crate::models::{
    ApprovalOperationMetadata, ApprovalRequest, ApprovalRequestedEvent, ApprovalResolvedEvent,
    ApprovalResponse,
};

#[derive(Debug, Clone)]
pub struct LocalApprovalClient {
    approval_endpoint: Option<String>,
}

impl LocalApprovalClient {
    pub fn new(approval_endpoint: Option<String>) -> Self {
        Self { approval_endpoint }
    }

    pub fn request(&self, metadata: &ApprovalOperationMetadata) -> Result<bool> {
        let request = ApprovalRequest {
            kind: "approval_request".to_string(),
            request_id: Uuid::new_v4().to_string(),
            message: approval_message(metadata),
            metadata: metadata.clone(),
        };

        if let Some(endpoint) = &self.approval_endpoint {
            if let Ok(accepted) = request_via_app(endpoint, &request) {
                return Ok(accepted);
            }

            let _ = launch_desktop_app();
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                thread::sleep(Duration::from_millis(150));
                if let Ok(accepted) = request_via_app(endpoint, &request) {
                    return Ok(accepted);
                }
            }
        }

        request_via_native_dialog(&request)
    }
}

pub fn approval_message(metadata: &ApprovalOperationMetadata) -> String {
    match metadata.tool_name.as_str() {
        "execute_command" => format!(
            "是否允许在连接 '{}' 上执行命令？\n\n说明：{}\n\n命令：\n{}",
            metadata.instance_id.as_deref().unwrap_or("-"),
            metadata.command_description.as_deref().unwrap_or("-"),
            metadata.command.as_deref().unwrap_or("-"),
        ),
        "upload_file" => format!(
            "是否允许上传文件到连接 '{}'？\n\n{}",
            metadata.instance_id.as_deref().unwrap_or("-"),
            metadata.remote_path.as_deref().unwrap_or("-"),
        ),
        "download_file" => format!(
            "是否允许从连接 '{}' 下载文件？\n\n{}",
            metadata.instance_id.as_deref().unwrap_or("-"),
            metadata.remote_path.as_deref().unwrap_or("-"),
        ),
        _ => format!("是否允许执行 SSH 操作 '{}'？", metadata.tool_name),
    }
}

fn request_via_app(endpoint: &str, request: &ApprovalRequest) -> Result<bool> {
    let payload = serde_json::to_string(request).context("failed to encode approval request")?;
    let response = send_request(endpoint, &payload)?;
    let response: ApprovalResponse =
        serde_json::from_str(response.trim()).context("failed to decode approval response")?;

    if response.kind != "approval_response" || response.request_id != request.request_id {
        bail!("approval response does not match request");
    }

    Ok(response.accepted)
}

pub struct ApprovalQueue {
    active_request_id: Option<String>,
    active_request: Option<ApprovalRequest>,
    queued_requests: VecDeque<ApprovalRequest>,
    waiters: HashMap<String, SyncSender<bool>>,
}

pub struct EnqueueResult {
    pub event: ApprovalRequestedEvent,
    pub activated: bool,
}

impl ApprovalQueue {
    pub fn new() -> Self {
        Self {
            active_request_id: None,
            active_request: None,
            queued_requests: VecDeque::new(),
            waiters: HashMap::new(),
        }
    }

    pub fn enqueue(&mut self, request: ApprovalRequest, waiter: SyncSender<bool>) -> EnqueueResult {
        self.waiters.insert(request.request_id.clone(), waiter);

        let activated = if self.active_request_id.is_none() {
            self.active_request_id = Some(request.request_id.clone());
            self.active_request = Some(request.clone());
            true
        } else {
            self.queued_requests.push_back(request.clone());
            false
        };

        EnqueueResult {
            event: ApprovalRequestedEvent {
                request: self
                    .active_request
                    .clone()
                    .expect("active request must exist after enqueue"),
                pending_count: self.queued_requests.len(),
            },
            activated,
        }
    }

    pub fn resolve(
        &mut self,
        request_id: &str,
        accepted: bool,
    ) -> Result<(ApprovalResolvedEvent, Option<ApprovalRequestedEvent>)> {
        match self.active_request_id.as_deref() {
            Some(active_id) if active_id == request_id => {}
            Some(_) => bail!("approval request '{request_id}' is not currently active"),
            None => bail!("no approval request is currently active"),
        }

        if let Some(waiter) = self.waiters.remove(request_id) {
            let _ = waiter.send(accepted);
        } else {
            bail!("approval request '{request_id}' was not found");
        }

        self.active_request_id = None;
        self.active_request = None;

        let next_event = if let Some(next_request) = self.queued_requests.pop_front() {
            self.active_request_id = Some(next_request.request_id.clone());
            self.active_request = Some(next_request.clone());
            Some(ApprovalRequestedEvent {
                request: next_request,
                pending_count: self.queued_requests.len(),
            })
        } else {
            None
        };

        let resolved = ApprovalResolvedEvent {
            request_id: request_id.to_string(),
            accepted,
            pending_count: self.queued_requests.len() + usize::from(next_event.is_some()),
        };

        Ok((resolved, next_event))
    }

    pub fn reject_all(&mut self) {
        let waiters = std::mem::take(&mut self.waiters);
        self.active_request_id = None;
        self.active_request = None;
        self.queued_requests.clear();

        for (_, waiter) in waiters {
            let _ = waiter.send(false);
        }
    }

    pub fn pending_count(&self) -> usize {
        self.waiters.len()
    }

    pub fn current_event(&self) -> Option<ApprovalRequestedEvent> {
        self.active_request
            .clone()
            .map(|request| ApprovalRequestedEvent {
                request,
                pending_count: self.queued_requests.len(),
            })
    }
}

fn launch_desktop_app() -> Result<()> {
    let current_exe = std::env::current_exe().context("failed to resolve current executable")?;
    let desktop = resolve_desktop_binary(&current_exe)
        .ok_or_else(|| anyhow!("xiic-ssh-manager-desktop binary was not found"))?;
    Command::new(desktop)
        .arg("--approval-only")
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
    use std::sync::mpsc;

    use crate::models::{ApprovalOperationMetadata, ApprovalRequest};

    use super::{ApprovalQueue, approval_message, resolve_desktop_binary};

    #[test]
    fn formats_command_approval_message() {
        let metadata = ApprovalOperationMetadata {
            tool_name: "execute_command".into(),
            command: Some("rm -rf /tmp/demo".into()),
            command_description: Some("清理测试目录".into()),
            remote_path: None,
            instance_id: Some("dev".into()),
        };

        let message = approval_message(&metadata);

        assert!(message.contains("dev"));
        assert!(message.contains("清理测试目录"));
        assert!(message.contains("rm -rf /tmp/demo"));
    }

    #[test]
    fn missing_desktop_binary_returns_none() {
        let path = PathBuf::from("/tmp/xiic-ssh-mcp-test/target/debug/xiic-ssh-mcp");

        assert!(resolve_desktop_binary(&path).is_none());
    }

    #[test]
    fn approval_queue_serializes_concurrent_requests() {
        let mut queue = ApprovalQueue::new();
        let request1 = request("req-1");
        let request2 = request("req-2");
        let (tx1, rx1) = mpsc::sync_channel(1);
        let (tx2, rx2) = mpsc::sync_channel(1);

        let first = queue.enqueue(request1.clone(), tx1);
        let second = queue.enqueue(request2.clone(), tx2);

        assert!(first.activated);
        assert_eq!(first.event.request.request_id, "req-1");
        assert_eq!(first.event.pending_count, 0);
        assert!(!second.activated);
        assert_eq!(second.event.request.request_id, "req-1");
        assert_eq!(second.event.pending_count, 1);

        let (resolved, next) = queue.resolve("req-1", true).unwrap();
        assert_eq!(resolved.request_id, "req-1");
        assert!(resolved.accepted);
        assert_eq!(resolved.pending_count, 1);
        assert_eq!(rx1.recv().unwrap(), true);

        let next = next.expect("next request should become active");
        assert_eq!(next.request.request_id, "req-2");
        assert_eq!(next.pending_count, 0);

        queue.reject_all();
        assert_eq!(rx2.recv().unwrap(), false);
        assert_eq!(queue.pending_count(), 0);
    }

    fn request(id: &str) -> ApprovalRequest {
        ApprovalRequest {
            kind: "approval_request".into(),
            request_id: id.into(),
            message: "demo".into(),
            metadata: ApprovalOperationMetadata {
                tool_name: "execute_command".into(),
                command: Some("echo hello".into()),
                command_description: Some("输出问候".into()),
                remote_path: None,
                instance_id: Some("dev".into()),
            },
        }
    }
}
