use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::SyncSender;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use uuid::Uuid;

use crate::local_ipc::{approval_server_healthy, send_request};
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

        // 如果用户启用了系统弹窗审批，直接走原生对话框，不启动审批 App
        if crate::settings::load_settings().use_system_approval {
            eprintln!("[xiic-ssh-mcp] 使用系统弹窗进行审批（settings.use_system_approval）");
            return request_via_native_dialog(&request);
        }

        if let Some(endpoint) = &self.approval_endpoint {
            if let Ok(accepted) = request_via_app(endpoint, &request) {
                return Ok(accepted);
            }

            if !approval_server_healthy(endpoint) {
                if let Err(e) = launch_desktop_app() {
                    eprintln!("[xiic-ssh-mcp] 启动审批 App 失败: {e:#}");
                }
            }

            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                thread::sleep(Duration::from_millis(200));
                if let Ok(accepted) = request_via_app(endpoint, &request) {
                    return Ok(accepted);
                }
            }

            eprintln!(
                "[xiic-ssh-mcp] 审批 App 未能在 10 秒内就绪（endpoint={endpoint}），降级到系统原生弹窗"
            );
        }

        request_via_native_dialog(&request)
    }

    /// 预启动审批 App 并等待其就绪。
    /// 在 MCP 服务器初始化阶段调用，避免首次审批请求的冷启动延迟。
    pub fn pre_launch(&self) {
        let endpoint = match &self.approval_endpoint {
            Some(ep) => ep.clone(),
            None => return,
        };

        if approval_server_healthy(&endpoint) {
            eprintln!("[xiic-ssh-mcp] 审批 App 已在运行");
            return;
        }

        eprintln!("[xiic-ssh-mcp] 正在预启动审批 App...");

        match launch_desktop_app() {
            Ok(_) => {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut waited = 0u32;
                while Instant::now() < deadline {
                    if approval_server_healthy(&endpoint) {
                        eprintln!("[xiic-ssh-mcp] 审批 App 已就绪（约 {waited} 秒）");
                        return;
                    }
                    thread::sleep(Duration::from_millis(200));
                    waited += 1;
                }
                eprintln!(
                    "[xiic-ssh-mcp] 预启动完成但审批 App 未在 10 秒内就绪，后续将自动重试"
                );
            }
            Err(e) => {
                eprintln!("[xiic-ssh-mcp] 预启动审批 App 失败: {e:#}");
            }
        }
    }
}

pub fn approval_message(metadata: &ApprovalOperationMetadata) -> String {
    match metadata.tool_name.as_str() {
        "execute_command" => format!(
            "是否允许在连接 '{}' 上执行命令？\n\n命令：\n{}",
            metadata.instance_id.as_deref().unwrap_or("-"),
            metadata.command.as_deref().unwrap_or("-"),
        ),
        "upload_file" => format!(
            "是否允许上传本地文件到连接 '{}'？\n\n本地：{}\n远端：{}",
            metadata.instance_id.as_deref().unwrap_or("-"),
            metadata.local_path.as_deref().unwrap_or("-"),
            metadata.remote_path.as_deref().unwrap_or("-"),
        ),
        "download_file" => format!(
            "是否允许从连接 '{}' 下载文件？\n\n远端：{}\n本地：{}",
            metadata.instance_id.as_deref().unwrap_or("-"),
            metadata.remote_path.as_deref().unwrap_or("-"),
            metadata.local_path.as_deref().unwrap_or("默认 Downloads 目录"),
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
    let approval_app = resolve_approval_binary(&current_exe)
        .ok_or_else(|| anyhow!("xiic-ssh-approval binary was not found"))?;

    // 如果是 debug 构建且 Vite 开发服务器未运行，自动启动它
    if binary_requires_dev_server(&approval_app) && !approval_dev_server_is_ready() {
        eprintln!("[xiic-ssh-mcp] 正在启动 Vite 开发服务器 (port 1430)...");
        let repo_root = current_exe
            .ancestors()
            .nth(3)
            .ok_or_else(|| anyhow!("failed to resolve project root"))?;

        let _vite_child = Command::new("npx")
            .args(["vite", "--port", "1430"])
            .current_dir(&repo_root)
            .spawn()
            .context("failed to launch Vite dev server")?;

        // 等待 Vite 开发服务器就绪（最多 15 秒）
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut ready = false;
        while Instant::now() < deadline {
            if approval_dev_server_is_ready() {
                ready = true;
                break;
            }
            thread::sleep(Duration::from_millis(300));
        }

        if ready {
            eprintln!("[xiic-ssh-mcp] Vite 开发服务器已就绪");
        } else {
            eprintln!("[xiic-ssh-mcp] 警告: Vite 开发服务器未能在 15 秒内就绪，审批窗口可能无法正常显示");
        }
    }

    Command::new(approval_app)
        .env("TAURI_DEV", "1")
        .spawn()
        .context("failed to launch xiic-ssh-approval")?;
    Ok(())
}

fn resolve_approval_binary(current_exe: &Path) -> Option<PathBuf> {
    let approval_name = approval_binary_name();
    let sibling = current_exe.with_file_name(approval_name);
    if sibling.exists() {
        return Some(sibling);
    }

    let repo_root = current_exe.ancestors().nth(3)?;

    for profile in ["debug", "release"] {
        let candidate = repo_root
            .join("approval-tauri")
            .join("target")
            .join(profile)
            .join(approval_name);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}

fn approval_binary_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "xiic-ssh-approval.exe"
    }

    #[cfg(not(target_os = "windows"))]
    {
        "xiic-ssh-approval"
    }
}

fn binary_requires_dev_server(path: &Path) -> bool {
    matches!(
        path.parent().and_then(|dir| dir.file_name()).and_then(|name| name.to_str()),
        Some("debug")
    )
}

fn approval_dev_server_is_ready() -> bool {
    let addr: SocketAddr = match "127.0.0.1:1430".parse() {
        Ok(addr) => addr,
        Err(_) => return false,
    };
    TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
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

    use super::{ApprovalQueue, approval_message, resolve_approval_binary};

    #[test]
    fn formats_command_approval_message() {
        let metadata = ApprovalOperationMetadata {
            tool_name: "execute_command".into(),
            command: Some("rm -rf /tmp/demo".into()),
            remote_path: None,
            local_path: None,
            instance_id: Some("dev".into()),
        };

        let message = approval_message(&metadata);

        assert!(message.contains("dev"));
        assert!(message.contains("rm -rf /tmp/demo"));
    }

    #[test]
    fn missing_approval_binary_returns_none() {
        let path = PathBuf::from("/tmp/xiic-ssh-mcp-test/target/debug/xiic-ssh-mcp");

        assert!(resolve_approval_binary(&path).is_none());
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
                remote_path: None,
                local_path: None,
                instance_id: Some("dev".into()),
            },
        }
    }
}
