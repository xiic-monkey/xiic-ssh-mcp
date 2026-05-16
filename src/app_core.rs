use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use ssh2::{CheckResult, KnownHostFileKind, Session};
use uuid::Uuid;

use crate::credentials::SecretStore;
use crate::local_ipc::send_notification;
use crate::models::{
    AuthKind, CreateSessionResult, DownloadFileArgs, DownloadFileResult, DownloadToLocalArgs,
    DownloadToLocalResult, ExecuteCommandArgs, ExecuteCommandResult, InstanceDraft,
    InstanceSummary, ListServersResult, McpConfigBundle, McpConfigRequest, OperationLogEntry,
    RuleAction, RuleType, SecretPayload, StoredInstance, TestConnectionResult, UploadFileArgs,
    UploadFileResult, UploadLocalFileArgs, UploadLocalFileResult, WhitelistRule,
};
use crate::storage::InstanceStore;
use crate::whitelist::WhitelistChecker;

pub const DEFAULT_KEYRING_SERVICE: &str = "com.xiic.ssh-manager";

#[derive(Clone)]
pub struct DesktopCore {
    store: InstanceStore,
    secrets: SecretStore,
    sessions: Arc<Mutex<HashMap<String, ManagedSession>>>,
    notify_endpoint: Option<String>,
}

struct ManagedSession {
    instance_id: String,
    session: Session,
}

struct ResolvedInstance {
    metadata: StoredInstance,
    secret: SecretPayload,
}

impl DesktopCore {
    pub fn new(db_path: PathBuf, keyring_service: impl Into<String>) -> Result<Self> {
        Self::new_with_socket(db_path, keyring_service, None)
    }

    pub fn new_with_socket(
        db_path: PathBuf,
        keyring_service: impl Into<String>,
        notify_endpoint: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            store: InstanceStore::new(db_path)?,
            secrets: SecretStore::new(keyring_service),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            notify_endpoint,
        })
    }

    pub fn list_servers(&self) -> Result<ListServersResult> {
        let servers = self.list_instances()?;
        Ok(ListServersResult { servers })
    }

    pub fn list_instances(&self) -> Result<Vec<InstanceSummary>> {
        let instances = self.store.list_instances()?;
        instances
            .into_iter()
            .map(|instance| {
                let has_secret = self.has_secret(&instance.instance_id)?;
                Ok(InstanceSummary::from_stored(instance, has_secret))
            })
            .collect()
    }

    pub fn get_operation_logs(&self, limit: Option<u64>) -> Result<Vec<OperationLogEntry>> {
        self.store.get_operation_logs(limit)
    }

    pub fn get_operation_logs_since(
        &self,
        since_id: i64,
        limit: u64,
    ) -> Result<Vec<OperationLogEntry>> {
        self.store.get_operation_logs_since(since_id, limit)
    }

    fn notify_ui(&self) {
        if let Some(endpoint) = &self.notify_endpoint {
            let _ = send_notification(endpoint);
        }
    }

    pub fn save_instance(&self, draft: InstanceDraft) -> Result<InstanceSummary> {
        let draft = draft.normalize();
        self.validate_metadata(&draft)?;

        let existing_secret = self.load_secret(&draft.instance_id)?;
        let secret = self.secret_for_draft(&draft, existing_secret.as_ref(), true)?;
        let stored = self.store.save_instance(&draft)?;
        self.store.save_secret(&draft.instance_id, &secret)?;
        if let Err(err) = self.secrets.save_secret(&draft.instance_id, &secret) {
            eprintln!(
                "warning: failed to store keychain secret for '{}': {err:#}",
                draft.instance_id
            );
        }

        Ok(InstanceSummary::from_stored(stored, true))
    }

    pub fn delete_instance(&self, instance_id: &str) -> Result<()> {
        self.store.delete_instance(instance_id)?;
        self.store.delete_secret(instance_id)?;
        let _ = self.secrets.delete_secret(instance_id);

        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("session manager lock poisoned"))?;
        sessions.retain(|_, session| session.instance_id != instance_id);
        Ok(())
    }

    pub fn test_connection(&self, draft: InstanceDraft) -> Result<TestConnectionResult> {
        let draft = draft.normalize();
        self.validate_metadata(&draft)?;
        let has_inline_secret =
            draft.password.is_some() || draft.private_key.is_some() || draft.passphrase.is_some();
        let has_saved_instance =
            !draft.instance_id.is_empty() && self.store.get_instance(&draft.instance_id)?.is_some();
        let should_try_saved_secret =
            has_saved_instance && (draft.keep_existing_secret || !has_inline_secret);

        let existing_secret = if should_try_saved_secret {
            self.load_secret(&draft.instance_id)?
        } else {
            None
        };
        let secret = self.secret_for_draft(&draft, existing_secret.as_ref(), false)?;
        let resolved = ResolvedInstance {
            metadata: StoredInstance {
                instance_id: draft.instance_id.clone(),
                name: draft.name.clone(),
                host: draft.host.clone(),
                port: draft.port,
                username: draft.username.clone(),
                auth_kind: draft.auth_kind.clone(),
                host_key_check: draft.host_key_check,
                notes: draft.notes.clone(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            secret,
        };

        match connect(&resolved) {
            Ok(_) => Ok(TestConnectionResult {
                success: true,
                message: "SSH connection succeeded.".to_string(),
            }),
            Err(err) => Ok(TestConnectionResult {
                success: false,
                message: err.to_string(),
            }),
        }
    }

    pub fn mcp_config_bundle(&self, request: McpConfigRequest<'_>) -> Result<McpConfigBundle> {
        let mut args = vec![
            "--db-path".to_string(),
            request.db_path.to_string(),
            "--keyring-service".to_string(),
            request.keyring_service.to_string(),
        ];
        if let Some(endpoint) = request.notify_endpoint {
            args.push("--notify-socket".to_string());
            args.push(endpoint.to_string());
        }
        args.push("--approval-mode".to_string());
        args.push("auto".to_string());
        if let Some(endpoint) = request.approval_endpoint {
            args.push("--approval-endpoint".to_string());
            args.push(endpoint.to_string());
        }

        let stdio_json = serde_json::to_string_pretty(&serde_json::json!({
            "mcpServers": {
                "xiic-ssh": {
                    "command": request.command_path,
                    "args": args,
                    "env": {
                        "HOME": env::var("HOME").unwrap_or_else(|_| "/home".to_string()),
                        "SSH_ASKPASS_REQUIRE": "never"
                    }
                }
            }
        }))?;

        Ok(McpConfigBundle {
            command: request.command_path.to_string(),
            args,
            stdio_json,
            helper_found: request.helper_found,
            helper_warning: request.helper_warning,
        })
    }

    pub fn create_session(&self, instance_id: &str) -> Result<CreateSessionResult> {
        let resolved = self.resolve_instance(instance_id)?;
        let session = connect(&resolved)
            .with_context(|| format!("failed to connect to instance '{}'", instance_id))?;
        let session_id = Uuid::new_v4().to_string();
        let connected_at = Utc::now();

        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("session manager lock poisoned"))?;
        sessions.insert(
            session_id.clone(),
            ManagedSession {
                instance_id: instance_id.to_string(),
                session,
            },
        );
        drop(sessions);

        let details = serde_json::json!({
            "instance_id": instance_id,
            "name": resolved.metadata.name,
            "host": resolved.metadata.host,
            "port": resolved.metadata.port,
        });
        self.store.insert_log(
            &session_id,
            instance_id,
            "create_session",
            &serde_json::to_string(&details).unwrap_or_default(),
        )?;
        self.notify_ui();

        Ok(CreateSessionResult {
            session_id,
            instance_id: instance_id.to_string(),
            connected_at,
        })
    }

    pub fn execute_command(&self, args: ExecuteCommandArgs) -> Result<ExecuteCommandResult> {
        if args.command.trim().is_empty() {
            bail!("command cannot be empty");
        }

        let timeout_ms = args
            .timeout_secs
            .and_then(|s| s.checked_mul(1_000))
            .map(|ms| u32::try_from(ms).unwrap_or(u32::MAX))
            .unwrap_or(30_000);

        let (instance_id, session_id, command, result) = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| anyhow!("session manager lock poisoned"))?;
            let managed = sessions
                .get_mut(&args.session_id)
                .with_context(|| format!("unknown session_id '{}'", args.session_id))?;
            let instance_id = managed.instance_id.clone();

            managed.session.set_timeout(timeout_ms);

            let mut channel = managed
                .session
                .channel_session()
                .context("failed to open SSH channel")?;
            channel
                .exec(&args.command)
                .with_context(|| format!("failed to execute command '{}'", args.command))?;

            let mut stdout = String::new();
            channel
                .read_to_string(&mut stdout)
                .context("failed to read command stdout")?;

            let mut stderr = String::new();
            channel
                .stderr()
                .read_to_string(&mut stderr)
                .context("failed to read command stderr")?;

            channel
                .wait_close()
                .context("failed waiting for command exit")?;
            let exit_code = channel.exit_status().context("failed to read exit code")?;

            (
                instance_id,
                args.session_id.clone(),
                args.command.clone(),
                ExecuteCommandResult {
                    stdout,
                    stderr,
                    exit_code,
                },
            )
        };

        let instance_name = self
            .store
            .get_instance(&instance_id)?
            .map(|i| i.name)
            .unwrap_or_else(|| instance_id.clone());

        let details = serde_json::json!({
            "instance_name": instance_name,
            "command": command,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.exit_code,
        });
        self.store.insert_log(
            &session_id,
            &instance_id,
            "execute_command",
            &serde_json::to_string(&details).unwrap_or_default(),
        )?;
        self.notify_ui();

        Ok(result)
    }

    pub fn upload_file(&self, args: UploadFileArgs) -> Result<UploadFileResult> {
        let local_path = args.local_path.clone();
        let bytes = std::fs::read(&local_path)
            .with_context(|| format!("failed to read local path '{}'", local_path))?;

        let (instance_id, session_id, remote_path, bytes_written) = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| anyhow!("session manager lock poisoned"))?;
            let managed = sessions
                .get_mut(&args.session_id)
                .with_context(|| format!("unknown session_id '{}'", args.session_id))?;
            let instance_id = managed.instance_id.clone();

            managed.session.set_timeout(30_000);

            let sftp = managed
                .session
                .sftp()
                .context("failed to open SFTP session")?;
            let remote = PathBuf::from(&args.remote_path);
            if !args.overwrite && sftp.stat(&remote).is_ok() {
                bail!("remote path '{}' already exists", args.remote_path);
            }

            let mut file = sftp
                .create(&remote)
                .with_context(|| format!("failed to open remote path '{}'", args.remote_path))?;
            file.write_all(&bytes)
                .with_context(|| format!("failed to write remote path '{}'", args.remote_path))?;
            file.flush()
                .with_context(|| format!("failed to flush remote path '{}'", args.remote_path))?;

            (
                instance_id,
                args.session_id.clone(),
                args.remote_path.clone(),
                bytes.len(),
            )
        };

        let instance_name = self
            .store
            .get_instance(&instance_id)?
            .map(|i| i.name)
            .unwrap_or_else(|| instance_id.clone());

        let details = serde_json::json!({
            "instance_name": instance_name,
            "local_path": local_path.clone(),
            "remote_path": remote_path.clone(),
            "bytes_written": bytes_written,
        });
        self.store.insert_log(
            &session_id,
            &instance_id,
            "upload_file",
            &serde_json::to_string(&details).unwrap_or_default(),
        )?;
        self.notify_ui();

        Ok(UploadFileResult {
            local_path,
            remote_path,
            bytes_written,
        })
    }

    pub fn upload_local_file(&self, args: UploadLocalFileArgs) -> Result<UploadLocalFileResult> {
        let result = self.upload_file(UploadFileArgs {
            session_id: args.session_id,
            local_path: args.local_path.clone(),
            remote_path: args.remote_path.clone(),
            overwrite: args.overwrite,
        })?;

        Ok(UploadLocalFileResult {
            bytes_written: result.bytes_written,
            local_path: args.local_path,
            remote_path: args.remote_path,
        })
    }

    pub fn download_file(&self, args: DownloadFileArgs) -> Result<DownloadFileResult> {
        let resolved_local_path =
            resolve_download_path(&args.remote_path, args.local_path.as_deref())?;
        let (instance_id, session_id, remote_path, result) = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| anyhow!("session manager lock poisoned"))?;
            let managed = sessions
                .get_mut(&args.session_id)
                .with_context(|| format!("unknown session_id '{}'", args.session_id))?;
            let instance_id = managed.instance_id.clone();

            managed.session.set_timeout(30_000);

            let sftp = managed
                .session
                .sftp()
                .context("failed to open SFTP session")?;
            let mut file = sftp
                .open(PathBuf::from(&args.remote_path).as_path())
                .with_context(|| format!("failed to open remote path '{}'", args.remote_path))?;

            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .with_context(|| format!("failed to read remote path '{}'", args.remote_path))?;
            if let Some(parent) = resolved_local_path.parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "failed to create parent directory for '{}'",
                        resolved_local_path.display()
                    )
                })?;
            }
            std::fs::write(&resolved_local_path, &bytes).with_context(|| {
                format!(
                    "failed to write local path '{}'",
                    resolved_local_path.display()
                )
            })?;

            (
                instance_id,
                args.session_id.clone(),
                args.remote_path.clone(),
                DownloadFileResult {
                    local_path: resolved_local_path.display().to_string(),
                    remote_path: args.remote_path.clone(),
                    size: bytes.len(),
                    encoding: "local_path".to_string(),
                },
            )
        };

        let instance_name = self
            .store
            .get_instance(&instance_id)?
            .map(|i| i.name)
            .unwrap_or_else(|| instance_id.clone());

        let details = serde_json::json!({
            "instance_name": instance_name,
            "local_path": result.local_path.clone(),
            "remote_path": remote_path,
            "size": result.size,
        });
        self.store.insert_log(
            &session_id,
            &instance_id,
            "download_file",
            &serde_json::to_string(&details).unwrap_or_default(),
        )?;
        self.notify_ui();

        Ok(result)
    }

    pub fn download_to_local(&self, args: DownloadToLocalArgs) -> Result<DownloadToLocalResult> {
        if !args.overwrite && Path::new(&args.local_path).exists() {
            bail!("local path '{}' already exists", args.local_path);
        }

        let result = self.download_file(DownloadFileArgs {
            session_id: args.session_id,
            remote_path: args.remote_path.clone(),
            local_path: Some(args.local_path.clone()),
        })?;

        Ok(DownloadToLocalResult {
            local_path: result.local_path,
            remote_path: args.remote_path,
            bytes_written: result.size,
        })
    }

    pub fn create_whitelist_checker(&self) -> WhitelistChecker {
        WhitelistChecker::new(self.store.clone())
    }

    pub fn list_whitelist_rules(&self) -> Result<Vec<WhitelistRule>> {
        self.store.list_whitelist_rules()
    }

    pub fn add_whitelist_rule(
        &self,
        rule_type: &RuleType,
        pattern: &str,
        action: &RuleAction,
    ) -> Result<i64> {
        self.store.add_whitelist_rule(rule_type, pattern, action)
    }

    pub fn remove_whitelist_rule(&self, id: i64) -> Result<()> {
        self.store.remove_whitelist_rule(id)
    }

    pub fn get_session_instance_id(&self, session_id: &str) -> Result<String> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("session manager lock poisoned"))?;
        sessions
            .get(session_id)
            .map(|s| s.instance_id.clone())
            .with_context(|| format!("unknown session_id '{}'", session_id))
    }

    fn validate_metadata(&self, draft: &InstanceDraft) -> Result<()> {
        if draft.instance_id.is_empty() {
            bail!("instance_id cannot be empty");
        }
        if draft.name.is_empty() {
            bail!("name cannot be empty");
        }
        if draft.host.is_empty() {
            bail!("host cannot be empty");
        }
        if draft.username.is_empty() {
            bail!("username cannot be empty");
        }
        if draft.port == 0 {
            bail!("port must be greater than zero");
        }
        Ok(())
    }

    fn resolve_instance(&self, instance_id: &str) -> Result<ResolvedInstance> {
        let metadata = self
            .store
            .get_instance(instance_id)?
            .with_context(|| format!("unknown instance_id '{}'", instance_id))?;
        let secret = self
            .load_secret(instance_id)?
            .with_context(|| format!("missing secret for instance '{}'", instance_id))?;

        Ok(ResolvedInstance { metadata, secret })
    }

    fn load_secret(&self, instance_id: &str) -> Result<Option<SecretPayload>> {
        if let Some(secret) = self.secrets.load_secret(instance_id)? {
            return Ok(Some(secret));
        }
        self.store.load_secret(instance_id)
    }

    fn has_secret(&self, instance_id: &str) -> Result<bool> {
        if self.secrets.has_secret(instance_id)? {
            return Ok(true);
        }
        self.store.has_secret(instance_id)
    }

    fn secret_for_draft(
        &self,
        draft: &InstanceDraft,
        existing_secret: Option<&SecretPayload>,
        saving: bool,
    ) -> Result<SecretPayload> {
        let password = draft.password.clone();
        let private_key = draft.private_key.clone();
        let passphrase = draft.passphrase.clone();

        let provided_secret = SecretPayload {
            password: password.clone(),
            private_key: private_key.clone(),
            passphrase: passphrase.clone(),
        };

        let has_provided_secret = provided_secret.password.is_some()
            || provided_secret.private_key.is_some()
            || provided_secret.passphrase.is_some();

        let resolved = if has_provided_secret {
            provided_secret
        } else if let Some(existing_secret) = existing_secret {
            existing_secret.clone()
        } else if draft.keep_existing_secret || saving {
            existing_secret.cloned().unwrap_or(SecretPayload {
                password: None,
                private_key: None,
                passphrase: None,
            })
        } else {
            provided_secret
        };

        match draft.auth_kind {
            AuthKind::Password => {
                if resolved.password.is_none() {
                    bail!("password authentication requires a password");
                }
            }
            AuthKind::PrivateKey => {
                if resolved.private_key.is_none() {
                    bail!("private key authentication requires a private_key");
                }
            }
        }

        Ok(resolved)
    }
}

fn resolve_download_path(remote_path: &str, requested_local_path: Option<&str>) -> Result<PathBuf> {
    if let Some(local_path) = requested_local_path {
        return Ok(PathBuf::from(local_path));
    }

    let file_name = Path::new(remote_path)
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow!("remote_path '{}' does not include a file name", remote_path))?;
    let home = env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join("Downloads").join(file_name))
}

fn connect(instance: &ResolvedInstance) -> Result<Session> {
    // 解析主机地址并连接（最多等待 10 秒）
    let addr = format!("{}:{}", instance.metadata.host, instance.metadata.port);
    let socket_addrs: Vec<_> = std::net::ToSocketAddrs::to_socket_addrs(&addr)
        .with_context(|| format!("failed to resolve host '{}'", instance.metadata.host))?
        .collect();

    if socket_addrs.is_empty() {
        bail!("no addresses found for host '{}'", instance.metadata.host);
    }

    let connect_timeout = Duration::from_secs(10);
    let mut last_err = None;
    let mut tried_idx = 0;

    let tcp = loop {
        if tried_idx >= socket_addrs.len() {
            break Err(anyhow::anyhow!(
                "failed to connect to {} within 10s: {:?}",
                addr,
                last_err
            ));
        }

        match TcpStream::connect_timeout(&socket_addrs[tried_idx], connect_timeout) {
            Ok(stream) => break Ok(stream),
            Err(e) => {
                last_err = Some(e);
                tried_idx += 1;
            }
        }
    }?;

    tcp.set_read_timeout(Some(Duration::from_secs(30)))
        .context("failed to set TCP read timeout")?;
    tcp.set_write_timeout(Some(Duration::from_secs(30)))
        .context("failed to set TCP write timeout")?;

    let mut session = Session::new().context("failed to create SSH session")?;
    session.set_tcp_stream(tcp);

    // 为 SSH 会话设置总超时（包括握手和认证）
    session.set_timeout(30_000);

    session.handshake().context("SSH handshake failed")?;

    if instance.metadata.host_key_check {
        verify_host_key(&session, instance)?;
    }

    match instance.metadata.auth_kind {
        AuthKind::PrivateKey => session
            .userauth_pubkey_memory(
                &instance.metadata.username,
                None,
                instance
                    .secret
                    .private_key
                    .as_deref()
                    .ok_or_else(|| anyhow!("missing private_key"))?,
                instance.secret.passphrase.as_deref(),
            )
            .with_context(|| {
                format!(
                    "private key authentication failed for '{}@{}'",
                    instance.metadata.username, instance.metadata.host
                )
            })?,
        AuthKind::Password => session
            .userauth_password(
                &instance.metadata.username,
                instance
                    .secret
                    .password
                    .as_deref()
                    .ok_or_else(|| anyhow!("missing password"))?,
            )
            .with_context(|| {
                format!(
                    "password authentication failed for '{}@{}'",
                    instance.metadata.username, instance.metadata.host
                )
            })?,
    }

    if !session.authenticated() {
        bail!("SSH authentication did not complete successfully");
    }

    Ok(session)
}

fn verify_host_key(session: &Session, instance: &ResolvedInstance) -> Result<()> {
    let (host_key, _) = session
        .host_key()
        .context("server did not present a host key")?;
    let mut known_hosts = session
        .known_hosts()
        .context("failed to create known_hosts handler")?;
    let known_hosts_path = known_hosts_path()?;

    known_hosts
        .read_file(&known_hosts_path, KnownHostFileKind::OpenSSH)
        .with_context(|| {
            format!(
                "failed to read known_hosts file at '{}'",
                known_hosts_path.display()
            )
        })?;

    match known_hosts.check_port(
        instance.metadata.host.as_str(),
        instance.metadata.port,
        host_key,
    ) {
        CheckResult::Match => Ok(()),
        CheckResult::Mismatch => bail!(
            "host key mismatch for '{}:{}'",
            instance.metadata.host,
            instance.metadata.port
        ),
        CheckResult::NotFound => bail!(
            "host key for '{}:{}' not found in known_hosts",
            instance.metadata.host,
            instance.metadata.port
        ),
        CheckResult::Failure => bail!("failed to validate host key"),
    }
}

fn known_hosts_path() -> Result<PathBuf> {
    let home = env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".ssh").join("known_hosts"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_to_local_rejects_existing_file_when_overwrite_disabled() {
        let test_dir = env::temp_dir().join(format!("xiic-ssh-mcp-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&test_dir).expect("test dir should be created");
        let db_path = test_dir.join("instances.sqlite3");
        let local_path = test_dir.join("existing.txt");
        std::fs::write(&local_path, "keep me").expect("existing file should be written");

        let core = DesktopCore::new(db_path, "com.xiic.ssh-manager.test")
            .expect("test core should initialize");
        let err = core
            .download_to_local(DownloadToLocalArgs {
                session_id: "missing-session".to_string(),
                remote_path: "/tmp/remote.txt".to_string(),
                local_path: local_path.display().to_string(),
                overwrite: false,
            })
            .expect_err("existing local file should not be overwritten");

        assert!(err.to_string().contains("already exists"));
        assert_eq!(
            std::fs::read_to_string(&local_path).expect("existing file should still be readable"),
            "keep me"
        );

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }
}
