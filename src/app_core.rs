use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use ssh2::{CheckResult, KnownHostFileKind, Session};
use uuid::Uuid;

use crate::approval::prompt_sudo_password;
use crate::credentials::SecretStore;
use crate::local_ipc::send_notification;
use crate::models::{
    AuthKind, CloseSessionResult, CreateSessionResult, DownloadFileArgs, DownloadFileResult,
    DownloadToLocalArgs, DownloadToLocalResult, ExecuteCommandArgs, ExecuteCommandResult,
    InstanceDraft, InstanceSummary, ListServersResult, McpConfigBundle, McpConfigRequest,
    OperationLogEntry, RequestContext, RuleAction, RuleType, SecretPayload, StoredInstance,
    SudoCommandArgs, TestConnectionResult, UploadFileArgs, UploadFileResult, UploadLocalFileArgs,
    UploadLocalFileResult, WhitelistRule,
};
use crate::storage::InstanceStore;
use crate::whitelist::WhitelistChecker;

pub const DEFAULT_CLIENT_ID: &str = "xiic-ssh-default";
const MAX_COMMAND_STREAM_BYTES: u64 = 4 * 1024 * 1024;

type SharedSession = Arc<Mutex<ManagedSession>>;

#[derive(Clone)]
pub struct DesktopCore {
    store: InstanceStore,
    secrets: SecretStore,
    sessions: Arc<Mutex<HashMap<String, SharedSession>>>,
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
    pub fn new(db_path: PathBuf) -> Result<Self> {
        Self::new_with_socket(db_path, None)
    }

    pub fn new_with_socket(db_path: PathBuf, notify_endpoint: Option<String>) -> Result<Self> {
        let core = Self {
            store: InstanceStore::new(db_path.clone())?,
            secrets: SecretStore::new(db_path)?,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            notify_endpoint,
        };
        Ok(core)
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
                // Listing metadata must remain available while the login keychain is locked or
                // waiting for user authorization. Session creation still reports the precise
                // credential error through `resolve_instance`.
                let has_secret = match self.has_secret(&instance.instance_id) {
                    Ok(value) => value,
                    Err(err) => {
                        eprintln!(
                            "[xiic-ssh-mcp] unable to inspect secret for '{}': {err:#}",
                            instance.instance_id
                        );
                        false
                    }
                };
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

    pub fn log_client_connection(&self, ctx: &RequestContext, operation: &str) -> Result<()> {
        let details = serde_json::json!({
            "client_id": ctx.client_id,
            "client_session_id": ctx.client_session_id,
        });
        self.store.insert_log(
            &ctx.client_id,
            &ctx.client_session_id,
            "",
            "",
            operation,
            &serde_json::to_string(&details).unwrap_or_default(),
        )?;
        self.notify_ui();
        Ok(())
    }

    fn notify_ui(&self) {
        if let Some(endpoint) = &self.notify_endpoint {
            let _ = send_notification(endpoint);
        }
    }

    pub fn save_instance(&self, draft: InstanceDraft) -> Result<InstanceSummary> {
        let draft = draft.normalize();
        self.validate_metadata(&draft)?;

        let has_provided_secret = draft.password.is_some()
            || draft.private_key.is_some()
            || draft.private_key_path.is_some()
            || draft.passphrase.is_some();
        let (existing_secret, can_restore_existing_secret) = match self
            .load_secret(&draft.instance_id)
        {
            Ok(secret) => (secret, true),
            Err(err) if has_provided_secret => {
                eprintln!(
                    "[xiic-ssh-mcp] existing secret for '{}' is unavailable; replacing it with the supplied credential: {err:#}",
                    draft.instance_id
                );
                (None, false)
            }
            Err(err) => return Err(err),
        };
        let secret = self.secret_for_draft(&draft, existing_secret.as_ref(), true)?;
        if let Err(err) = self.save_and_verify_secret(&draft.instance_id, &secret) {
            if can_restore_existing_secret {
                self.restore_secret(&draft.instance_id, existing_secret.as_ref())
                    .context("failed to restore previous credential after keychain save failure")?;
            }
            return Err(err);
        }
        let stored = match self.store.save_instance(&draft) {
            Ok(stored) => stored,
            Err(err) => {
                if can_restore_existing_secret {
                    self.restore_secret(&draft.instance_id, existing_secret.as_ref())
                        .context(
                            "failed to restore previous credential after metadata save failure",
                        )?;
                }
                return Err(err).context("failed to save instance metadata");
            }
        };
        Ok(InstanceSummary::from_stored(stored, true))
    }

    pub fn delete_instance(&self, instance_id: &str) -> Result<()> {
        let existing_secret = self.load_secret(instance_id)?;
        self.secrets.delete_secret(instance_id)?;
        if let Err(err) = self.store.delete_instance(instance_id) {
            self.restore_secret(instance_id, existing_secret.as_ref())
                .context("failed to restore credential after metadata deletion failure")?;
            return Err(err);
        }

        let session_entries: Vec<(String, SharedSession)> = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("session manager lock poisoned"))?
            .iter()
            .map(|(id, session)| (id.clone(), session.clone()))
            .collect();
        let mut session_ids = Vec::new();
        for (session_id, session) in session_entries {
            if session
                .lock()
                .map_err(|_| anyhow!("SSH session lock poisoned"))?
                .instance_id
                == instance_id
            {
                session_ids.push(session_id);
            }
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("session manager lock poisoned"))?;
        for session_id in session_ids {
            sessions.remove(&session_id);
        }
        Ok(())
    }

    pub fn test_connection(&self, draft: InstanceDraft) -> Result<TestConnectionResult> {
        let draft = draft.normalize();
        self.validate_metadata(&draft)?;
        let has_inline_secret = draft.password.is_some()
            || draft.private_key.is_some()
            || draft.private_key_path.is_some()
            || draft.passphrase.is_some();
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
        let mut args = vec!["--db-path".to_string(), request.db_path.to_string()];
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
        args.push("--client-id".to_string());
        args.push(request.client_id.to_string());

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

    pub fn create_session(
        &self,
        ctx: &RequestContext,
        instance_id: &str,
    ) -> Result<CreateSessionResult> {
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
            Arc::new(Mutex::new(ManagedSession {
                instance_id: instance_id.to_string(),
                session,
            })),
        );
        drop(sessions);

        let details = serde_json::json!({
            "client_id": ctx.client_id,
            "client_session_id": ctx.client_session_id,
            "instance_id": instance_id,
            "name": resolved.metadata.name,
            "host": resolved.metadata.host,
            "port": resolved.metadata.port,
        });
        self.store.insert_log(
            &ctx.client_id,
            &ctx.client_session_id,
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

    pub fn execute_command(
        &self,
        ctx: &RequestContext,
        args: ExecuteCommandArgs,
    ) -> Result<ExecuteCommandResult> {
        if args.command.trim().is_empty() {
            bail!("command cannot be empty");
        }

        let timeout_ms = args
            .timeout_secs
            .and_then(|s| s.checked_mul(1_000))
            .map(|ms| u32::try_from(ms).unwrap_or(u32::MAX))
            .unwrap_or(30_000);

        let (instance_id, session_id, command, result) = {
            let session = self.get_session(&args.session_id)?;
            let managed = session
                .lock()
                .map_err(|_| anyhow!("SSH session lock poisoned"))?;
            let instance_id = managed.instance_id.clone();

            managed.session.set_timeout(timeout_ms);

            let mut channel = managed
                .session
                .channel_session()
                .context("failed to open SSH channel")?;
            channel
                .exec(&args.command)
                .with_context(|| format!("failed to execute command '{}'", args.command))?;

            let stdout = read_limited_utf8(&mut channel, "command stdout")?;
            let stderr = read_limited_utf8(&mut channel.stderr(), "command stderr")?;

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
            "client_id": ctx.client_id,
            "client_session_id": ctx.client_session_id,
            "instance_name": instance_name,
            "command": command,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.exit_code,
        });
        self.store.insert_log(
            &ctx.client_id,
            &ctx.client_session_id,
            &session_id,
            &instance_id,
            "execute_command",
            &serde_json::to_string(&details).unwrap_or_default(),
        )?;
        self.notify_ui();

        Ok(result)
    }

    pub fn upload_file(
        &self,
        ctx: &RequestContext,
        args: UploadFileArgs,
    ) -> Result<UploadFileResult> {
        let local_path = args.local_path.clone();
        let mut local_file = File::open(&local_path)
            .with_context(|| format!("failed to open local path '{}'", local_path))?;

        let (instance_id, session_id, remote_path, bytes_written) = {
            let session = self.get_session(&args.session_id)?;
            let managed = session
                .lock()
                .map_err(|_| anyhow!("SSH session lock poisoned"))?;
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
            let bytes_written = std::io::copy(&mut local_file, &mut file)
                .with_context(|| format!("failed to write remote path '{}'", args.remote_path))?;
            file.flush()
                .with_context(|| format!("failed to flush remote path '{}'", args.remote_path))?;

            (
                instance_id,
                args.session_id.clone(),
                args.remote_path.clone(),
                usize::try_from(bytes_written).context("uploaded file is too large to report")?,
            )
        };

        let instance_name = self
            .store
            .get_instance(&instance_id)?
            .map(|i| i.name)
            .unwrap_or_else(|| instance_id.clone());

        let details = serde_json::json!({
            "client_id": ctx.client_id,
            "client_session_id": ctx.client_session_id,
            "instance_name": instance_name,
            "local_path": local_path.clone(),
            "remote_path": remote_path.clone(),
            "bytes_written": bytes_written,
        });
        self.store.insert_log(
            &ctx.client_id,
            &ctx.client_session_id,
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

    pub fn upload_local_file(
        &self,
        ctx: &RequestContext,
        args: UploadLocalFileArgs,
    ) -> Result<UploadLocalFileResult> {
        let result = self.upload_file(
            ctx,
            UploadFileArgs {
                session_id: args.session_id,
                local_path: args.local_path.clone(),
                remote_path: args.remote_path.clone(),
                overwrite: args.overwrite,
            },
        )?;

        Ok(UploadLocalFileResult {
            bytes_written: result.bytes_written,
            local_path: args.local_path,
            remote_path: args.remote_path,
        })
    }

    pub fn download_file(
        &self,
        ctx: &RequestContext,
        args: DownloadFileArgs,
    ) -> Result<DownloadFileResult> {
        let resolved_local_path =
            resolve_download_path(&args.remote_path, args.local_path.as_deref())?;
        let (instance_id, session_id, remote_path, result) = {
            let session = self.get_session(&args.session_id)?;
            let managed = session
                .lock()
                .map_err(|_| anyhow!("SSH session lock poisoned"))?;
            let instance_id = managed.instance_id.clone();

            managed.session.set_timeout(30_000);

            let sftp = managed
                .session
                .sftp()
                .context("failed to open SFTP session")?;
            let mut file = sftp
                .open(PathBuf::from(&args.remote_path).as_path())
                .with_context(|| format!("failed to open remote path '{}'", args.remote_path))?;

            if let Some(parent) = resolved_local_path.parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "failed to create parent directory for '{}'",
                        resolved_local_path.display()
                    )
                })?;
            }
            let mut local_file = File::create(&resolved_local_path).with_context(|| {
                format!(
                    "failed to create local path '{}'",
                    resolved_local_path.display()
                )
            })?;
            let bytes_written = std::io::copy(&mut file, &mut local_file).with_context(|| {
                format!(
                    "failed to write local path '{}'",
                    resolved_local_path.display()
                )
            })?;
            local_file.flush().with_context(|| {
                format!(
                    "failed to flush local path '{}'",
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
                    size: usize::try_from(bytes_written)
                        .context("downloaded file is too large to report")?,
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
            "client_id": ctx.client_id,
            "client_session_id": ctx.client_session_id,
            "instance_name": instance_name,
            "local_path": result.local_path.clone(),
            "remote_path": remote_path,
            "size": result.size,
        });
        self.store.insert_log(
            &ctx.client_id,
            &ctx.client_session_id,
            &session_id,
            &instance_id,
            "download_file",
            &serde_json::to_string(&details).unwrap_or_default(),
        )?;
        self.notify_ui();

        Ok(result)
    }

    pub fn download_to_local(
        &self,
        ctx: &RequestContext,
        args: DownloadToLocalArgs,
    ) -> Result<DownloadToLocalResult> {
        if !args.overwrite && Path::new(&args.local_path).exists() {
            bail!("local path '{}' already exists", args.local_path);
        }

        let result = self.download_file(
            ctx,
            DownloadFileArgs {
                session_id: args.session_id,
                remote_path: args.remote_path.clone(),
                local_path: Some(args.local_path.clone()),
            },
        )?;

        Ok(DownloadToLocalResult {
            local_path: result.local_path,
            remote_path: args.remote_path,
            bytes_written: result.size,
        })
    }

    pub fn close_session(
        &self,
        ctx: &RequestContext,
        session_id: &str,
    ) -> Result<CloseSessionResult> {
        let instance_id = {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| anyhow!("session manager lock poisoned"))?;
            let session = sessions
                .remove(session_id)
                .with_context(|| format!("unknown session_id '{}'", session_id))?;
            drop(sessions);
            session
                .lock()
                .map_err(|_| anyhow!("SSH session lock poisoned"))?
                .instance_id
                .clone()
        };
        // ManagedSession dropped here → ssh2 Session disconnected automatically

        let result = CloseSessionResult {
            session_id: session_id.to_string(),
            instance_id: instance_id.clone(),
            disconnected_at: Utc::now(),
        };

        let instance_name = self
            .store
            .get_instance(&instance_id)?
            .map(|i| i.name)
            .unwrap_or_else(|| instance_id.clone());

        let details = serde_json::json!({
            "client_id": ctx.client_id,
            "client_session_id": ctx.client_session_id,
            "instance_name": instance_name,
            "instance_id": instance_id,
        });
        self.store.insert_log(
            &ctx.client_id,
            &ctx.client_session_id,
            session_id,
            &instance_id,
            "close_session",
            &serde_json::to_string(&details).unwrap_or_default(),
        )?;
        self.notify_ui();

        Ok(result)
    }

    pub fn sudo_command(
        &self,
        ctx: &RequestContext,
        args: SudoCommandArgs,
    ) -> Result<ExecuteCommandResult> {
        if args.command.trim().is_empty() {
            bail!("command cannot be empty");
        }

        // 弹出系统原生密码输入框获取 sudo 密码
        let password = prompt_sudo_password().context("failed to get sudo password")?;

        let timeout_ms = args
            .timeout_secs
            .and_then(|s| s.checked_mul(1_000))
            .map(|ms| u32::try_from(ms).unwrap_or(u32::MAX))
            .unwrap_or(30_000);

        let sudo_cmd = format!("sudo -S {}", args.command);

        let (instance_id, session_id, command, result) = {
            let session = self.get_session(&args.session_id)?;
            let managed = session
                .lock()
                .map_err(|_| anyhow!("SSH session lock poisoned"))?;
            let instance_id = managed.instance_id.clone();

            managed.session.set_timeout(timeout_ms);

            let mut channel = managed
                .session
                .channel_session()
                .context("failed to open SSH channel")?;

            channel
                .exec(&sudo_cmd)
                .context("failed to execute sudo command")?;

            // 将密码写入 stdin，然后关闭写入端以发送 EOF
            let pw_with_newline = format!("{}\n", password);
            channel
                .write_all(pw_with_newline.as_bytes())
                .context("failed to write sudo password to stdin")?;
            // 尽早清除内存中的密码明文
            drop(pw_with_newline);
            drop(password);
            channel
                .send_eof()
                .context("failed to send EOF after sudo password")?;

            let stdout = read_limited_utf8(&mut channel, "sudo command stdout")?;
            let stderr = read_limited_utf8(&mut channel.stderr(), "sudo command stderr")?;

            channel
                .wait_close()
                .context("failed waiting for sudo command exit")?;
            let exit_code = channel
                .exit_status()
                .context("failed to read sudo exit code")?;

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

        // 日志不包含密码信息
        let details = serde_json::json!({
            "client_id": ctx.client_id,
            "client_session_id": ctx.client_session_id,
            "instance_name": instance_name,
            "command": format!("sudo {}", command),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.exit_code,
        });
        self.store.insert_log(
            &ctx.client_id,
            &ctx.client_session_id,
            &session_id,
            &instance_id,
            "sudo",
            &serde_json::to_string(&details).unwrap_or_default(),
        )?;
        self.notify_ui();

        Ok(result)
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
        let session = self.get_session(session_id)?;
        let instance_id = session
            .lock()
            .map_err(|_| anyhow!("SSH session lock poisoned"))?
            .instance_id
            .clone();
        Ok(instance_id)
    }

    fn get_session(&self, session_id: &str) -> Result<SharedSession> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("session manager lock poisoned"))?;
        sessions
            .get(session_id)
            .cloned()
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
        self.secrets.load_secret(instance_id)
    }

    fn has_secret(&self, instance_id: &str) -> Result<bool> {
        self.secrets.has_secret(instance_id)
    }

    fn save_and_verify_secret(&self, instance_id: &str, secret: &SecretPayload) -> Result<()> {
        self.secrets.save_secret(instance_id, secret)?;
        let persisted = self.secrets.load_secret(instance_id)?;
        if persisted.as_ref() != Some(secret) {
            bail!(
                "encrypted credential verification failed for instance '{}'",
                instance_id
            );
        }
        Ok(())
    }

    fn restore_secret(&self, instance_id: &str, secret: Option<&SecretPayload>) -> Result<()> {
        match secret {
            Some(secret) => self.save_and_verify_secret(instance_id, secret),
            None => self.secrets.delete_secret(instance_id),
        }
    }

    pub fn get_private_key_path(&self, instance_id: &str) -> Result<Option<String>> {
        Ok(self
            .load_secret(instance_id)?
            .and_then(|secret| secret.private_key_path))
    }

    fn secret_for_draft(
        &self,
        draft: &InstanceDraft,
        existing_secret: Option<&SecretPayload>,
        saving: bool,
    ) -> Result<SecretPayload> {
        let password = draft.password.clone();
        let private_key = draft.private_key.clone();
        let private_key_path = draft.private_key_path.clone();
        let passphrase = draft.passphrase.clone();

        let provided_secret = SecretPayload {
            password: password.clone(),
            private_key: private_key.clone(),
            private_key_path: private_key_path.clone(),
            passphrase: passphrase.clone(),
        };

        let has_provided_secret = provided_secret.password.is_some()
            || provided_secret.private_key.is_some()
            || provided_secret.private_key_path.is_some()
            || provided_secret.passphrase.is_some();

        let resolved = if has_provided_secret {
            provided_secret
        } else if let Some(existing_secret) = existing_secret {
            existing_secret.clone()
        } else if draft.keep_existing_secret || saving {
            existing_secret.cloned().unwrap_or(SecretPayload {
                password: None,
                private_key: None,
                private_key_path: None,
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
                if resolved.private_key.is_some() && resolved.private_key_path.is_some() {
                    bail!(
                        "private key authentication requires either private_key or private_key_path, not both"
                    );
                }
                if resolved.private_key.is_none() && resolved.private_key_path.is_none() {
                    bail!("private key authentication requires a private_key or private_key_path");
                }
            }
        }

        Ok(resolved)
    }
}

fn read_limited_utf8(reader: &mut impl Read, label: &str) -> Result<String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_COMMAND_STREAM_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {label}"))?;
    if bytes.len() as u64 > MAX_COMMAND_STREAM_BYTES {
        bail!(
            "{label} exceeded the {} MiB output limit",
            MAX_COMMAND_STREAM_BYTES / (1024 * 1024)
        );
    }
    String::from_utf8(bytes).with_context(|| format!("{label} is not valid UTF-8"))
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
        AuthKind::PrivateKey => {
            let private_key = instance.secret.private_key.as_deref();
            let private_key_path = instance.secret.private_key_path.as_deref();

            if private_key.is_some() && private_key_path.is_some() {
                bail!(
                    "private key authentication requires either private_key or private_key_path, not both"
                );
            }

            if let Some(private_key_path) = private_key_path {
                session
                    .userauth_pubkey_file(
                        &instance.metadata.username,
                        None,
                        Path::new(private_key_path),
                        instance.secret.passphrase.as_deref(),
                    )
                    .with_context(|| {
                        format!(
                            "private key authentication failed for '{}@{}'",
                            instance.metadata.username, instance.metadata.host
                        )
                    })?;
            } else if let Some(private_key) = private_key {
                session
                    .userauth_pubkey_memory(
                        &instance.metadata.username,
                        None,
                        private_key,
                        instance.secret.passphrase.as_deref(),
                    )
                    .with_context(|| {
                        format!(
                            "private key authentication failed for '{}@{}'",
                            instance.metadata.username, instance.metadata.host
                        )
                    })?;
            } else {
                bail!("private key authentication requires a private_key or private_key_path");
            }
        }
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
    #[cfg(any())]
    use std::collections::{HashMap as TestHashMap, HashSet};
    #[cfg(any())]
    use std::sync::{Arc as TestArc, Mutex as TestMutex};

    #[cfg(any())]
    use anyhow::anyhow;

    #[cfg(any())]
    use crate::credentials::CredentialBackend;

    #[cfg(any())]
    #[derive(Default)]
    struct MockCredentialBackend {
        entries: TestMutex<TestHashMap<String, String>>,
        fail_get: TestMutex<HashSet<String>>,
        fail_set: TestMutex<HashSet<String>>,
        fail_delete: TestMutex<HashSet<String>>,
        discard_next_set: TestMutex<HashSet<String>>,
    }

    #[cfg(any())]
    impl MockCredentialBackend {
        fn key(service_name: &str, account: &str) -> String {
            format!("{service_name}|{account}")
        }

        fn fail_next_set(&self, account: &str) {
            self.fail_set
                .lock()
                .expect("fail set should lock")
                .insert(account.to_string());
        }

        fn fail_next_get(&self, account: &str) {
            self.fail_get
                .lock()
                .expect("fail get set should lock")
                .insert(account.to_string());
        }

        fn discard_next_set(&self, account: &str) {
            self.discard_next_set
                .lock()
                .expect("discard set should lock")
                .insert(account.to_string());
        }

        fn fail_next_delete(&self, account: &str) {
            self.fail_delete
                .lock()
                .expect("fail delete set should lock")
                .insert(account.to_string());
        }

        fn load_payload(&self, service_name: &str, account: &str) -> Option<SecretPayload> {
            self.entries
                .lock()
                .expect("entries should lock")
                .get(&Self::key(service_name, account))
                .map(|payload| serde_json::from_str(payload).expect("payload should decode"))
        }
    }

    #[cfg(any())]
    impl CredentialBackend for MockCredentialBackend {
        fn set_password(&self, service_name: &str, account: &str, payload: &str) -> Result<()> {
            if self
                .fail_set
                .lock()
                .expect("fail set should lock")
                .remove(account)
            {
                return Err(anyhow!("mock keychain set failed"));
            }

            if self
                .discard_next_set
                .lock()
                .expect("discard set should lock")
                .remove(account)
            {
                return Ok(());
            }

            self.entries
                .lock()
                .expect("entries should lock")
                .insert(Self::key(service_name, account), payload.to_string());
            Ok(())
        }

        fn get_password(&self, service_name: &str, account: &str) -> Result<Option<String>> {
            if self
                .fail_get
                .lock()
                .expect("fail get set should lock")
                .remove(account)
            {
                return Err(anyhow!("mock keychain read failed"));
            }

            Ok(self
                .entries
                .lock()
                .expect("entries should lock")
                .get(&Self::key(service_name, account))
                .cloned())
        }

        fn delete_password(&self, service_name: &str, account: &str) -> Result<()> {
            if self
                .fail_delete
                .lock()
                .expect("fail delete set should lock")
                .remove(account)
            {
                return Err(anyhow!("mock keychain delete failed"));
            }

            self.entries
                .lock()
                .expect("entries should lock")
                .remove(&Self::key(service_name, account));
            Ok(())
        }
    }

    #[cfg(any())]
    const TEST_SERVICE: &str = "com.xiic.ssh-manager.test";

    fn make_test_core() -> (DesktopCore, PathBuf) {
        let test_dir = env::temp_dir().join(format!("xiic-ssh-mcp-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&test_dir).expect("test dir should be created");
        let db_path = test_dir.join("instances.sqlite3");
        let core = DesktopCore::new(db_path).expect("test core should initialize");
        (core, test_dir)
    }

    #[cfg(any())]
    fn make_mock_core() -> (DesktopCore, PathBuf, TestArc<MockCredentialBackend>) {
        let test_dir = env::temp_dir().join(format!("xiic-ssh-mcp-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&test_dir).expect("test dir should be created");
        let db_path = test_dir.join("instances.sqlite3");
        let backend = TestArc::new(MockCredentialBackend::default());
        let core = DesktopCore::new_with_secret_store(
            db_path,
            SecretStore::with_backend(TEST_SERVICE, backend.clone()),
            None,
        )
        .expect("test core should initialize");
        (core, test_dir, backend)
    }

    #[cfg(any())]
    fn make_mock_core_from_db(
        db_path: PathBuf,
        backend: TestArc<MockCredentialBackend>,
    ) -> DesktopCore {
        DesktopCore::new_with_secret_store(
            db_path,
            SecretStore::with_backend(TEST_SERVICE, backend),
            None,
        )
        .expect("test core should initialize")
    }

    #[cfg(any())]
    fn password_draft(instance_id: &str) -> InstanceDraft {
        InstanceDraft {
            instance_id: instance_id.to_string(),
            name: "Production".to_string(),
            host: "example.com".to_string(),
            port: 22,
            username: "root".to_string(),
            auth_kind: AuthKind::Password,
            host_key_check: false,
            notes: None,
            password: Some("secret".to_string()),
            private_key: None,
            private_key_path: None,
            passphrase: None,
            keep_existing_secret: false,
        }
    }

    #[cfg(any())]
    fn password_secret(password: &str) -> SecretPayload {
        SecretPayload {
            password: Some(password.to_string()),
            private_key: None,
            private_key_path: None,
            passphrase: None,
        }
    }

    #[cfg(any())]
    fn save_legacy_secret(store: &InstanceStore, instance_id: &str, secret: &SecretPayload) {
        store
            .save_instance(&password_draft(instance_id))
            .expect("legacy instance should be saved");
        store
            .save_secret(instance_id, secret)
            .expect("legacy secret should be saved");
    }

    fn test_context() -> RequestContext {
        RequestContext {
            client_id: "test-client".to_string(),
            client_session_id: Uuid::new_v4().to_string(),
        }
    }

    #[test]
    #[cfg(any())]
    fn save_instance_stores_secret_only_in_keychain() {
        let (core, test_dir, backend) = make_mock_core();

        let summary = core
            .save_instance(password_draft("prod"))
            .expect("instance should save");

        assert!(summary.has_secret);
        assert_eq!(
            backend
                .load_payload(TEST_SERVICE, "prod")
                .expect("secret should be in keychain"),
            password_secret("secret")
        );
        assert!(
            core.store
                .load_secret("prod")
                .expect("sqlite secret lookup should succeed")
                .is_none(),
            "new saves must not write instance_secrets"
        );

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }

    #[test]
    #[cfg(any())]
    fn list_instances_keeps_metadata_when_keychain_read_fails() {
        let (core, test_dir, backend) = make_mock_core();
        core.save_instance(password_draft("prod"))
            .expect("initial instance should save");
        backend.fail_next_get("prod");

        let instances = core
            .list_instances()
            .expect("metadata list should remain available");

        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].instance_id, "prod");
        assert!(!instances[0].has_secret);

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }

    #[test]
    #[cfg(any())]
    fn save_instance_replaces_an_unreadable_secret_when_new_credential_is_supplied() {
        let (core, test_dir, backend) = make_mock_core();
        core.save_instance(password_draft("prod"))
            .expect("initial instance should save");
        backend.fail_next_get("prod");
        let mut replacement = password_draft("prod");
        replacement.password = Some("replacement".to_string());

        core.save_instance(replacement)
            .expect("new credential should recover an unreadable old entry");

        assert_eq!(
            backend
                .load_payload(TEST_SERVICE, "prod")
                .expect("replacement credential should be stored"),
            password_secret("replacement")
        );

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }

    #[test]
    #[cfg(any())]
    fn save_instance_fails_when_keychain_save_fails_without_sqlite_fallback() {
        let (core, test_dir, backend) = make_mock_core();
        backend.fail_next_set("prod");

        let err = core
            .save_instance(password_draft("prod"))
            .expect_err("keychain failure should fail save");

        assert!(err.to_string().contains("failed to store secret"));
        assert!(
            core.store
                .load_secret("prod")
                .expect("sqlite secret lookup should succeed")
                .is_none(),
            "failed keychain save must not fall back to SQLite"
        );

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }

    #[test]
    #[cfg(any())]
    fn save_instance_fails_when_keychain_write_cannot_be_read_back() {
        let (core, test_dir, backend) = make_mock_core();
        backend.discard_next_set("prod");

        let err = core
            .save_instance(password_draft("prod"))
            .expect_err("unreadable keychain save should fail");

        assert!(err.to_string().contains("verification failed"));
        assert!(
            core.store
                .get_instance("prod")
                .expect("instance lookup should succeed")
                .is_none(),
            "metadata must not be saved when the credential cannot be verified"
        );

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }

    #[test]
    #[cfg(any())]
    fn metadata_save_failure_restores_previous_keychain_secret() {
        let (core, test_dir, backend) = make_mock_core();
        core.save_instance(password_draft("prod"))
            .expect("initial instance should save");
        let connection = rusqlite::Connection::open(test_dir.join("instances.sqlite3"))
            .expect("database should open");
        connection
            .execute_batch(
                "CREATE TRIGGER fail_instance_update
                 BEFORE UPDATE ON instances
                 BEGIN
                   SELECT RAISE(ABORT, 'mock metadata update failed');
                 END;",
            )
            .expect("failure trigger should be created");
        drop(connection);
        let mut updated = password_draft("prod");
        updated.name = "Changed".to_string();
        updated.password = Some("replacement".to_string());

        let error = core
            .save_instance(updated)
            .expect_err("metadata failure should fail save");

        assert!(
            error
                .to_string()
                .contains("failed to save instance metadata")
        );
        assert_eq!(
            backend
                .load_payload(TEST_SERVICE, "prod")
                .expect("previous credential should remain"),
            password_secret("secret")
        );
        assert_eq!(
            core.store
                .get_instance("prod")
                .expect("instance lookup should succeed")
                .expect("instance should remain")
                .name,
            "Production"
        );

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }

    #[test]
    #[cfg(any())]
    fn keychain_delete_failure_preserves_instance_metadata() {
        let (core, test_dir, backend) = make_mock_core();
        core.save_instance(password_draft("prod"))
            .expect("initial instance should save");
        backend.fail_next_delete("prod");

        let error = core
            .delete_instance("prod")
            .expect_err("keychain failure should fail deletion");

        assert!(format!("{error:#}").contains("mock keychain delete failed"));
        assert!(
            core.store
                .get_instance("prod")
                .expect("instance lookup should succeed")
                .is_some(),
            "metadata must remain when credential deletion fails"
        );
        assert_eq!(
            backend
                .load_payload(TEST_SERVICE, "prod")
                .expect("credential should remain"),
            password_secret("secret")
        );

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }

    #[test]
    #[cfg(any())]
    fn metadata_delete_failure_restores_keychain_secret() {
        let (core, test_dir, backend) = make_mock_core();
        core.save_instance(password_draft("prod"))
            .expect("initial instance should save");
        let connection = rusqlite::Connection::open(test_dir.join("instances.sqlite3"))
            .expect("database should open");
        connection
            .execute_batch(
                "CREATE TRIGGER fail_instance_delete
                 BEFORE DELETE ON instances
                 BEGIN
                   SELECT RAISE(ABORT, 'mock metadata delete failed');
                 END;",
            )
            .expect("failure trigger should be created");
        drop(connection);

        let error = core
            .delete_instance("prod")
            .expect_err("metadata failure should fail deletion");

        assert!(error.to_string().contains("failed to delete instance"));
        assert!(
            core.store
                .get_instance("prod")
                .expect("instance lookup should succeed")
                .is_some(),
            "metadata should remain after the failed deletion"
        );
        assert_eq!(
            backend
                .load_payload(TEST_SERVICE, "prod")
                .expect("credential should be restored"),
            password_secret("secret")
        );

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }

    #[test]
    #[cfg(any())]
    fn legacy_sqlite_secret_migrates_to_keychain_and_is_deleted() {
        let test_dir = env::temp_dir().join(format!("xiic-ssh-mcp-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&test_dir).expect("test dir should be created");
        let db_path = test_dir.join("instances.sqlite3");
        let store = InstanceStore::new(db_path.clone()).expect("store should initialize");
        save_legacy_secret(&store, "prod", &password_secret("legacy"));

        let backend = TestArc::new(MockCredentialBackend::default());
        let core = make_mock_core_from_db(db_path, backend.clone());

        assert_eq!(
            backend
                .load_payload(TEST_SERVICE, "prod")
                .expect("secret should migrate to keychain"),
            password_secret("legacy")
        );
        assert!(
            core.store
                .load_secret("prod")
                .expect("sqlite secret lookup should succeed")
                .is_none(),
            "migrated secret should be deleted from SQLite"
        );

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }

    #[test]
    #[cfg(any())]
    fn legacy_secret_is_preserved_when_keychain_migration_cannot_be_verified() {
        let test_dir = env::temp_dir().join(format!("xiic-ssh-mcp-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&test_dir).expect("test dir should be created");
        let db_path = test_dir.join("instances.sqlite3");
        let store = InstanceStore::new(db_path.clone()).expect("store should initialize");
        save_legacy_secret(&store, "prod", &password_secret("legacy"));

        let backend = TestArc::new(MockCredentialBackend::default());
        backend.discard_next_set("prod");
        let _core = make_mock_core_from_db(db_path.clone(), backend);

        assert!(
            store
                .load_secret("prod")
                .expect("legacy secret lookup should succeed")
                .is_some(),
            "legacy secret must remain until the keychain copy can be read back"
        );

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }

    #[test]
    #[cfg(any())]
    fn legacy_sqlite_secret_does_not_overwrite_existing_keychain_secret() {
        let test_dir = env::temp_dir().join(format!("xiic-ssh-mcp-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&test_dir).expect("test dir should be created");
        let db_path = test_dir.join("instances.sqlite3");
        let store = InstanceStore::new(db_path.clone()).expect("store should initialize");
        save_legacy_secret(&store, "prod", &password_secret("legacy"));

        let backend = TestArc::new(MockCredentialBackend::default());
        backend
            .set_password(
                TEST_SERVICE,
                "prod",
                &serde_json::to_string(&password_secret("keychain")).expect("secret should encode"),
            )
            .expect("existing keychain secret should save");
        let core = make_mock_core_from_db(db_path, backend.clone());

        assert_eq!(
            backend
                .load_payload(TEST_SERVICE, "prod")
                .expect("keychain secret should remain"),
            password_secret("keychain")
        );
        assert!(
            core.store
                .load_secret("prod")
                .expect("sqlite secret lookup should succeed")
                .is_none(),
            "conflicting legacy secret should be deleted"
        );

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }

    #[test]
    #[cfg(any())]
    fn legacy_sqlite_secret_is_not_used_when_keychain_is_missing() {
        let test_dir = env::temp_dir().join(format!("xiic-ssh-mcp-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&test_dir).expect("test dir should be created");
        let db_path = test_dir.join("instances.sqlite3");
        let store = InstanceStore::new(db_path.clone()).expect("store should initialize");
        save_legacy_secret(&store, "prod", &password_secret("legacy"));

        let backend = TestArc::new(MockCredentialBackend::default());
        backend.fail_next_set("prod");
        let core = make_mock_core_from_db(db_path, backend);

        assert!(
            core.load_secret("prod")
                .expect("keychain lookup should succeed")
                .is_none(),
            "runtime load must not fall back to SQLite"
        );
        assert!(
            !core
                .has_secret("prod")
                .expect("keychain has_secret lookup should succeed"),
            "runtime has_secret must not fall back to SQLite"
        );
        assert!(
            core.store
                .load_secret("prod")
                .expect("sqlite secret should remain after failed migration")
                .is_some(),
            "failed migration should preserve legacy row"
        );

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }

    #[test]
    fn download_to_local_rejects_existing_file_when_overwrite_disabled() {
        let (core, test_dir) = make_test_core();
        let local_path = test_dir.join("existing.txt");
        std::fs::write(&local_path, "keep me").expect("existing file should be written");

        let err = core
            .download_to_local(
                &test_context(),
                DownloadToLocalArgs {
                    session_id: "missing-session".to_string(),
                    remote_path: "/tmp/remote.txt".to_string(),
                    local_path: local_path.display().to_string(),
                    overwrite: false,
                },
            )
            .expect_err("existing local file should not be overwritten");

        assert!(err.to_string().contains("already exists"));
        assert_eq!(
            std::fs::read_to_string(&local_path).expect("existing file should still be readable"),
            "keep me"
        );

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }

    #[test]
    fn command_output_over_limit_is_rejected() {
        let bytes = vec![b'a'; (MAX_COMMAND_STREAM_BYTES + 1) as usize];
        let mut reader = std::io::Cursor::new(bytes);

        let error = read_limited_utf8(&mut reader, "command stdout")
            .expect_err("oversized output should fail");

        assert!(error.to_string().contains("4 MiB"));
    }

    #[test]
    fn secret_for_draft_accepts_private_key_path() {
        let (core, test_dir) = make_test_core();
        let draft = InstanceDraft {
            instance_id: "prod".to_string(),
            name: "Production".to_string(),
            host: "example.com".to_string(),
            port: 22,
            username: "root".to_string(),
            auth_kind: AuthKind::PrivateKey,
            host_key_check: false,
            notes: None,
            password: None,
            private_key: None,
            private_key_path: Some("/Users/test/.ssh/id_ed25519".to_string()),
            passphrase: Some("hunter2".to_string()),
            keep_existing_secret: false,
        };

        let resolved = core
            .secret_for_draft(&draft, None, false)
            .expect("private key path should be accepted");

        assert_eq!(
            resolved.private_key_path.as_deref(),
            Some("/Users/test/.ssh/id_ed25519")
        );
        assert_eq!(resolved.passphrase.as_deref(), Some("hunter2"));

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }

    #[test]
    fn secret_for_draft_rejects_both_private_key_sources() {
        let (core, test_dir) = make_test_core();
        let draft = InstanceDraft {
            instance_id: "prod".to_string(),
            name: "Production".to_string(),
            host: "example.com".to_string(),
            port: 22,
            username: "root".to_string(),
            auth_kind: AuthKind::PrivateKey,
            host_key_check: false,
            notes: None,
            password: None,
            private_key: Some("-----BEGIN OPENSSH PRIVATE KEY-----".to_string()),
            private_key_path: Some("/Users/test/.ssh/id_ed25519".to_string()),
            passphrase: None,
            keep_existing_secret: false,
        };

        let err = core
            .secret_for_draft(&draft, None, false)
            .expect_err("simultaneous private key sources should fail");

        assert!(
            err.to_string()
                .contains("either private_key or private_key_path")
        );

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }

    #[test]
    fn secret_for_draft_keeps_existing_private_key_path() {
        let (core, test_dir) = make_test_core();
        let draft = InstanceDraft {
            instance_id: "prod".to_string(),
            name: "Production".to_string(),
            host: "example.com".to_string(),
            port: 22,
            username: "root".to_string(),
            auth_kind: AuthKind::PrivateKey,
            host_key_check: false,
            notes: None,
            password: None,
            private_key: None,
            private_key_path: None,
            passphrase: None,
            keep_existing_secret: true,
        };
        let existing_secret = SecretPayload {
            password: None,
            private_key: None,
            private_key_path: Some("/Users/test/.ssh/id_ed25519".to_string()),
            passphrase: Some("hunter2".to_string()),
        };

        let resolved = core
            .secret_for_draft(&draft, Some(&existing_secret), false)
            .expect("existing private key path should be preserved");

        assert_eq!(resolved, existing_secret);

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }

    #[test]
    fn close_session_unknown_id_returns_error() {
        let (core, test_dir) = make_test_core();
        let err = core
            .close_session(&test_context(), "nonexistent-session-id")
            .expect_err("unknown session_id should fail");

        assert!(err.to_string().contains("unknown session_id"));
        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }

    #[test]
    fn sudo_command_empty_command_bails() {
        let (core, test_dir) = make_test_core();
        // 空命令校验在 prompt_sudo_password 之前，不需要 GUI
        let err = core
            .sudo_command(
                &test_context(),
                SudoCommandArgs {
                    session_id: "any".to_string(),
                    command: "   ".to_string(),
                    timeout_secs: None,
                },
            )
            .expect_err("empty command should fail");

        assert!(err.to_string().contains("command cannot be empty"));
        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }
}
