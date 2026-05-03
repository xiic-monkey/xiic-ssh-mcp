use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use ssh2::{CheckResult, KnownHostFileKind, Session};
use uuid::Uuid;

use crate::credentials::SecretStore;
use crate::models::{
    AuthKind, CreateSessionResult, DownloadFileArgs, DownloadFileResult, DownloadEncoding,
    ExecuteCommandArgs, ExecuteCommandResult, InstanceDraft, InstanceSummary, McpConfigBundle,
    SecretPayload, StoredInstance, TestConnectionResult, UploadEncoding, UploadFileArgs,
    UploadFileResult,
};
use crate::storage::InstanceStore;

pub const DEFAULT_KEYRING_SERVICE: &str = "com.xiic.ssh-manager";

#[derive(Clone)]
pub struct DesktopCore {
    store: InstanceStore,
    secrets: SecretStore,
    sessions: Arc<Mutex<HashMap<String, ManagedSession>>>,
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
        Ok(Self {
            store: InstanceStore::new(db_path)?,
            secrets: SecretStore::new(keyring_service),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        })
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

    pub fn save_instance(&self, draft: InstanceDraft) -> Result<InstanceSummary> {
        let draft = draft.normalize();
        self.validate_metadata(&draft)?;

        let existing_secret = self.load_secret(&draft.instance_id)?;
        let secret = self.secret_for_draft(&draft, existing_secret.as_ref(), true)?;
        let stored = self.store.save_instance(&draft)?;
        self.store.save_secret(&draft.instance_id, &secret)?;
        if let Err(err) = self.secrets.save_secret(&draft.instance_id, &secret) {
            eprintln!("warning: failed to store keychain secret for '{}': {err:#}", draft.instance_id);
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
        let has_inline_secret = draft.password.is_some()
            || draft.private_key.is_some()
            || draft.passphrase.is_some();
        let has_saved_instance = !draft.instance_id.is_empty()
            && self.store.get_instance(&draft.instance_id)?.is_some();
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

    pub fn mcp_config_bundle(
        &self,
        command_path: &str,
        db_path: &str,
        keyring_service: &str,
    ) -> Result<McpConfigBundle> {
        let args = vec![
            "--db-path".to_string(),
            db_path.to_string(),
            "--keyring-service".to_string(),
            keyring_service.to_string(),
        ];

        let stdio_json = serde_json::to_string_pretty(&serde_json::json!({
            "mcpServers": {
                "xiic-ssh": {
                    "command": command_path,
                    "args": args
                }
            }
        }))?;

        Ok(McpConfigBundle {
            command: command_path.to_string(),
            args,
            stdio_json,
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

        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("session manager lock poisoned"))?;
        let managed = sessions
            .get_mut(&args.session_id)
            .with_context(|| format!("unknown session_id '{}'", args.session_id))?;

        if let Some(timeout_secs) = args.timeout_secs {
            let timeout_ms = timeout_secs
                .checked_mul(1_000)
                .ok_or_else(|| anyhow!("timeout_secs is too large"))?;
            managed
                .session
                .set_timeout(u32::try_from(timeout_ms).map_err(|_| anyhow!("timeout_secs exceeds ssh timeout limits"))?);
        } else {
            managed.session.set_timeout(0);
        }

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

        Ok(ExecuteCommandResult {
            stdout,
            stderr,
            exit_code,
        })
    }

    pub fn upload_file(&self, args: UploadFileArgs) -> Result<UploadFileResult> {
        let bytes = match args.encoding {
            UploadEncoding::Utf8 => args.content.into_bytes(),
            UploadEncoding::Base64 => BASE64
                .decode(args.content)
                .context("failed to decode upload content as base64")?,
        };

        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("session manager lock poisoned"))?;
        let managed = sessions
            .get_mut(&args.session_id)
            .with_context(|| format!("unknown session_id '{}'", args.session_id))?;

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

        Ok(UploadFileResult {
            bytes_written: bytes.len(),
        })
    }

    pub fn download_file(&self, args: DownloadFileArgs) -> Result<DownloadFileResult> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("session manager lock poisoned"))?;
        let managed = sessions
            .get_mut(&args.session_id)
            .with_context(|| format!("unknown session_id '{}'", args.session_id))?;

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

        let (content, encoding) = match args.encoding {
            DownloadEncoding::Utf8 => (
                String::from_utf8(bytes.clone())
                    .context("remote file is not valid UTF-8; use base64 encoding instead")?,
                "utf8".to_string(),
            ),
            DownloadEncoding::Base64 => (BASE64.encode(bytes.clone()), "base64".to_string()),
        };

        Ok(DownloadFileResult {
            content,
            size: bytes.len(),
            encoding,
        })
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

fn connect(instance: &ResolvedInstance) -> Result<Session> {
    let tcp = TcpStream::connect((instance.metadata.host.as_str(), instance.metadata.port))
        .with_context(|| {
            format!(
                "failed to open TCP connection to {}:{}",
                instance.metadata.host, instance.metadata.port
            )
        })?;
    tcp.set_read_timeout(Some(Duration::from_secs(30)))
        .context("failed to set TCP read timeout")?;
    tcp.set_write_timeout(Some(Duration::from_secs(30)))
        .context("failed to set TCP write timeout")?;

    let mut session = Session::new().context("failed to create SSH session")?;
    session.set_tcp_stream(tcp);
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
