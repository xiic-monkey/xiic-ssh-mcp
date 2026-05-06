use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ssh2::{CheckResult, KnownHostFileKind, Session};
use uuid::Uuid;

use crate::config::{InstanceConfig, InstanceRegistry};

#[derive(Debug, Serialize)]
pub struct CreateSessionResult {
    pub session_id: String,
    pub instance_id: String,
    pub connected_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ExecuteCommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

#[derive(Debug, Serialize)]
pub struct UploadFileResult {
    pub local_path: String,
    pub remote_path: String,
    pub bytes_written: usize,
}

#[derive(Debug, Serialize)]
pub struct DownloadFileResult {
    pub local_path: String,
    pub remote_path: String,
    pub size: usize,
}

#[derive(Debug, Deserialize)]
pub struct ExecuteCommandArgs {
    pub session_id: String,
    pub command: String,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct UploadFileArgs {
    pub session_id: String,
    pub local_path: String,
    pub remote_path: String,
    #[serde(default = "default_overwrite")]
    pub overwrite: bool,
}

#[derive(Debug, Deserialize)]
pub struct DownloadFileArgs {
    pub session_id: String,
    pub remote_path: String,
    #[serde(default)]
    pub local_path: Option<String>,
}

fn default_overwrite() -> bool {
    true
}

struct ManagedSession {
    last_used_at: DateTime<Utc>,
    session: Session,
}

pub struct SessionManager {
    instances: InstanceRegistry,
    sessions: HashMap<String, ManagedSession>,
}

impl SessionManager {
    pub fn new(instances: InstanceRegistry) -> Self {
        Self {
            instances,
            sessions: HashMap::new(),
        }
    }

    pub fn create_session(&mut self, instance_id: &str) -> Result<CreateSessionResult> {
        let instance = self
            .instances
            .get(instance_id)
            .with_context(|| format!("unknown instance_id '{}'", instance_id))?
            .clone();

        let session = connect(&instance)
            .with_context(|| format!("failed to connect to instance '{}'", instance_id))?;
        let session_id = Uuid::new_v4().to_string();
        let connected_at = Utc::now();

        self.sessions.insert(
            session_id.clone(),
            ManagedSession {
                last_used_at: connected_at,
                session,
            },
        );

        Ok(CreateSessionResult {
            session_id,
            instance_id: instance_id.to_string(),
            connected_at,
        })
    }

    pub fn execute_command(&mut self, args: ExecuteCommandArgs) -> Result<ExecuteCommandResult> {
        let managed = self.get_session_mut(&args.session_id)?;
        if args.command.trim().is_empty() {
            bail!("command cannot be empty");
        }

        if let Some(timeout_secs) = args.timeout_secs {
            let timeout_ms = timeout_secs
                .checked_mul(1_000)
                .ok_or_else(|| anyhow!("timeout_secs is too large"))?;
            let timeout_ms = u32::try_from(timeout_ms)
                .map_err(|_| anyhow!("timeout_secs exceeds ssh timeout limits"))?;
            managed.session.set_timeout(timeout_ms);
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

        managed.last_used_at = Utc::now();

        Ok(ExecuteCommandResult {
            stdout,
            stderr,
            exit_code,
        })
    }

    pub fn upload_file(&mut self, args: UploadFileArgs) -> Result<UploadFileResult> {
        let managed = self.get_session_mut(&args.session_id)?;
        let local_path = args.local_path.clone();
        let bytes = std::fs::read(&local_path)
            .with_context(|| format!("failed to read local path '{}'", local_path))?;

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

        managed.last_used_at = Utc::now();

        Ok(UploadFileResult {
            local_path,
            remote_path: args.remote_path,
            bytes_written: bytes.len(),
        })
    }

    pub fn download_file(&mut self, args: DownloadFileArgs) -> Result<DownloadFileResult> {
        let managed = self.get_session_mut(&args.session_id)?;
        let resolved_local_path =
            resolve_download_path(&args.remote_path, args.local_path.as_deref())?;
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
            format!("failed to write local path '{}'", resolved_local_path.display())
        })?;

        managed.last_used_at = Utc::now();

        Ok(DownloadFileResult {
            local_path: resolved_local_path.display().to_string(),
            remote_path: args.remote_path,
            size: bytes.len(),
        })
    }

    fn get_session_mut(&mut self, session_id: &str) -> Result<&mut ManagedSession> {
        self.sessions
            .get_mut(session_id)
            .with_context(|| format!("unknown session_id '{}'", session_id))
    }
}

fn connect(instance: &InstanceConfig) -> Result<Session> {
    let tcp = TcpStream::connect((instance.host.as_str(), instance.port)).with_context(|| {
        format!(
            "failed to open TCP connection to {}:{}",
            instance.host, instance.port
        )
    })?;
    tcp.set_read_timeout(Some(Duration::from_secs(30)))
        .context("failed to set TCP read timeout")?;
    tcp.set_write_timeout(Some(Duration::from_secs(30)))
        .context("failed to set TCP write timeout")?;

    let mut session = Session::new().context("failed to create SSH session")?;
    session.set_tcp_stream(tcp);
    session.handshake().context("SSH handshake failed")?;

    if instance.host_key_check {
        verify_host_key(&session, instance)?;
    }

    if let Some(private_key) = &instance.private_key {
        session
            .userauth_pubkey_memory(
                &instance.username,
                None,
                private_key,
                instance.passphrase.as_deref(),
            )
            .with_context(|| {
                format!(
                    "private key authentication failed for '{}@{}'",
                    instance.username, instance.host
                )
            })?;
    } else if let Some(password) = &instance.password {
        session
            .userauth_password(&instance.username, password)
            .with_context(|| {
                format!(
                    "password authentication failed for '{}@{}'",
                    instance.username, instance.host
                )
            })?;
    }

    if !session.authenticated() {
        bail!("SSH authentication did not complete successfully");
    }

    Ok(session)
}

fn verify_host_key(session: &Session, instance: &InstanceConfig) -> Result<()> {
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

    match known_hosts.check_port(instance.host.as_str(), instance.port, host_key) {
        CheckResult::Match => Ok(()),
        CheckResult::Mismatch => bail!(
            "host key mismatch for '{}:{}'",
            instance.host,
            instance.port
        ),
        CheckResult::NotFound => bail!(
            "host key for '{}:{}' not found in known_hosts",
            instance.host,
            instance.port
        ),
        CheckResult::Failure => bail!("failed to validate host key"),
    }
}

fn known_hosts_path() -> Result<PathBuf> {
    let home = env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".ssh").join("known_hosts"))
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

#[cfg(test)]
mod tests {
    use std::env;
    use std::path::PathBuf;

    use super::resolve_download_path;

    #[test]
    fn resolve_download_path_uses_explicit_local_path() {
        let path = resolve_download_path("/remote/demo.txt", Some("/tmp/out.txt")).unwrap();
        assert_eq!(path, PathBuf::from("/tmp/out.txt"));
    }

    #[test]
    fn resolve_download_path_defaults_to_downloads_dir() {
        let home = env::var("HOME").expect("HOME should be set in test environment");
        let path = resolve_download_path("/remote/demo.txt", None).unwrap();
        assert_eq!(path, PathBuf::from(home).join("Downloads").join("demo.txt"));
    }
}
