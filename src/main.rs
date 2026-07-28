use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use xiic_ssh_mcp::app_core::{DEFAULT_CLIENT_ID, DesktopCore};
use xiic_ssh_mcp::broker::{run_broker, run_stdio_bridge};
use xiic_ssh_mcp::local_ipc::{
    broker_server_healthy, default_approval_endpoint, default_broker_endpoint,
    default_notify_endpoint, remove_stale_endpoint,
};
use xiic_ssh_mcp::models::WhitelistMode;
use xiic_ssh_mcp::paths::shared_app_data_dir;
use xiic_ssh_mcp::single_instance::SingleInstanceGuard;

fn main() -> Result<()> {
    let options = CliOptions::parse(env::args().skip(1))?;
    let runtime = resolve_runtime_paths(&options)?;

    if !options.daemon {
        ensure_daemon(&options, &runtime)?;
        return run_stdio_bridge(&runtime.broker_endpoint, &options.client_id);
    }

    let lock_path = runtime.data_dir.join("mcp.lock");
    let _instance_lock = match SingleInstanceGuard::acquire(&lock_path, || {
        broker_server_healthy(&runtime.broker_endpoint)
    })? {
        Some(lock) => lock,
        None => return Ok(()),
    };
    let core = Arc::new(DesktopCore::new_with_socket(
        runtime.db_path.clone(),
        Some(runtime.notify_endpoint.clone()),
    )?);

    if !broker_server_healthy(&runtime.broker_endpoint) {
        remove_stale_endpoint(&runtime.broker_endpoint);
    }

    run_broker(
        &runtime.broker_endpoint,
        core,
        options.whitelist_mode,
        Some(runtime.approval_endpoint),
    )
}

fn ensure_daemon(options: &CliOptions, runtime: &RuntimePaths) -> Result<()> {
    if broker_server_healthy(&runtime.broker_endpoint) {
        return Ok(());
    }

    let exe = env::current_exe().context("failed to resolve current executable")?;
    let mut command = Command::new(exe);
    command
        .arg("--daemon")
        .arg("--db-path")
        .arg(&runtime.db_path)
        .arg("--whitelist")
        .arg(whitelist_mode_as_str(options.whitelist_mode))
        .arg("--broker-endpoint")
        .arg(&runtime.broker_endpoint)
        .arg("--notify-socket")
        .arg(&runtime.notify_endpoint)
        .arg("--approval-endpoint")
        .arg(&runtime.approval_endpoint)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    command.spawn().context("failed to launch MCP daemon")?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if broker_server_healthy(&runtime.broker_endpoint) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    anyhow::bail!(
        "MCP daemon did not become healthy at '{}'",
        runtime.broker_endpoint
    )
}

struct RuntimePaths {
    data_dir: PathBuf,
    db_path: PathBuf,
    notify_endpoint: String,
    approval_endpoint: String,
    broker_endpoint: String,
}

fn resolve_runtime_paths(options: &CliOptions) -> Result<RuntimePaths> {
    let db_path = match &options.db_path {
        Some(path) => path.clone(),
        None => shared_app_data_dir()?.join("instances.sqlite3"),
    };
    let data_dir = db_path
        .parent()
        .map(PathBuf::from)
        .unwrap_or(shared_app_data_dir()?);
    let notify_endpoint = options
        .notify_socket
        .clone()
        .unwrap_or_else(|| default_notify_endpoint(&data_dir));
    let approval_endpoint = options
        .approval_endpoint
        .clone()
        .unwrap_or_else(|| default_approval_endpoint(&data_dir));
    let broker_endpoint = options
        .broker_endpoint
        .clone()
        .unwrap_or_else(|| default_broker_endpoint(&data_dir));

    Ok(RuntimePaths {
        data_dir,
        db_path,
        notify_endpoint,
        approval_endpoint,
        broker_endpoint,
    })
}

struct CliOptions {
    db_path: Option<PathBuf>,
    notify_socket: Option<String>,
    whitelist_mode: WhitelistMode,
    approval_endpoint: Option<String>,
    broker_endpoint: Option<String>,
    client_id: String,
    daemon: bool,
}

impl CliOptions {
    fn parse<I>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let mut db_path = None;
        let mut notify_socket = None;
        let mut whitelist_mode = WhitelistMode::Strict;
        let mut approval_endpoint = None;
        let mut broker_endpoint = None;
        let mut client_id = DEFAULT_CLIENT_ID.to_string();
        let mut daemon = false;
        let mut iter = args.into_iter();

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--daemon" => {
                    daemon = true;
                }
                "--db-path" => {
                    let value = iter
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--db-path requires a value"))?;
                    db_path = Some(PathBuf::from(value));
                }
                "--keyring-service" => {
                    let _legacy_keyring_service = iter
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--keyring-service requires a value"))?;
                }
                "--notify-socket" => {
                    let value = iter
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--notify-socket requires a value"))?;
                    notify_socket = Some(value);
                }
                "--whitelist" => {
                    let value = iter
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--whitelist requires 'strict' or 'off'"))?;
                    whitelist_mode = match value.as_str() {
                        "strict" => WhitelistMode::Strict,
                        "off" => WhitelistMode::Off,
                        _ => {
                            return Err(anyhow::anyhow!(
                                "--whitelist must be 'strict' or 'off', got '{}'",
                                value
                            ));
                        }
                    };
                }
                "--approval-endpoint" => {
                    approval_endpoint =
                        Some(iter.next().ok_or_else(|| {
                            anyhow::anyhow!("--approval-endpoint requires a value")
                        })?);
                }
                "--broker-endpoint" => {
                    broker_endpoint =
                        Some(iter.next().ok_or_else(|| {
                            anyhow::anyhow!("--broker-endpoint requires a value")
                        })?);
                }
                "--client-id" => {
                    client_id = iter
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--client-id requires a value"))?;
                }
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                _ => {
                    return Err(anyhow::anyhow!(format!("unknown argument: {arg}")));
                }
            }
        }

        Ok(Self {
            db_path,
            notify_socket,
            whitelist_mode,
            approval_endpoint,
            broker_endpoint,
            client_id,
            daemon,
        })
    }
}

fn whitelist_mode_as_str(mode: WhitelistMode) -> &'static str {
    match mode {
        WhitelistMode::Strict => "strict",
        WhitelistMode::Off => "off",
    }
}

fn print_help() {
    println!(
        "xiic-ssh-mcp\n\n\
         Usage:\n  \
         xiic-ssh-mcp [--db-path <path>] [--client-id <id>] [--broker-endpoint <path-or-pipe>] [--daemon] [--notify-socket <path>] [--approval-endpoint <path-or-pipe>] [--whitelist strict|off]\n\n\
         Options:\n  \
         --daemon                  Run the long-lived local MCP daemon\n  \
         --db-path <path>          Path to SQLite database (defaults to the shared app data dir)\n  \
         --client-id <id>          Stable client/agent id for operation logs\n  \
         --broker-endpoint <x>     Local IPC endpoint for stdio helper <-> daemon bridge\n  \
         --keyring-service <srv>   Deprecated legacy option; accepted but ignored\n  \
         --notify-socket <path>    Local IPC endpoint for UI log notifications\n  \
         --approval-endpoint <x>   Local IPC endpoint for approval request/response\n  \
         --whitelist <mode>        Whitelist mode: 'strict' (default) or 'off'\n",
    );
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use xiic_ssh_mcp::local_ipc::{
        default_approval_endpoint, default_broker_endpoint, default_notify_endpoint,
    };
    use xiic_ssh_mcp::paths::shared_app_data_dir;

    use super::{CliOptions, resolve_runtime_paths};

    #[test]
    fn cli_defaults_to_shared_app_data_runtime_paths() {
        let options = CliOptions::parse(["--client-id".to_string(), "codex".to_string()])
            .expect("default CLI options should parse");
        let runtime = resolve_runtime_paths(&options).expect("runtime paths should resolve");
        let data_dir = shared_app_data_dir().expect("shared data dir should resolve");

        assert_eq!(runtime.db_path, data_dir.join("instances.sqlite3"));
        assert_eq!(runtime.notify_endpoint, default_notify_endpoint(&data_dir));
        assert_eq!(
            runtime.approval_endpoint,
            default_approval_endpoint(&data_dir)
        );
        assert_eq!(runtime.broker_endpoint, default_broker_endpoint(&data_dir));
    }

    #[test]
    fn explicit_db_path_still_overrides_runtime_defaults() {
        let options =
            CliOptions::parse(["--db-path".to_string(), "/tmp/xiic-ssh.sqlite3".to_string()])
                .expect("explicit db path should parse");
        let runtime = resolve_runtime_paths(&options).expect("runtime paths should resolve");

        assert_eq!(runtime.db_path, PathBuf::from("/tmp/xiic-ssh.sqlite3"));
    }
}
