use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use xiic_ssh_mcp::app_core::{DEFAULT_CLIENT_ID, DEFAULT_KEYRING_SERVICE, DesktopCore};
use xiic_ssh_mcp::broker::{run_broker, run_stdio_bridge};
use xiic_ssh_mcp::local_ipc::{
    broker_server_healthy, default_broker_endpoint, notify_server_healthy, remove_stale_endpoint,
};
use xiic_ssh_mcp::models::{ApprovalMode, WhitelistMode};
use xiic_ssh_mcp::paths::shared_app_data_dir;
use xiic_ssh_mcp::single_instance::SingleInstanceGuard;

fn main() -> Result<()> {
    let options = CliOptions::parse(env::args().skip(1))?;
    let data_dir = options
        .db_path
        .parent()
        .map(PathBuf::from)
        .unwrap_or(shared_app_data_dir()?);
    let broker_endpoint = options
        .broker_endpoint
        .clone()
        .unwrap_or_else(|| default_broker_endpoint(&data_dir));

    if !options.daemon {
        ensure_daemon(&options, &broker_endpoint)?;
        return run_stdio_bridge(&broker_endpoint, &options.client_id);
    }

    let lock_path = options
        .db_path
        .parent()
        .map(|dir| dir.join("mcp.lock"))
        .unwrap_or_else(|| PathBuf::from("mcp.lock"));
    let _instance_lock = match SingleInstanceGuard::acquire(&lock_path, || {
        options
            .notify_socket
            .as_deref()
            .map(notify_server_healthy)
            .unwrap_or(true)
    })? {
        Some(lock) => lock,
        None => return Ok(()),
    };
    let approval_endpoint = options.approval_endpoint.clone();
    let core = Arc::new(DesktopCore::new_with_socket(
        options.db_path,
        options.keyring_service,
        options.notify_socket,
    )?);

    if !broker_server_healthy(&broker_endpoint) {
        remove_stale_endpoint(&broker_endpoint);
    }

    run_broker(
        &broker_endpoint,
        core,
        options.whitelist_mode,
        options.approval_mode,
        approval_endpoint,
    )
}

fn ensure_daemon(options: &CliOptions, broker_endpoint: &str) -> Result<()> {
    if broker_server_healthy(broker_endpoint) {
        return Ok(());
    }

    let exe = env::current_exe().context("failed to resolve current executable")?;
    let mut command = Command::new(exe);
    command
        .arg("--daemon")
        .arg("--db-path")
        .arg(&options.db_path)
        .arg("--keyring-service")
        .arg(&options.keyring_service)
        .arg("--approval-mode")
        .arg(approval_mode_as_str(options.approval_mode))
        .arg("--whitelist")
        .arg(whitelist_mode_as_str(options.whitelist_mode))
        .arg("--broker-endpoint")
        .arg(broker_endpoint)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if let Some(endpoint) = &options.notify_socket {
        command.arg("--notify-socket").arg(endpoint);
    }
    if let Some(endpoint) = &options.approval_endpoint {
        command.arg("--approval-endpoint").arg(endpoint);
    }

    command.spawn().context("failed to launch MCP daemon")?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if broker_server_healthy(broker_endpoint) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    anyhow::bail!("MCP daemon did not become healthy at '{}'", broker_endpoint)
}

struct CliOptions {
    db_path: PathBuf,
    keyring_service: String,
    notify_socket: Option<String>,
    whitelist_mode: WhitelistMode,
    approval_mode: ApprovalMode,
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
        let mut keyring_service = DEFAULT_KEYRING_SERVICE.to_string();
        let mut notify_socket = None;
        let mut whitelist_mode = WhitelistMode::Strict;
        let mut approval_mode = ApprovalMode::Auto;
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
                    keyring_service = iter
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
                "--approval-mode" => {
                    let value = iter.next().ok_or_else(|| {
                        anyhow::anyhow!(
                            "--approval-mode requires 'auto', 'elicitation', or 'local'"
                        )
                    })?;
                    approval_mode = match value.as_str() {
                        "auto" => ApprovalMode::Auto,
                        "elicitation" => ApprovalMode::Elicitation,
                        "local" => ApprovalMode::Local,
                        _ => {
                            return Err(anyhow::anyhow!(
                                "--approval-mode must be 'auto', 'elicitation', or 'local', got '{}'",
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

        let db_path = db_path.ok_or_else(|| {
            anyhow::anyhow!("missing --db-path; launch this helper via the desktop app's MCP 配置")
        })?;

        Ok(Self {
            db_path,
            keyring_service,
            notify_socket,
            whitelist_mode,
            approval_mode,
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

fn approval_mode_as_str(mode: ApprovalMode) -> &'static str {
    match mode {
        ApprovalMode::Auto => "auto",
        ApprovalMode::Elicitation => "elicitation",
        ApprovalMode::Local => "local",
    }
}

fn print_help() {
    println!(
        "xiic-ssh-mcp\n\n\
         Usage:\n  \
         xiic-ssh-mcp --db-path <path> [--client-id <id>] [--broker-endpoint <path-or-pipe>] [--daemon] [--keyring-service <service>] [--notify-socket <path>] [--approval-endpoint <path-or-pipe>] [--whitelist strict|off] [--approval-mode auto|elicitation|local]\n\n\
         Options:\n  \
         --daemon                  Run the long-lived local MCP daemon\n  \
         --db-path <path>          Path to SQLite database\n  \
         --client-id <id>          Stable client/agent id for operation logs\n  \
         --broker-endpoint <x>     Local IPC endpoint for stdio helper <-> daemon bridge\n  \
         --keyring-service <srv>   Keyring service name (default: {})\n  \
         --notify-socket <path>    Local IPC endpoint for UI log notifications\n  \
         --approval-endpoint <x>   Local IPC endpoint for approval request/response\n  \
         --whitelist <mode>        Whitelist mode: 'strict' (default) or 'off'\n  \
         --approval-mode <mode>    Approval mode: 'auto' (default), 'elicitation', or 'local'\n",
        DEFAULT_KEYRING_SERVICE,
    );
}
