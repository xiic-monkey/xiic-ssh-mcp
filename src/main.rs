use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use xiic_ssh_mcp::app_core::{DEFAULT_KEYRING_SERVICE, DesktopCore};
use xiic_ssh_mcp::local_ipc::{notify_server_healthy, remove_stale_endpoint};
use xiic_ssh_mcp::mcp::McpServer;
use xiic_ssh_mcp::models::{ApprovalMode, WhitelistMode};
use xiic_ssh_mcp::single_instance::SingleInstanceGuard;

fn main() -> Result<()> {
    let options = CliOptions::parse(env::args().skip(1))?;
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
    let mut server = McpServer::new(
        core,
        options.whitelist_mode,
        options.approval_mode,
        approval_endpoint.clone(),
    );

    // 启动前清除残留的 approval socket，防止审批 App 绑定失败
    if let Some(ref ep) = approval_endpoint {
        remove_stale_endpoint(ep);
    }

    server.pre_launch();
    server.run()
}

struct CliOptions {
    db_path: PathBuf,
    keyring_service: String,
    notify_socket: Option<String>,
    whitelist_mode: WhitelistMode,
    approval_mode: ApprovalMode,
    approval_endpoint: Option<String>,
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
        let mut iter = args.into_iter();

        while let Some(arg) = iter.next() {
            match arg.as_str() {
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
        })
    }
}

fn print_help() {
    println!(
        "xiic-ssh-mcp\n\n\
         Usage:\n  \
         xiic-ssh-mcp --db-path <path> [--keyring-service <service>] [--notify-socket <path>] [--approval-endpoint <path-or-pipe>] [--whitelist strict|off] [--approval-mode auto|elicitation|local]\n\n\
         Options:\n  \
         --db-path <path>          Path to SQLite database\n  \
         --keyring-service <srv>   Keyring service name (default: {})\n  \
         --notify-socket <path>    Local IPC endpoint for UI log notifications\n  \
         --approval-endpoint <x>   Local IPC endpoint for approval request/response\n  \
         --whitelist <mode>        Whitelist mode: 'strict' (default) or 'off'\n  \
         --approval-mode <mode>    Approval mode: 'auto' (default), 'elicitation', or 'local'\n",
        DEFAULT_KEYRING_SERVICE,
    );
}
