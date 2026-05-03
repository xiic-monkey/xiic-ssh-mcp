use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use xiic_ssh_mcp::app_core::{DEFAULT_KEYRING_SERVICE, DesktopCore};
use xiic_ssh_mcp::mcp::McpServer;

fn main() -> Result<()> {
    let options = CliOptions::parse(env::args().skip(1))?;
    let core = Arc::new(DesktopCore::new(
        options.db_path,
        options.keyring_service,
    )?);
    let mut server = McpServer::new(core);
    server.run()
}

struct CliOptions {
    db_path: PathBuf,
    keyring_service: String,
}

impl CliOptions {
    fn parse<I>(args: I) -> Result<Self>
    where
        I: IntoIterator<Item = String>,
    {
        let mut db_path = None;
        let mut keyring_service = DEFAULT_KEYRING_SERVICE.to_string();
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
        })
    }
}

fn print_help() {
    println!(
        "xiic-ssh-mcp\n\nUsage:\n  xiic-ssh-mcp --db-path <path> [--keyring-service <service>]\n"
    );
}
