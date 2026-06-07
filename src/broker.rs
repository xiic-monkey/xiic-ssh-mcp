use std::io::{self, BufReader, Read, Write};
#[cfg(unix)]
use std::net::Shutdown;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
#[cfg(target_os = "windows")]
use std::{fs::File, os::windows::io::FromRawHandle};

use anyhow::{Context, Result, anyhow};
use chrono::Utc;

use crate::app_core::DesktopCore;
use crate::local_ipc::{
    BROKER_HEALTH_CHECK_KIND, BROKER_HEALTH_OK_KIND, broker_server_healthy, remove_stale_endpoint,
};
use crate::mcp::McpServer;
use crate::mcp_protocol::{IncomingMessage, MessageFraming, read_message, write_message};
use crate::models::{ApprovalMode, BrokerHello, BrokerWelcome, RequestContext, WhitelistMode};

pub fn run_stdio_bridge(endpoint: &str, client_id: &str) -> Result<()> {
    let mut stream = connect_broker_stream(endpoint)?;
    let hello = BrokerHello {
        kind: "broker_hello".to_string(),
        client_id: client_id.to_string(),
        protocol_version: "2024-11-05".to_string(),
        pid: std::process::id(),
        started_at: Utc::now().to_rfc3339(),
    };
    serde_json::to_writer(&mut stream, &hello).context("failed to write broker hello")?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut welcome = String::new();
    {
        let mut reader = BufReader::new(stream.try_clone()?);
        std::io::BufRead::read_line(&mut reader, &mut welcome)
            .context("failed to read broker welcome")?;
    }
    let _welcome: BrokerWelcome =
        serde_json::from_str(welcome.trim()).context("invalid broker welcome")?;

    let mut upstream_reader = stream.try_clone()?;
    let mut upstream_writer = stream;

    let inbound = std::thread::spawn(move || -> Result<()> {
        let stdin = io::stdin();
        let mut stdin_reader = BufReader::new(stdin.lock());
        loop {
            let message = match read_message(&mut stdin_reader)? {
                Some(message) => message,
                None => {
                    shutdown_write(&upstream_writer)?;
                    break;
                }
            };
            write_message(&mut upstream_writer, &message.payload, message.framing)?;
        }
        Ok(())
    });

    let outbound = std::thread::spawn(move || -> Result<()> {
        let stdout = io::stdout();
        let mut stdout_writer = stdout.lock();
        let mut upstream_buf = BufReader::new(&mut upstream_reader);
        loop {
            let message = match read_message(&mut upstream_buf)? {
                Some(message) => message,
                None => break,
            };
            write_message(&mut stdout_writer, &message.payload, message.framing)?;
        }
        Ok(())
    });

    inbound
        .join()
        .map_err(|_| anyhow!("stdio bridge inbound panicked"))??;
    outbound
        .join()
        .map_err(|_| anyhow!("stdio bridge outbound panicked"))??;
    Ok(())
}

pub fn run_broker(
    endpoint: &str,
    core: Arc<DesktopCore>,
    whitelist_mode: WhitelistMode,
    approval_mode: ApprovalMode,
    approval_endpoint: Option<String>,
) -> Result<()> {
    #[cfg(unix)]
    {
        if broker_server_healthy(endpoint) {
            return Ok(());
        }

        remove_stale_endpoint(endpoint);
        let listener = UnixListener::bind(endpoint).with_context(|| endpoint.to_string())?;
        eprintln!("[xiic-ssh-mcp] broker listening on {endpoint}");

        for stream in listener.incoming() {
            let stream = stream.context("failed to accept broker connection")?;
            let core = core.clone();
            let approval_endpoint = approval_endpoint.clone();
            std::thread::spawn(move || {
                if let Err(err) = handle_broker_connection(
                    stream,
                    core,
                    whitelist_mode,
                    approval_mode,
                    approval_endpoint,
                ) {
                    eprintln!("[xiic-ssh-mcp] broker connection failed: {err:#}");
                }
            });
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        if broker_server_healthy(endpoint) {
            return Ok(());
        }

        eprintln!("[xiic-ssh-mcp] broker listening on {endpoint}");
        loop {
            let stream = create_windows_pipe_server(endpoint)
                .with_context(|| format!("failed to accept broker pipe '{endpoint}'"))?;
            let core = core.clone();
            let approval_endpoint = approval_endpoint.clone();
            std::thread::spawn(move || {
                if let Err(err) = handle_broker_connection(
                    stream,
                    core,
                    whitelist_mode,
                    approval_mode,
                    approval_endpoint,
                ) {
                    eprintln!("[xiic-ssh-mcp] broker connection failed: {err:#}");
                }
            });
        }
    }

    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = (
            endpoint,
            core,
            whitelist_mode,
            approval_mode,
            approval_endpoint,
        );
        anyhow::bail!("MCP broker daemon is not supported on this platform yet");
    }
}

fn handle_broker_connection<S>(
    stream: S,
    core: Arc<DesktopCore>,
    whitelist_mode: WhitelistMode,
    approval_mode: ApprovalMode,
    approval_endpoint: Option<String>,
) -> Result<()>
where
    S: Read + Write + CloneStream,
{
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    let mut hello_line = String::new();
    std::io::BufRead::read_line(&mut reader, &mut hello_line)?;
    let first_message: serde_json::Value =
        serde_json::from_str(hello_line.trim()).context("invalid broker greeting")?;
    if first_message.get("kind").and_then(|kind| kind.as_str()) == Some(BROKER_HEALTH_CHECK_KIND) {
        writer.write_all(
            format!(
                "{}\n",
                serde_json::json!({
                    "kind": BROKER_HEALTH_OK_KIND
                })
            )
            .as_bytes(),
        )?;
        writer.flush()?;
        return Ok(());
    }

    let hello: BrokerHello =
        serde_json::from_value(first_message).context("invalid broker hello")?;

    let client_session_id = uuid::Uuid::new_v4().to_string();
    let welcome = BrokerWelcome {
        kind: "broker_welcome".to_string(),
        client_session_id: client_session_id.clone(),
    };
    writer.write_all(format!("{}\n", serde_json::to_string(&welcome)?).as_bytes())?;
    writer.flush()?;

    let ctx = RequestContext {
        client_id: hello.client_id.clone(),
        client_session_id: client_session_id.clone(),
    };

    core.log_client_connection(&ctx, "client_connected")?;

    let mut server = McpServer::new(
        core.clone(),
        whitelist_mode,
        approval_mode,
        approval_endpoint,
    );
    server.pre_launch();

    loop {
        let message = match read_message(&mut reader)? {
            Some(message) => message,
            None => break,
        };

        if is_broker_health_check(&message) {
            write_message(
                &mut writer,
                &serde_json::json!({
                    "kind": BROKER_HEALTH_OK_KIND
                }),
                MessageFraming::Newline,
            )?;
            continue;
        }

        server.dispatch_with_context(
            ctx.clone(),
            message.payload,
            message.framing,
            &mut reader,
            &mut writer,
        )?;
    }

    core.log_client_connection(&ctx, "client_disconnected")?;
    Ok(())
}

fn is_broker_health_check(message: &IncomingMessage) -> bool {
    message.payload.get("kind").and_then(|kind| kind.as_str()) == Some(BROKER_HEALTH_CHECK_KIND)
}

trait CloneStream {
    fn try_clone(&self) -> io::Result<Self>
    where
        Self: Sized;
}

#[cfg(unix)]
impl CloneStream for UnixStream {
    fn try_clone(&self) -> io::Result<Self> {
        UnixStream::try_clone(self)
    }
}

#[cfg(target_os = "windows")]
impl CloneStream for File {
    fn try_clone(&self) -> io::Result<Self> {
        File::try_clone(self)
    }
}

#[cfg(unix)]
fn connect_broker_stream(endpoint: &str) -> Result<UnixStream> {
    UnixStream::connect(endpoint).with_context(|| endpoint.to_string())
}

#[cfg(target_os = "windows")]
fn connect_broker_stream(endpoint: &str) -> Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(endpoint)
        .with_context(|| format!("failed to connect to broker pipe '{endpoint}'"))
}

#[cfg(not(any(unix, target_os = "windows")))]
fn connect_broker_stream(_endpoint: &str) -> Result<UnsupportedStream> {
    anyhow::bail!("MCP broker bridge is not supported on this platform yet")
}

#[cfg(unix)]
fn shutdown_write(stream: &UnixStream) -> Result<()> {
    stream
        .shutdown(Shutdown::Write)
        .context("failed to shutdown broker bridge write side")
}

#[cfg(target_os = "windows")]
fn shutdown_write(stream: &File) -> Result<()> {
    stream.sync_all().context("failed to flush broker bridge")
}

#[cfg(not(any(unix, target_os = "windows")))]
fn shutdown_write(_stream: &UnsupportedStream) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn create_windows_pipe_server(endpoint: &str) -> Result<File> {
    use std::ffi::OsStr;
    use std::iter;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::CreateNamedPipeW;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    let wide_endpoint: Vec<u16> = OsStr::new(endpoint)
        .encode_wide()
        .chain(iter::once(0))
        .collect();

    let handle = unsafe {
        CreateNamedPipeW(
            wide_endpoint.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            64 * 1024,
            64 * 1024,
            0,
            std::ptr::null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("failed to create broker pipe '{endpoint}'"));
    }

    let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) } != 0;
    if !connected {
        let error = unsafe { GetLastError() };
        if error != ERROR_PIPE_CONNECTED {
            unsafe {
                CloseHandle(handle);
            }
            return Err(io::Error::from_raw_os_error(error as i32))
                .with_context(|| format!("failed to connect broker pipe '{endpoint}'"));
        }
    }

    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(not(any(unix, target_os = "windows")))]
struct UnsupportedStream;
