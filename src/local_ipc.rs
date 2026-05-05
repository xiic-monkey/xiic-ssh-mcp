use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

use anyhow::{Context, Result};

pub const LOG_NOTIFICATION_PAYLOAD: &str = "log_updated";

#[cfg(target_os = "windows")]
pub const WINDOWS_NOTIFY_PIPE: &str = r"\\.\pipe\com.xiic.sshmanager.notify";
#[cfg(target_os = "windows")]
pub const WINDOWS_APPROVAL_PIPE: &str = r"\\.\pipe\com.xiic.sshmanager.approval";

pub fn default_notify_endpoint(data_dir: &Path) -> String {
    #[cfg(target_os = "windows")]
    {
        let _ = data_dir;
        WINDOWS_NOTIFY_PIPE.to_string()
    }

    #[cfg(not(target_os = "windows"))]
    {
        data_dir.join("notify.sock").to_string_lossy().into_owned()
    }
}

pub fn default_approval_endpoint(data_dir: &Path) -> String {
    #[cfg(target_os = "windows")]
    {
        let _ = data_dir;
        WINDOWS_APPROVAL_PIPE.to_string()
    }

    #[cfg(not(target_os = "windows"))]
    {
        data_dir
            .join("approval.sock")
            .to_string_lossy()
            .into_owned()
    }
}

pub fn remove_stale_endpoint(endpoint: &str) {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = std::fs::remove_file(endpoint);
    }

    #[cfg(target_os = "windows")]
    {
        let _ = endpoint;
    }
}

pub fn send_notification(endpoint: &str) -> Result<()> {
    let payload = format!("{LOG_NOTIFICATION_PAYLOAD}\n");
    send_line(endpoint, &payload)
}

pub fn send_line(endpoint: &str, payload: &str) -> Result<()> {
    with_stream(endpoint, |stream| {
        stream
            .write_all(payload.as_bytes())
            .context("failed to write IPC payload")?;
        stream.flush().context("failed to flush IPC payload")?;
        Ok(())
    })
}

pub fn send_request(endpoint: &str, payload: &str) -> Result<String> {
    with_stream(endpoint, |stream| {
        stream
            .write_all(payload.as_bytes())
            .context("failed to write IPC request")?;
        stream
            .write_all(b"\n")
            .context("failed to finish IPC request")?;
        stream.flush().context("failed to flush IPC request")?;

        let mut response = String::new();
        let mut reader = BufReader::new(stream);
        reader
            .read_line(&mut response)
            .context("failed to read IPC response")?;
        Ok(response.trim().to_string())
    })
}

fn with_stream<T, F>(endpoint: &str, op: F) -> Result<T>
where
    F: FnOnce(&mut dyn ReadWrite) -> Result<T>,
{
    #[cfg(not(target_os = "windows"))]
    {
        use std::os::unix::net::UnixStream;

        let mut stream = UnixStream::connect(endpoint)
            .with_context(|| format!("failed to connect to IPC endpoint '{endpoint}'"))?;
        return op(&mut stream);
    }

    #[cfg(target_os = "windows")]
    {
        let mut stream = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(endpoint)
            .with_context(|| format!("failed to connect to IPC endpoint '{endpoint}'"))?;
        return op(&mut stream);
    }
}

trait ReadWrite: Read + Write {}

impl<T> ReadWrite for T where T: Read + Write {}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::io::{BufRead, BufReader, ErrorKind, Write};
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;
    #[cfg(unix)]
    use std::thread;

    #[cfg(unix)]
    #[test]
    fn unix_endpoints_use_socket_paths() {
        let root = std::path::Path::new("/tmp/xiic-ssh");
        assert!(super::default_notify_endpoint(root).ends_with("notify.sock"));
        assert!(super::default_approval_endpoint(root).ends_with("approval.sock"));
    }

    #[cfg(unix)]
    #[test]
    fn unix_request_round_trip_uses_newline_protocol() {
        let socket_path = format!("/private/tmp/xiic-ssh-{}.sock", uuid::Uuid::new_v4());
        let listener = match UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => return,
            Err(err) => panic!("failed to bind unix test socket: {err}"),
        };

        let handle = thread::spawn({
            let socket_path = socket_path.clone();
            move || {
                let (mut stream, _) = listener.accept().expect("accept should succeed");
                let mut request = String::new();
                BufReader::new(&mut stream)
                    .read_line(&mut request)
                    .expect("should read request line");
                assert_eq!(request.trim(), "{\"hello\":true}");
                stream
                    .write_all(b"{\"accepted\":true}\n")
                    .expect("should write response");
                let _ = std::fs::remove_file(socket_path);
            }
        });

        let response =
            super::send_request(&socket_path, "{\"hello\":true}").expect("request should succeed");

        handle.join().expect("server thread should join");
        assert_eq!(response, "{\"accepted\":true}");
    }
}
