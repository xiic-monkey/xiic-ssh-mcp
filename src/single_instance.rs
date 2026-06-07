use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

pub struct SingleInstanceGuard {
    path: PathBuf,
    _file: File,
}

impl SingleInstanceGuard {
    pub fn acquire<F>(path: &Path, is_healthy: F) -> Result<Option<Self>>
    where
        F: Fn() -> bool,
    {
        for attempt in 0..3 {
            match OpenOptions::new().write(true).create_new(true).open(path) {
                Ok(mut file) => {
                    write_lock_owner_pid(&mut file).with_context(|| {
                        format!(
                            "failed to write single-instance owner to '{}'",
                            path.display()
                        )
                    })?;
                    return Ok(Some(Self {
                        path: path.to_path_buf(),
                        _file: file,
                    }));
                }
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                    if should_yield_to_existing_instance(path, &is_healthy)? {
                        return Ok(None);
                    }

                    remove_stale_lock(path)?;
                    if attempt < 2 {
                        continue;
                    }

                    match OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(path)
                    {
                        Ok(mut file) => {
                            write_lock_owner_pid(&mut file).with_context(|| {
                                format!(
                                    "failed to write single-instance owner to '{}'",
                                    path.display()
                                )
                            })?;
                            return Ok(Some(Self {
                                path: path.to_path_buf(),
                                _file: file,
                            }));
                        }
                        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                            if should_yield_to_existing_instance(path, &is_healthy)? {
                                return Ok(None);
                            }
                            bail!("another instance lock exists at '{}'", path.display());
                        }
                        Err(err) => {
                            return Err(err).with_context(|| {
                                format!(
                                    "failed to recover single-instance lock '{}'",
                                    path.display()
                                )
                            });
                        }
                    }
                }
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("failed to create single-instance lock '{}'", path.display())
                    });
                }
            }
        }

        bail!(
            "failed to acquire single-instance lock '{}'",
            path.display()
        )
    }
}

fn should_yield_to_existing_instance<F>(path: &Path, is_healthy: &F) -> Result<bool>
where
    F: Fn() -> bool,
{
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if existing_owner_alive(path)? || is_healthy() {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(100));
    }

    Ok(existing_owner_alive(path)? || is_healthy())
}

fn remove_stale_lock(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| {
            format!(
                "failed to remove stale single-instance lock '{}'",
                path.display()
            )
        }),
    }
}

fn write_lock_owner_pid(file: &mut File) -> Result<()> {
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    write!(file, "{}", std::process::id())?;
    file.flush()?;
    Ok(())
}

fn existing_owner_alive(path: &Path) -> Result<bool> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("failed to open single-instance lock '{}'", path.display()))?;
    let mut pid_text = String::new();
    file.read_to_string(&mut pid_text)?;
    let pid_text = pid_text.trim();
    if pid_text.is_empty() {
        return Ok(false);
    }

    let pid: u32 = match pid_text.parse() {
        Ok(pid) => pid,
        Err(_) => return Ok(false),
    };

    Ok(process_alive(pid))
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as i32, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(windows)]
fn process_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    const STILL_ACTIVE: u32 = 259;

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return false;
    }

    let mut exit_code = 0;
    let ok = unsafe {
        windows_sys::Win32::System::Threading::GetExitCodeProcess(handle, &mut exit_code)
    };
    unsafe {
        CloseHandle(handle);
    }
    ok != 0 && exit_code == STILL_ACTIVE
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;

    use super::SingleInstanceGuard;

    #[test]
    fn acquires_lock_after_stale_pid_file() {
        let lock_path =
            std::env::temp_dir().join(format!("xiic-ssh-mcp-lock-{}.lock", uuid::Uuid::new_v4()));

        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
                .expect("should create stale lock");
            writeln!(file, "999999").expect("should write fake pid");
        }

        let guard = SingleInstanceGuard::acquire(&lock_path, || false)
            .expect("stale lock should be recoverable")
            .expect("should acquire recovered lock");

        drop(guard);
        assert!(!lock_path.exists(), "lock should be cleaned up on drop");
    }
}
