use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
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
                Ok(file) => {
                    return Ok(Some(Self {
                        path: path.to_path_buf(),
                        _file: file,
                    }));
                }
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                    let deadline = Instant::now() + Duration::from_secs(2);
                    while Instant::now() < deadline {
                        if is_healthy() {
                            return Ok(None);
                        }
                        thread::sleep(Duration::from_millis(100));
                    }

                    if attempt < 2 {
                        let _ = std::fs::remove_file(path);
                        continue;
                    }

                    if is_healthy() {
                        return Ok(None);
                    }

                    bail!("another instance lock exists at '{}'", path.display());
                }
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("failed to create single-instance lock '{}'", path.display())
                    });
                }
            }
        }

        bail!("failed to acquire single-instance lock '{}'", path.display())
    }
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
