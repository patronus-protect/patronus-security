// SPDX-License-Identifier: GPL-3.0-only
//! Shared atomic-file and cache-lock helpers for generated tokenizer artifacts.

use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime},
};

const LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const STALE_LOCK_AGE: Duration = Duration::from_secs(300);

pub(super) fn remove_file_if_exists(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

pub(super) fn file_blake3(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

pub(super) fn write_json_atomic<T: Serialize>(
    destination: &Path,
    value: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    let parent = destination
        .parent()
        .ok_or_else(|| format!("metadata path has no parent: {}", destination.display()))?;
    let mut temporary = TemporaryPath::new(parent, "tokenizer.meta.tmp")?;
    {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(temporary.path())?;
        serde_json::to_writer_pretty(&mut file, value)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    temporary.persist(destination)
}

pub(super) struct TemporaryPath {
    path: PathBuf,
    active: bool,
}

impl TemporaryPath {
    pub(super) fn new(parent: &Path, name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let suffix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_nanos();
        let path = parent.join(format!("{name}.{}.{}", std::process::id(), suffix));
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(Self { path, active: true })
    }
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn persist(&mut self, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
        replace_file(&self.path, destination)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for TemporaryPath {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::rename(source, destination)?;
    Ok(())
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if destination.exists() {
        fs::remove_file(destination)?;
    }
    fs::rename(source, destination)?;
    Ok(())
}

pub(super) struct CacheLock {
    path: PathBuf,
}

impl CacheLock {
    pub(super) fn acquire(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let started = Instant::now();
        loop {
            match OpenOptions::new().write(true).create_new(true).open(path) {
                Ok(mut file) => {
                    writeln!(file, "pid={}", std::process::id())?;
                    file.sync_all()?;
                    return Ok(Self {
                        path: path.to_path_buf(),
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    if lock_is_stale(path) {
                        let _ = fs::remove_file(path);
                        continue;
                    }
                    if started.elapsed() >= LOCK_TIMEOUT {
                        return Err(format!(
                            "timed out waiting for tokenizer conversion lock {}",
                            path.display()
                        )
                        .into());
                    }
                    thread::sleep(Duration::from_millis(25));
                }
                Err(err) => return Err(err.into()),
            }
        }
    }
}

impl Drop for CacheLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn lock_is_stale(path: &Path) -> bool {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|age| age >= STALE_LOCK_AGE)
}
