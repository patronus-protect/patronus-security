// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared Hugging Face transport. Model selection and preparation belong to callers.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
    time::{Duration, Instant},
};

const ATTEMPTS: usize = 4;

/// One budget for lock acquisition, HTTP attempts, backoff and streaming.
/// OS DNS resolution and filesystem operations cannot be preempted by ureq.
#[derive(Clone, Copy, Debug)]
pub struct DownloadOptions {
    pub timeout: Duration,
}
impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(600),
        }
    }
}
fn download_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| ureq::AgentBuilder::new().build())
}

#[allow(clippy::too_many_arguments)]
pub fn download_hf_file_at_revision(
    token: Option<&str>,
    repo: &str,
    revision: &str,
    source_path: &str,
    dest_file: &Path,
    required: bool,
    label: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    download_hf_file_with_options(
        token,
        repo,
        revision,
        source_path,
        dest_file,
        required,
        label,
        &DownloadOptions::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn download_hf_file_with_options(
    token: Option<&str>,
    repo: &str,
    revision: &str,
    source_path: &str,
    dest_file: &Path,
    required: bool,
    label: &str,
    options: &DownloadOptions,
) -> Result<bool, Box<dyn std::error::Error>> {
    let url = format!("https://huggingface.co/{repo}/resolve/{revision}/{source_path}");
    log::info!("Downloading {label} {source_path} from Hugging Face -> {dest_file:?}");
    download_url(token, &url, dest_file, required, options)
}
fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "asset download deadline exceeded"))
}
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn temporary(dest: &Path) -> io::Result<(Temporary, File)> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = sibling(
            dest,
            &format!(
                ".patronus-download-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ),
        );
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((Temporary(path), file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}
fn download_url(
    token: Option<&str>,
    url: &str,
    dest: &Path,
    required: bool,
    options: &DownloadOptions,
) -> Result<bool, Box<dyn std::error::Error>> {
    let deadline = Instant::now().checked_add(options.timeout).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "download timeout overflows clock",
        )
    })?;
    remaining(deadline)?;
    if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    // Keep the lock file: unlinking it would allow another process to lock a new inode.
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(sibling(dest, ".patronus-download.lock"))?;
    loop {
        remaining(deadline)?;
        match fs2::FileExt::try_lock_exclusive(&lock) {
            Ok(()) => break,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(remaining(deadline)?.min(Duration::from_millis(20)));
            }
            Err(e) => return Err(e.into()),
        }
    }
    // File ownership keeps the cross-process lock alive through the atomic rename.
    for attempt in 1..=ATTEMPTS {
        let mut request = download_agent().get(url).timeout(remaining(deadline)?);
        if let Some(token) = token {
            request = request.set("Authorization", &format!("Bearer {token}"));
        }
        let response = match request.call() {
            Ok(response) => response,
            Err(error) => {
                if download_error_is_retryable(&error) && attempt < ATTEMPTS {
                    log::warn!(
                        "transient asset download failure (attempt {attempt}/{ATTEMPTS}); retrying"
                    );
                    std::thread::sleep(
                        remaining(deadline)?.min(Duration::from_millis(250 * attempt as u64)),
                    );
                    continue;
                }
                if !required {
                    return Ok(false);
                }
                return Err(error.into());
            }
        };
        if response.status() != 200 {
            if !required {
                return Ok(false);
            }
            return Err(format!("asset download returned HTTP {}", response.status()).into());
        }
        let (temp, mut output) = temporary(dest)?;
        let mut reader = response.into_reader();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            remaining(deadline)?;
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            output.write_all(&buffer[..count])?;
        }
        remaining(deadline)?;
        output.sync_all()?;
        drop(output);
        remaining(deadline)?;
        // Never remove a good destination before the replacement is ready.
        fs::rename(&temp.0, dest)?;
        return Ok(true);
    }
    unreachable!("every final attempt returns")
}

pub fn download_error_is_retryable(error: &ureq::Error) -> bool {
    match error {
        ureq::Error::Status(status, _) => *status == 429 || (500..=599).contains(status),
        ureq::Error::Transport(_) => true,
    }
}
pub fn get_hf_token() -> Option<String> {
    std::env::var("HF_TOKEN")
        .ok()
        .or_else(|| std::env::var("HUGGINGFACE_HUB_TOKEN").ok())
        .or_else(|| std::env::var("HUGGING_FACE_HUB_TOKEN").ok())
        .or_else(|| {
            let path = std::env::var("HF_HOME")
                .ok()
                .map(|p| PathBuf::from(p).join("token"))
                .or_else(|| dirs::home_dir().map(|p| p.join(".cache/huggingface/token")))?;
            fs::read_to_string(path).ok()
        })
        .map(|token| token.trim().to_owned())
        .filter(|token| !token.is_empty())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "ark-download-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn file(&self) -> PathBuf {
            self.0.join("model.bin")
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn serve(responses: Vec<(&'static str, Duration)>) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/file", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            for (response, delay) in responses {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    if socket.read(&mut byte).unwrap_or(0) == 0 {
                        break;
                    }
                    request.push(byte[0]);
                }
                if let Some((headers, body)) = response.split_once("\r\n\r\n") {
                    let _ = write!(socket, "{headers}\r\n\r\n");
                    std::thread::sleep(delay);
                    let _ = socket.write_all(body.as_bytes());
                }
            }
        });
        (url, task)
    }
    fn options() -> DownloadOptions {
        DownloadOptions {
            timeout: Duration::from_secs(3),
        }
    }
    #[test]
    fn agent_is_shared_and_only_transient_statuses_retry() {
        assert!(std::ptr::eq(download_agent(), download_agent()));
        for status in [429, 500, 503, 599] {
            assert!(download_error_is_retryable(&ureq::Error::Status(
                status,
                ureq::Response::new(status, "test", "").unwrap()
            )));
        }
        for status in [400, 401, 403, 404] {
            assert!(!download_error_is_retryable(&ureq::Error::Status(
                status,
                ureq::Response::new(status, "test", "").unwrap()
            )));
        }
    }
    #[test]
    fn retry_then_atomically_replace_existing_file() {
        let dir = Directory::new();
        fs::write(dir.file(), b"old good bytes").unwrap();
        let (url, server) = serve(vec![
            (
                "HTTP/1.1 503 Busy\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                Duration::ZERO,
            ),
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nnew",
                Duration::ZERO,
            ),
        ]);
        assert!(download_url(None, &url, &dir.file(), true, &options()).unwrap());
        server.join().unwrap();
        assert_eq!(fs::read(dir.file()).unwrap(), b"new");
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 2); // destination + stable lock
    }
    #[test]
    fn optional_absence_preserves_existing_file() {
        let dir = Directory::new();
        fs::write(dir.file(), b"old").unwrap();
        let (url, server) = serve(vec![(
            "HTTP/1.1 404 Missing\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            Duration::ZERO,
        )]);
        assert!(!download_url(None, &url, &dir.file(), false, &options()).unwrap());
        server.join().unwrap();
        assert_eq!(fs::read(dir.file()).unwrap(), b"old");
    }
    #[test]
    fn truncated_body_preserves_existing_file_and_cleans_temporary() {
        let dir = Directory::new();
        fs::write(dir.file(), b"old").unwrap();
        let (url, server) = serve(vec![(
            "HTTP/1.1 200 OK\r\nContent-Length: 99\r\nConnection: close\r\n\r\nshort",
            Duration::ZERO,
        )]);
        assert!(download_url(None, &url, &dir.file(), true, &options()).is_err());
        server.join().unwrap();
        assert_eq!(fs::read(dir.file()).unwrap(), b"old");
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 2);
    }
    #[test]
    fn stalled_body_obeys_the_stream_deadline() {
        let dir = Directory::new();
        fs::write(dir.file(), b"old").unwrap();
        let (url, server) = serve(vec![(
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nnew",
            Duration::from_millis(400),
        )]);
        let started = Instant::now();
        assert!(download_url(
            None,
            &url,
            &dir.file(),
            true,
            &DownloadOptions {
                timeout: Duration::from_millis(80)
            }
        )
        .is_err());
        assert!(started.elapsed() < Duration::from_millis(350));
        server.join().unwrap();
        assert_eq!(fs::read(dir.file()).unwrap(), b"old");
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 2);
    }
    #[test]
    fn held_destination_lock_obeys_budget_without_touching_existing_file() {
        let dir = Directory::new();
        fs::write(dir.file(), b"old").unwrap();
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(sibling(&dir.file(), ".patronus-download.lock"))
            .unwrap();
        fs2::FileExt::lock_exclusive(&lock).unwrap();
        assert!(download_url(
            None,
            "http://127.0.0.1:1/unused",
            &dir.file(),
            true,
            &DownloadOptions {
                timeout: Duration::from_millis(30)
            }
        )
        .is_err());
        assert_eq!(fs::read(dir.file()).unwrap(), b"old");
    }
}
