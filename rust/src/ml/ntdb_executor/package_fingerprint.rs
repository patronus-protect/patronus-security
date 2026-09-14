// SPDX-License-Identifier: GPL-3.0-only
//! Deferred distributed identity, bound to the files present during model load.
//! Local inference retains descriptors and checks metadata, but never hashes assets.
use std::{
    fs::{File, Metadata},
    io::{BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::OnceLock,
    time::SystemTime,
};

use super::{ntdb_error, NtdbResult};

pub(super) struct DeferredPackageFingerprint {
    manifest_json: String,
    assets: Vec<Asset>,
    value: OnceLock<Result<String, String>>,
}

struct Asset {
    relative: String,
    path: PathBuf,
    file: File,
    stamp: AssetStamp,
}

#[derive(Debug, PartialEq, Eq)]
struct AssetStamp {
    length: u64,
    modified: SystemTime,
    identity: platform::Stamp,
}

impl AssetStamp {
    fn read(file: &File) -> std::io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            length: metadata.len(),
            modified: metadata.modified()?,
            identity: platform::stamp(file, &metadata)?,
        })
    }
}

impl DeferredPackageFingerprint {
    pub(super) fn new(
        package_dir: &Path,
        manifest_json: &str,
        mut files: Vec<String>,
    ) -> NtdbResult<Self> {
        files.sort();
        let assets = files
            .into_iter()
            .map(|relative| {
                let path = package_dir.join(&relative);
                // Keep normal read/write/delete sharing so atomic model updates remain possible.
                let file = File::open(&path)?;
                let stamp = AssetStamp::read(&file)?;
                Ok(Asset {
                    relative,
                    path,
                    file,
                    stamp,
                })
            })
            .collect::<NtdbResult<Vec<_>>>()?;
        Ok(Self {
            manifest_json: manifest_json.to_owned(),
            assets,
            value: OnceLock::new(),
        })
    }

    pub(super) fn require_unchanged_assets(&self) -> NtdbResult<()> {
        for asset in &self.assets {
            // Check both the held file (in-place writes) and its current path (replacement).
            let unchanged = (|| -> std::io::Result<bool> {
                let held = AssetStamp::read(&asset.file)?;
                let current = AssetStamp::read(&File::open(&asset.path)?)?;
                Ok(held == asset.stamp && current == asset.stamp)
            })();
            match unchanged {
                Ok(true) => {}
                result => {
                    let detail = result
                        .err()
                        .map(|error| format!(": {error}"))
                        .unwrap_or_default();
                    return Err(ntdb_error(format!(
                        "NTDB assets changed or became unavailable after runtime initialization: {}{detail}; reload before distributed inference",
                        asset.path.display()
                    )));
                }
            }
        }
        Ok(())
    }

    pub(super) fn get(&self) -> NtdbResult<&str> {
        self.value
            .get_or_init(|| {
                (|| {
                    self.require_unchanged_assets()?;
                    let fingerprint = self.fingerprint_held_assets()?;
                    self.require_unchanged_assets()?;
                    Ok(fingerprint)
                })()
                .map_err(|error: Box<dyn std::error::Error + Send + Sync>| error.to_string())
            })
            .as_deref()
            .map_err(|error| ntdb_error(error.clone()))
    }

    fn fingerprint_held_assets(&self) -> NtdbResult<String> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"patronus-ntdb-package-v1\0");
        hasher.update(self.manifest_json.as_bytes());
        for asset in &self.assets {
            hasher.update(&(asset.relative.len() as u64).to_le_bytes());
            hasher.update(asset.relative.as_bytes());
            // OnceLock serializes this sole reader; cloned handles share the cursor.
            let mut file = asset.file.try_clone()?;
            file.seek(SeekFrom::Start(0))?;
            let mut reader = BufReader::new(file);
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
        }
        Ok(hasher.finalize().to_hex().to_string())
    }
}

#[cfg(unix)]
mod platform {
    use super::{File, Metadata};
    use std::os::unix::fs::MetadataExt;

    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct Stamp {
        device: u64,
        inode: u64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    }

    pub(super) fn stamp(_file: &File, metadata: &Metadata) -> std::io::Result<Stamp> {
        Ok(Stamp {
            device: metadata.dev(),
            inode: metadata.ino(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }
}

#[cfg(windows)]
mod platform {
    use super::{File, Metadata};
    use std::{ffi::c_void, mem::MaybeUninit, os::windows::io::AsRawHandle};

    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct Stamp {
        volume: u64,
        file_id: [u8; 16],
        change_time: i64,
    }

    #[repr(C)]
    struct FileBasicInfo {
        creation_time: i64,
        last_access_time: i64,
        last_write_time: i64,
        change_time: i64,
        file_attributes: u32,
    }

    #[repr(C)]
    struct FileIdInfo {
        volume_serial_number: u64,
        file_id: [u8; 16],
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandleEx(
            file: *mut c_void,
            class: i32,
            information: *mut c_void,
            size: u32,
        ) -> i32;
    }

    // https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex
    pub(super) fn stamp(file: &File, _metadata: &Metadata) -> std::io::Result<Stamp> {
        let mut basic = MaybeUninit::<FileBasicInfo>::uninit();
        let mut identity = MaybeUninit::<FileIdInfo>::uninit();
        // SAFETY: the live File owns the handle; each output matches its documented
        // FILE_INFO_BY_HANDLE_CLASS layout and is read only after successful initialization.
        unsafe {
            if GetFileInformationByHandleEx(
                file.as_raw_handle(),
                0,
                basic.as_mut_ptr().cast(),
                std::mem::size_of::<FileBasicInfo>() as u32,
            ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if GetFileInformationByHandleEx(
                file.as_raw_handle(),
                18,
                identity.as_mut_ptr().cast(),
                std::mem::size_of::<FileIdInfo>() as u32,
            ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let basic = basic.assume_init();
            let identity = identity.assume_init();
            Ok(Stamp {
                volume: identity.volume_serial_number,
                file_id: identity.file_id,
                change_time: basic.change_time,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new(name: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("ark-fingerprint-{name}-{}", std::process::id()));
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join("weights.bin"), b"original bytes").unwrap();
            Self(root)
        }
        fn path(&self) -> PathBuf {
            self.0.join("weights.bin")
        }
        fn deferred(&self) -> DeferredPackageFingerprint {
            DeferredPackageFingerprint::new(&self.0, "manifest", vec!["weights.bin".into()])
                .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn restore_mtime(path: &Path, time: SystemTime) {
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(time)
            .unwrap();
    }

    #[test]
    fn atomic_replacement_with_restored_mtime_is_rejected() {
        let fixture = Fixture::new("replacement");
        let deferred = fixture.deferred();
        let mtime = fs::metadata(fixture.path()).unwrap().modified().unwrap();
        let replacement = fixture.0.join("replacement");
        fs::write(&replacement, b"modified bytes").unwrap();
        restore_mtime(&replacement, mtime);
        fs::rename(replacement, fixture.path()).unwrap();
        assert!(deferred
            .get()
            .unwrap_err()
            .to_string()
            .contains("assets changed"));
    }

    #[test]
    fn in_place_rewrite_with_restored_mtime_is_rejected() {
        let fixture = Fixture::new("rewrite");
        let deferred = fixture.deferred();
        let mtime = fs::metadata(fixture.path()).unwrap().modified().unwrap();
        fs::write(fixture.path(), b"modified bytes").unwrap();
        restore_mtime(&fixture.path(), mtime);
        assert!(deferred
            .get()
            .unwrap_err()
            .to_string()
            .contains("assets changed"));
    }

    #[test]
    fn load_validation_and_deferred_creation_do_not_read_asset_bytes() {
        let fixture = Fixture::new("lazy");
        let deferred = fixture.deferred();
        deferred.require_unchanged_assets().unwrap();
        assert!(deferred.value.get().is_none());
        // Reading would advance this cursor, shared with the retained descriptor.
        assert_eq!(
            deferred.assets[0]
                .file
                .try_clone()
                .unwrap()
                .stream_position()
                .unwrap(),
            0
        );
        fs::write(fixture.path(), b"different length").unwrap();
        assert!(deferred.require_unchanged_assets().is_err());
    }

    #[test]
    fn retained_descriptor_never_hashes_atomic_replacement() {
        let fixture = Fixture::new("held");
        let deferred = fixture.deferred();
        let original = deferred.fingerprint_held_assets().unwrap();
        let replacement = fixture.0.join("replacement");
        fs::write(&replacement, b"modified bytes").unwrap();
        fs::rename(replacement, fixture.path()).unwrap();
        assert_eq!(deferred.fingerprint_held_assets().unwrap(), original);
        assert!(deferred.get().is_err());
    }

    #[test]
    fn missing_assets_cannot_silently_share_an_unknown_stamp() {
        let fixture = Fixture::new("missing");
        let deferred = fixture.deferred();
        fs::remove_file(fixture.path()).unwrap();
        assert!(deferred.require_unchanged_assets().is_err());
        assert!(deferred.get().is_err());
    }

    #[test]
    fn cached_identity_stays_bound_to_the_loaded_runtime() {
        let fixture = Fixture::new("cached");
        let deferred = fixture.deferred();
        let original = deferred.get().unwrap().to_owned();
        fs::write(fixture.path(), b"modified bytes").unwrap();
        assert_eq!(deferred.get().unwrap(), original);
    }
}
