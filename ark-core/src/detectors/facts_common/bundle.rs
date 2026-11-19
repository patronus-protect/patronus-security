// SPDX-License-Identifier: MIT OR Apache-2.0
//! A downloaded model release directory, read only after it is verified:
//! `manifest.json` lists the sha256 of every release file, and with a pin
//! (the sha256 of `manifest.json` itself) a changed manifest, and with it any
//! changed file, is refused. Shared by Cat's shell-risk bundle and the text
//! category model bundles.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Deserialize)]
struct Manifest {
    files: HashMap<String, String>,
}

/// Lowercase hex sha256 of `bytes`.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))
}

/// A bundle directory with its verified manifest.
pub(crate) struct VerifiedBundle {
    dir: PathBuf,
    manifest_path: PathBuf,
    files: HashMap<String, String>,
}

impl VerifiedBundle {
    /// Read `dir/manifest.json`; `manifest_sha256` pins it.
    pub(crate) fn open(dir: &Path, manifest_sha256: Option<&str>) -> Result<Self, String> {
        let manifest_path = dir.join("manifest.json");
        let manifest_bytes = read(&manifest_path)?;
        if let Some(pin) = manifest_sha256 {
            let actual = sha256_hex(&manifest_bytes);
            if !actual.eq_ignore_ascii_case(pin) {
                return Err(format!(
                    "{} sha256 {actual} is not the pinned release manifest {pin}",
                    manifest_path.display()
                ));
            }
        }
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| format!("invalid {}: {error}", manifest_path.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            manifest_path,
            files: manifest.files,
        })
    }

    /// Refuse a manifest that lists `name` with another content than
    /// `embedded`, the copy compiled into this runtime.
    pub(crate) fn require_embedded(&self, name: &str, embedded: &str) -> Result<(), String> {
        match self.files.get(name) {
            Some(sha) if !sha256_hex(embedded.as_bytes()).eq_ignore_ascii_case(sha) => {
                Err(format!(
                    "{} lists a {name} that differs from the one this runtime embeds",
                    self.manifest_path.display()
                ))
            }
            _ => Ok(()),
        }
    }

    /// The bytes of release file `name`, once their sha256 matches the manifest.
    pub(crate) fn read(&self, name: &str) -> Result<Vec<u8>, String> {
        let expected = self
            .files
            .get(name)
            .ok_or_else(|| format!("{} does not list {name}", self.manifest_path.display()))?;
        let path = self.dir.join(name);
        let bytes = read(&path)?;
        let actual = sha256_hex(&bytes);
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(format!(
                "{} sha256 {actual} does not match manifest {expected}",
                path.display()
            ));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Write `files` and a manifest of them into a fresh directory; returns
    /// the directory and the manifest's sha256.
    pub(crate) fn write_bundle(name: &str, files: &[(&str, &[u8])]) -> (PathBuf, String) {
        let dir = std::env::temp_dir().join(format!("{name}_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let mut listed = serde_json::Map::new();
        for (file, bytes) in files {
            fs::write(dir.join(file), bytes).unwrap();
            listed.insert(file.to_string(), sha256_hex(bytes).into());
        }
        let manifest = serde_json::json!({ "files": listed }).to_string();
        fs::write(dir.join("manifest.json"), &manifest).unwrap();
        (dir, sha256_hex(manifest.as_bytes()))
    }

    #[test]
    fn reads_only_files_the_pinned_manifest_vouches_for() {
        let (dir, pin) = write_bundle("verified_bundle", &[("a.json", b"{}"), ("b.txt", b"b")]);
        let bundle = VerifiedBundle::open(&dir, Some(&pin)).unwrap();
        assert_eq!(bundle.read("a.json").unwrap(), b"{}");
        assert!(bundle
            .read("missing")
            .unwrap_err()
            .contains("does not list"));
        fs::write(dir.join("b.txt"), "changed").unwrap();
        assert!(bundle.read("b.txt").unwrap_err().contains("does not match"));
        assert!(bundle.require_embedded("a.json", "{}").is_ok());
        assert!(bundle.require_embedded("a.json", "[]").is_err());
        assert!(bundle.require_embedded("unlisted", "x").is_ok());
        assert!(VerifiedBundle::open(&dir, Some(&"0".repeat(64)))
            .err()
            .unwrap()
            .contains("not the pinned release manifest"));
        assert!(VerifiedBundle::open(&dir, None).is_ok());
        fs::remove_dir_all(dir).ok();
    }
}
