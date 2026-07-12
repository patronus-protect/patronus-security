use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use super::{
    manifest::{MiniLmManifest, PackageManifest},
    ntdb_error, NtdbResult,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EncoderKey {
    identity: String,
    vocab_size: usize,
    embedding_dim: usize,
}

#[derive(Debug)]
pub struct StaticEncoder {
    embedding_matrix: Arc<[f32]>,
    vocab_size: usize,
    embedding_dim: usize,
}

impl StaticEncoder {
    pub fn embedding_matrix(&self) -> &[f32] {
        &self.embedding_matrix
    }

    pub fn vocab_size(&self) -> usize {
        self.vocab_size
    }

    pub fn embedding_dim(&self) -> usize {
        self.embedding_dim
    }
}

#[derive(Default)]
pub struct StaticEncoderStore {
    encoders: HashMap<EncoderKey, Arc<StaticEncoder>>,
}

impl StaticEncoderStore {
    pub fn load_for_package(
        &mut self,
        package_dir: &Path,
        manifest: &PackageManifest,
    ) -> NtdbResult<Arc<StaticEncoder>> {
        let embedding_path = package_dir
            .join("minilm")
            .join(&manifest.minilm.embedding_matrix_file);
        self.load(&embedding_path, &manifest.minilm)
    }

    pub fn load(
        &mut self,
        embedding_path: &Path,
        manifest: &MiniLmManifest,
    ) -> NtdbResult<Arc<StaticEncoder>> {
        let key = EncoderKey {
            identity: encoder_identity(embedding_path, manifest),
            vocab_size: manifest.vocab_size,
            embedding_dim: manifest.embedding_dim,
        };
        if let Some(existing) = self.encoders.get(&key) {
            return Ok(Arc::clone(existing));
        }

        let expected_len = manifest.vocab_size * manifest.embedding_dim;
        let embedding_matrix = read_embedding_matrix(embedding_path, expected_len)?;
        let encoder = Arc::new(StaticEncoder {
            embedding_matrix: Arc::from(embedding_matrix),
            vocab_size: manifest.vocab_size,
            embedding_dim: manifest.embedding_dim,
        });
        self.encoders.insert(key, Arc::clone(&encoder));
        Ok(encoder)
    }

    #[cfg(feature = "test-util")]
    pub fn len(&self) -> usize {
        self.encoders.len()
    }
}

fn encoder_identity(embedding_path: &Path, manifest: &MiniLmManifest) -> String {
    manifest
        .shared_embedder_identity()
        .map(ToString::to_string)
        .unwrap_or_else(|| {
            canonical_or_original(embedding_path)
                .to_string_lossy()
                .to_string()
        })
}

fn canonical_or_original(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn read_embedding_matrix(path: impl AsRef<Path>, expected_len: usize) -> NtdbResult<Vec<f32>> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|err| {
        ntdb_error(format!(
            "failed to read embedding matrix {}: {err}",
            path.display()
        ))
    })?;

    if bytes.len() == expected_len * 2 {
        Ok(bytes
            .chunks_exact(2)
            .map(|chunk| {
                let bits = u16::from_le_bytes([chunk[0], chunk[1]]);
                f16_to_f32(bits)
            })
            .collect())
    } else if bytes.len() == expected_len * 4 {
        Ok(bytes
            .chunks_exact(4)
            .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect())
    } else {
        Err(ntdb_error(format!(
            "embedding matrix size mismatch: got {} bytes, expected {} for f16 or {} for f32",
            bytes.len(),
            expected_len * 2,
            expected_len * 4
        )))
    }
}

fn f16_to_f32(h: u16) -> f32 {
    let sign = (h & 0x8000) as u32;
    let exponent = (h & 0x7C00) as u32;
    let fraction = (h & 0x03FF) as u32;

    let f_bits = if exponent == 0 {
        if fraction == 0 {
            sign << 16
        } else {
            let mut m = fraction;
            let mut e = 0;
            while (m & 0x0400) == 0 {
                m <<= 1;
                e += 1;
            }
            let new_exponent = 127 - 15 - e + 1;
            let new_fraction = (m & 0x03FF) << 13;
            (sign << 16) | (new_exponent << 23) | new_fraction
        }
    } else if exponent == 0x7C00 {
        let new_exponent = 0xFF << 23;
        let new_fraction = if fraction == 0 { 0 } else { fraction << 13 };
        (sign << 16) | new_exponent | new_fraction
    } else {
        let new_exponent = (exponent >> 10) + 127 - 15;
        let new_fraction = fraction << 13;
        (sign << 16) | (new_exponent << 23) | new_fraction
    };
    f32::from_bits(f_bits)
}
