// SPDX-License-Identifier: AGPL-3.0-only
use std::{
    collections::HashMap,
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};

use memmap2::{Mmap, MmapOptions};

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
    embedding_matrix: EmbeddingMatrix,
    vocab_size: usize,
    embedding_dim: usize,
}

#[derive(Debug)]
enum EmbeddingMatrix {
    F16(Mmap),
    F32(Mmap),
}

impl StaticEncoder {
    pub fn vocab_size(&self) -> usize {
        self.vocab_size
    }

    pub fn embedding_dim(&self) -> usize {
        self.embedding_dim
    }

    pub(super) fn accumulate_token_embedding(&self, token_index: usize, target: &mut [f32]) {
        let start = token_index * self.embedding_dim;
        let end = start + self.embedding_dim;
        match &self.embedding_matrix {
            EmbeddingMatrix::F16(values) => {
                for (target, bytes) in target
                    .iter_mut()
                    .zip(values[start * 2..end * 2].chunks_exact(2))
                {
                    *target += f16_to_f32(u16::from_le_bytes([bytes[0], bytes[1]]));
                }
            }
            EmbeddingMatrix::F32(values) => {
                for (target, bytes) in target
                    .iter_mut()
                    .zip(values[start * 4..end * 4].chunks_exact(4))
                {
                    *target += f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                }
            }
        }
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
            embedding_matrix,
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

fn read_embedding_matrix(
    path: impl AsRef<Path>,
    expected_len: usize,
) -> NtdbResult<EmbeddingMatrix> {
    let path = path.as_ref();
    let file = File::open(path).map_err(|err| {
        ntdb_error(format!(
            "failed to open embedding matrix {}: {err}",
            path.display()
        ))
    })?;
    let byte_len = file
        .metadata()
        .map_err(|err| {
            ntdb_error(format!(
                "failed to read embedding matrix metadata {}: {err}",
                path.display()
            ))
        })?
        .len() as usize;
    // The package is immutable while loaded. Mapping it avoids copying the full
    // lookup table and lets the OS page in only token rows that are actually used.
    let bytes = unsafe { MmapOptions::new().map(&file) }.map_err(|err| {
        ntdb_error(format!(
            "failed to map embedding matrix {}: {err}",
            path.display()
        ))
    })?;

    if byte_len == expected_len * 2 {
        Ok(EmbeddingMatrix::F16(bytes))
    } else if byte_len == expected_len * 4 {
        Ok(EmbeddingMatrix::F32(bytes))
    } else {
        Err(ntdb_error(format!(
            "embedding matrix size mismatch: got {} bytes, expected {} for f16 or {} for f32",
            byte_len,
            expected_len * 2,
            expected_len * 4
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::{read_embedding_matrix, StaticEncoder};
    use std::{fs, time::SystemTime};

    fn mapped(values: &[u8], expected_len: usize) -> super::EmbeddingMatrix {
        let path = std::env::temp_dir().join(format!(
            "patronus_embedding_map_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, values).unwrap();
        let matrix = read_embedding_matrix(&path, expected_len).unwrap();
        fs::remove_file(path).unwrap();
        matrix
    }

    #[test]
    fn accumulates_f16_embeddings_without_expanding_the_matrix() {
        let encoder = StaticEncoder {
            embedding_matrix: mapped(&[0x00, 0x3c, 0x00, 0x40, 0x00, 0x42, 0x00, 0x44], 4),
            vocab_size: 2,
            embedding_dim: 2,
        };
        let mut target = [0.5, 1.0];

        encoder.accumulate_token_embedding(1, &mut target);

        assert_eq!(target, [3.5, 5.0]);
    }

    #[test]
    fn accumulates_f32_embedding_packages_unchanged() {
        let encoder = StaticEncoder {
            embedding_matrix: mapped(
                &[1.0_f32, 2.0, 3.0, 4.0]
                    .into_iter()
                    .flat_map(f32::to_le_bytes)
                    .collect::<Vec<_>>(),
                4,
            ),
            vocab_size: 2,
            embedding_dim: 2,
        };
        let mut target = [0.5, 1.0];

        encoder.accumulate_token_embedding(1, &mut target);

        assert_eq!(target, [3.5, 5.0]);
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
