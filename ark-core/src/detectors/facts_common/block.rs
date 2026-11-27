// SPDX-License-Identifier: MIT OR Apache-2.0
//! A Patronus block file (`patronus.block/1`): one safetensors file per
//! released model. The tensors hold the weights; the safetensors metadata
//! holds everything else as strings (vocabularies, heads, thresholds, policy
//! levels, core policies, the Cedar schema). The same file runs without ARK
//! through the block's `block.py`, the reference implementation in one file.
//!
//! Format: an 8-byte little-endian header length, a JSON header (per tensor
//! `dtype`, `shape`, `data_offsets`; `__metadata__` string map), then the
//! tensor bytes. With a pin (the sha256 of the whole file) a changed file is
//! refused.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use super::bundle::sha256_hex;

/// Format name in the metadata key `format`.
pub const BLOCK_FORMAT: &str = "patronus.block/1";

#[derive(Deserialize)]
struct TensorInfo {
    dtype: String,
    shape: Vec<usize>,
    data_offsets: (usize, usize),
}

/// A read and checked block file.
#[derive(Debug)]
pub struct BlockFile {
    name: String,
    metadata: HashMap<String, String>,
    tensors: HashMap<String, (String, Vec<usize>, Vec<u8>)>,
}

impl BlockFile {
    /// Read `path`; `sha256` pins the file.
    pub fn open(path: &Path, sha256: Option<&str>) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        if let Some(pin) = sha256 {
            let actual = sha256_hex(&bytes);
            if !actual.eq_ignore_ascii_case(pin) {
                return Err(format!(
                    "{} sha256 {actual} is not the pinned block {pin}",
                    path.display()
                ));
            }
        }
        Self::from_bytes(&bytes, &path.display().to_string())
    }

    /// A block from the bytes of a file; `name` names it in errors.
    pub fn from_bytes(bytes: &[u8], name: &str) -> Result<Self, String> {
        let bad = |what: &str| format!("{name}: {what}");
        let len_bytes: [u8; 8] = bytes
            .get(..8)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| bad("too short"))?;
        let header_len =
            usize::try_from(u64::from_le_bytes(len_bytes)).map_err(|_| bad("bad header length"))?;
        let header = bytes
            .get(8..8 + header_len)
            .ok_or_else(|| bad("truncated header"))?;
        let data = &bytes[8 + header_len..];
        let mut raw: HashMap<String, serde_json::Value> =
            serde_json::from_slice(header).map_err(|error| bad(&format!("header: {error}")))?;
        let metadata: HashMap<String, String> = match raw.remove("__metadata__") {
            Some(m) => {
                serde_json::from_value(m).map_err(|error| bad(&format!("metadata: {error}")))?
            }
            None => HashMap::new(),
        };
        if metadata.get("format").map(String::as_str) != Some(BLOCK_FORMAT) {
            return Err(bad(&format!("not a {BLOCK_FORMAT} file")));
        }
        let mut tensors = HashMap::new();
        for (key, value) in raw {
            let info: TensorInfo = serde_json::from_value(value)
                .map_err(|error| bad(&format!("tensor {key}: {error}")))?;
            let (start, end) = info.data_offsets;
            let slice = data
                .get(start..end)
                .ok_or_else(|| bad(&format!("tensor {key} out of range")))?;
            tensors.insert(key, (info.dtype, info.shape, slice.to_vec()));
        }
        Ok(Self {
            name: name.to_string(),
            metadata,
            tensors,
        })
    }

    /// The block type (`tool-call`, `cat-shell`).
    pub fn kind(&self) -> &str {
        self.metadata.get("block").map_or("", String::as_str)
    }

    /// A metadata string.
    pub fn meta(&self, key: &str) -> Result<&str, String> {
        self.metadata
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("{}: metadata has no {key}", self.name))
    }

    /// Refuse a block of another type.
    pub fn require_kind(&self, kind: &str) -> Result<(), String> {
        if self.kind() == kind {
            Ok(())
        } else {
            Err(format!(
                "{}: a {:?} block, not {kind:?}",
                self.name,
                self.kind()
            ))
        }
    }

    /// Refuse a block whose metadata `key` is not the sha256 of `embedded`,
    /// the copy compiled into this runtime.
    pub fn require_embedded(&self, key: &str, embedded: &str) -> Result<(), String> {
        if self
            .meta(key)?
            .eq_ignore_ascii_case(&sha256_hex(embedded.as_bytes()))
        {
            Ok(())
        } else {
            Err(format!(
                "{}: {key} differs from the copy this runtime embeds",
                self.name
            ))
        }
    }

    fn tensor(&self, key: &str, dtype: &str, width: usize) -> Result<(&[u8], &[usize]), String> {
        let (dt, shape, bytes) = self
            .tensors
            .get(key)
            .ok_or_else(|| format!("{}: no tensor {key}", self.name))?;
        if dt != dtype || bytes.len() != shape.iter().product::<usize>() * width {
            return Err(format!(
                "{}: tensor {key} is {dt} {shape:?}, expected {dtype}",
                self.name
            ));
        }
        Ok((bytes, shape))
    }

    /// An `F32` tensor and its shape.
    pub fn f32s(&self, key: &str) -> Result<(Vec<f32>, Vec<usize>), String> {
        let (bytes, shape) = self.tensor(key, "F32", 4)?;
        Ok((
            bytes
                .as_chunks::<4>()
                .0
                .iter()
                .map(|b| f32::from_le_bytes(*b))
                .collect(),
            shape.to_vec(),
        ))
    }

    /// An `F64` tensor and its shape.
    pub fn f64s(&self, key: &str) -> Result<(Vec<f64>, Vec<usize>), String> {
        let (bytes, shape) = self.tensor(key, "F64", 8)?;
        Ok((
            bytes
                .as_chunks::<8>()
                .0
                .iter()
                .map(|b| f64::from_le_bytes(*b))
                .collect(),
            shape.to_vec(),
        ))
    }
}

#[cfg(test)]
pub(crate) fn test_block(
    meta: &[(&str, &str)],
    tensors: &[(&str, &str, Vec<usize>, Vec<u8>)],
) -> Vec<u8> {
    let mut header = serde_json::Map::new();
    let mut m: serde_json::Map<String, serde_json::Value> = meta
        .iter()
        .map(|(k, v)| (k.to_string(), (*v).into()))
        .collect();
    m.insert("format".into(), BLOCK_FORMAT.into());
    header.insert("__metadata__".into(), m.into());
    let mut data = Vec::new();
    for (k, dtype, shape, bytes) in tensors {
        header.insert(
            k.to_string(),
            serde_json::json!({"dtype": dtype, "shape": shape, "data_offsets": [data.len(), data.len() + bytes.len()]}),
        );
        data.extend_from_slice(bytes);
    }
    let h = serde_json::Value::Object(header).to_string();
    let mut out = (h.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(h.as_bytes());
    out.extend_from_slice(&data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_metadata_and_tensors() {
        let w: Vec<u8> = [1.5f32, -2.0]
            .iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();
        let bytes = test_block(
            &[("block", "tool-call"), ("config", "{}")],
            &[("weights", "F32", vec![2, 1], w)],
        );
        let b = BlockFile::from_bytes(&bytes, "t").unwrap();
        assert_eq!(b.kind(), "tool-call");
        assert_eq!(b.f32s("weights").unwrap(), (vec![1.5, -2.0], vec![2, 1]));
        assert!(b.f64s("weights").is_err());
        assert!(b.require_kind("cat-shell").is_err());
        assert!(BlockFile::from_bytes(&bytes[..20], "t").is_err());
    }
}
