// SPDX-License-Identifier: MIT OR Apache-2.0
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

use super::mmbert_tokenizer::MmbertPairTokenizer;

static GLOBAL_TOKENIZER_STORE: OnceLock<TokenizerStore> = OnceLock::new();

pub fn global_tokenizer_store() -> &'static TokenizerStore {
    GLOBAL_TOKENIZER_STORE.get_or_init(TokenizerStore::default)
}

#[derive(Default)]
pub struct TokenizerStore {
    mmbert_cache: Mutex<HashMap<PathBuf, Arc<MmbertPairTokenizer>>>,
}

impl TokenizerStore {
    pub fn load_mmbert(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<Arc<MmbertPairTokenizer>, std::io::Error> {
        let path = canonical_or_owned(path.as_ref());
        let mut cache = self
            .mmbert_cache
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if let Some(tok) = cache.get(&path) {
            return Ok(Arc::clone(tok));
        }
        let tokenizer = if path.extension().is_some_and(|ext| ext == "json") {
            let bytes = crate::assets::mmbert_tokenizer::compact_tokenizer_bytes(&path)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            MmbertPairTokenizer::from_bytes(&bytes)?
        } else {
            MmbertPairTokenizer::from_file(&path)?
        };
        let tok = Arc::new(tokenizer);
        cache.insert(path, Arc::clone(&tok));
        Ok(tok)
    }
}

fn canonical_or_owned(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}
