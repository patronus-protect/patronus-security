// SPDX-License-Identifier: GPL-3.0-only
use std::{collections::VecDeque, io, path::Path, sync::Arc};

use super::{mmbert_tokenizer::MmbertPairTokenizer, tokenizer_store::global_tokenizer_store};

pub const TEXT_WINDOW_BYTES: usize = 128 * 1024;
pub const MODEL_TOKENS: usize = 256;
pub const CONTENT_TOKENS: usize = MODEL_TOKENS - 2;
pub const MAX_CHUNK_OVERLAP_TOKENS: usize = 64;
pub const TOKENIZER_FAMILY: &str = "mmbert";

pub type EncodedInputs = (Vec<i64>, Vec<i64>, Vec<i64>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenChunk {
    pub token_ids: Vec<u32>,
    pub byte_span: (usize, usize),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChunkOverlapTokens(usize);

impl ChunkOverlapTokens {
    pub const ZERO: Self = Self(0);

    pub fn get(self) -> usize {
        self.0
    }
}

impl TryFrom<i64> for ChunkOverlapTokens {
    type Error = String;

    fn try_from(overlap: i64) -> Result<Self, Self::Error> {
        if !(0..=MAX_CHUNK_OVERLAP_TOKENS as i64).contains(&overlap) {
            return Err(chunk_overlap_error());
        }
        Ok(Self(overlap as usize))
    }
}

impl TryFrom<usize> for ChunkOverlapTokens {
    type Error = String;

    fn try_from(overlap: usize) -> Result<Self, Self::Error> {
        if overlap > MAX_CHUNK_OVERLAP_TOKENS {
            return Err(chunk_overlap_error());
        }
        Ok(Self(overlap))
    }
}

fn chunk_overlap_error() -> String {
    format!("chunk_overlap_tokens must be between 0 and {MAX_CHUNK_OVERLAP_TOKENS}")
}

fn empty_token_chunk() -> TokenChunk {
    TokenChunk {
        token_ids: Vec::new(),
        byte_span: (0, 0),
    }
}

/// The single classifier tokenizer shared by NTDB v4 and L3.
#[derive(Clone)]
pub struct RuntimeTokenizer(pub(crate) Arc<MmbertPairTokenizer>);

impl RuntimeTokenizer {
    pub fn load(dir: impl AsRef<Path>) -> io::Result<Self> {
        global_tokenizer_store()
            .load_mmbert(dir.as_ref().join("tokenizer.mmbpe"))
            .map(Self)
    }

    pub fn token_chunks(&self, text: &str) -> Vec<TokenChunk> {
        let mut chunks = Vec::new();
        for (base, window) in text_windows(text) {
            let tokens = self.0.encode_window(window);
            for tokens in tokens.chunks(CONTENT_TOKENS) {
                chunks.push(TokenChunk {
                    token_ids: tokens.iter().map(|token| token.id).collect(),
                    byte_span: (base + tokens[0].start, base + tokens[tokens.len() - 1].end),
                });
            }
        }
        if chunks.is_empty() {
            chunks.push(empty_token_chunk());
        }
        chunks
    }

    pub fn token_chunks_with_overlap(
        &self,
        text: &str,
        overlap: usize,
    ) -> io::Result<Vec<TokenChunk>> {
        let overlap = ChunkOverlapTokens::try_from(overlap)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
            .get();
        if overlap == 0 {
            return Ok(self.token_chunks(text));
        }
        let stride = CONTENT_TOKENS - overlap;
        let mut pending = VecDeque::new();
        let mut chunks = Vec::new();
        for (base, window) in text_windows(text) {
            pending.extend(
                self.0
                    .encode_window(window)
                    .into_iter()
                    .map(|token| (token.id, base + token.start, base + token.end)),
            );
            while pending.len() >= CONTENT_TOKENS {
                let last = pending
                    .get(CONTENT_TOKENS - 1)
                    .expect("full token chunk has a final token");
                chunks.push(TokenChunk {
                    token_ids: pending
                        .iter()
                        .take(CONTENT_TOKENS)
                        .map(|token| token.0)
                        .collect(),
                    byte_span: (
                        pending
                            .front()
                            .expect("full token chunk has a first token")
                            .1,
                        last.2,
                    ),
                });
                pending.drain(..stride);
            }
        }
        if chunks.is_empty() && pending.is_empty() {
            chunks.push(empty_token_chunk());
        } else if pending.len() > overlap {
            chunks.push(TokenChunk {
                token_ids: pending.iter().map(|token| token.0).collect(),
                byte_span: (
                    pending
                        .front()
                        .expect("remaining chunk has a first token")
                        .1,
                    pending.back().expect("remaining chunk has a final token").2,
                ),
            });
        }
        Ok(chunks)
    }

    /// Assemble model inputs without text access, tokenization, or truncation.
    #[cfg(test)]
    pub fn inputs(&self, tokens: &[u32]) -> io::Result<EncodedInputs> {
        self.batch_inputs(&[tokens], true, true)
    }

    pub(crate) fn batch_inputs(
        &self,
        chunks: &[&[u32]],
        attention_mask: bool,
        token_type_ids: bool,
    ) -> io::Result<EncodedInputs> {
        let total = chunks.len() * MODEL_TOKENS;
        let mut ids = Vec::with_capacity(total);
        let mut mask = Vec::with_capacity(if attention_mask { total } else { 0 });
        for tokens in chunks {
            if tokens.len() > CONTENT_TOKENS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "chunk has {} content tokens; maximum is {CONTENT_TOKENS}",
                        tokens.len()
                    ),
                ));
            }
            let start = ids.len();
            ids.push(i64::from(self.0.bos()));
            ids.extend(tokens.iter().copied().map(i64::from));
            ids.push(i64::from(self.0.eos()));
            if attention_mask {
                mask.resize(ids.len(), 1);
                mask.resize(start + MODEL_TOKENS, 0);
            }
            ids.resize(start + MODEL_TOKENS, 0);
        }
        Ok((
            ids,
            mask,
            if token_type_ids {
                vec![0; total]
            } else {
                Vec::new()
            },
        ))
    }

    /// Convenience API for a single already-small text input. Long documents
    /// must use token_chunks and submit every chunk; never silently truncate.
    pub(crate) fn single_chunk_ids(&self, text: &str) -> io::Result<Vec<u32>> {
        let mut chunks = self.token_chunks(text);
        if chunks.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "text exceeds one classifier chunk; submit the prepared token chunks",
            ));
        }
        Ok(chunks.remove(0).token_ids)
    }
}

/// Disjoint UTF-8 windows. Every source byte enters the tokenizer once.
pub(crate) fn text_windows(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut start = 0;
    std::iter::from_fn(move || {
        if start == text.len() {
            return None;
        }
        let mut end = start.saturating_add(TEXT_WINDOW_BYTES).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let window = (start, &text[start..end]);
        start = end;
        Some(window)
    })
}

/// Exact cache identity follows model input, including byte-fallback tokens
/// that may share the same source character span.
pub(crate) fn token_key(tokens: &[u32]) -> Vec<u8> {
    tokens.iter().flat_map(|id| id.to_le_bytes()).collect()
}

#[cfg(test)]
pub(crate) fn fixture_tokenizer() -> RuntimeTokenizer {
    RuntimeTokenizer(Arc::new(
        MmbertPairTokenizer::from_file(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tokenizer.mmbpe"),
        )
        .unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_offsets_track_metaspace_merges_added_tokens_and_byte_fallback() {
        let tokenizer = fixture_tokenizer();
        for (text, expected) in [
            ("a bc", vec![(400, 0, 1), (3, 1, 2), (401, 2, 4)]),
            (" a", vec![(400, 0, 2)]),
            ("a   <mask>a", vec![(400, 0, 1), (99, 1, 10), (400, 10, 11)]),
            ("é", vec![(3, 0, 0), (1195, 0, 2), (1169, 0, 2)]),
            ("▁a", vec![(400, 0, 4)]),
        ] {
            // Repeat to exercise the piece cache with the same normalized
            // pieces and different source alignment (virtual/real metaspace).
            for _ in 0..2 {
                let actual = tokenizer
                    .0
                    .encode_window(text)
                    .into_iter()
                    .map(|t| (t.id, t.start, t.end))
                    .collect::<Vec<_>>();
                assert_eq!(actual, expected, "{text:?}");
            }
        }
    }

    #[test]
    fn every_byte_is_tokenized_once_in_bounded_utf8_windows() {
        let tokenizer = fixture_tokenizer();
        for text in [
            "a ".repeat(TEXT_WINDOW_BYTES * 2),
            "界🙂é".repeat(TEXT_WINDOW_BYTES / 3),
            "x".repeat(TEXT_WINDOW_BYTES + 1),
        ] {
            tokenizer.0.encoded_windows.lock().unwrap().clear();
            let chunks = tokenizer.token_chunks(&text);
            let calls = tokenizer.0.encoded_windows.lock().unwrap().clone();
            assert_eq!(calls.iter().sum::<usize>(), text.len());
            assert!(calls.iter().all(|bytes| *bytes <= TEXT_WINDOW_BYTES));
            assert_eq!(
                calls,
                text_windows(&text)
                    .map(|(_, text)| text.len())
                    .collect::<Vec<_>>()
            );
            assert!(chunks
                .iter()
                .all(|chunk| chunk.token_ids.len() <= CONTENT_TOKENS));
            assert_eq!(chunks.first().unwrap().byte_span.0, 0);
            assert_eq!(chunks.last().unwrap().byte_span.1, text.len());
            for chunk in &chunks {
                assert!(text.get(chunk.byte_span.0..chunk.byte_span.1).is_some());
            }
            assert!(chunks
                .windows(2)
                .all(|pair| pair[0].byte_span.1 >= pair[1].byte_span.0));
        }
    }

    #[test]
    fn model_inputs_preserve_every_id_and_never_truncate() {
        let tokenizer = fixture_tokenizer();
        for count in [0, 1, 253, 254, 255, 256, 257, 508] {
            let text = " a".repeat(count);
            let chunks = tokenizer.token_chunks(&text);
            assert_eq!(
                chunks.iter().map(|c| c.token_ids.len()).sum::<usize>(),
                count
            );
            assert_eq!(chunks.len(), count.div_ceil(CONTENT_TOKENS).max(1));
            for chunk in chunks {
                let calls = tokenizer.0.encoded_windows.lock().unwrap().len();
                let (ids, mask, types) = tokenizer.inputs(&chunk.token_ids).unwrap();
                assert_eq!(ids.len(), MODEL_TOKENS);
                assert_eq!(mask.len(), MODEL_TOKENS);
                assert_eq!(types, vec![0; MODEL_TOKENS]);
                assert_eq!(ids[0], 1);
                assert_eq!(ids[chunk.token_ids.len() + 1], 2);
                assert_eq!(
                    &ids[1..chunk.token_ids.len() + 1],
                    chunk
                        .token_ids
                        .iter()
                        .copied()
                        .map(i64::from)
                        .collect::<Vec<_>>()
                );
                assert_eq!(mask.iter().sum::<i64>() as usize, chunk.token_ids.len() + 2);
                assert!(ids[chunk.token_ids.len() + 2..].iter().all(|id| *id == 0));
                assert_eq!(tokenizer.0.encoded_windows.lock().unwrap().len(), calls);
            }
        }
        for count in [255, 256, 257] {
            assert!(tokenizer.inputs(&vec![400; count]).is_err());
        }
    }

    #[test]
    fn token_overlap_reuses_the_requested_tail_and_preserves_source_spans() {
        let tokenizer = fixture_tokenizer();
        let text = " a".repeat(CONTENT_TOKENS * 3);
        let disjoint = tokenizer.token_chunks(text.as_str());
        let overlapped = tokenizer
            .token_chunks_with_overlap(text.as_str(), 64)
            .unwrap();

        assert_eq!(disjoint.len(), 3);
        assert_eq!(overlapped.len(), 4);
        for pair in overlapped.windows(2) {
            assert_eq!(
                &pair[0].token_ids[CONTENT_TOKENS - 64..],
                &pair[1].token_ids[..64]
            );
            assert!(pair[0].byte_span.1 > pair[1].byte_span.0);
        }
        assert_eq!(overlapped.first().unwrap().byte_span.0, 0);
        assert_eq!(overlapped.last().unwrap().byte_span.1, text.len());
    }

    #[test]
    fn token_overlap_is_bounded_and_zero_preserves_existing_chunks() {
        let tokenizer = fixture_tokenizer();
        let text = "hello world ".repeat(800);

        assert_eq!(
            tokenizer.token_chunks_with_overlap(&text, 0).unwrap(),
            tokenizer.token_chunks(&text)
        );
        assert!(tokenizer.token_chunks_with_overlap(&text, 64).is_ok());
        assert!(tokenizer.token_chunks_with_overlap(&text, 65).is_err());
    }

    #[test]
    fn zero_overlap_preserves_chunk_boundaries_across_tokenizer_windows() {
        let tokenizer = fixture_tokenizer();
        let text = "a ".repeat(TEXT_WINDOW_BYTES);
        let legacy = tokenizer.token_chunks(&text);
        let configured = tokenizer.token_chunks_with_overlap(&text, 0).unwrap();

        assert_eq!(configured, legacy);
        let boundary = legacy
            .windows(2)
            .find(|pair| {
                pair[0].byte_span.1 <= TEXT_WINDOW_BYTES && pair[1].byte_span.0 >= TEXT_WINDOW_BYTES
            })
            .expect("fixture crosses the internal tokenizer window boundary");
        assert!(boundary[0].token_ids.len() < CONTENT_TOKENS);
        assert_eq!(boundary[1].token_ids.len(), CONTENT_TOKENS);
    }

    #[test]
    fn batch_inputs_preserve_row_boundaries_and_optional_inputs() {
        let tokenizer = fixture_tokenizer();
        let full = vec![7; CONTENT_TOKENS];
        let chunks: &[&[u32]] = &[&[7, 8], &[], &full];
        let (ids, mask, types) = tokenizer.batch_inputs(chunks, true, true).unwrap();
        assert_eq!(ids.len(), MODEL_TOKENS * 3);
        assert_eq!(
            &ids[..4],
            &[
                i64::from(tokenizer.0.bos()),
                7,
                8,
                i64::from(tokenizer.0.eos())
            ]
        );
        assert!(ids[4..MODEL_TOKENS].iter().all(|&id| id == 0));
        assert_eq!(
            &ids[MODEL_TOKENS..MODEL_TOKENS + 2],
            &[i64::from(tokenizer.0.bos()), i64::from(tokenizer.0.eos())]
        );
        assert_eq!(&mask[..4], &[1; 4]);
        assert!(mask[4..MODEL_TOKENS].iter().all(|&value| value == 0));
        assert_eq!(&mask[MODEL_TOKENS..MODEL_TOKENS + 2], &[1; 2]);
        assert!(mask[MODEL_TOKENS + 2..MODEL_TOKENS * 2]
            .iter()
            .all(|&value| value == 0));
        assert!(mask[MODEL_TOKENS * 2..].iter().all(|&value| value == 1));
        assert_eq!(types, vec![0; MODEL_TOKENS * 3]);
        let (without_optional, mask, types) = tokenizer.batch_inputs(chunks, false, false).unwrap();
        assert_eq!(without_optional, ids);
        assert!(mask.is_empty());
        assert!(types.is_empty());
        assert_eq!(
            tokenizer.batch_inputs(&[], true, true).unwrap(),
            (vec![], vec![], vec![])
        );
    }

    #[test]
    fn batch_inputs_reject_oversized_later_chunk() {
        let tokenizer = fixture_tokenizer();
        let oversized = vec![7; CONTENT_TOKENS + 1];
        assert_eq!(
            tokenizer
                .batch_inputs(&[&[7], &oversized], true, false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn text_convenience_api_rejects_multiple_chunks_without_truncation() {
        let tokenizer = fixture_tokenizer();
        assert!(tokenizer.single_chunk_ids(&" a".repeat(255)).is_err());
        assert_eq!(tokenizer.single_chunk_ids(" a").unwrap(), [400]);
    }

    #[test]
    fn compact_loader_never_falls_back_to_json() {
        let dir = std::env::temp_dir().join(format!("ark-no-hf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("tokenizer.json"), "{}").unwrap();
        assert!(RuntimeTokenizer::load(&dir).is_err());
        std::fs::write(dir.join("tokenizer.mmbpe"), b"invalid!").unwrap();
        assert!(RuntimeTokenizer::load(&dir).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn compact_store_shares_tokenizer_and_cache_keys_follow_ids() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let a = RuntimeTokenizer::load(&dir).unwrap();
        let b = RuntimeTokenizer::load(&dir).unwrap();
        assert!(Arc::ptr_eq(&a.0, &b.0));
        assert_eq!(token_key(&[3, 1]), token_key(&[3, 1]));
        assert_ne!(token_key(&[3, 1]), token_key(&[1, 3]));
        assert_ne!(token_key(&[1]), token_key(&[1, 0]));
    }
}
