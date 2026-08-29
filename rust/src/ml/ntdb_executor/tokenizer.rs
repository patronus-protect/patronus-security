// SPDX-License-Identifier: GPL-3.0-only
use std::{path::Path, sync::Arc};

use tokenizers::Tokenizer;

use crate::ml::{mmbert_tokenizer::MmbertPairTokenizer, tokenizer_store::global_tokenizer_store};

use super::{ntdb_error, NtdbResult};

const BOUNDED_TOKENIZER_WINDOW_TOKENS: usize = 32_768;
const TOKENIZER_WINDOW_START_BYTES: usize = 128 * 1024;

pub(super) struct EncodedText {
    pub(super) ids: Vec<u32>,
    pub(super) offsets: Vec<(usize, usize)>,
}

pub(super) struct EncodedTokenChunk {
    pub(super) ids: Vec<u32>,
    pub(super) byte_span: (usize, usize),
}

#[derive(Clone)]
pub enum RuntimeTokenizer {
    MmbertPair(Arc<MmbertPairTokenizer>),
    HuggingFace(Arc<Tokenizer>),
}

impl RuntimeTokenizer {
    pub fn load(dir: impl AsRef<Path>) -> NtdbResult<Self> {
        let dir = dir.as_ref();
        let store = global_tokenizer_store();
        let mmbpe_path = dir.join("tokenizer.mmbpe");
        if mmbpe_path.exists() {
            match store.load_mmbert(&mmbpe_path) {
                Ok(tokenizer) => return Ok(Self::MmbertPair(tokenizer)),
                Err(err) => log::warn!(
                    "failed to load mmBERT compact NTDB tokenizer {}; falling back to tokenizer.json: {err}",
                    mmbpe_path.display()
                ),
            }
        }

        let json_path = dir.join("tokenizer.json");
        store
            .load_huggingface(&json_path)
            .map(Self::HuggingFace)
            .map_err(|err| ntdb_error(format!("failed to load NTDB tokenizer: {err}")))
    }

    pub(super) fn encode(&self, text: &str, add_special_tokens: bool) -> NtdbResult<EncodedText> {
        match self {
            Self::HuggingFace(tokenizer) => {
                let encoding = tokenizer
                    .encode(text, add_special_tokens)
                    .map_err(|err| ntdb_error(format!("failed to encode NTDB text: {err}")))?;
                Ok(EncodedText {
                    ids: encoding.get_ids().to_vec(),
                    offsets: encoding.get_offsets().to_vec(),
                })
            }
            Self::MmbertPair(tokenizer) => {
                let ids = tokenizer.encode_with_special_tokens(text, add_special_tokens);
                Ok(EncodedText {
                    offsets: fallback_offsets(text, ids.len()),
                    ids,
                })
            }
        }
    }

    pub(super) fn encode_token_chunks(
        &self,
        text: &str,
        chunk_token_limit: usize,
    ) -> NtdbResult<Vec<EncodedTokenChunk>> {
        let chunk_token_limit = chunk_token_limit.max(1);
        match self {
            Self::MmbertPair(tokenizer) => bounded_text_token_chunks(
                text,
                chunk_token_limit,
                BOUNDED_TOKENIZER_WINDOW_TOKENS,
                |slice| {
                    let ids = tokenizer.encode_with_special_tokens(slice, false);
                    let offsets = approximate_offsets(slice, ids.len());
                    Ok(EncodedText { ids, offsets })
                },
            ),
            Self::HuggingFace(_) => {
                let encoding = self.encode(text, false)?;
                Ok(chunk_encoded_text(
                    &encoding.ids,
                    &encoding.offsets,
                    chunk_token_limit,
                    0,
                ))
            }
        }
    }
}

fn bounded_text_token_chunks<F>(
    text: &str,
    chunk_token_limit: usize,
    window_token_limit: usize,
    mut encode: F,
) -> NtdbResult<Vec<EncodedTokenChunk>>
where
    F: FnMut(&str) -> NtdbResult<EncodedText>,
{
    if text.is_empty() {
        return Ok(vec![EncodedTokenChunk {
            ids: Vec::new(),
            byte_span: (0, 0),
        }]);
    }

    let mut chunks = Vec::new();
    let mut start = 0usize;
    let window_token_limit = window_token_limit.max(chunk_token_limit).max(1);
    while start < text.len() {
        let mut end = bounded_window_end(text, start, TOKENIZER_WINDOW_START_BYTES);
        let mut encoded = encode(&text[start..end])?;
        while encoded.ids.len() > window_token_limit {
            let next = shrink_window_end(text, start, end);
            if next == end || next <= start {
                break;
            }
            end = next;
            encoded = encode(&text[start..end])?;
        }

        if encoded.ids.is_empty() {
            start = end;
            continue;
        }
        chunks.extend(chunk_encoded_text(
            &encoded.ids,
            &encoded.offsets,
            chunk_token_limit,
            start,
        ));
        start = end;
    }

    if chunks.is_empty() {
        chunks.push(EncodedTokenChunk {
            ids: Vec::new(),
            byte_span: (0, 0),
        });
    }
    Ok(chunks)
}

fn bounded_window_end(text: &str, start: usize, max_bytes: usize) -> usize {
    let target = start.saturating_add(max_bytes).min(text.len());
    previous_char_boundary(text, start, target).max(next_char_boundary(text, start))
}

fn shrink_window_end(text: &str, start: usize, current_end: usize) -> usize {
    let midpoint = start + (current_end - start) / 2;
    previous_char_boundary(text, start, midpoint).max(next_char_boundary(text, start))
}

fn previous_char_boundary(text: &str, start: usize, mut index: usize) -> usize {
    while index > start && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn next_char_boundary(text: &str, start: usize) -> usize {
    let mut index = (start + 1).min(text.len());
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

fn fallback_offsets(text: &str, token_count: usize) -> Vec<(usize, usize)> {
    approximate_offsets(text, token_count)
}

fn approximate_offsets(text: &str, token_count: usize) -> Vec<(usize, usize)> {
    if token_count == 0 {
        return Vec::new();
    }
    let mut offsets = Vec::with_capacity(token_count);
    for index in 0..token_count {
        let start = previous_char_boundary(text, 0, index * text.len() / token_count);
        let end = previous_char_boundary(text, start, (index + 1) * text.len() / token_count);
        offsets.push((start, end.max(start)));
    }
    offsets
}

fn chunk_encoded_text(
    token_ids: &[u32],
    offsets: &[(usize, usize)],
    chunk_size: usize,
    base_offset: usize,
) -> Vec<EncodedTokenChunk> {
    if token_ids.is_empty() {
        return vec![EncodedTokenChunk {
            ids: Vec::new(),
            byte_span: (base_offset, base_offset),
        }];
    }
    token_ids
        .chunks(chunk_size)
        .zip(offsets.chunks(chunk_size))
        .map(|(ids, chunk_offsets)| EncodedTokenChunk {
            ids: ids.to_vec(),
            byte_span: byte_span(chunk_offsets, base_offset),
        })
        .collect()
}

fn byte_span(offsets: &[(usize, usize)], base_offset: usize) -> (usize, usize) {
    let start = offsets
        .iter()
        .find(|(start, end)| end > start)
        .map(|(start, _)| *start)
        .unwrap_or(0);
    let end = offsets
        .iter()
        .rev()
        .find(|(start, end)| end > start)
        .map(|(_, end)| *end)
        .unwrap_or(start);
    (base_offset + start, base_offset + end)
}

#[cfg(test)]
mod tests {
    use std::{fs, time::SystemTime};

    use tokenizers::{
        models::wordlevel::WordLevel, pre_tokenizers::whitespace::Whitespace, Tokenizer,
    };

    use super::{bounded_text_token_chunks, chunk_encoded_text, EncodedText, RuntimeTokenizer};

    #[test]
    fn bounded_token_chunks_respect_limit_and_utf8_boundaries() {
        let text = "aé🙂bc";
        let chunks =
            bounded_text_token_chunks(text, 2, 2, |slice| Ok(char_encoded_text(slice))).unwrap();

        assert!(chunks.iter().all(|chunk| chunk.ids.len() <= 2));
        assert_eq!(chunks.iter().map(|chunk| chunk.ids.len()).sum::<usize>(), 5);
        for chunk in chunks {
            assert!(text.is_char_boundary(chunk.byte_span.0));
            assert!(text.is_char_boundary(chunk.byte_span.1));
            assert!(chunk.byte_span.0 < chunk.byte_span.1);
        }
    }

    #[test]
    fn huggingface_token_chunks_match_full_encode_chunking() {
        let model = WordLevel::builder()
            .vocab(
                [
                    ("[UNK]".to_string(), 0),
                    ("hello".to_string(), 1),
                    ("world".to_string(), 2),
                ]
                .into_iter()
                .collect(),
            )
            .unk_token("[UNK]".to_string())
            .build()
            .unwrap();
        let mut tokenizer = Tokenizer::new(model);
        tokenizer.with_pre_tokenizer(Some(Whitespace));
        let runtime = RuntimeTokenizer::HuggingFace(std::sync::Arc::new(tokenizer));

        let text = "hello world hello";
        let encoded = runtime.encode(text, false).unwrap();
        let expected = chunk_encoded_text(&encoded.ids, &encoded.offsets, 2, 0);
        let actual = runtime.encode_token_chunks(text, 2).unwrap();

        assert_eq!(actual.len(), expected.len());
        for (actual, expected) in actual.iter().zip(expected.iter()) {
            assert_eq!(actual.ids, expected.ids);
            assert_eq!(actual.byte_span, expected.byte_span);
        }
    }

    #[test]
    fn bounded_token_chunks_do_not_cap_the_document() {
        let text = "abcdef";
        let chunks =
            bounded_text_token_chunks(text, 1, 3, |slice| Ok(char_encoded_text(slice))).unwrap();

        assert_eq!(chunks.len(), 6);
        assert!(chunks.iter().all(|chunk| chunk.ids.len() <= 1));
        assert_eq!(chunks.iter().map(|chunk| chunk.ids.len()).sum::<usize>(), 6);
    }

    #[test]
    fn bounded_tokenizer_windows_respect_window_token_limit() {
        let text = "abcdef";
        let chunks =
            bounded_text_token_chunks(text, 2, 3, |slice| Ok(char_encoded_text(slice))).unwrap();

        let lengths = chunks
            .iter()
            .map(|chunk| chunk.ids.len())
            .collect::<Vec<_>>();
        assert_eq!(lengths, vec![2, 1, 2, 1]);
        assert_eq!(chunks.iter().map(|chunk| chunk.ids.len()).sum::<usize>(), 6);
    }

    fn char_encoded_text(text: &str) -> EncodedText {
        EncodedText {
            ids: text.chars().map(|value| value as u32).collect(),
            offsets: text
                .char_indices()
                .map(|(start, value)| (start, start + value.len_utf8()))
                .collect(),
        }
    }

    #[test]
    fn unrelated_files_do_not_replace_huggingface_json() {
        let suffix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "patronus_compact_fallback_{}_{}",
            std::process::id(),
            suffix
        ));
        fs::create_dir_all(&dir).unwrap();
        let model = WordLevel::builder()
            .vocab(
                [("[UNK]".to_string(), 0), ("hello".to_string(), 1)]
                    .into_iter()
                    .collect(),
            )
            .unk_token("[UNK]".to_string())
            .build()
            .unwrap();
        let mut tokenizer = Tokenizer::new(model);
        tokenizer.with_pre_tokenizer(Some(Whitespace));
        tokenizer.save(dir.join("tokenizer.json"), false).unwrap();
        fs::write(dir.join("unrelated.bin"), b"corrupt").unwrap();

        let loaded = RuntimeTokenizer::load(&dir).unwrap();
        assert!(matches!(loaded, RuntimeTokenizer::HuggingFace(_)));
        assert_eq!(loaded.encode("hello", false).unwrap().ids, vec![1]);

        fs::remove_dir_all(dir).unwrap();
    }
}
