// SPDX-License-Identifier: GPL-3.0-only
use std::path::Path;

use kitoken::{InsertionPosition, Kitoken};
use tokenizers::Tokenizer;

use crate::{diagnostics::PhaseMetricScope, ml::mmbert_tokenizer::MmbertPairTokenizer};

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

pub(super) enum RuntimeTokenizer {
    Compact(Kitoken),
    MmbertPair(MmbertPairTokenizer),
    HuggingFace(Tokenizer),
}

impl RuntimeTokenizer {
    pub(super) fn load(dir: impl AsRef<Path>) -> NtdbResult<Self> {
        let dir = dir.as_ref();
        let compact_path = dir.join("tokenizer.kit");
        if compact_path.exists() {
            match Kitoken::from_file(&compact_path) {
                Ok(tokenizer) => return Ok(Self::Compact(tokenizer)),
                Err(err) => log::warn!(
                    "failed to load compact NTDB tokenizer {}; falling back to tokenizer.json: {err}",
                    compact_path.display()
                ),
            }
        }

        let mmbpe_path = dir.join("tokenizer.mmbpe");
        if mmbpe_path.exists() {
            match MmbertPairTokenizer::from_file(&mmbpe_path) {
                Ok(tokenizer) => return Ok(Self::MmbertPair(tokenizer)),
                Err(err) => log::warn!(
                    "failed to load mmBERT compact NTDB tokenizer {}; falling back to tokenizer.json: {err}",
                    mmbpe_path.display()
                ),
            }
        }

        let json_path = dir.join("tokenizer.json");
        Ok(Self::HuggingFace(load_huggingface(&json_path)?))
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
            Self::Compact(tokenizer) => {
                let mut metrics = PhaseMetricScope::new(
                    "ntdb_tokenizer_compact",
                    format!(
                        "text_bytes={} add_special_tokens={add_special_tokens}",
                        text.len()
                    ),
                );
                // This flag recognizes special vocabulary inside the input; templates are
                // still applied explicitly below, just as HuggingFace separates both steps.
                let content_ids = tokenizer.encode(text, true).map_err(|err| {
                    ntdb_error(format!("failed to encode compact NTDB text: {err}"))
                })?;
                metrics.checkpoint("after_ids", format!("ids={}", content_ids.len()));
                let content_offsets = compact_offsets(tokenizer, text, &content_ids)?;
                metrics.checkpoint(
                    "after_offsets",
                    format!("offsets={}", content_offsets.len()),
                );
                if !add_special_tokens {
                    return Ok(EncodedText {
                        ids: content_ids,
                        offsets: content_offsets,
                    });
                }

                with_templates(tokenizer, content_ids, content_offsets)
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
            Self::Compact(tokenizer) => {
                let mut metrics = PhaseMetricScope::new(
                    "ntdb_tokenizer_compact_chunks",
                    format!(
                        "text_bytes={} chunk_token_limit={} window_tokens={} start_bytes={}",
                        text.len(),
                        chunk_token_limit,
                        BOUNDED_TOKENIZER_WINDOW_TOKENS,
                        TOKENIZER_WINDOW_START_BYTES
                    ),
                );
                let chunks = bounded_text_token_chunks(
                    text,
                    chunk_token_limit,
                    BOUNDED_TOKENIZER_WINDOW_TOKENS,
                    |slice| {
                        let ids = tokenizer.encode(slice, true).map_err(|err| {
                            ntdb_error(format!("failed to encode compact NTDB text window: {err}"))
                        })?;
                        let offsets = compact_offsets(tokenizer, slice, &ids)?;
                        Ok(EncodedText { ids, offsets })
                    },
                )?;
                metrics.checkpoint("after_chunks", format!("chunks={}", chunks.len()));
                Ok(chunks)
            }
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

    pub(super) fn decode(&self, ids: &[u32], skip_special_tokens: bool) -> NtdbResult<String> {
        match self {
            Self::HuggingFace(tokenizer) => tokenizer
                .decode(ids, skip_special_tokens)
                .map_err(|err| ntdb_error(format!("failed to decode NTDB chunk: {err}"))),
            Self::Compact(tokenizer) => {
                let bytes = tokenizer.decode(ids, !skip_special_tokens).map_err(|err| {
                    ntdb_error(format!("failed to decode compact NTDB chunk: {err}"))
                })?;
                String::from_utf8(bytes).map_err(|err| {
                    ntdb_error(format!(
                        "compact NTDB tokenizer returned invalid UTF-8: {err}"
                    ))
                })
            }
            Self::MmbertPair(_) => Err(ntdb_error(
                "mmBERT compact NTDB tokenizer does not support decode",
            )),
        }
    }
}

pub(crate) fn convert_huggingface_to_compact(
    json_path: &Path,
    compact_path: &Path,
) -> NtdbResult<()> {
    let tokenizer = Kitoken::from_tokenizers_file(json_path).map_err(|err| {
        ntdb_error(format!(
            "failed to convert HuggingFace tokenizer {} to Kitoken: {err}",
            json_path.display()
        ))
    })?;
    tokenizer.to_file(compact_path).map_err(|err| {
        ntdb_error(format!(
            "failed to write compact tokenizer {}: {err}",
            compact_path.display()
        ))
    })?;
    validate_compact_tokenizer(json_path, compact_path)
}

fn validate_compact_tokenizer(json_path: &Path, compact_path: &Path) -> NtdbResult<()> {
    let reference = RuntimeTokenizer::HuggingFace(load_huggingface(json_path)?);
    let compact = RuntimeTokenizer::Compact(Kitoken::from_file(compact_path).map_err(|err| {
        ntdb_error(format!(
            "failed to validate compact tokenizer {}: {err}",
            compact_path.display()
        ))
    })?);

    const SMOKE_TEXTS: &[&str] = &[
        "",
        "Hello world",
        "Übermäßig große Straße",
        "ＡＢＣ ① ﬁle ℌello 中文。",
        "emoji 👩‍💻🙂 and e\u{301}",
        "\0 control\ttext\nnext",
        "null\0byte",
        "bell\u{7}control",
        "unit\u{1f}separator",
        "<tag>repeat repeat</tag>",
    ];

    for text in SMOKE_TEXTS {
        for add_special_tokens in [false, true] {
            let expected = reference.encode(text, add_special_tokens)?;
            let actual = compact.encode(text, add_special_tokens)?;
            if actual.ids != expected.ids || actual.offsets != expected.offsets {
                return Err(ntdb_error(format!(
                    "compact tokenizer parity check failed for {text:?}, special_tokens={add_special_tokens}"
                )));
            }
            for skip_special_tokens in [false, true] {
                if compact.decode(&actual.ids, skip_special_tokens)?
                    != reference.decode(&expected.ids, skip_special_tokens)?
                {
                    return Err(ntdb_error(format!(
                        "compact tokenizer decode parity check failed for {text:?}, special_tokens={add_special_tokens}, skip_special_tokens={skip_special_tokens}"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn load_huggingface(json_path: &Path) -> NtdbResult<Tokenizer> {
    let mut tokenizer = Tokenizer::from_file(json_path).map_err(|err| {
        ntdb_error(format!(
            "failed to load NTDB tokenizer {}: {err}",
            json_path.display()
        ))
    })?;
    tokenizer
        .with_truncation(None)
        .map_err(|err| ntdb_error(format!("failed to disable tokenizer truncation: {err}")))?;
    tokenizer.with_padding(None);
    Ok(tokenizer)
}

fn with_templates(
    tokenizer: &Kitoken,
    content_ids: Vec<u32>,
    content_offsets: Vec<(usize, usize)>,
) -> NtdbResult<EncodedText> {
    let mut prefix = Vec::new();
    let mut suffix = Vec::new();
    for template in &tokenizer.config().templates {
        let target = match template.position {
            InsertionPosition::SequenceStart | InsertionPosition::SubSequenceStart => {
                Some(&mut prefix)
            }
            InsertionPosition::SequenceEnd | InsertionPosition::SubSequenceEnd => Some(&mut suffix),
            _ => None,
        };
        if let Some(target) = target {
            target.extend(tokenizer.encode(&template.content, true).map_err(|err| {
                ntdb_error(format!(
                    "failed to encode compact tokenizer template: {err}"
                ))
            })?);
        }
    }

    let mut ids = Vec::with_capacity(prefix.len() + content_ids.len() + suffix.len());
    ids.extend_from_slice(&prefix);
    ids.extend(content_ids);
    ids.extend_from_slice(&suffix);
    let mut offsets = Vec::with_capacity(ids.len());
    offsets.resize(prefix.len(), (0, 0));
    offsets.extend(content_offsets);
    offsets.resize(ids.len(), (0, 0));
    Ok(EncodedText { ids, offsets })
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

fn compact_offsets(
    tokenizer: &Kitoken,
    text: &str,
    ids: &[u32],
) -> NtdbResult<Vec<(usize, usize)>> {
    let source = text.as_bytes();
    let mut cursor = 0usize;
    let mut offsets = Vec::with_capacity(ids.len());
    for id in ids {
        let piece = tokenizer.decode([*id], true).map_err(|err| {
            ntdb_error(format!("failed to decode compact NTDB token {id}: {err}"))
        })?;
        if piece.is_empty() {
            offsets.push((0, 0));
            continue;
        }

        let start = find_from(source, &piece, cursor).ok_or_else(|| {
            ntdb_error(format!(
                "compact NTDB token {id} could not be aligned to the original text at byte {cursor}"
            ))
        })?;
        let raw_end = start + piece.len();
        let skipped = &source[cursor..start];
        let (offset_start, offset_end) = if !piece[0].is_ascii_whitespace()
            && !skipped.is_empty()
            && skipped
                .iter()
                .all(|byte| byte.is_ascii_control() && !byte.is_ascii_whitespace())
        {
            // ModernBERT's Split + ByteLevel chain drops a C0 prefix attached to a word.
            // HuggingFace then reports that token against the pre-token start and contracts
            // its end once more while translating ByteLevel offsets. Preserve this observable
            // behavior because these offsets become L3 candidate spans.
            let contracted_end = raw_end.saturating_sub(skipped.len() * 2);
            (cursor, contracted_end.max(cursor + 1))
        } else {
            // HuggingFace reports every byte-fallback fragment against the complete UTF-8 scalar.
            (
                utf8_scalar_span_containing(text, start).map_or(start, |span| span.0),
                utf8_scalar_span_containing(text, raw_end - 1).map_or(raw_end, |span| span.1),
            )
        };
        offsets.push((offset_start, offset_end));
        cursor = raw_end;
    }
    Ok(offsets)
}

fn utf8_scalar_span_containing(text: &str, byte_index: usize) -> Option<(usize, usize)> {
    if byte_index >= text.len() {
        return None;
    }

    let mut start = byte_index;
    while start > 0 && !text.is_char_boundary(start) {
        start -= 1;
    }

    let mut end = byte_index + 1;
    while end < text.len() && !text.is_char_boundary(end) {
        end += 1;
    }

    Some((start, end))
}

fn find_from(source: &[u8], piece: &[u8], cursor: usize) -> Option<usize> {
    if piece.is_empty() || cursor > source.len() || piece.len() > source.len() - cursor {
        return None;
    }
    let remaining = &source[cursor..];
    if remaining.starts_with(piece) {
        return Some(cursor);
    }
    remaining
        .windows(piece.len())
        .position(|candidate| candidate == piece)
        .map(|relative| cursor + relative)
}

#[cfg(test)]
mod tests {
    use std::{env, fs, path::PathBuf, time::SystemTime};

    use tokenizers::{
        models::wordlevel::WordLevel, pre_tokenizers::whitespace::Whitespace, Tokenizer,
    };

    use super::{
        bounded_text_token_chunks, chunk_encoded_text, convert_huggingface_to_compact, find_from,
        utf8_scalar_span_containing, EncodedText, RuntimeTokenizer,
    };
    use crate::ml::tokenizer_parity::{first_difference, texts};

    #[test]
    fn alignment_can_skip_bytes_removed_by_the_tokenizer() {
        assert_eq!(find_from(b"\0 control", b" control", 0), Some(1));
    }

    #[test]
    fn alignment_does_not_search_before_the_cursor() {
        assert_eq!(find_from(b"one two one", b"one", 4), Some(8));
    }

    #[test]
    fn utf8_scalar_span_maps_continuation_bytes_without_full_text_table() {
        let text = "Aé🙂";

        assert_eq!(utf8_scalar_span_containing(text, 0), Some((0, 1)));
        assert_eq!(utf8_scalar_span_containing(text, 1), Some((1, 3)));
        assert_eq!(utf8_scalar_span_containing(text, 2), Some((1, 3)));
        assert_eq!(utf8_scalar_span_containing(text, 3), Some((3, 7)));
        assert_eq!(utf8_scalar_span_containing(text, 6), Some((3, 7)));
        assert_eq!(utf8_scalar_span_containing(text, 7), None);
    }

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
        let runtime = RuntimeTokenizer::HuggingFace(tokenizer);

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
    fn corrupt_compact_tokenizer_falls_back_to_huggingface_json() {
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
        fs::write(dir.join("tokenizer.kit"), b"corrupt").unwrap();

        let loaded = RuntimeTokenizer::load(&dir).unwrap();
        assert!(matches!(loaded, RuntimeTokenizer::HuggingFace(_)));
        assert_eq!(loaded.encode("hello", false).unwrap().ids, vec![1]);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[ignore = "requires a real ModernBERT HuggingFace tokenizer directory"]
    fn modernbert_kit_matches_huggingface_ids_templates_decode_and_offsets() {
        let reference_dir = required_path("PATRONUS_TEST_MODERNBERT_HF_DIR");
        let suffix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let compact_dir = std::env::temp_dir().join(format!(
            "patronus_modernbert_conversion_{}_{}",
            std::process::id(),
            suffix
        ));
        fs::create_dir_all(&compact_dir).unwrap();
        convert_huggingface_to_compact(
            &reference_dir.join("tokenizer.json"),
            &compact_dir.join("tokenizer.kit"),
        )
        .unwrap();
        let reference = RuntimeTokenizer::load(&reference_dir).unwrap();
        let compact = RuntimeTokenizer::load(&compact_dir).unwrap();
        assert!(matches!(reference, RuntimeTokenizer::HuggingFace(_)));
        assert!(matches!(compact, RuntimeTokenizer::Compact(_)));

        let mut offset_mismatches = Vec::new();
        for (case, text) in texts().iter().enumerate() {
            for add_special_tokens in [false, true] {
                let expected = reference.encode(text, add_special_tokens).unwrap();
                let actual = compact.encode(text, add_special_tokens).unwrap();
                assert_eq!(
                    first_difference(&expected.ids, &actual.ids),
                    None,
                    "ModernBERT ID mismatch at case {case}, specials={add_special_tokens}, text={text:?}"
                );
                if actual.offsets != expected.offsets {
                    offset_mismatches.push(format!(
                        "case={case} specials={add_special_tokens} text={text:?} expected={:?} actual={:?}",
                        expected.offsets, actual.offsets
                    ));
                }
                for skip_special_tokens in [false, true] {
                    assert_eq!(
                        compact.decode(&actual.ids, skip_special_tokens).unwrap(),
                        reference
                            .decode(&expected.ids, skip_special_tokens)
                            .unwrap(),
                        "ModernBERT decode mismatch at case {case}, specials={add_special_tokens}, skip_specials={skip_special_tokens}, text={text:?}"
                    );
                }
            }
        }
        assert!(
            offset_mismatches.is_empty(),
            "ModernBERT offset mismatches: {}\n{}",
            offset_mismatches.len(),
            offset_mismatches
                .iter()
                .take(20)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
        fs::remove_dir_all(compact_dir).unwrap();
    }

    fn required_path(name: &str) -> PathBuf {
        env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("{name} must point to a tokenizer directory"))
    }
}
