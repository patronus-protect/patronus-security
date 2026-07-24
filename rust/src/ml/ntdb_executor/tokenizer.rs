// SPDX-License-Identifier: GPL-3.0-only
use std::path::Path;

use kitoken::{InsertionPosition, Kitoken};
use tokenizers::Tokenizer;

use super::{ntdb_error, NtdbResult};

pub(super) struct EncodedText {
    pub(super) ids: Vec<u32>,
    pub(super) offsets: Vec<(usize, usize)>,
}

pub(super) enum RuntimeTokenizer {
    Compact(Kitoken),
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
                // This flag recognizes special vocabulary inside the input; templates are
                // still applied explicitly below, just as HuggingFace separates both steps.
                let content_ids = tokenizer.encode(text, true).map_err(|err| {
                    ntdb_error(format!("failed to encode compact NTDB text: {err}"))
                })?;
                let content_offsets = compact_offsets(tokenizer, text, &content_ids)?;
                if !add_special_tokens {
                    return Ok(EncodedText {
                        ids: content_ids,
                        offsets: content_offsets,
                    });
                }

                with_templates(tokenizer, content_ids, content_offsets)
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

fn compact_offsets(
    tokenizer: &Kitoken,
    text: &str,
    ids: &[u32],
) -> NtdbResult<Vec<(usize, usize)>> {
    let source = text.as_bytes();
    let mut char_bounds = vec![(0usize, 0usize); source.len()];
    for (start, ch) in text.char_indices() {
        let end = start + ch.len_utf8();
        char_bounds[start..end].fill((start, end));
    }

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
                char_bounds.get(start).map_or(start, |span| span.0),
                char_bounds.get(raw_end - 1).map_or(raw_end, |span| span.1),
            )
        };
        offsets.push((offset_start, offset_end));
        cursor = raw_end;
    }
    Ok(offsets)
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

    use super::{convert_huggingface_to_compact, find_from, RuntimeTokenizer};
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
