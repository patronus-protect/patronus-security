// SPDX-License-Identifier: AGPL-3.0-only
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
};

const MAGIC: &[u8; 8] = b"MMBPE\0\x01\0";

#[derive(Clone)]
struct AddedToken {
    id: u32,
    content: String,
    lstrip: bool,
}

#[derive(Clone, Copy)]
struct Merge {
    rank: u32,
    output: u32,
}

pub(crate) struct MmbertPairTokenizer {
    chars: HashMap<char, u32>,
    bytes: [u32; 256],
    merges: HashMap<u64, Merge>,
    added: Vec<AddedToken>,
    added_matcher: AhoCorasick,
    bos: u32,
    eos: u32,
    unknown: u32,
}

impl MmbertPairTokenizer {
    pub(crate) fn from_file(path: &Path) -> io::Result<Self> {
        let mut reader = BufReader::new(File::open(path)?);
        let mut magic = [0; 8];
        reader.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid mmBPE file",
            ));
        }
        let bos = read_u32(&mut reader)?;
        let eos = read_u32(&mut reader)?;
        let unknown = read_u32(&mut reader)?;

        let char_count = read_u32(&mut reader)? as usize;
        let mut chars = HashMap::with_capacity(char_count);
        for _ in 0..char_count {
            let value = char::from_u32(read_u32(&mut reader)?)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid character"))?;
            chars.insert(value, read_u32(&mut reader)?);
        }

        let mut bytes = [0; 256];
        for id in &mut bytes {
            *id = read_u32(&mut reader)?;
        }

        let merge_count = read_u32(&mut reader)? as usize;
        let mut merges = HashMap::with_capacity(merge_count);
        for _ in 0..merge_count {
            let left = read_u32(&mut reader)?;
            let right = read_u32(&mut reader)?;
            let output = read_u32(&mut reader)?;
            let rank = read_u32(&mut reader)?;
            merges
                .entry(pair_key(left, right))
                .or_insert(Merge { rank, output });
        }

        let added_count = read_u32(&mut reader)? as usize;
        let mut added = Vec::with_capacity(added_count);
        for _ in 0..added_count {
            let id = read_u32(&mut reader)?;
            let lstrip = read_u32(&mut reader)? != 0;
            let mut content = vec![0; read_u32(&mut reader)? as usize];
            reader.read_exact(&mut content)?;
            added.push(AddedToken {
                id,
                content: String::from_utf8(content)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
                lstrip,
            });
        }
        let added_matcher = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(added.iter().map(|token| token.content.as_str()))
            .map_err(io::Error::other)?;
        Ok(Self {
            chars,
            bytes,
            merges,
            added,
            added_matcher,
            bos,
            eos,
            unknown,
        })
    }

    pub(crate) fn encode(&self, text: &str) -> Vec<u32> {
        self.encode_with_special_tokens(text, true)
    }

    fn encode_with_special_tokens(&self, text: &str, add_special_tokens: bool) -> Vec<u32> {
        let mut ids = Vec::new();
        if add_special_tokens {
            ids.push(self.bos);
        }
        let mut previous = 0;
        for matched in self.added_matcher.find_iter(text) {
            let token = &self.added[matched.pattern().as_usize()];
            let start = if token.lstrip {
                whitespace_start(&text[..matched.start()]).max(previous)
            } else {
                matched.start()
            };
            self.encode_plain(&text[previous..start], &mut ids);
            ids.push(token.id);
            previous = matched.end();
        }
        self.encode_plain(&text[previous..], &mut ids);
        if add_special_tokens {
            ids.push(self.eos);
        }
        ids
    }

    fn encode_plain(&self, text: &str, ids: &mut Vec<u32>) {
        if text.is_empty() {
            return;
        }
        let mut normalized = text.replace(' ', "▁");
        if !normalized.starts_with('▁') {
            normalized.insert(0, '▁');
        }
        let mut start = 0;
        for (index, value) in normalized.char_indices() {
            if value == '▁' && index > start {
                self.encode_piece(&normalized[start..index], ids);
                start = index;
            }
        }
        self.encode_piece(&normalized[start..], ids);
    }

    fn encode_piece(&self, piece: &str, output: &mut Vec<u32>) {
        let mut symbols = Vec::with_capacity(piece.chars().count());
        for value in piece.chars() {
            if let Some(id) = self.chars.get(&value) {
                symbols.push(*id);
            } else {
                let mut encoded = [0; 4];
                let fallback = value
                    .encode_utf8(&mut encoded)
                    .bytes()
                    .map(|byte| self.bytes[byte as usize])
                    .collect::<Vec<_>>();
                if fallback.iter().any(|id| *id == u32::MAX) {
                    symbols.push(self.unknown);
                } else {
                    symbols.extend(fallback);
                }
            }
        }
        loop {
            let next = symbols
                .windows(2)
                .enumerate()
                .filter_map(|(index, pair)| {
                    self.merges
                        .get(&pair_key(pair[0], pair[1]))
                        .map(|merge| (merge.rank, index, merge.output))
                })
                .min_by_key(|(rank, index, _)| (*rank, *index));
            let Some((_, index, merged)) = next else {
                break;
            };
            symbols[index] = merged;
            symbols.remove(index + 1);
        }
        output.extend(symbols);
    }
}

fn whitespace_start(value: &str) -> usize {
    value
        .char_indices()
        .rev()
        .find_map(|(index, value)| (!value.is_whitespace()).then_some(index + value.len_utf8()))
        .unwrap_or(0)
}

fn pair_key(left: u32, right: u32) -> u64 {
    ((left as u64) << 32) | right as u64
}

fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use std::{env, path::PathBuf};

    use tokenizers::Tokenizer;

    use super::MmbertPairTokenizer;
    use crate::ml::tokenizer_parity::{first_difference, texts};

    #[test]
    #[ignore = "requires real mmBERT HuggingFace and .mmbpe tokenizer files"]
    fn mmbert_mmbpe_matches_huggingface_ids_and_special_tokens() {
        let reference_path = required_path("PATRONUS_TEST_MMBERT_TOKENIZER_JSON");
        let compact_path = required_path("PATRONUS_TEST_MMBERT_TOKENIZER_MMBPE");
        let reference = Tokenizer::from_file(&reference_path).unwrap();
        let compact = MmbertPairTokenizer::from_file(&compact_path).unwrap();

        for (case, text) in texts().iter().enumerate() {
            for add_special_tokens in [false, true] {
                let expected = reference
                    .encode(text.as_str(), add_special_tokens)
                    .unwrap()
                    .get_ids()
                    .to_vec();
                let actual = compact.encode_with_special_tokens(text, add_special_tokens);
                assert_eq!(
                    first_difference(&expected, &actual),
                    None,
                    "mmBERT ID mismatch at case {case}, specials={add_special_tokens}, text={text:?}"
                );
            }
        }
    }

    fn required_path(name: &str) -> PathBuf {
        env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("{name} must point to a tokenizer file"))
    }
}
