// SPDX-License-Identifier: GPL-3.0-only
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::{
    cmp::Ordering,
    collections::{BinaryHeap, HashMap},
    io::{self, BufReader, Read},
    path::Path,
    sync::Mutex,
};

const MAGIC: &[u8; 8] = b"MMBPE\0\x01\0";
const PIECE_CACHE_MAX_ENTRIES: usize = 65_536;
const PIECE_CACHE_MAX_BYTES: usize = 96;

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

#[derive(Clone, Copy, Eq, PartialEq)]
struct MergeCandidate {
    rank: u32,
    index: usize,
    output: u32,
    left: u32,
    right: u32,
}

impl Ord for MergeCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .rank
            .cmp(&self.rank)
            .then_with(|| other.index.cmp(&self.index))
    }
}

impl PartialOrd for MergeCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EncodedToken {
    pub(crate) id: u32,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

pub struct MmbertPairTokenizer {
    chars: HashMap<char, u32>,
    bytes: [u32; 256],
    merges: HashMap<u64, Merge>,
    added: Vec<AddedToken>,
    added_matcher: AhoCorasick,
    bos: u32,
    eos: u32,
    unknown: u32,
    piece_cache: Mutex<HashMap<String, Vec<EncodedToken>>>,
    pub(crate) fingerprint: blake3::Hash,
    #[cfg(test)]
    pub(crate) encoded_windows: Mutex<Vec<usize>>,
}

impl MmbertPairTokenizer {
    pub(crate) fn from_file(path: &Path) -> io::Result<Self> {
        let data = std::fs::read(path)?;
        let fingerprint = blake3::hash(&data);
        let mut reader = BufReader::new(data.as_slice());
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
            piece_cache: Mutex::new(HashMap::new()),
            fingerprint,
            #[cfg(test)]
            encoded_windows: Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn bos(&self) -> u32 {
        self.bos
    }

    pub(crate) fn eos(&self) -> u32 {
        self.eos
    }

    #[cfg(test)]
    pub(crate) fn encode_with_special_tokens(&self, text: &str, specials: bool) -> Vec<u32> {
        let mut ids = Vec::new();
        if specials {
            ids.push(self.bos);
        }
        for (_, window) in super::tokenizer::text_windows(text) {
            ids.extend(self.encode_window(window).into_iter().map(|token| token.id));
        }
        if specials {
            ids.push(self.eos);
        }
        ids
    }

    pub(crate) fn encode_window(&self, text: &str) -> Vec<EncodedToken> {
        assert!(text.len() <= super::tokenizer::TEXT_WINDOW_BYTES);
        #[cfg(test)]
        self.encoded_windows.lock().unwrap().push(text.len());
        let mut tokens = Vec::new();
        let mut previous = 0;
        for matched in self.added_matcher.find_iter(text) {
            let token = &self.added[matched.pattern().as_usize()];
            let start = if token.lstrip {
                whitespace_start(&text[..matched.start()]).max(previous)
            } else {
                matched.start()
            };
            self.encode_plain(&text[previous..start], previous, &mut tokens);
            tokens.push(EncodedToken {
                id: token.id,
                start,
                end: matched.end(),
            });
            previous = matched.end();
        }
        self.encode_plain(&text[previous..], previous, &mut tokens);
        tokens
    }

    fn encode_plain(&self, text: &str, base: usize, output: &mut Vec<EncodedToken>) {
        if text.is_empty() {
            return;
        }
        // Keep source alignment through the metaspace transformation. A virtual
        // leading metaspace consumes no source bytes; byte fallback tokens share
        // the original character's span, including when a chunk splits it.
        let mut normalized = String::new();
        let mut alignment = Vec::new();
        if !text.starts_with([' ', '▁']) {
            normalized.push('▁');
            alignment.extend(std::iter::repeat_n((0, 0), '▁'.len_utf8()));
        }
        for (start, value) in text.char_indices() {
            let normalized_value = if value == ' ' { '▁' } else { value };
            normalized.push(normalized_value);
            alignment.extend(std::iter::repeat_n(
                (start, start + value.len_utf8()),
                normalized_value.len_utf8(),
            ));
        }
        let mut start = 0;
        for (index, value) in normalized.char_indices() {
            if value == '▁' && index > start {
                self.append_piece(
                    &normalized[start..index],
                    &alignment[start..index],
                    base,
                    output,
                );
                start = index;
            }
        }
        self.append_piece(&normalized[start..], &alignment[start..], base, output);
    }

    fn append_piece(
        &self,
        piece: &str,
        alignment: &[(usize, usize)],
        base: usize,
        output: &mut Vec<EncodedToken>,
    ) {
        let tokens = self.encode_piece(piece);
        output.extend(tokens.into_iter().map(|token| EncodedToken {
            id: token.id,
            start: base + alignment[token.start].0,
            end: base + alignment[token.end - 1].1,
        }));
    }

    fn encode_piece(&self, piece: &str) -> Vec<EncodedToken> {
        if piece.len() <= PIECE_CACHE_MAX_BYTES {
            if let Some(tokens) = self
                .piece_cache
                .lock()
                .expect("mmBERT piece cache mutex poisoned")
                .get(piece)
                .cloned()
            {
                return tokens;
            }
        }
        let mut symbols = Vec::with_capacity(piece.chars().count());
        for (start, value) in piece.char_indices() {
            let end = start + value.len_utf8();
            if let Some(id) = self.chars.get(&value) {
                symbols.push(EncodedToken {
                    id: *id,
                    start,
                    end,
                });
            } else {
                let mut encoded = [0; 4];
                let bytes = value.encode_utf8(&mut encoded).as_bytes();
                if bytes
                    .iter()
                    .any(|byte| self.bytes[*byte as usize] == u32::MAX)
                {
                    symbols.push(EncodedToken {
                        id: self.unknown,
                        start,
                        end,
                    });
                } else {
                    symbols.extend(bytes.iter().map(|byte| EncodedToken {
                        id: self.bytes[*byte as usize],
                        start,
                        end,
                    }));
                }
            }
        }
        merge_symbols(&mut symbols, &self.merges);
        if piece.len() <= PIECE_CACHE_MAX_BYTES {
            let mut cache = self
                .piece_cache
                .lock()
                .expect("mmBERT piece cache mutex poisoned");
            if cache.len() < PIECE_CACHE_MAX_ENTRIES {
                cache.insert(piece.to_string(), symbols.clone());
            }
        }
        symbols
    }
}

fn merge_symbols(symbols: &mut Vec<EncodedToken>, merges: &HashMap<u64, Merge>) {
    const END: usize = usize::MAX;

    if symbols.len() < 2 {
        return;
    }

    let mut previous = vec![END; symbols.len()];
    let mut next = vec![END; symbols.len()];
    let mut active = vec![true; symbols.len()];
    for index in 0..symbols.len() {
        if index > 0 {
            previous[index] = index - 1;
        }
        if index + 1 < symbols.len() {
            next[index] = index + 1;
        }
    }

    let mut heap = BinaryHeap::with_capacity(symbols.len());
    for index in 0..symbols.len() - 1 {
        push_candidate(index, symbols, &next, merges, &mut heap);
    }

    while let Some(candidate) = heap.pop() {
        let right_index = next[candidate.index];
        if right_index == END
            || !active[candidate.index]
            || !active[right_index]
            || symbols[candidate.index].id != candidate.left
            || symbols[right_index].id != candidate.right
        {
            continue;
        }

        symbols[candidate.index].id = candidate.output;
        symbols[candidate.index].end = symbols[right_index].end;
        active[right_index] = false;
        let after = next[right_index];
        next[candidate.index] = after;
        if after != END {
            previous[after] = candidate.index;
        }

        let before = previous[candidate.index];
        if before != END {
            push_candidate(before, symbols, &next, merges, &mut heap);
        }
        push_candidate(candidate.index, symbols, &next, merges, &mut heap);
    }

    let mut write = 0;
    for read in 0..symbols.len() {
        if active[read] {
            symbols[write] = symbols[read];
            write += 1;
        }
    }
    symbols.truncate(write);
}

fn push_candidate(
    index: usize,
    symbols: &[EncodedToken],
    next: &[usize],
    merges: &HashMap<u64, Merge>,
    heap: &mut BinaryHeap<MergeCandidate>,
) {
    let right_index = next[index];
    if right_index == usize::MAX {
        return;
    }
    let left = symbols[index].id;
    let right = symbols[right_index].id;
    if let Some(merge) = merges.get(&pair_key(left, right)) {
        heap.push(MergeCandidate {
            rank: merge.rank,
            index,
            output: merge.output,
            left,
            right,
        });
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

        let runtime = crate::ml::tokenizer::RuntimeTokenizer(std::sync::Arc::new(
            MmbertPairTokenizer::from_file(&compact_path).unwrap(),
        ));
        for (case, text) in texts().iter().enumerate() {
            for (_, window) in crate::ml::tokenizer::text_windows(text) {
                for add_special_tokens in [false, true] {
                    let expected = reference
                        .encode(window, add_special_tokens)
                        .unwrap()
                        .get_ids()
                        .to_vec();
                    let actual = compact.encode_with_special_tokens(window, add_special_tokens);
                    assert_eq!(first_difference(&expected, &actual), None,
                        "mmBERT ID mismatch at case {case}, specials={add_special_tokens}, text={window:?}");
                }
                let reference_encoding = reference.encode(window, false).unwrap();
                let actual = compact.encode_window(window);
                for (token, expected) in actual.iter().zip(reference_encoding.get_offsets()) {
                    // The inserted leading metaspace has no source bytes.
                    if token.end > token.start {
                        assert_eq!(
                            (token.start, token.end),
                            *expected,
                            "mmBERT offset mismatch, case {case}, id {}",
                            token.id
                        );
                    }
                }
                let chunks = runtime.token_chunks(window);
                assert_eq!(
                    chunks
                        .iter()
                        .flat_map(|chunk| chunk.token_ids.iter().copied())
                        .collect::<Vec<_>>(),
                    reference_encoding.get_ids()
                );
                for chunk in chunks {
                    let (ids, mask, _) = runtime.inputs(&chunk.token_ids).unwrap();
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
                }
            }
        }
    }

    fn required_path(name: &str) -> PathBuf {
        env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("{name} must point to a tokenizer file"))
    }
}
