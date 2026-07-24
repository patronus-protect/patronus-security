use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use serde::Deserialize;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, BufReader, BufWriter, Read, Write},
    path::Path,
    time::Instant,
};
use tokenizers::Tokenizer;

const MAGIC: &[u8; 8] = b"MMBPE\0\x01\0";

#[derive(Deserialize)]
struct TokenizerJson {
    added_tokens: Vec<AddedToken>,
    model: BpeJson,
}

#[derive(Clone, Deserialize)]
struct AddedToken {
    id: u32,
    content: String,
    lstrip: bool,
}

#[derive(Deserialize)]
struct BpeJson {
    vocab: HashMap<String, u32>,
    merges: Vec<[String; 2]>,
}

#[derive(Clone, Copy)]
struct Merge {
    rank: u32,
    output: u32,
}

struct PairTokenizer {
    chars: HashMap<char, u32>,
    bytes: [u32; 256],
    merges: HashMap<u64, Merge>,
    added: Vec<AddedToken>,
    added_matcher: AhoCorasick,
    bos: u32,
    eos: u32,
    unknown: u32,
}

impl PairTokenizer {
    fn from_file(path: &Path) -> io::Result<Self> {
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
        let patterns = added.iter().map(|token| token.content.as_str());
        let added_matcher = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(patterns)
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

    fn encode(&self, text: &str, add_special_tokens: bool) -> Vec<u32> {
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

fn convert(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let parsed: TokenizerJson = serde_json::from_slice(&fs::read(source)?)?;
    let vocab = &parsed.model.vocab;
    let mut chars = vocab
        .iter()
        .filter_map(|(token, id)| {
            let mut values = token.chars();
            let value = values.next()?;
            values.next().is_none().then_some((value, *id))
        })
        .collect::<Vec<_>>();
    chars.sort_unstable_by_key(|(value, _)| *value);

    let mut bytes = [0; 256];
    for (byte, id) in bytes.iter_mut().enumerate() {
        *id = vocab
            .get(&format!("<{byte:#04X}>"))
            .copied()
            .unwrap_or(u32::MAX);
    }

    let mut writer = BufWriter::new(File::create(destination)?);
    writer.write_all(MAGIC)?;
    write_u32(&mut writer, *vocab.get("<bos>").ok_or("missing <bos>")?)?;
    write_u32(&mut writer, *vocab.get("<eos>").ok_or("missing <eos>")?)?;
    write_u32(&mut writer, *vocab.get("<unk>").ok_or("missing <unk>")?)?;
    write_u32(&mut writer, chars.len() as u32)?;
    for (value, id) in chars {
        write_u32(&mut writer, value as u32)?;
        write_u32(&mut writer, id)?;
    }
    for id in bytes {
        write_u32(&mut writer, id)?;
    }

    write_u32(&mut writer, parsed.model.merges.len() as u32)?;
    for (rank, [left, right]) in parsed.model.merges.iter().enumerate() {
        let left_id = *vocab
            .get(left)
            .ok_or_else(|| format!("missing merge token {left:?}"))?;
        let right_id = *vocab
            .get(right)
            .ok_or_else(|| format!("missing merge token {right:?}"))?;
        let output_id = *vocab
            .get(&format!("{left}{right}"))
            .ok_or_else(|| format!("missing merged token {left:?} + {right:?}"))?;
        write_u32(&mut writer, left_id)?;
        write_u32(&mut writer, right_id)?;
        write_u32(&mut writer, output_id)?;
        write_u32(&mut writer, rank as u32)?;
    }

    write_u32(&mut writer, parsed.added_tokens.len() as u32)?;
    for token in parsed.added_tokens {
        write_u32(&mut writer, token.id)?;
        write_u32(&mut writer, u32::from(token.lstrip))?;
        write_u32(&mut writer, token.content.len() as u32)?;
        writer.write_all(token.content.as_bytes())?;
    }
    writer.flush()?;
    Ok(())
}

#[derive(Deserialize)]
struct DatasetRow {
    text: String,
}

fn parity(
    tokenizer_json: &Path,
    binary: &Path,
    dataset_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let reference = Tokenizer::from_file(tokenizer_json).map_err(io::Error::other)?;
    let compact = PairTokenizer::from_file(binary)?;
    let mut texts = load_texts(dataset_dir)?;
    texts.extend(
        [
            "",
            " ",
            "   ",
            "\n",
            "\n\n\n\n",
            "\t\t\t",
            "ＡＢＣ ① ﬁle ℌello 你好，世界 🦀",
            "before <mask> after",
            "<table><tr><td>value</td></tr></table>",
            "zero\u{200b}width\0control",
        ]
        .into_iter()
        .map(str::to_string),
    );
    let started = Instant::now();
    for (checked, text) in texts.iter().enumerate() {
        for add_special_tokens in [false, true] {
            let expected = reference
                .encode(text.as_str(), add_special_tokens)
                .map_err(io::Error::other)?
                .get_ids()
                .to_vec();
            let actual = compact.encode(text, add_special_tokens);
            if actual != expected {
                let difference = actual
                    .iter()
                    .zip(&expected)
                    .position(|(actual, expected)| actual != expected)
                    .unwrap_or(actual.len().min(expected.len()));
                return Err(format!(
                    "token mismatch at text {checked}, special={add_special_tokens}, token={difference}\nexpected={expected:?}\nactual={actual:?}\ntext={text:?}"
                )
                .into());
            }
        }
    }
    println!(
        "texts={} encodings={} mismatches=0 elapsed_ms={:.2}",
        texts.len(),
        texts.len() * 2,
        started.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}

fn benchmark_compact(binary: &Path, dataset_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let tokenizer = PairTokenizer::from_file(binary)?;
    let load_ms = started.elapsed().as_secs_f64() * 1000.0;
    let texts = load_texts(dataset_dir)?;
    let started = Instant::now();
    let (tokens, checksum) = texts.iter().fold((0usize, 0u64), |(count, hash), text| {
        let ids = tokenizer.encode(text, true);
        (
            count + ids.len(),
            ids.iter().fold(hash, |hash, id| {
                hash.wrapping_mul(31).wrapping_add(*id as u64)
            }),
        )
    });
    println!(
        "runtime=compact texts={} tokens={tokens} checksum={checksum} load_ms={load_ms:.2} encode_ms={:.2}",
        texts.len(),
        started.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}

fn benchmark_reference(
    tokenizer_json: &Path,
    dataset_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let tokenizer = Tokenizer::from_file(tokenizer_json).map_err(io::Error::other)?;
    let load_ms = started.elapsed().as_secs_f64() * 1000.0;
    let texts = load_texts(dataset_dir)?;
    let started = Instant::now();
    let mut tokens = 0;
    let mut checksum = 0u64;
    for text in &texts {
        let encoded = tokenizer
            .encode(text.as_str(), true)
            .map_err(io::Error::other)?;
        tokens += encoded.len();
        checksum = encoded.get_ids().iter().fold(checksum, |hash, id| {
            hash.wrapping_mul(31).wrapping_add(*id as u64)
        });
    }
    println!(
        "runtime=reference texts={} tokens={tokens} checksum={checksum} load_ms={load_ms:.2} encode_ms={:.2}",
        texts.len(),
        started.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}

fn load_texts(dataset_dir: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut paths = fs::read_dir(dataset_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .collect::<Vec<_>>();
    paths.sort();
    let mut texts = Vec::new();
    for path in paths {
        for line in fs::read_to_string(path)?.lines() {
            texts.push(serde_json::from_str::<DatasetRow>(line)?.text);
        }
    }
    Ok(texts)
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

fn write_u32(writer: &mut impl Write, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    match args.as_slice() {
        [_, command, source, destination] if command == "convert" => {
            convert(Path::new(source), Path::new(destination))
        }
        [_, command, tokenizer_json, binary, dataset_dir] if command == "parity" => parity(
            Path::new(tokenizer_json),
            Path::new(binary),
            Path::new(dataset_dir),
        ),
        [_, command, binary, dataset_dir] if command == "benchmark-compact" => {
            benchmark_compact(Path::new(binary), Path::new(dataset_dir))
        }
        [_, command, tokenizer_json, dataset_dir] if command == "benchmark-reference" => {
            benchmark_reference(Path::new(tokenizer_json), Path::new(dataset_dir))
        }
        _ => Err("usage: mmbert_pair_tokenizer convert <tokenizer.json> <tokenizer.mmbpe> | parity <tokenizer.json> <tokenizer.mmbpe> <dataset-dir> | benchmark-compact <tokenizer.mmbpe> <dataset-dir> | benchmark-reference <tokenizer.json> <dataset-dir>".into()),
    }
}
