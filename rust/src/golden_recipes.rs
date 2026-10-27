// SPDX-License-Identifier: GPL-3.0-only
//! Test-time materialization of secret-safe golden recipes.
//!
//! DLP goldens store secret values as `{"gen": "<generator>", "seed": <u64>}` recipes
//! plus a carrier template with `<<secret:N>>` placeholders. This module mirrors
//! `python/patronus_ark/dlp_synth/recipes.py` on the shared spec
//! `python/patronus_ark/dlp_synth/generators.json`: SplitMix64 seeded with the recipe
//! seed, alphabets concatenated from their chunks, literal segments copied,
//! alphabet segments drawing `alphabet[next_u64() % alphabet.len()]` per
//! character, checksum segments (`crc32_base62`, `iso7064_mod11_10`, `bech32`
//! under the HRP of the last literal) over the text since the last literal, and encoded segments that build bytes from
//! hex/ASCII/random/alphabet parts and emit them as hex, base64 (padded,
//! optionally wrapped), unpadded base64, base64url, bcrypt radix-64 or
//! Base58Check. Placeholders may encode (`<<secret:N|base64>>`, `hex`, `url`,
//! `json`) or split (`<<secret:N[a:b]>>`) the value they insert (golden schema
//! v2). A recipe with `fill` yields the documented example/test variant of the
//! generator's shape for hard negatives (T06). The Python module documents the
//! format. Not public API.

use std::{collections::BTreeMap, fmt, path::Path};

use serde::Deserialize;

/// SplitMix64 (Steele, Lea & Flood 2014), the shared golden PRNG.
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

#[derive(Debug)]
pub enum RecipeError {
    Spec(String),
    UnknownGenerator(String),
    Template(String),
}

impl fmt::Display for RecipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spec(message) => write!(f, "invalid generator spec: {message}"),
            Self::UnknownGenerator(name) => write!(f, "unknown generator {name:?}"),
            Self::Template(message) => write!(f, "invalid template: {message}"),
        }
    }
}

impl std::error::Error for RecipeError {}

/// One secret recipe as stored in a golden row.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRecipe {
    pub gen: String,
    pub seed: u64,
    /// Example/test fill word (`EXAMPLEKEY`, `deadbeef` …) of a hard negative.
    #[serde(default)]
    pub fill: Option<String>,
}

impl SecretRecipe {
    pub fn new(gen: &str, seed: u64) -> Self {
        Self {
            gen: gen.to_owned(),
            seed,
            fill: None,
        }
    }

    /// The example/test variant of `gen` filled with `fill`.
    pub fn filled(gen: &str, seed: u64, fill: &str) -> Self {
        Self {
            fill: Some(fill.to_owned()),
            ..Self::new(gen, seed)
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Literal {
    lit: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Random {
    alphabet: String,
    len: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Checksum {
    checksum: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Encoded {
    encode: String,
    bytes: Vec<BytePart>,
    #[serde(default)]
    wrap: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HexPart {
    hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Utf8Part {
    utf8: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RandomBytes {
    random: usize,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum BytePart {
    Hex(HexPart),
    Utf8(Utf8Part),
    RandomBytes(RandomBytes),
    Chars(Random),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Segment {
    Literal(Literal),
    Random(Random),
    Checksum(Checksum),
    Encoded(Encoded),
}

#[derive(Deserialize)]
struct Generator {
    segments: Vec<Segment>,
}

#[derive(Deserialize)]
struct Spec {
    version: u32,
    prng: String,
    alphabets: BTreeMap<String, Vec<String>>,
    generators: BTreeMap<String, Generator>,
}

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BCRYPT64: &[u8] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const ENCODINGS: &[&str] = &[
    "hex",
    "base64",
    "base64_unpadded",
    "base64url",
    "bcrypt64",
    "base58check",
];

/// Output alphabet of an encoding that a fill word may repeat over (T06).
fn encoded_alphabet(encoding: &str) -> Option<&'static [u8]> {
    match encoding {
        "hex" => Some(b"0123456789abcdef"),
        "base64" | "base64_unpadded" => Some(BASE64),
        "base64url" => Some(BASE64URL),
        "bcrypt64" => Some(BCRYPT64),
        _ => None,
    }
}

/// `word` repeated to `length` characters.
fn repeat_word(word: &str, length: usize) -> String {
    word.chars().cycle().take(length).collect()
}

fn checksum_length(kind: &str) -> Option<usize> {
    match kind {
        "crc32_base62" => Some(6),
        "iso7064_mod11_10" => Some(1),
        "bech32" => Some(6),
        _ => None,
    }
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.is_empty() || !hex.len().is_multiple_of(2) || !hex.is_ascii() {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).ok())
        .collect()
}

/// CRC-32/ISO-HDLC (zlib `crc32`).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn crc32_base62(text: &str) -> String {
    let mut checksum = crc32(text.as_bytes());
    let mut digits = [b'0'; 6];
    for digit in digits.iter_mut().rev() {
        *digit = BASE62[(checksum % 62) as usize];
        checksum /= 62;
    }
    String::from_utf8(digits.to_vec()).expect("base62 is ASCII")
}

fn iso7064_mod11_10(digits: &str) -> Result<String, RecipeError> {
    let mut product = 10;
    for character in digits.chars() {
        let digit = character
            .to_digit(10)
            .ok_or_else(|| RecipeError::Spec(format!("iso7064 input {digits:?} is not numeric")))?;
        let total = match (digit + product) % 10 {
            0 => 10,
            total => total,
        };
        product = 2 * total % 11;
    }
    Ok(((11 - product) % 10).to_string())
}

const BECH32: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// BIP 173 checksum of `data` (Bech32 characters) under the HRP that `literal`
/// ends with (`AGE-SECRET-KEY-1`, `age1`); upper case if `literal` is.
fn bech32_checksum(literal: &str, data: &str) -> Result<String, RecipeError> {
    let hrp = literal
        .strip_suffix('1')
        .filter(|hrp| !hrp.is_empty())
        .ok_or_else(|| {
            RecipeError::Spec(format!(
                "a bech32 checksum needs a preceding literal ending in HRP + '1', got {literal:?}"
            ))
        })?
        .to_ascii_lowercase();
    let mut values: Vec<u32> = hrp.bytes().map(|byte| u32::from(byte >> 5)).collect();
    values.push(0);
    values.extend(hrp.bytes().map(|byte| u32::from(byte & 31)));
    for character in data.bytes() {
        let index = BECH32
            .iter()
            .position(|&symbol| symbol == character.to_ascii_lowercase())
            .ok_or_else(|| {
                RecipeError::Spec(format!("bech32 data {data:?} leaves the Bech32 alphabet"))
            })?;
        values.push(index as u32);
    }
    values.extend([0; 6]);
    const GENERATOR: [u32; 5] = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3];
    let mut check: u32 = 1;
    for value in values {
        let top = check >> 25;
        check = ((check & 0x1FF_FFFF) << 5) ^ value;
        for (bit, generator) in GENERATOR.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                check ^= generator;
            }
        }
    }
    check ^= 1;
    let upper = literal.bytes().any(|byte| byte.is_ascii_uppercase())
        && !literal.bytes().any(|byte| byte.is_ascii_lowercase());
    Ok((0..6)
        .map(|index| {
            let symbol = BECH32[((check >> (5 * (5 - index))) & 31) as usize];
            char::from(if upper {
                symbol.to_ascii_uppercase()
            } else {
                symbol
            })
        })
        .collect())
}

fn base58check(payload: &[u8]) -> String {
    let checksum = ring::digest::digest(
        &ring::digest::SHA256,
        ring::digest::digest(&ring::digest::SHA256, payload).as_ref(),
    );
    let mut raw = payload.to_vec();
    raw.extend_from_slice(&checksum.as_ref()[..4]);
    let leading_zeros = raw.iter().take_while(|byte| **byte == 0).count();
    // Big-endian base-58 digits, built by repeated multiply-add.
    let mut digits: Vec<u8> = Vec::new();
    for byte in &raw {
        let mut carry = u32::from(*byte);
        for digit in digits.iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    std::iter::repeat_n(b'1', leading_zeros)
        .chain(digits.iter().rev().map(|digit| BASE58[*digit as usize]))
        .map(char::from)
        .collect()
}

fn radix64(raw: &[u8], alphabet: &[u8], pad: bool) -> String {
    let mut encoded = String::with_capacity(raw.len().div_ceil(3) * 4);
    for chunk in raw.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..chunk.len() + 1 {
            encoded.push(char::from(
                alphabet[((bits >> (18 - 6 * index)) & 63) as usize],
            ));
        }
        if pad {
            for _ in chunk.len()..3 {
                encoded.push('=');
            }
        }
    }
    encoded
}

fn wrap_lines(encoded: &str, width: usize) -> String {
    encoded
        .as_bytes()
        .chunks(width)
        .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
        .collect::<Vec<_>>()
        .join("\n")
}

impl Encoded {
    fn byte_length(&self) -> usize {
        self.bytes
            .iter()
            .map(|part| match part {
                BytePart::Hex(HexPart { hex }) => hex.len() / 2,
                BytePart::Utf8(Utf8Part { utf8 }) => utf8.len(),
                BytePart::RandomBytes(RandomBytes { random }) => *random,
                BytePart::Chars(Random { len, .. }) => *len,
            })
            .sum()
    }

    fn length(&self) -> usize {
        let size = self.byte_length();
        match self.encode.as_str() {
            "hex" => 2 * size,
            "base64" => {
                let length = size.div_ceil(3) * 4;
                self.wrap
                    .map_or(length, |width| length + length.saturating_sub(1) / width)
            }
            // Constant leading bytes keep the value in one base58 digit range.
            "base58check" => ((size + 4) as f64 * 8.0 / 58f64.log2()).ceil() as usize,
            _ => (size * 4).div_ceil(3),
        }
    }
}

/// Parsed `generators.json`.
pub struct GeneratorSet {
    alphabets: BTreeMap<String, Vec<char>>,
    generators: BTreeMap<String, Generator>,
}

impl GeneratorSet {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RecipeError> {
        let raw = std::fs::read_to_string(path.as_ref())
            .map_err(|error| RecipeError::Spec(error.to_string()))?;
        Self::parse(&raw)
    }

    pub fn parse(raw: &str) -> Result<Self, RecipeError> {
        let spec: Spec =
            serde_json::from_str(raw).map_err(|error| RecipeError::Spec(error.to_string()))?;
        if spec.version != 2 || spec.prng != "splitmix64" {
            return Err(RecipeError::Spec("unsupported version or prng".into()));
        }
        let mut alphabets = BTreeMap::new();
        for (name, chunks) in spec.alphabets {
            let alphabet = chunks.concat();
            let chars = alphabet.chars().collect::<Vec<_>>();
            let unique = chars.iter().collect::<std::collections::BTreeSet<_>>();
            if chars.is_empty() || !alphabet.is_ascii() || unique.len() != chars.len() {
                return Err(RecipeError::Spec(format!(
                    "alphabet {name} must be non-empty, ASCII and duplicate-free"
                )));
            }
            alphabets.insert(name, chars);
        }
        for (name, generator) in &spec.generators {
            for segment in &generator.segments {
                let valid = match segment {
                    Segment::Literal(Literal { lit }) => !lit.is_empty() && lit.is_ascii(),
                    Segment::Random(Random { alphabet, len }) => {
                        *len > 0 && alphabets.contains_key(alphabet)
                    }
                    Segment::Checksum(Checksum { checksum }) => checksum_length(checksum).is_some(),
                    Segment::Encoded(encoded) => Self::valid_encoded(encoded, &alphabets),
                };
                if !valid {
                    return Err(RecipeError::Spec(format!("{name}: invalid segment")));
                }
            }
        }
        Ok(Self {
            alphabets,
            generators: spec.generators,
        })
    }

    fn valid_encoded(encoded: &Encoded, alphabets: &BTreeMap<String, Vec<char>>) -> bool {
        let parts_valid = !encoded.bytes.is_empty()
            && encoded.bytes.iter().all(|part| match part {
                BytePart::Hex(HexPart { hex }) => decode_hex(hex).is_some(),
                BytePart::Utf8(Utf8Part { utf8 }) => !utf8.is_empty() && utf8.is_ascii(),
                BytePart::RandomBytes(RandomBytes { random }) => *random > 0,
                BytePart::Chars(Random { alphabet, len }) => {
                    *len > 0 && alphabets.contains_key(alphabet)
                }
            });
        // Base58Check needs a constant non-zero lead byte for a fixed length.
        let lead_valid = encoded.encode != "base58check"
            || matches!(
                encoded.bytes.first(),
                Some(BytePart::Hex(HexPart { hex })) if decode_hex(hex).is_some_and(|raw| raw[0] != 0)
            );
        let wrap_valid = encoded
            .wrap
            .is_none_or(|width| width > 0 && encoded.encode == "base64");
        parts_valid && lead_valid && wrap_valid && ENCODINGS.contains(&encoded.encode.as_str())
    }

    pub fn names(&self) -> Vec<&str> {
        self.generators.keys().map(String::as_str).collect()
    }

    fn generator(&self, name: &str) -> Result<&Generator, RecipeError> {
        self.generators
            .get(name)
            .ok_or_else(|| RecipeError::UnknownGenerator(name.to_owned()))
    }

    /// Fixed output length in characters (all generators are fixed-length).
    pub fn length(&self, name: &str) -> Result<usize, RecipeError> {
        Ok(self
            .generator(name)?
            .segments
            .iter()
            .map(|segment| match segment {
                Segment::Literal(Literal { lit }) => lit.chars().count(),
                Segment::Random(Random { len, .. }) => *len,
                Segment::Checksum(Checksum { checksum }) => {
                    checksum_length(checksum).expect("validated checksum kind")
                }
                Segment::Encoded(encoded) => encoded.length(),
            })
            .sum())
    }

    fn draw(&self, rng: &mut SplitMix64, alphabet: &str, len: usize, out: &mut String) {
        let alphabet = &self.alphabets[alphabet];
        for _ in 0..len {
            out.push(alphabet[(rng.next_u64() % alphabet.len() as u64) as usize]);
        }
    }

    fn encode(&self, encoded: &Encoded, rng: &mut SplitMix64) -> String {
        let mut raw = Vec::with_capacity(encoded.byte_length());
        for part in &encoded.bytes {
            match part {
                BytePart::Hex(HexPart { hex }) => {
                    raw.extend(decode_hex(hex).expect("validated hex part"));
                }
                BytePart::Utf8(Utf8Part { utf8 }) => raw.extend_from_slice(utf8.as_bytes()),
                BytePart::RandomBytes(RandomBytes { random }) => {
                    raw.extend((0..*random).map(|_| (rng.next_u64() % 256) as u8));
                }
                BytePart::Chars(Random { alphabet, len }) => {
                    let mut chars = String::new();
                    self.draw(rng, alphabet, *len, &mut chars);
                    raw.extend_from_slice(chars.as_bytes());
                }
            }
        }
        Self::encode_raw(encoded, &raw)
    }

    fn encode_raw(encoded: &Encoded, raw: &[u8]) -> String {
        match encoded.encode.as_str() {
            "hex" => raw.iter().map(|byte| format!("{byte:02x}")).collect(),
            "base58check" => base58check(raw),
            "base64url" => radix64(raw, BASE64URL, false),
            "base64_unpadded" => radix64(raw, BASE64, false),
            "bcrypt64" => radix64(raw, BCRYPT64, false),
            _ => {
                let base64 = radix64(raw, BASE64, true);
                match encoded.wrap {
                    Some(width) => wrap_lines(&base64, width),
                    None => base64,
                }
            }
        }
    }

    fn fits(&self, word: &str, alphabet: &str) -> bool {
        let alphabet = &self.alphabets[alphabet];
        word.chars().all(|character| alphabet.contains(&character))
    }

    /// An encoded segment of a fill recipe and whether the fill word went into it.
    fn encode_filled(
        &self,
        encoded: &Encoded,
        rng: &mut SplitMix64,
        fill: &str,
    ) -> Result<(String, bool), RecipeError> {
        if encoded.encode == "base58check" {
            return Err(RecipeError::Template(
                "a fill recipe cannot use Base58Check segments (the check value stays valid)"
                    .into(),
            ));
        }
        let all_random = encoded
            .bytes
            .iter()
            .all(|part| matches!(part, BytePart::RandomBytes(_)));
        let fits_output = encoded_alphabet(&encoded.encode)
            .is_some_and(|alphabet| fill.bytes().all(|byte| alphabet.contains(&byte)));
        if all_random && fits_output {
            let shape = Self::encode_raw(encoded, &vec![0; encoded.byte_length()]);
            let mut characters = fill.chars().cycle();
            let value = shape
                .chars()
                .map(|character| match character {
                    '=' | '\n' => character,
                    _ => characters.next().expect("cycle of a non-empty word"),
                })
                .collect();
            return Ok((value, true));
        }
        let mut raw = Vec::with_capacity(encoded.byte_length());
        let mut filled = false;
        for part in &encoded.bytes {
            match part {
                BytePart::Hex(HexPart { hex }) => {
                    raw.extend(decode_hex(hex).expect("validated hex part"));
                }
                BytePart::Utf8(Utf8Part { utf8 }) => raw.extend_from_slice(utf8.as_bytes()),
                BytePart::RandomBytes(RandomBytes { random }) => {
                    raw.extend_from_slice(repeat_word(fill, *random).as_bytes());
                    filled = true;
                }
                BytePart::Chars(Random { alphabet, len }) if self.fits(fill, alphabet) => {
                    raw.extend_from_slice(repeat_word(fill, *len).as_bytes());
                    filled = true;
                }
                BytePart::Chars(Random { alphabet, len }) => {
                    let mut chars = String::new();
                    self.draw(rng, alphabet, *len, &mut chars);
                    raw.extend_from_slice(chars.as_bytes());
                }
            }
        }
        Ok((Self::encode_raw(encoded, &raw), filled))
    }

    pub fn generate(&self, name: &str, seed: u64) -> Result<String, RecipeError> {
        self.generate_filled(name, seed, None)
    }

    /// Generate `name`, or with `fill` its documented example/test variant:
    /// literals kept, alphabet segments and parts that hold every character of
    /// `fill` repeat it, the others are drawn, check values are zeros (ones if
    /// zeros are valid) and random-only encoded segments repeat `fill` over
    /// their output alphabet (padding and line breaks kept) or encode its bytes.
    pub fn generate_filled(
        &self,
        name: &str,
        seed: u64,
        fill: Option<&str>,
    ) -> Result<String, RecipeError> {
        if let Some(word) = fill {
            if word.is_empty() || !word.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
                return Err(RecipeError::Template(format!(
                    "fill must be a non-empty ASCII alphanumeric word, got {word:?}"
                )));
            }
        }
        let mut rng = SplitMix64::new(seed);
        let mut value = String::new();
        let mut filled = false;
        // Checksums cover the text emitted since the most recent literal.
        let mut since_literal = String::new();
        let mut literal = "";
        for segment in &self.generator(name)?.segments {
            let mut part = String::new();
            match segment {
                Segment::Literal(Literal { lit }) => {
                    value.push_str(lit);
                    since_literal.clear();
                    literal = lit;
                    continue;
                }
                Segment::Random(Random { alphabet, len }) => match fill {
                    Some(word) if self.fits(word, alphabet) => {
                        part = repeat_word(word, *len);
                        filled = true;
                    }
                    _ => self.draw(&mut rng, alphabet, *len, &mut part),
                },
                Segment::Checksum(Checksum { checksum }) => {
                    match checksum.as_str() {
                        "crc32_base62" => part = crc32_base62(&since_literal),
                        "bech32" => part = bech32_checksum(literal, &since_literal)?,
                        _ => part = iso7064_mod11_10(&since_literal)?,
                    }
                    if fill.is_some() {
                        let zeros = "0".repeat(part.len());
                        part = if zeros == part {
                            "1".repeat(part.len())
                        } else {
                            zeros
                        };
                    }
                }
                Segment::Encoded(encoded) => match fill {
                    Some(word) => {
                        let (encoded, filled_segment) =
                            self.encode_filled(encoded, &mut rng, word)?;
                        part = encoded;
                        filled |= filled_segment;
                    }
                    None => part = self.encode(encoded, &mut rng),
                },
            }
            value.push_str(&part);
            since_literal.push_str(&part);
        }
        if let Some(word) = fill.filter(|_| !filled) {
            return Err(RecipeError::Template(format!(
                "fill {word:?} fits no segment of {name}"
            )));
        }
        Ok(value)
    }
}

const PLACEHOLDER_OPEN: &str = "<<secret:";
const PLACEHOLDER_CLOSE: &str = ">>";

/// One inserted placeholder: code points `start..end` of the text hold part
/// `part` of secret `secret` (0 unless the secret is split), encoded with
/// `encoding` if the placeholder names one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    pub secret: usize,
    pub part: usize,
    pub start: usize,
    pub end: usize,
    pub encoding: Option<String>,
}

enum Placement {
    Whole(Option<String>),
    Slice(usize, usize),
}

/// Canonical non-negative decimal (no sign, no leading zeros).
fn parse_index(digits: &str) -> Option<usize> {
    let canonical = !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'));
    digits.parse().ok().filter(|_| canonical)
}

fn parse_placeholder(body: &str) -> Option<(usize, Placement)> {
    if let Some((index, encoding)) = body.split_once('|') {
        let valid = !encoding.is_empty()
            && encoding
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
        if !valid {
            return None;
        }
        return Some((parse_index(index)?, Placement::Whole(Some(encoding.into()))));
    }
    if let Some((index, range)) = body.split_once('[') {
        let (start, end) = range.strip_suffix(']')?.split_once(':')?;
        let placement = Placement::Slice(parse_index(start)?, parse_index(end)?);
        return Some((parse_index(index)?, placement));
    }
    Some((parse_index(body)?, Placement::Whole(None)))
}

/// Encode `value` like a `<<secret:N|encoding>>` placeholder.
pub fn transform(value: &str, encoding: &str) -> Result<String, RecipeError> {
    let raw = value.as_bytes();
    Ok(match encoding {
        "base64" => radix64(raw, BASE64, true),
        "hex" => raw.iter().map(|byte| format!("{byte:02x}")).collect(),
        "url" => raw
            .iter()
            .map(|&byte| match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    char::from(byte).to_string()
                }
                _ => format!("%{byte:02X}"),
            })
            .collect(),
        "json" => value
            .chars()
            .map(|character| match character {
                '"' => "\\\"".into(),
                '\\' => "\\\\".into(),
                '\n' => "\\n".into(),
                '\r' => "\\r".into(),
                '\t' => "\\t".into(),
                '\u{8}' => "\\b".into(),
                '\u{c}' => "\\f".into(),
                control if u32::from(control) < 0x20 => {
                    format!("\\u{:04x}", u32::from(control))
                }
                other => other.to_string(),
            })
            .collect(),
        other => {
            return Err(RecipeError::Template(format!(
                "unknown placeholder encoding {other:?}"
            )))
        }
    })
}

/// Materialize `template`, returning the text and every inserted fragment in
/// text order, with half-open Unicode-code-point offsets.
pub fn materialize_fragments(
    generators: &GeneratorSet,
    template: &str,
    secrets: &[SecretRecipe],
) -> Result<(String, Vec<Fragment>), RecipeError> {
    let bad = |message: String| RecipeError::Template(format!("{message} in {template:?}"));
    let mut pieces = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find(PLACEHOLDER_OPEN) {
        let (before, after) = rest.split_at(open);
        let after = &after[PLACEHOLDER_OPEN.len()..];
        let close = after
            .find(PLACEHOLDER_CLOSE)
            .ok_or_else(|| bad("unterminated placeholder".into()))?;
        let (index, placement) = parse_placeholder(&after[..close])
            .filter(|(index, _)| *index < secrets.len())
            .ok_or_else(|| bad(format!("bad placeholder {:?}", &after[..close])))?;
        pieces.push((before, index, placement));
        rest = &after[close + PLACEHOLDER_CLOSE.len()..];
    }
    if pieces.is_empty() {
        return Err(bad("no placeholder".into()));
    }
    let mut values = Vec::with_capacity(secrets.len());
    for (index, recipe) in secrets.iter().enumerate() {
        let value = generators.generate_filled(&recipe.gen, recipe.seed, recipe.fill.as_deref())?;
        let uses = pieces
            .iter()
            .filter(|(_, used, _)| *used == index)
            .map(|(_, _, placement)| placement)
            .collect::<Vec<_>>();
        let slices = uses
            .iter()
            .filter_map(|placement| match placement {
                Placement::Slice(start, end) => Some((*start, *end)),
                Placement::Whole(_) => None,
            })
            .collect::<Vec<_>>();
        let valid = if slices.is_empty() {
            uses.len() == 1
        } else {
            let mut cursor = 0;
            let ordered = slices.iter().all(|&(start, end)| {
                let next = start == cursor && start < end;
                cursor = end;
                next
            });
            slices.len() == uses.len()
                && slices.len() >= 2
                && ordered
                && cursor == value.chars().count()
        };
        if !valid {
            return Err(bad(format!(
                "secret {index} must be used once or split in order"
            )));
        }
        values.push(value);
    }
    let mut text = String::with_capacity(template.len());
    let mut fragments = Vec::with_capacity(pieces.len());
    let mut parts = vec![0; secrets.len()];
    let mut chars = 0;
    for (before, index, placement) in pieces {
        text.push_str(before);
        chars += before.chars().count();
        let value = &values[index];
        let (inserted, encoding) = match placement {
            Placement::Slice(start, end) => (
                value
                    .chars()
                    .skip(start)
                    .take(end - start)
                    .collect::<String>(),
                None,
            ),
            Placement::Whole(None) => (value.clone(), None),
            Placement::Whole(Some(encoding)) => {
                let encoded = transform(value, &encoding)?;
                if &encoded == value {
                    return Err(bad(format!(
                        "encoding {encoding:?} leaves secret {index} unchanged"
                    )));
                }
                (encoded, Some(encoding))
            }
        };
        let length = inserted.chars().count();
        fragments.push(Fragment {
            secret: index,
            part: parts[index],
            start: chars,
            end: chars + length,
            encoding,
        });
        parts[index] += 1;
        text.push_str(&inserted);
        chars += length;
    }
    text.push_str(rest);
    Ok((text, fragments))
}

/// Materialize `template`, returning the text and each secret's half-open
/// Unicode-code-point span, indexed like `secrets`. Split secrets have no single
/// span; use [`materialize_fragments`] for them.
pub fn materialize(
    generators: &GeneratorSet,
    template: &str,
    secrets: &[SecretRecipe],
) -> Result<(String, Vec<(usize, usize)>), RecipeError> {
    let (text, fragments) = materialize_fragments(generators, template, secrets)?;
    if fragments.iter().any(|fragment| fragment.part > 0) {
        return Err(RecipeError::Template(format!(
            "template splits a secret, use materialize_fragments: {template:?}"
        )));
    }
    let mut spans = vec![(0, 0); secrets.len()];
    for fragment in fragments {
        spans[fragment.secret] = (fragment.start, fragment.end);
    }
    Ok((text, spans))
}

#[cfg(test)]
mod tests {
    use super::bech32_checksum;

    #[test]
    fn bech32_checksum_matches_the_bip173_vectors() {
        // BIP 173 valid strings: "A12UEL5L" and "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw".
        assert_eq!(bech32_checksum("A1", "").unwrap(), "2UEL5L");
        assert_eq!(
            bech32_checksum("abcdef1", "qpzry9x8gf2tvdw0s3jn54khce6mua7l").unwrap(),
            "mqqqxw"
        );
        assert!(bech32_checksum("age", "qq").is_err());
        assert!(bech32_checksum("age1", "qb").is_err());
    }
}
