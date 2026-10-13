// SPDX-License-Identifier: GPL-3.0-only
//! Test-time materialization of secret-safe golden recipes.
//!
//! DLP goldens store secret values as `{"gen": "<generator>", "seed": <u64>}` recipes
//! plus a carrier template with `<<secret:N>>` placeholders. This module mirrors
//! `python/patronus_ark/dlp_synth/recipes.py` on the shared spec
//! `python/patronus_ark/dlp_synth/generators.json`: SplitMix64 seeded with the recipe
//! seed, alphabets concatenated from their chunks, literal segments copied,
//! alphabet segments drawing `alphabet[next_u64() % alphabet.len()]` per
//! character, checksum segments (`crc32_base62`, `iso7064_mod11_10`) over the
//! text since the last literal, and encoded segments that build bytes from
//! hex/ASCII/random/alphabet parts and emit them as hex, base64 (padded,
//! optionally wrapped), unpadded base64, base64url, bcrypt radix-64 or
//! Base58Check. The Python module documents the format. Not public API.

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
}

impl SecretRecipe {
    pub fn new(gen: &str, seed: u64) -> Self {
        Self {
            gen: gen.to_owned(),
            seed,
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

fn checksum_length(kind: &str) -> Option<usize> {
    match kind {
        "crc32_base62" => Some(6),
        "iso7064_mod11_10" => Some(1),
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
        match encoded.encode.as_str() {
            "hex" => raw.iter().map(|byte| format!("{byte:02x}")).collect(),
            "base58check" => base58check(&raw),
            "base64url" => radix64(&raw, BASE64URL, false),
            "base64_unpadded" => radix64(&raw, BASE64, false),
            "bcrypt64" => radix64(&raw, BCRYPT64, false),
            _ => {
                let base64 = radix64(&raw, BASE64, true);
                match encoded.wrap {
                    Some(width) => wrap_lines(&base64, width),
                    None => base64,
                }
            }
        }
    }

    pub fn generate(&self, name: &str, seed: u64) -> Result<String, RecipeError> {
        let mut rng = SplitMix64::new(seed);
        let mut value = String::new();
        // Checksums cover the text emitted since the most recent literal.
        let mut since_literal = String::new();
        for segment in &self.generator(name)?.segments {
            let mut part = String::new();
            match segment {
                Segment::Literal(Literal { lit }) => {
                    value.push_str(lit);
                    since_literal.clear();
                    continue;
                }
                Segment::Random(Random { alphabet, len }) => {
                    self.draw(&mut rng, alphabet, *len, &mut part);
                }
                Segment::Checksum(Checksum { checksum }) => match checksum.as_str() {
                    "crc32_base62" => part = crc32_base62(&since_literal),
                    _ => part = iso7064_mod11_10(&since_literal)?,
                },
                Segment::Encoded(encoded) => part = self.encode(encoded, &mut rng),
            }
            value.push_str(&part);
            since_literal.push_str(&part);
        }
        Ok(value)
    }
}

const PLACEHOLDER_OPEN: &str = "<<secret:";
const PLACEHOLDER_CLOSE: &str = ">>";

/// Materialize `template`, returning the text and each secret's half-open
/// Unicode-code-point span, indexed like `secrets`.
pub fn materialize(
    generators: &GeneratorSet,
    template: &str,
    secrets: &[SecretRecipe],
) -> Result<(String, Vec<(usize, usize)>), RecipeError> {
    let mut text = String::with_capacity(template.len());
    let mut spans: Vec<Option<(usize, usize)>> = vec![None; secrets.len()];
    let mut chars = 0;
    let mut rest = template;
    while let Some(open) = rest.find(PLACEHOLDER_OPEN) {
        let (before, after) = rest.split_at(open);
        text.push_str(before);
        chars += before.chars().count();
        let after = &after[PLACEHOLDER_OPEN.len()..];
        let close = after.find(PLACEHOLDER_CLOSE).ok_or_else(|| {
            RecipeError::Template(format!("unterminated placeholder in {template:?}"))
        })?;
        let digits = &after[..close];
        let canonical = !digits.is_empty()
            && digits.bytes().all(|byte| byte.is_ascii_digit())
            && (digits == "0" || !digits.starts_with('0'));
        let index = digits
            .parse::<usize>()
            .ok()
            .filter(|index| canonical && *index < secrets.len())
            .ok_or_else(|| {
                RecipeError::Template(format!("bad placeholder {digits:?} in {template:?}"))
            })?;
        if spans[index].is_some() {
            return Err(RecipeError::Template(format!(
                "placeholder {index} used twice in {template:?}"
            )));
        }
        let recipe = &secrets[index];
        let value = generators.generate(&recipe.gen, recipe.seed)?;
        let length = value.chars().count();
        spans[index] = Some((chars, chars + length));
        text.push_str(&value);
        chars += length;
        rest = &after[close + PLACEHOLDER_CLOSE.len()..];
    }
    text.push_str(rest);
    let spans = spans
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| RecipeError::Template(format!("unused secret in {template:?}")))?;
    if spans.is_empty() {
        return Err(RecipeError::Template(format!(
            "template has no placeholder: {template:?}"
        )));
    }
    Ok((text, spans))
}
