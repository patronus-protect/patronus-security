// SPDX-License-Identifier: GPL-3.0-only
//! Test-time materialization of secret-safe golden recipes.
//!
//! DLP goldens store secret values as `{"gen": "<generator>", "seed": <u64>}` recipes
//! plus a carrier template with `<<secret:N>>` placeholders. This module mirrors
//! `python/patronus_ark/dlp_synth/recipes.py` on the shared spec
//! `python/patronus_ark/dlp_synth/generators.json`: SplitMix64 seeded with the recipe
//! seed, alphabets concatenated from their chunks, literal segments copied,
//! alphabet segments drawing
//! `alphabet[next_u64() % alphabet.len()]` per character. Not public API.

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
#[serde(untagged)]
enum Segment {
    Literal(Literal),
    Random(Random),
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
        if spec.version != 1 || spec.prng != "splitmix64" {
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
                    Segment::Literal(Literal { lit }) => lit.is_ascii(),
                    Segment::Random(Random { alphabet, .. }) => alphabets.contains_key(alphabet),
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
            })
            .sum())
    }

    pub fn generate(&self, name: &str, seed: u64) -> Result<String, RecipeError> {
        let mut rng = SplitMix64::new(seed);
        let mut value = String::new();
        for segment in &self.generator(name)?.segments {
            match segment {
                Segment::Literal(Literal { lit }) => value.push_str(lit),
                Segment::Random(Random { alphabet, len }) => {
                    let alphabet = &self.alphabets[alphabet];
                    for _ in 0..*len {
                        value.push(alphabet[(rng.next_u64() % alphabet.len() as u64) as usize]);
                    }
                }
            }
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
