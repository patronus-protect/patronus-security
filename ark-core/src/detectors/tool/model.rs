// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tool-call model: featurizer -> TF-IDF (presence tokens and `char_wb`
//! n-grams, sublinear tf, l2 per block, as scikit-learn) -> all linear heads
//! in one pass over the active weight rows. Softmax heads (`paw`, `sight`,
//! `sight_group`) give one label; sigmoid heads (`sinks:<label>`,
//! `sources:<label>`) are on at their calibrated threshold.
//!
//! A release is a bundle directory ([`crate::detectors::facts_common::bundle`]):
//! `manifest.json`, `model.json` (vocabularies, idf, heads, thresholds,
//! feature switches) and `weights.bin` (little-endian f32,
//! `[n_features][n_outputs]`), written by the reference `export.py`.

use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasherDefault, Hasher};
use std::path::Path;

use serde_json::Value;

use super::featurize::{featurize, Opts};
use super::json::Json;
use crate::detectors::facts_common::block::BlockFile;
use crate::detectors::facts_common::bundle::VerifiedBundle;

/// FNV-1a: short keys, no DoS concern, much cheaper than SipHash for the
/// ~2k lookups of one item.
#[derive(Default)]
struct Fnv(u64);

impl Hasher for Fnv {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut h = if self.0 == 0 {
            0xcbf29ce484222325
        } else {
            self.0
        };
        for b in bytes {
            h = (h ^ *b as u64).wrapping_mul(0x100000001b3);
        }
        self.0 = h;
    }
}

type FMap<V> = HashMap<String, V, BuildHasherDefault<Fnv>>;

struct Head {
    name: String,
    softmax: bool,
    offset: usize,
    classes: Vec<String>,
    threshold: f32,
}

/// The labels of one call: what the facts and policies read from the model.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ModelLabels {
    pub paw: Option<String>,
    pub sight: Option<String>,
    pub sinks: Vec<String>,
    pub sources: Vec<String>,
}

/// The model's output for one item: the labels and the probability of every
/// head (the chosen class of a softmax head, the sigmoid of a binary head).
#[derive(Clone, Debug, PartialEq)]
pub struct ModelOutput {
    pub labels: ModelLabels,
    pub p: BTreeMap<String, f32>,
}

/// A loaded tool-call model.
pub struct ToolModel {
    tok: FMap<u32>,
    tok_idf: Vec<f32>,
    chr: FMap<u32>,
    chr_idf: Vec<f32>,
    ngram: (usize, usize),
    n_out: usize,
    bias: Vec<f32>,
    w: Vec<f32>,
    heads: Vec<Head>,
    opts: Opts,
}

fn field<'a>(m: &'a Value, key: &str) -> Result<&'a Value, String> {
    m.get(key)
        .ok_or_else(|| format!("model.json: missing {key}"))
}

fn vocab(v: &Value, key: &str) -> Result<FMap<u32>, String> {
    let list = v
        .as_array()
        .ok_or_else(|| format!("model.json: {key} is not a list"))?;
    list.iter()
        .enumerate()
        .map(|(i, t)| {
            t.as_str()
                .map(|t| (t.to_string(), i as u32))
                .ok_or_else(|| format!("model.json: {key} holds a non-string"))
        })
        .collect()
}

fn floats(v: &Value, key: &str) -> Result<Vec<f32>, String> {
    let list = v
        .as_array()
        .ok_or_else(|| format!("model.json: {key} is not a list"))?;
    list.iter()
        .map(|x| {
            x.as_f64()
                .map(|f| f as f32)
                .ok_or_else(|| format!("model.json: {key} holds a non-number"))
        })
        .collect()
}

fn count(v: &Value, key: &str) -> Result<usize, String> {
    v.as_u64()
        .map(|n| n as usize)
        .ok_or_else(|| format!("model.json: {key} is not a count"))
}

fn push_block(
    x: &mut Vec<(u32, f32)>,
    counts: &HashMap<u32, u32, BuildHasherDefault<Fnv>>,
    idf: &[f32],
    base: u32,
) {
    let start = x.len();
    let mut norm = 0.0f32;
    for (&i, &c) in counts {
        let v = (1.0 + (c as f32).ln()) * idf[i as usize];
        norm += v * v;
        x.push((base + i, v));
    }
    let norm = norm.sqrt();
    if norm > 0.0 {
        x[start..].iter_mut().for_each(|e| e.1 /= norm);
    }
}

impl ToolModel {
    /// Load the release in `dir`; `manifest_sha256` pins its manifest.
    pub fn load(dir: &Path, manifest_sha256: Option<&str>) -> Result<Self, String> {
        let bundle = VerifiedBundle::open(dir, manifest_sha256)?;
        let m: Value = serde_json::from_slice(&bundle.read("model.json")?)
            .map_err(|error| format!("model.json: {error}"))?;
        let bytes = bundle.read("weights.bin")?;
        Self::from_parts(&m, &bytes)
    }

    /// The model of a `tool-call` block: `config` metadata (vocabularies,
    /// heads, n-gram range, feature switches) and the tensors `weights`
    /// (`[n_features, n_outputs]`), `intercepts`, `tok_idf`, `char_idf`.
    pub fn from_block(block: &BlockFile) -> Result<Self, String> {
        block.require_kind("tool-call")?;
        let mut m: Value = serde_json::from_str(block.meta("config")?)
            .map_err(|error| format!("block config: {error}"))?;
        for key in ["intercepts", "tok_idf", "char_idf"] {
            let (values, _) = block.f32s(key)?;
            m[key] = Value::from(values.into_iter().map(f64::from).collect::<Vec<_>>());
        }
        let (weights, shape) = block.f32s("weights")?;
        if shape.len() != 2 || shape[1] != m["n_outputs"].as_u64().unwrap_or(0) as usize {
            return Err(format!("block weights have shape {shape:?}"));
        }
        let bytes: Vec<u8> = weights.iter().flat_map(|w| w.to_le_bytes()).collect();
        Self::from_parts(&m, &bytes)
    }

    /// A model from the parsed `model.json` and the bytes of `weights.bin`.
    pub fn from_parts(m: &Value, weights: &[u8]) -> Result<Self, String> {
        let w: Vec<f32> = weights
            .as_chunks::<4>()
            .0
            .iter()
            .map(|b| f32::from_le_bytes(*b))
            .collect();
        let heads = field(m, "heads")?
            .as_array()
            .ok_or("model.json: heads is not a list")?
            .iter()
            .map(|h| {
                Ok(Head {
                    name: h["name"]
                        .as_str()
                        .ok_or("model.json: head without name")?
                        .into(),
                    softmax: h["kind"] == "softmax",
                    offset: count(&h["offset"], "offset")?,
                    classes: h["classes"].as_array().map_or(Vec::new(), |c| {
                        c.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    }),
                    threshold: h["threshold"].as_f64().unwrap_or(0.5) as f32,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let ngram = field(m, "char_ngram")?;
        let features = field(m, "features")?;
        let model = Self {
            tok: vocab(field(m, "tok_vocab")?, "tok_vocab")?,
            tok_idf: floats(field(m, "tok_idf")?, "tok_idf")?,
            chr: vocab(field(m, "char_vocab")?, "char_vocab")?,
            chr_idf: floats(field(m, "char_idf")?, "char_idf")?,
            ngram: (
                count(&ngram[0], "char_ngram")?,
                count(&ngram[1], "char_ngram")?,
            ),
            n_out: count(field(m, "n_outputs")?, "n_outputs")?,
            bias: floats(field(m, "intercepts")?, "intercepts")?,
            w,
            heads,
            opts: Opts {
                facts: features["facts"] == true,
                verbs: features["verbs"] == true,
            },
        };
        let n_features = model.tok.len() + model.chr.len();
        if model.w.len() != n_features * model.n_out
            || model.bias.len() != model.n_out
            || model.tok_idf.len() != model.tok.len()
            || model.chr_idf.len() != model.chr.len()
        {
            return Err(format!(
                "weights.bin holds {} values, model.json needs {n_features} x {}",
                model.w.len(),
                model.n_out
            ));
        }
        if let Some(h) = model.heads.iter().find(|h| {
            h.offset + h.classes.len().max(1) > model.n_out || (h.softmax && h.classes.is_empty())
        }) {
            return Err(format!("model.json: head {} is out of range", h.name));
        }
        Ok(model)
    }

    /// Sparse TF-IDF vector as (feature index, value), both blocks
    /// l2-normalised separately like scikit-learn.
    fn vectorize(&self, toks: &[String], text: &str) -> Vec<(u32, f32)> {
        let mut x = Vec::with_capacity(512);
        let mut counts: HashMap<u32, u32, BuildHasherDefault<Fnv>> = HashMap::default();
        for t in toks {
            if let Some(&i) = self.tok.get(t.as_str()) {
                *counts.entry(i).or_insert(0) += 1;
            }
        }
        push_block(&mut x, &counts, &self.tok_idf, 0);
        counts.clear();
        // char_wb: lowercase, split on whitespace, pad each word with one space, n-grams per word
        let lower = text.to_lowercase();
        let mut buf = String::new();
        for word in lower.split_whitespace() {
            let w: Vec<char> = std::iter::once(' ')
                .chain(word.chars())
                .chain(std::iter::once(' '))
                .collect();
            for n in self.ngram.0..=self.ngram.1 {
                let mut off = 0;
                loop {
                    buf.clear();
                    buf.extend(&w[off..(off + n).min(w.len())]);
                    if let Some(&i) = self.chr.get(buf.as_str()) {
                        *counts.entry(i).or_insert(0) += 1;
                    }
                    if off + n >= w.len() {
                        break;
                    }
                    off += 1;
                }
                if off == 0 {
                    break; // a short word is counted once, not again for larger n
                }
            }
        }
        push_block(&mut x, &counts, &self.chr_idf, self.tok.len() as u32);
        x
    }

    /// Every output: softmax per softmax head, sigmoid per binary head.
    fn scores(&self, x: &[(u32, f32)]) -> Vec<f32> {
        let mut z = self.bias.clone();
        for &(j, v) in x {
            let row = &self.w[j as usize * self.n_out..(j as usize + 1) * self.n_out];
            for (zo, wo) in z.iter_mut().zip(row) {
                *zo += v * wo;
            }
        }
        for h in &self.heads {
            if h.softmax {
                let s = &mut z[h.offset..h.offset + h.classes.len()];
                let mx = s.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
                let mut sum = 0.0;
                for v in s.iter_mut() {
                    *v = (*v - mx).exp();
                    sum += *v;
                }
                s.iter_mut().for_each(|v| *v /= sum);
            } else {
                z[h.offset] = 1.0 / (1.0 + (-z[h.offset]).exp());
            }
        }
        z
    }

    /// The raw outputs of a rendered item (`featurize`'s input).
    pub fn raw_scores(&self, item: &Json) -> Vec<f32> {
        let (toks, text) = featurize(item, self.opts);
        self.scores(&self.vectorize(&toks, &text))
    }

    /// Labels and probabilities from the raw outputs.
    pub fn decide(&self, z: &[f32]) -> ModelOutput {
        let mut labels = ModelLabels::default();
        let mut p = BTreeMap::new();
        for h in &self.heads {
            if h.softmax {
                let s = &z[h.offset..h.offset + h.classes.len()];
                let best = (0..s.len())
                    .max_by(|&a, &b| s[a].total_cmp(&s[b]))
                    .unwrap_or(0);
                p.insert(h.name.clone(), s[best]);
                let label = Some(h.classes[best].clone());
                match h.name.as_str() {
                    "paw" => labels.paw = label,
                    "sight" => labels.sight = label,
                    _ => {}
                }
            } else {
                p.insert(h.name.clone(), z[h.offset]);
                if z[h.offset] >= h.threshold {
                    match h.name.split_once(':') {
                        Some(("sinks", lab)) => labels.sinks.push(lab.to_string()),
                        Some(("sources", lab)) => labels.sources.push(lab.to_string()),
                        _ => {}
                    }
                }
            }
        }
        ModelOutput { labels, p }
    }

    /// The model's output for a rendered item.
    pub fn predict(&self, item: &Json) -> ModelOutput {
        self.decide(&self.raw_scores(item))
    }

    /// Number of features and outputs.
    pub fn shape(&self) -> (usize, usize) {
        (self.tok.len() + self.chr.len(), self.n_out)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn tiny_model_scores_and_decides() {
        // one token feature, one char feature; outputs: paw (2 classes), sinks:message
        let m = json!({
            "tok_vocab": ["N:send"], "tok_idf": [1.0], "char_vocab": [" se"], "char_idf": [1.0],
            "char_ngram": [3, 3], "n_outputs": 3, "intercepts": [0.0, 0.0, -1.0],
            "features": {"facts": false, "verbs": false},
            "heads": [{"name": "paw", "kind": "softmax", "offset": 0, "classes": ["read", "send"]},
                      {"name": "sinks:message", "kind": "sigmoid", "offset": 2, "threshold": 0.5}]
        });
        let w: Vec<f32> = vec![0.0, 4.0, 3.0, 0.0, 0.0, 0.0];
        let bytes: Vec<u8> = w.iter().flat_map(|f| f.to_le_bytes()).collect();
        let model = ToolModel::from_parts(&m, &bytes).unwrap();
        let out = model.predict(
            &Json::parse(r#"{"kind": "tool_call", "tool": "send", "arguments": "{}"}"#).unwrap(),
        );
        assert_eq!(out.labels.paw.as_deref(), Some("send"));
        assert_eq!(out.labels.sinks, ["message"]);
        assert!(ToolModel::from_parts(&m, &bytes[..8]).is_err());
    }
}
