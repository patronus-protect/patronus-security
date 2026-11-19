// SPDX-License-Identifier: GPL-3.0-only
use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{Arc, Mutex},
};

use super::{ntdb_error, NtdbResult};

/// Parsed LightGBM models keyed by the BLAKE3 hash of their file content.
///
/// Packages publish some heads twice under different names (byte-identical
/// files); the store parses and holds each distinct model once, shared across
/// the heads and packages of one loader.
#[derive(Default)]
pub(super) struct LightGbmStore {
    models: Mutex<HashMap<blake3::Hash, Arc<LightGbmModel>>>,
}

impl LightGbmStore {
    pub(super) fn load(&self, path: impl AsRef<Path>) -> NtdbResult<Arc<LightGbmModel>> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|err| {
            ntdb_error(format!(
                "failed to read LightGBM model {}: {err}",
                path.display()
            ))
        })?;
        let key = blake3::hash(text.as_bytes());
        if let Some(model) = self.lock()?.get(&key) {
            return Ok(Arc::clone(model));
        }
        // Parse outside the lock so packages loading in parallel do not wait on
        // each other; a concurrent duplicate parse keeps the first inserted model.
        let model = Arc::new(LightGbmModel::parse(&text)?);
        Ok(Arc::clone(self.lock()?.entry(key).or_insert(model)))
    }

    fn lock(
        &self,
    ) -> NtdbResult<std::sync::MutexGuard<'_, HashMap<blake3::Hash, Arc<LightGbmModel>>>> {
        self.models
            .lock()
            .map_err(|_| ntdb_error("LightGBM model store lock poisoned"))
    }
}

#[derive(Debug, Clone)]
pub struct LightGbmModel {
    trees: Box<[Tree]>,
    num_class: usize,
    feature_count: usize,
}

/// One regression tree in a compact layout: feature indices as `u16` and child
/// links as `i16` (load-time checked); thresholds and leaf values stay `f64` so
/// predictions are bit-identical to the reference LightGBM evaluation.
#[derive(Debug, Clone)]
pub struct Tree {
    split_feature: Box<[u16]>,
    threshold: Box<[f64]>,
    left_child: Box<[i16]>,
    right_child: Box<[i16]>,
    leaf_value: Box<[f64]>,
}

/// Largest tree the `i16` child links can address: leaves are encoded as
/// `-(leaf + 1)`, so leaf indices run down to `i16::MIN`.
const MAX_TREE_LEAVES: usize = i16::MAX as usize + 1;

impl LightGbmModel {
    fn parse(text: &str) -> NtdbResult<Self> {
        let num_class = get_value(text, "num_class")
            .unwrap_or("1")
            .parse::<usize>()
            .map_err(|err| ntdb_error(format!("invalid LightGBM num_class: {err}")))?;
        let feature_count = get_value(text, "max_feature_idx")
            .ok_or_else(|| ntdb_error("LightGBM model is missing max_feature_idx"))?
            .parse::<usize>()
            .map_err(|err| ntdb_error(format!("invalid LightGBM max_feature_idx: {err}")))?
            .saturating_add(1);
        if num_class == 0 {
            return Err(ntdb_error("LightGBM num_class must be positive"));
        }
        if !text.contains("objective=binary sigmoid:1") && !text.contains("objective=multiclass") {
            return Err(ntdb_error(
                "only LightGBM binary sigmoid and multiclass models are supported",
            ));
        }

        let mut trees = Vec::new();
        for block in text.split("\n\n") {
            let block = block.trim_start();
            if block.starts_with("Tree=") {
                trees.push(Tree::parse(block)?);
            }
        }
        if trees.is_empty() {
            return Err(ntdb_error("LightGBM model has no trees"));
        }
        Ok(Self {
            trees: trees.into_boxed_slice(),
            num_class,
            feature_count,
        })
    }

    pub fn feature_count(&self) -> usize {
        self.feature_count
    }

    pub fn predict_probability(&self, features: &[f32]) -> f32 {
        if self.num_class != 1 {
            return self
                .predict_probabilities(features)
                .get(1)
                .copied()
                .unwrap_or(0.0);
        }
        let raw = self
            .trees
            .iter()
            .map(|tree| tree.predict_raw(features))
            .sum::<f64>();
        sigmoid(raw) as f32
    }

    pub fn predict_probabilities(&self, features: &[f32]) -> Vec<f32> {
        if self.num_class == 1 {
            let positive = self.predict_probability(features);
            return vec![1.0 - positive, positive];
        }
        let mut logits = vec![0.0_f64; self.num_class];
        for (tree_index, tree) in self.trees.iter().enumerate() {
            logits[tree_index % self.num_class] += tree.predict_raw(features);
        }
        softmax(&logits)
    }
}

impl Tree {
    pub fn parse(block: &str) -> NtdbResult<Self> {
        let num_leaves = parse_value::<usize>(block, "num_leaves")?;
        if num_leaves == 0 {
            return Err(ntdb_error("LightGBM num_leaves must be positive"));
        }
        if num_leaves > MAX_TREE_LEAVES {
            return Err(ntdb_error(format!(
                "LightGBM trees with more than {MAX_TREE_LEAVES} leaves are not supported"
            )));
        }
        let num_cat = parse_value::<usize>(block, "num_cat")?;
        if num_cat != 0 {
            return Err(ntdb_error("categorical LightGBM trees are not supported"));
        }
        let is_linear = parse_value::<usize>(block, "is_linear")?;
        if is_linear != 0 {
            return Err(ntdb_error("linear LightGBM trees are not supported"));
        }
        // `u16::from_str` rejects indices above 65535, so a model with more
        // features fails to load instead of being evaluated on wrong features.
        let split_feature = parse_vec::<u16>(block, "split_feature")?;
        let threshold = parse_vec::<f64>(block, "threshold")?;
        let left_child = parse_vec::<i16>(block, "left_child")?;
        let right_child = parse_vec::<i16>(block, "right_child")?;
        let leaf_value = parse_vec::<f64>(block, "leaf_value")?;
        let expected_internal_nodes = num_leaves.saturating_sub(1);
        if leaf_value.len() != num_leaves {
            return Err(ntdb_error("LightGBM leaf count does not match num_leaves"));
        }
        for (name, len) in [
            ("split_feature", split_feature.len()),
            ("threshold", threshold.len()),
            ("left_child", left_child.len()),
            ("right_child", right_child.len()),
        ] {
            if len != expected_internal_nodes {
                return Err(ntdb_error(format!(
                    "LightGBM {name} length does not match num_leaves"
                )));
            }
        }
        Ok(Self {
            split_feature,
            threshold,
            left_child,
            right_child,
            leaf_value,
        })
    }

    pub fn predict_raw(&self, features: &[f32]) -> f64 {
        let leaf_index = self.predict_leaf_index(features);
        self.leaf_value.get(leaf_index).copied().unwrap_or(0.0)
    }

    fn predict_leaf_index(&self, features: &[f32]) -> usize {
        if self.split_feature.is_empty() {
            return 0;
        }
        let mut node = 0usize;
        loop {
            let feature_index = self.split_feature[node];
            let feature_value = features
                .get(usize::from(feature_index))
                .copied()
                .unwrap_or(0.0) as f64;
            let child = if feature_value <= self.threshold[node] {
                self.left_child[node]
            } else {
                self.right_child[node]
            };
            if child < 0 {
                return (-1 - i32::from(child)) as usize;
            }
            node = child as usize;
        }
    }
}

fn get_value<'a>(block: &'a str, key: &str) -> Option<&'a str> {
    block.lines().find_map(|line| {
        let (line_key, value) = line.split_once('=')?;
        (line_key == key).then_some(value)
    })
}

fn parse_value<T>(block: &str, key: &str) -> NtdbResult<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    get_value(block, key)
        .ok_or_else(|| ntdb_error(format!("missing LightGBM key {key}")))?
        .parse::<T>()
        .map_err(|err| ntdb_error(format!("invalid LightGBM key {key}: {err}")))
}

fn parse_vec<T>(block: &str, key: &str) -> NtdbResult<Box<[T]>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value =
        get_value(block, key).ok_or_else(|| ntdb_error(format!("missing LightGBM key {key}")))?;
    value
        .split_whitespace()
        .map(|item| {
            item.parse::<T>()
                .map_err(|err| ntdb_error(format!("invalid value in {key}: {item}: {err}")))
        })
        .collect()
}

fn sigmoid(value: f64) -> f64 {
    1.0 / (1.0 + (-value).exp())
}

fn softmax(values: &[f64]) -> Vec<f32> {
    let max_value = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let mut exp_values: Vec<f64> = values
        .iter()
        .map(|value| (value - max_value).exp())
        .collect();
    let denom: f64 = exp_values.iter().sum();
    if denom == 0.0 {
        return vec![0.0; values.len()];
    }
    exp_values
        .drain(..)
        .map(|value| (value / denom) as f32)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stump_model(leaf_value: f64) -> String {
        format!(
            "tree\nnum_class=1\nmax_feature_idx=0\nobjective=binary sigmoid:1\n\n\
             Tree=0\nnum_leaves=1\nnum_cat=0\nsplit_feature=\nthreshold=\nleft_child=\n\
             right_child=\nleaf_value={leaf_value}\nis_linear=0\n\nend of trees\n"
        )
    }

    const SPLIT_TREE: &str = "Tree=0\nnum_leaves=3\nnum_cat=0\nsplit_feature=3453 0\n\
        threshold=0.5 -1\nleft_child=1 -1\nright_child=-3 -2\nleaf_value=1 2 3\nis_linear=0\n";

    #[test]
    fn compact_tree_follows_both_branches() {
        let tree = Tree::parse(SPLIT_TREE).unwrap();
        let mut features = vec![0.0_f32; 3454];
        features[0] = -2.0;
        assert_eq!(tree.predict_raw(&features), 1.0);
        features[0] = 0.0;
        assert_eq!(tree.predict_raw(&features), 2.0);
        features[3453] = 0.75;
        assert_eq!(tree.predict_raw(&features), 3.0);
    }

    #[test]
    fn compact_tree_refuses_indices_beyond_its_integer_types() {
        let wide_feature = SPLIT_TREE.replace("split_feature=3453 0", "split_feature=65536 0");
        assert!(Tree::parse(&wide_feature).is_err());
        let too_many_leaves = SPLIT_TREE.replace("num_leaves=3", "num_leaves=32769");
        let error = Tree::parse(&too_many_leaves).unwrap_err().to_string();
        assert!(error.contains("32768 leaves"), "{error}");
    }

    #[test]
    fn store_shares_byte_identical_models_across_paths() {
        let root = std::env::temp_dir().join(format!("ark-lightgbm-store-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let (first, copy, other) = (root.join("a.txt"), root.join("b.txt"), root.join("c.txt"));
        fs::write(&first, stump_model(0.5)).unwrap();
        fs::write(&copy, stump_model(0.5)).unwrap();
        fs::write(&other, stump_model(-0.5)).unwrap();

        let store = LightGbmStore::default();
        let first = store.load(&first).unwrap();
        let copy = store.load(&copy).unwrap();
        let other = store.load(&other).unwrap();
        fs::remove_dir_all(&root).unwrap();

        assert!(Arc::ptr_eq(&first, &copy));
        assert!(!Arc::ptr_eq(&first, &other));
        assert_eq!(first.predict_probability(&[0.0]), sigmoid(0.5) as f32);
        assert_eq!(other.predict_probability(&[0.0]), sigmoid(-0.5) as f32);
    }
}
