// SPDX-License-Identifier: GPL-3.0-only
use std::{fs, path::Path};

use super::{ntdb_error, NtdbResult};

#[derive(Debug)]
pub struct LightGbmModel {
    trees: Vec<Tree>,
    num_class: usize,
}

#[derive(Debug)]
pub struct Tree {
    split_feature: Vec<usize>,
    threshold: Vec<f64>,
    left_child: Vec<i32>,
    right_child: Vec<i32>,
    leaf_value: Vec<f64>,
}

impl LightGbmModel {
    pub fn load(path: impl AsRef<Path>) -> NtdbResult<Self> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|err| {
            ntdb_error(format!(
                "failed to read LightGBM model {}: {err}",
                path.display()
            ))
        })?;
        let num_class = get_value(&text, "num_class")
            .unwrap_or("1")
            .parse::<usize>()
            .map_err(|err| ntdb_error(format!("invalid LightGBM num_class: {err}")))?;
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
        Ok(Self { trees, num_class })
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
        let num_cat = parse_value::<usize>(block, "num_cat")?;
        if num_cat != 0 {
            return Err(ntdb_error("categorical LightGBM trees are not supported"));
        }
        let is_linear = parse_value::<usize>(block, "is_linear")?;
        if is_linear != 0 {
            return Err(ntdb_error("linear LightGBM trees are not supported"));
        }
        let split_feature = parse_vec::<usize>(block, "split_feature")?;
        let threshold = parse_vec::<f64>(block, "threshold")?;
        let left_child = parse_vec::<i32>(block, "left_child")?;
        let right_child = parse_vec::<i32>(block, "right_child")?;
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
            let feature_value = features.get(feature_index).copied().unwrap_or(0.0) as f64;
            let child = if feature_value <= self.threshold[node] {
                self.left_child[node]
            } else {
                self.right_child[node]
            };
            if child < 0 {
                return (-child - 1) as usize;
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

fn parse_vec<T>(block: &str, key: &str) -> NtdbResult<Vec<T>>
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
