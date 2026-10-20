// SPDX-License-Identifier: GPL-3.0-only
//! Shannon entropy of candidate secret values.

/// Shannon entropy of `value` in bits per character (0 for an empty value).
pub fn shannon_entropy(value: &str) -> f64 {
    let mut ascii = [0usize; 128];
    let mut other = std::collections::HashMap::<char, usize>::new();
    let mut length = 0usize;
    for ch in value.chars() {
        length += 1;
        if ch.is_ascii() {
            ascii[ch as usize] += 1;
        } else {
            *other.entry(ch).or_default() += 1;
        }
    }
    if length == 0 {
        return 0.0;
    }
    let length = length as f64;
    ascii
        .iter()
        .chain(other.values())
        .filter(|count| **count > 0)
        .map(|&count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}
