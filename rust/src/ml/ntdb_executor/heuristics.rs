// SPDX-License-Identifier: GPL-3.0-only
use std::collections::HashMap;

const SPECIAL_CHARS: &str = "{}[]<>/\\;|=$`'\"#@%^&*~:";
const CODE_CHARS: &str = "{}[]<>;$=";

pub fn local_text_heuristics(text: &str, token_ids: &[u32]) -> [f32; 11] {
    let char_count = text.chars().count();
    let token_count = token_ids.len();
    let (mean_id, std_id, max_id) = token_id_stats(token_ids);

    [
        ((char_count as f32).ln_1p() / 8.0).min(1.0),
        ((token_count as f32).ln_1p() / 6.0).min(1.0),
        shannon_entropy(text) / 8.0,
        ratio(count_special(text), char_count),
        ratio(
            text.chars().filter(|c| (*c as u32) > 127).count(),
            char_count,
        ),
        ratio(
            text.chars().filter(|c| c.is_ascii_uppercase()).count(),
            char_count,
        ),
        mean_id / 250000.0,
        std_id / 250000.0,
        max_id / 250000.0,
        ratio(count_code(text), char_count),
        ratio(count_digits(text), char_count),
    ]
}

#[allow(clippy::too_many_arguments)]
pub fn global_text_heuristics(
    text: &str,
    token_ids: &[u32],
    chunk_count: usize,
    mean_local_entropy: f32,
    max_local_entropy: f32,
    mean_head_disagreement: f32,
    max_head_disagreement: f32,
    l2_proxy_score: f32,
) -> [f32; 18] {
    let char_count = text.chars().count();
    let (mean_id, std_id, max_id) = token_id_stats(token_ids);

    [
        ((char_count as f32).ln_1p() / 10.0).min(1.0),
        ((chunk_count as f32).ln_1p() / 4.0).min(1.0),
        shannon_entropy(text) / 8.0,
        ratio(count_special(text), char_count),
        ratio(
            text.chars().filter(|c| (*c as u32) > 127).count(),
            char_count,
        ),
        ratio(
            text.chars().filter(|c| c.is_ascii_uppercase()).count(),
            char_count,
        ),
        mean_local_entropy.clamp(0.0, 1.0),
        max_local_entropy.clamp(0.0, 1.0),
        mean_head_disagreement.clamp(0.0, 1.0),
        max_head_disagreement.clamp(0.0, 1.0),
        l2_proxy_score.clamp(0.0, 1.0),
        (1.0 - ((l2_proxy_score - 0.5).abs() * 2.0).min(1.0)).clamp(0.0, 1.0),
        if chunk_count <= 1 { 1.0 } else { 0.0 },
        mean_id / 250000.0,
        std_id / 250000.0,
        max_id / 250000.0,
        ratio(count_code(text), char_count),
        ratio(count_digits(text), char_count),
    ]
}

fn shannon_entropy(text: &str) -> f32 {
    if text.is_empty() {
        return 0.0;
    }
    let mut counts = HashMap::<char, usize>::new();
    for ch in text.chars() {
        *counts.entry(ch).or_insert(0) += 1;
    }
    let total = text.chars().count() as f32;
    let entropy = counts.values().fold(0.0, |acc, count| {
        let p = *count as f32 / total;
        acc - p * p.log2()
    });
    entropy.min(8.0)
}

fn count_special(text: &str) -> usize {
    text.chars().filter(|c| SPECIAL_CHARS.contains(*c)).count()
}

fn count_code(text: &str) -> usize {
    text.chars().filter(|c| CODE_CHARS.contains(*c)).count()
}

fn count_digits(text: &str) -> usize {
    text.chars().filter(|c| c.is_ascii_digit()).count()
}

fn ratio(numerator: usize, denominator: usize) -> f32 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f32 / denominator as f32
    }
}

fn token_id_stats(token_ids: &[u32]) -> (f32, f32, f32) {
    if token_ids.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    let n = token_ids.len() as f32;
    let sum: f64 = token_ids.iter().map(|&x| x as f64).sum();
    let mean = (sum / n as f64) as f32;

    let variance: f64 = token_ids
        .iter()
        .map(|&x| {
            let diff = x as f32 - mean;
            (diff * diff) as f64
        })
        .sum();
    let std = if token_ids.len() > 1 {
        (variance / token_ids.len() as f64).sqrt() as f32
    } else {
        0.0
    };

    let max = token_ids.iter().copied().max().unwrap_or(0) as f32;
    (mean, std, max)
}
