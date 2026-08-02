// SPDX-License-Identifier: GPL-3.0-only
use std::collections::HashMap;

const SPECIAL_CHARS: &str = "{}[]<>/\\;|=$`'\"#@%^&*~:";
const CODE_CHARS: &str = "{}[]<>;$=";

#[derive(Clone, Copy)]
pub struct SharedGlobalTextHeuristics {
    char_count_log: f32,
    shannon_entropy_norm: f32,
    special_ratio: f32,
    non_ascii_ratio: f32,
    uppercase_ratio: f32,
    token_mean_norm: f32,
    token_std_norm: f32,
    token_max_norm: f32,
    code_ratio: f32,
    digit_ratio: f32,
}

#[derive(Clone, Copy, Default)]
pub struct TokenIdStats {
    count: usize,
    sum: f64,
    sum_squares: f64,
    max: u32,
}

impl TokenIdStats {
    pub fn observe(&mut self, token_id: u32) {
        let value = token_id as f64;
        self.count += 1;
        self.sum += value;
        self.sum_squares += value * value;
        self.max = self.max.max(token_id);
    }

    pub fn observe_all(&mut self, token_ids: &[u32]) {
        for token_id in token_ids {
            self.observe(*token_id);
        }
    }

    fn mean_std_max(self) -> (f32, f32, f32) {
        if self.count == 0 {
            return (0.0, 0.0, 0.0);
        }
        let count = self.count as f64;
        let mean = self.sum / count;
        let variance = if self.count > 1 {
            (self.sum_squares / count) - (mean * mean)
        } else {
            0.0
        };
        (
            mean as f32,
            variance.max(0.0).sqrt() as f32,
            self.max as f32,
        )
    }
}

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

pub fn shared_global_text_heuristics_from_token_stats(
    text: &str,
    token_stats: TokenIdStats,
) -> SharedGlobalTextHeuristics {
    let stats = text_char_stats(text);
    let (mean_id, std_id, max_id) = token_stats.mean_std_max();

    SharedGlobalTextHeuristics {
        char_count_log: ((stats.char_count as f32).ln_1p() / 10.0).min(1.0),
        shannon_entropy_norm: stats.shannon_entropy / 8.0,
        special_ratio: ratio(stats.special_count, stats.char_count),
        non_ascii_ratio: ratio(stats.non_ascii_count, stats.char_count),
        uppercase_ratio: ratio(stats.uppercase_count, stats.char_count),
        token_mean_norm: mean_id / 250000.0,
        token_std_norm: std_id / 250000.0,
        token_max_norm: max_id / 250000.0,
        code_ratio: ratio(stats.code_count, stats.char_count),
        digit_ratio: ratio(stats.digit_count, stats.char_count),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn global_text_heuristics(
    shared: SharedGlobalTextHeuristics,
    chunk_count: usize,
    mean_local_entropy: f32,
    max_local_entropy: f32,
    mean_head_disagreement: f32,
    max_head_disagreement: f32,
    l2_proxy_score: f32,
) -> [f32; 18] {
    [
        shared.char_count_log,
        ((chunk_count as f32).ln_1p() / 4.0).min(1.0),
        shared.shannon_entropy_norm,
        shared.special_ratio,
        shared.non_ascii_ratio,
        shared.uppercase_ratio,
        mean_local_entropy.clamp(0.0, 1.0),
        max_local_entropy.clamp(0.0, 1.0),
        mean_head_disagreement.clamp(0.0, 1.0),
        max_head_disagreement.clamp(0.0, 1.0),
        l2_proxy_score.clamp(0.0, 1.0),
        (1.0 - ((l2_proxy_score - 0.5).abs() * 2.0).min(1.0)).clamp(0.0, 1.0),
        if chunk_count <= 1 { 1.0 } else { 0.0 },
        shared.token_mean_norm,
        shared.token_std_norm,
        shared.token_max_norm,
        shared.code_ratio,
        shared.digit_ratio,
    ]
}

struct TextCharStats {
    char_count: usize,
    shannon_entropy: f32,
    special_count: usize,
    non_ascii_count: usize,
    uppercase_count: usize,
    code_count: usize,
    digit_count: usize,
}

fn text_char_stats(text: &str) -> TextCharStats {
    if text.is_ascii() {
        return ascii_text_char_stats(text.as_bytes());
    }

    let mut counts = HashMap::<char, usize>::new();
    let mut stats = TextCharStats {
        char_count: 0,
        shannon_entropy: 0.0,
        special_count: 0,
        non_ascii_count: 0,
        uppercase_count: 0,
        code_count: 0,
        digit_count: 0,
    };
    for ch in text.chars() {
        stats.char_count += 1;
        *counts.entry(ch).or_insert(0) += 1;
        if SPECIAL_CHARS.contains(ch) {
            stats.special_count += 1;
        }
        if (ch as u32) > 127 {
            stats.non_ascii_count += 1;
        }
        if ch.is_ascii_uppercase() {
            stats.uppercase_count += 1;
        }
        if CODE_CHARS.contains(ch) {
            stats.code_count += 1;
        }
        if ch.is_ascii_digit() {
            stats.digit_count += 1;
        }
    }
    if stats.char_count > 0 {
        let total = stats.char_count as f32;
        stats.shannon_entropy = counts.values().fold(0.0, |acc, count| {
            let p = *count as f32 / total;
            acc - p * p.log2()
        });
        stats.shannon_entropy = stats.shannon_entropy.min(8.0);
    }
    stats
}

fn ascii_text_char_stats(bytes: &[u8]) -> TextCharStats {
    let mut counts = [0usize; 256];
    let mut stats = TextCharStats {
        char_count: bytes.len(),
        shannon_entropy: 0.0,
        special_count: 0,
        non_ascii_count: 0,
        uppercase_count: 0,
        code_count: 0,
        digit_count: 0,
    };
    for byte in bytes {
        counts[*byte as usize] += 1;
        if is_ascii_special(*byte) {
            stats.special_count += 1;
        }
        if byte.is_ascii_uppercase() {
            stats.uppercase_count += 1;
        }
        if is_ascii_code(*byte) {
            stats.code_count += 1;
        }
        if byte.is_ascii_digit() {
            stats.digit_count += 1;
        }
    }
    if stats.char_count > 0 {
        let total = stats.char_count as f32;
        stats.shannon_entropy =
            counts
                .iter()
                .filter(|count| **count > 0)
                .fold(0.0, |acc, count| {
                    let p = *count as f32 / total;
                    acc - p * p.log2()
                });
        stats.shannon_entropy = stats.shannon_entropy.min(8.0);
    }
    stats
}

fn is_ascii_special(byte: u8) -> bool {
    matches!(
        byte,
        b'{' | b'}'
            | b'['
            | b']'
            | b'<'
            | b'>'
            | b'/'
            | b'\\'
            | b';'
            | b'|'
            | b'='
            | b'$'
            | b'`'
            | b'\''
            | b'"'
            | b'#'
            | b'@'
            | b'%'
            | b'^'
            | b'&'
            | b'*'
            | b'~'
            | b':'
    )
}

fn is_ascii_code(byte: u8) -> bool {
    matches!(
        byte,
        b'{' | b'}' | b'[' | b']' | b'<' | b'>' | b';' | b'$' | b'='
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_global_text_stats_count_in_one_pass() {
        let stats = text_char_stats("Aa1{}");

        assert_eq!(stats.char_count, 5);
        assert_eq!(stats.special_count, 2);
        assert_eq!(stats.non_ascii_count, 0);
        assert_eq!(stats.uppercase_count, 1);
        assert_eq!(stats.code_count, 2);
        assert_eq!(stats.digit_count, 1);
        assert!(stats.shannon_entropy > 0.0);
    }
}
