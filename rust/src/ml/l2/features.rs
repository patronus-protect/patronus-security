use std::collections::HashSet;

pub(super) fn extract_ngrams(tokens: &[&str], min_n: usize, max_n: usize) -> Vec<String> {
    let mut ngrams = Vec::new();
    let len = tokens.len();
    for n in min_n..=max_n {
        if len >= n {
            for i in 0..=(len - n) {
                let ngram = tokens[i..i + n].join(" ");
                ngrams.push(ngram);
            }
        }
    }
    ngrams
}

pub(super) fn extract_char_ngrams(text: &str, min_n: usize, max_n: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut ngrams = Vec::new();
    for n in min_n..=max_n {
        if len >= n {
            for i in 0..=(len - n) {
                let ngram: String = chars[i..i + n].iter().collect();
                ngrams.push(ngram);
            }
        }
    }
    ngrams
}

pub(super) fn extract_handcrafted_features(text: &str) -> Vec<f64> {
    let t = text;
    let n = t.len().max(1) as f64;

    let words: Vec<&str> = t.split_whitespace().collect();
    let nw = words.len().max(1) as f64;

    let sentence_split: Vec<&str> = t.split(|c| c == '.' || c == '!' || c == '?').collect();
    let sentences: Vec<&str> = sentence_split
        .into_iter()
        .filter(|s| !s.trim().is_empty())
        .collect();
    let n_sentences = sentences.len().max(1) as f64;

    let mut alpha = 0.0f64;
    let mut digits = 0.0f64;
    let mut upper = 0.0f64;
    let mut special = 0.0f64;
    let mut non_ascii = 0.0f64;
    let mut punct = 0.0f64;

    let punct_chars = ".!?,;:\"'()[]{}\u{2013}\u{2014}";

    let chars: Vec<char> = t.chars().collect();
    let mut unique_chars_set = HashSet::new();
    for &c in &chars {
        unique_chars_set.insert(c);
        if c.is_alphabetic() {
            alpha += 1.0;
        }
        if c.is_ascii_digit() {
            digits += 1.0;
        }
        if c.is_uppercase() {
            upper += 1.0;
        }
        if !c.is_alphanumeric() && !c.is_whitespace() {
            special += 1.0;
        }
        if (c as u32) > 127 {
            non_ascii += 1.0;
        }
        if punct_chars.contains(c) {
            punct += 1.0;
        }
    }

    let unique_chars = unique_chars_set.len() as f64;
    let avg_word_len = words.iter().map(|w| w.len()).sum::<usize>() as f64 / nw;

    let mut cjk_count = 0.0;
    for &c in &chars {
        let codepoint = c as u32;
        if (codepoint >= 0x4E00 && codepoint <= 0x9FFF)
            || (codepoint >= 0x3040 && codepoint <= 0x30FF)
            || (codepoint >= 0xAC00 && codepoint <= 0xD7AF)
        {
            cjk_count += 1.0;
        }
    }
    let cjk_ratio = if chars.is_empty() {
        0.0
    } else {
        cjk_count / chars.len() as f64
    };

    let lower = t.to_lowercase();
    let url_count = (lower.matches("http://").count() + lower.matches("https://").count()) as f64;

    vec![
        n.ln_1p(),
        nw,
        avg_word_len,
        unique_chars / n,
        special / n,
        upper / alpha.max(1.0),
        digits / n,
        non_ascii / n,
        cjk_ratio,
        url_count,
        punct / n,
        n_sentences,
        n / n_sentences,
    ]
}
