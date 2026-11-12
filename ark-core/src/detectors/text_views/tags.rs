// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded ASCII views of invisible Unicode tag text, preserving source offsets.
//!
//! The tag sequence of a subdivision flag emoji (U+1F3F4, tag letters, U+E007F
//! cancel tag, e.g. the flag of England) is an emoji, not hidden text.
use regex::Regex;
use std::sync::OnceLock;

pub fn views(text: &str) -> impl Iterator<Item = (usize, String)> + '_ {
    static TAGS: OnceLock<Regex> = OnceLock::new();
    TAGS.get_or_init(|| Regex::new(r"[\x{e0020}-\x{e007e}]+").unwrap())
        .find_iter(text)
        .filter(|run| !is_flag_sequence(text, run.range()))
        .flat_map(|run| {
            let mut offset = 0;
            std::iter::from_fn(move || {
                if offset == run.len() {
                    return None;
                }
                // Every tag scalar occupies exactly four UTF-8 bytes. Keep overlap
                // so short instructions spanning a view boundary remain visible.
                let start = offset;
                let end = (start + 4096).min(run.len());
                let decoded = run.as_str()[start..end]
                    .chars()
                    .map(|c| char::from_u32(c as u32 - 0xe0000).unwrap())
                    .collect();
                offset = if end == run.len() { end } else { end - 2048 };
                Some((run.start() + start, decoded))
            })
        })
}

fn is_flag_sequence(text: &str, run: std::ops::Range<usize>) -> bool {
    text[..run.start].ends_with('\u{1F3F4}') && text[run.end..].starts_with('\u{E007F}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subdivision_flags_are_not_hidden_text() {
        let tags = |text: &str| -> String {
            text.chars()
                .map(|c| char::from_u32(c as u32 + 0xe0000).unwrap())
                .collect()
        };
        let flag = format!("\u{1F3F4}{}\u{E007F}", tags("gbeng"));
        assert_eq!(views(&format!("Go {flag}!")).count(), 0);
        let hidden = format!("Go {}!", tags("hidden note"));
        let decoded: Vec<_> = views(&hidden).collect();
        assert_eq!(decoded, vec![(3, "hidden note".to_string())]);
    }
}
