// SPDX-License-Identifier: GPL-3.0-only
//! Bounded ASCII views of invisible Unicode tag text, preserving source offsets.
use regex::Regex;
use std::sync::OnceLock;

pub(crate) fn views(text: &str) -> impl Iterator<Item = (usize, String)> + '_ {
    static TAGS: OnceLock<Regex> = OnceLock::new();
    TAGS.get_or_init(|| Regex::new(r"[\x{e0020}-\x{e007e}]+").unwrap())
        .find_iter(text)
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
