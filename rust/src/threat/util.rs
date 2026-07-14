// SPDX-License-Identifier: AGPL-3.0-only
use super::patterns::{injection_signal_re, sensitive_term_ac};

pub(super) fn text_windows(text: &str, window_bytes: usize) -> impl Iterator<Item = &str> {
    text.split('\n').flat_map(move |paragraph| {
        if paragraph.len() <= window_bytes {
            return vec![paragraph];
        }

        let mut windows = Vec::new();
        let mut start = 0;
        while start < paragraph.len() {
            let mut end = (start + window_bytes).min(paragraph.len());
            while !paragraph.is_char_boundary(end) {
                end -= 1;
            }
            windows.push(&paragraph[start..end]);
            if end == paragraph.len() {
                break;
            }

            start = end.saturating_sub(window_bytes / 3);
            while !paragraph.is_char_boundary(start) {
                start += 1;
            }
        }
        windows
    })
}

pub(super) fn contains_injection_signal(text: &str) -> bool {
    injection_signal_re().is_match(text)
}

pub(super) fn contains_sensitive_term(lower: &str) -> bool {
    sensitive_term_ac().is_match(lower)
}
