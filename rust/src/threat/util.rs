#![allow(dead_code)]

use super::patterns::{
    email_address_re, injection_signal_re, secret_transfer_material_re, sensitive_term_ac,
    url_transfer_destination_re,
};

pub(super) fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

pub(super) fn contains_transfer_verb(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "send", "upload", "post", "email", "forward", "leak", "share", "paste", "copy",
        ],
    )
}

pub(super) fn contains_secret_transfer_material(lower: &str) -> bool {
    contains_any(
        lower,
        &[
            "api key",
            "access token",
            "auth token",
            "bearer token",
            "refresh token",
            "secret token",
            "private key",
            "password",
            "credential",
            ".env",
        ],
    ) || secret_transfer_material_re().is_match(lower)
}

pub(super) fn contains_secret_transfer_destination(lower: &str) -> bool {
    contains_any(lower, &["webhook", "attacker", "external", "pastebin"])
        || email_address_re().is_match(lower)
        || url_transfer_destination_re().is_match(lower)
}

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
