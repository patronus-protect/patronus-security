// SPDX-License-Identifier: GPL-3.0-only
//! Generic credentials: tokens, credential assignments, auth headers,
//! cookies and connection strings.
use crate::detectors::dlp::dlp::DlpPattern;

pub(super) const RULES: &[DlpPattern] = &[
    // ── Generische Credential-Patterns ───────────────────────────────────────
    DlpPattern {
        name: "dlp_jwt_token",
        pattern: r"(?P<anchor_1>ey[a-zA-Z0-9_\-=]{10,}\.){2}[a-zA-Z0-9_\-=]{10,}",
        entity_group: "SECRET_TOKEN",
        validator: None,
        span_group: None,
    },
    DlpPattern {
        name: "dlp_credential_in_url",
        pattern: r#"(?i)[?&](?:password|passwd|passwort|kennwort|secret|geheimnis|token|apikey|api_key|api-key)=([^\\\s&"'\]},]{4,})"#,
        entity_group: "CREDENTIAL",
        validator: Some(is_unredacted_url_credential),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_env_var_secret",
        pattern: r"(?-i:[A-Z][A-Z0-9]*[_\-](?:SECRET(?:[_\-]ACCESS)?[_\-]?KEY|SECRET|PASSWORD|PASSWD|PASSWORT|KENNWORT|GEHEIMNIS|TOKEN|API[_\-]?KEY))\s*=\s*([^\s]{8,})",
        entity_group: "CREDENTIAL",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
    // ── Generic credentials / connection strings ───────────────────────────
    DlpPattern {
        name: "dlp_password_assignment",
        pattern: r#"(?i)\b(?:password|passwort|passwd|kennwort|pwd)\b\s*(?:=|:|\bis\b|\bist\b|\blautet\b)\s*["']?([^\s"';,}\]]{4,150})"#,
        entity_group: "CREDENTIAL",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_generic_credential_assignment",
        pattern: r#"(?i)\b(?:api[ _-]?key|access[ _-]?token|refresh[ _-]?token|auth[ _-]?token|client[ _-]?secret|encryption[ _-]?key|master[ _-]?key|api[ _-]?schl(?:ü|ue)ssel|zugangstoken|geheimnis|verschl(?:ü|ue)sselungsschl(?:ü|ue)ssel|secret|token)\b\s*(?:=|:|\bis\b|\bist\b|\blautet\b)\s*["']?([^\s"';,}\]]{8,150})"#,
        entity_group: "CREDENTIAL",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_bearer_token",
        pattern: r"(?i)\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9._~+/=-]{8,})",
        entity_group: "SECRET_TOKEN",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_basic_auth",
        pattern: r"(?i)\bAuthorization\s*:\s*Basic\s+([A-Za-z0-9+/]{8,}={0,2})",
        entity_group: "CREDENTIAL",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_signed_url_signature",
        pattern: r"(?i)[?&](?:X-Amz-Signature|X-Goog-Signature|Signature|sig)=([A-Fa-f0-9]{16,}|[A-Za-z0-9_~+/%=-]{20,})",
        entity_group: "CREDENTIAL",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_session_cookie",
        pattern: r"(?i)\b(?:Cookie|Set-Cookie)\s*:[^\r\n]{0,200}?\b(?:sessionid|session|JSESSIONID|PHPSESSID)=([A-Za-z0-9._~+/%=-]{8,})",
        entity_group: "CREDENTIAL",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
    DlpPattern {
        name: "dlp_csrf_token",
        pattern: r"(?i)\b(?:X-CSRF-Token|X-XSRF-Token|csrf[ _-]?token|xsrf[ _-]?token)\b\s*(?::|=)?\s*([A-Za-z0-9._~+/%=-]{8,})",
        entity_group: "SECRET_TOKEN",
        validator: Some(is_secret_value),
        span_group: Some(1),
    },
];

/// Runs after `hashes::RULES`, see the registry order in `rules/mod.rs`.
pub(super) const URL_USERINFO_RULES: &[DlpPattern] = &[DlpPattern {
    name: "dlp_url_userinfo_password",
    pattern: r#"(?i)\b(?:jdbc:)?[a-z][a-z0-9+.-]{1,20}://[^/\s:@]+:([^@\s/]{4,150})@[^\s/]+"#,
    entity_group: "CREDENTIAL",
    validator: Some(is_secret_value),
    span_group: Some(1),
}];

fn is_unredacted_url_credential(candidate: &str) -> bool {
    is_secret_value(candidate)
}

/// Shared value check of the credential and hash rules.
pub(super) fn is_secret_value(candidate: &str) -> bool {
    let value = candidate
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase();
    let references_secret_storage = value.contains("getenv(")
        || value.contains("environ.")
        || value.starts_with("process.env.")
        || value.contains("env::var(")
        || value.contains("secret_key_ref");
    let has_multiple_characters = value
        .chars()
        .next()
        .is_some_and(|first| value.chars().any(|character| character != first));
    value.len() >= 4
        && has_multiple_characters
        && !references_secret_storage
        && !matches!(
            value.as_str(),
            "redacted"
                | "[redacted]"
                | "%5bredacted%5d"
                | "changeme"
                | "your-token-here"
                | "replace-me"
                | "your_api_key_here"
        )
        && !value.starts_with("${")
        && !value.starts_with('<')
        && !value.starts_with('[')
}

/// Marker words of documented example and test values, lower case. Long
/// markers are rare in random base62 (about 62^-6 per position); they count at
/// the start or end of a word (`EXAMPLEKEY`, `CYEXAMPLE`, `Musterpasswort`),
/// not inside one (`resampler`).
const LONG_EXAMPLE_MARKERS: &[&str] = &["example", "sample", "beispiel", "muster"];

/// Short markers turn up by chance in random tokens (`…7Test…`); they count
/// only as a whole word or when repeated.
const SHORT_EXAMPLE_MARKERS: &[&str] = &["test", "fake", "dummy"];

/// Values longer than this (alphanumeric characters, i.e. PEM bodies) need a
/// repeated short marker: one whole short word turns up by chance in long base64.
const WHOLE_MARKER_MAX_LEN: usize = 256;

/// Lines above a value that may hold its example context.
const EXAMPLE_CONTEXT_LINES_BEFORE: usize = 3;

/// Share of a value (in per mille of its alphanumeric characters) that repeated
/// chunks, sequential runs and same-character runs must cover.
const LOW_VARIETY_MIN_COVERAGE: usize = 600;

/// Example/test marker check shared by every secret rule (T06): `value` names
/// an example or test value if it holds `EXAMPLE`, `SAMPLE`, `BEISPIEL` or
/// `MUSTER` at the start or end of a word, `TEST`/`TESTKEY`, `FAKE` or `DUMMY`
/// as a whole word, or any marker at least twice. Words end at separators and
/// at case or letter/digit changes (`myTestKey`, `TEST_TOKEN`); a marker merely
/// embedded in a word (`aXtestQ`, `resampler`) does not count. The Stripe mode
/// segment (`sk_test_`) is format, not a marker.
pub(crate) fn has_example_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if LONG_EXAMPLE_MARKERS
        .iter()
        .chain(SHORT_EXAMPLE_MARKERS)
        .any(|marker| lower.matches(marker).count() >= 2)
    {
        return true;
    }
    let whole_short_words =
        value.bytes().filter(u8::is_ascii_alphanumeric).count() <= WHOLE_MARKER_MAX_LEN;
    value_words(value).any(|(start, word)| {
        let word = word.to_ascii_lowercase();
        let stem = word.strip_suffix("key").unwrap_or(&word);
        LONG_EXAMPLE_MARKERS
            .iter()
            .any(|marker| stem.starts_with(marker) || stem.ends_with(marker))
            || (whole_short_words
                && SHORT_EXAMPLE_MARKERS.contains(&stem)
                && !is_stripe_mode(value, start, &word))
    })
}

/// How a value lacks variety (T06), see [`low_variety`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LowVariety {
    /// Random enough.
    No,
    /// Covered only together with sequential runs (`AKIA1234567890ABCDEF`):
    /// a hand-typed demo value as often as a documented one, so it needs
    /// explicit example context even in a fixed provider format.
    Sequential,
    /// Covered by repeated chunks and same-character runs alone.
    Repeated,
}

/// Low-variety check (T06): repeated chunks (`abcabc…`, `deadbeefdeadbeef…`),
/// sequential runs (`1234567890abcdef`) and same-character runs (`000000…`)
/// cover at least 60 % of the value's alphanumeric characters.
#[cfg(test)]
pub(crate) fn is_low_variety(value: &str) -> bool {
    low_variety(value) != LowVariety::No
}

/// [`is_low_variety`] with the kind of coverage. Only a fixed-format provider
/// value ([`LowVariety::Repeated`]) or a value in explicit example context is
/// rejected for this; a generic password such as `abcabcabcabc` stays a secret.
pub(crate) fn low_variety(value: &str) -> LowVariety {
    let (repeated, with_sequential, length) = low_variety_coverage(value);
    let enough = |covered: usize| covered * 1000 >= length * LOW_VARIETY_MIN_COVERAGE;
    if length == 0 {
        LowVariety::No
    } else if enough(repeated) {
        LowVariety::Repeated
    } else if enough(with_sequential) {
        LowVariety::Sequential
    } else {
        LowVariety::No
    }
}

/// Whether any repeated chunk, sequential run or same-character run occurs in
/// `value`: a cheap precondition for a low-variety part of it.
pub(crate) fn has_low_variety_run(value: &str) -> bool {
    low_variety_coverage(value).1 > 0
}

/// Alphanumeric characters of `value` covered by repeated chunks and
/// same-character runs, covered when sequential runs are added, and the
/// number of alphanumeric characters (0 below 8).
fn low_variety_coverage(value: &str) -> (usize, usize, usize) {
    let mut characters = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'\\' {
            // Escaped line breaks (`\n`) of PEM bodies in JSON strings.
            bytes.next();
        } else if byte.is_ascii_alphanumeric() {
            characters.push(byte.to_ascii_lowercase());
        }
    }
    characters.truncate(8192);
    let length = characters.len();
    if length < 8 {
        return (0, 0, 0);
    }
    let mut covered = vec![false; length];
    for period in 1..=64.min(length - 1) {
        // Same-character runs need 8 characters, repeated chunks 6 repeated ones.
        let min_repeated = if period == 1 { 7 } else { 6 };
        let mut index = 0;
        while index + period < length {
            let mut end = index;
            while end + period < length && characters[end] == characters[end + period] {
                end += 1;
            }
            if end - index >= min_repeated {
                covered[index..end + period].fill(true);
            }
            index = end + 1;
        }
    }
    let count = |covered: &[bool]| covered.iter().filter(|covered| **covered).count();
    let repeated = count(&covered);
    let mut start = 0;
    for index in 1..=length {
        let ascending = index < length && {
            let (previous, next) = (characters[index - 1], characters[index]);
            next == previous + 1 || matches!((previous, next), (b'9', b'0' | b'a'))
        };
        if !ascending {
            if index - start >= 6 {
                covered[start..index].fill(true);
            }
            start = index;
        }
    }
    (repeated, count(&covered), length)
}

/// Explicit example/test context (T06): the line of the value or one of the
/// three lines before it (a comment above a config block) calls the value an example, sample, dummy, fake, fixture, mock,
/// placeholder or documentation value (DE: Beispiel…, Muster…, Testdaten,
/// Testwert…, Platzhalter, Dokumentation). Host names such as `example.com`
/// and paths do not count.
pub(crate) fn has_example_context(text: &str, start: usize, end: usize) -> bool {
    let mut window_start = start;
    for _ in 0..=EXAMPLE_CONTEXT_LINES_BEFORE {
        window_start = text[..window_start].rfind('\n').unwrap_or(0);
    }
    let window_end = text[end..]
        .find('\n')
        .map_or(text.len(), |index| end + index);
    let window_start = floor_char_boundary(text, window_start.max(start.saturating_sub(512)));
    let window_end = floor_char_boundary(text, window_end.min(end + 256));
    text[window_start..window_end]
        .split(|character: char| {
            !(character.is_alphanumeric() || matches!(character, '.' | '/' | '@'))
        })
        .map(|word| word.trim_end_matches('.').to_lowercase())
        .any(|word| {
            matches!(
                word.as_str(),
                "example"
                    | "examples"
                    | "sample"
                    | "samples"
                    | "dummy"
                    | "fake"
                    | "fixture"
                    | "fixtures"
                    | "mock"
                    | "placeholder"
                    | "docs"
                    | "documentation"
                    | "dokumentation"
                    | "testdaten"
            ) || ["beispiel", "muster", "testwert", "platzhalter"]
                .iter()
                .any(|prefix| word.starts_with(prefix))
        })
}

/// T06 decision for one match: a marker word rejects every secret rule;
/// repeated-chunk values reject fixed-format rules always, sequential-run values
/// and generic credential rules only in explicit example context.
pub(crate) fn is_example_value(
    value: &str,
    fixed_format: bool,
    example_context: impl FnOnce() -> bool,
) -> bool {
    has_example_marker(value)
        || match low_variety(value) {
            LowVariety::No => false,
            LowVariety::Repeated if fixed_format => true,
            LowVariety::Repeated | LowVariety::Sequential => example_context(),
        }
}

/// Alphanumeric words of `value` with their byte offsets, split at every other
/// character, at lower→upper and letter↔digit changes and before the last
/// capital of an upper-case run that continues in lower case (`AKIATest`).
fn value_words(value: &str) -> impl Iterator<Item = (usize, &str)> {
    #[derive(PartialEq)]
    enum Class {
        Upper,
        Lower,
        Digit,
    }
    fn class(byte: u8) -> Option<Class> {
        match byte {
            b'A'..=b'Z' => Some(Class::Upper),
            b'a'..=b'z' => Some(Class::Lower),
            b'0'..=b'9' => Some(Class::Digit),
            _ => None,
        }
    }
    let bytes = value.as_bytes();
    let mut boundaries = Vec::new();
    let mut word_start = None;
    for (index, &byte) in bytes.iter().enumerate() {
        let Some(current) = class(byte) else {
            if let Some(start) = word_start.take() {
                boundaries.push((start, index));
            }
            continue;
        };
        let Some(start) = word_start else {
            word_start = Some(index);
            continue;
        };
        let previous = class(bytes[index - 1]).expect("inside a word");
        if previous == current {
            continue;
        }
        if previous == Class::Upper && current == Class::Lower {
            if index - start >= 2 {
                boundaries.push((start, index - 1));
                word_start = Some(index - 1);
            }
            continue;
        }
        boundaries.push((start, index));
        word_start = Some(index);
    }
    if let Some(start) = word_start {
        boundaries.push((start, bytes.len()));
    }
    boundaries
        .into_iter()
        .map(move |(start, end)| (start, &value[start..end]))
}

/// `test` in a Stripe key prefix (`sk_test_`, `rk_test_`, `pk_test_`).
fn is_stripe_mode(value: &str, start: usize, word: &str) -> bool {
    word == "test"
        && start >= 3
        && matches!(
            &value.as_bytes()[start - 3..start],
            b"sk_" | b"rk_" | b"pk_" | b"sk-" | b"rk-"
        )
        && matches!(value.as_bytes().get(start + 4), Some(b'_' | b'-'))
        && value.as_bytes()[..start - 3]
            .last()
            .is_none_or(|byte| !byte.is_ascii_alphanumeric())
}

fn floor_char_boundary(text: &str, mut index: usize) -> usize {
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::{
        has_example_context, has_example_marker, is_example_value, is_low_variety, low_variety,
        LowVariety,
    };

    /// Deterministic pseudo-random base62 strings (SplitMix64).
    fn random_base62(seed: u64, length: usize) -> String {
        const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let mut state = seed;
        (0..length)
            .map(|_| {
                state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut mixed = state;
                mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                mixed ^= mixed >> 31;
                BASE62[(mixed % 62) as usize] as char
            })
            .collect()
    }

    #[test]
    fn marker_words_count_as_whole_words_or_long_markers() {
        for value in [
            concat!("AKIA", "IOSFODNN7", "EXAMPLE"),
            concat!("wJalrXUtnFEMI/", "K7MDENG/bPxRfiCY", "EXAMPLEKEY"),
            concat!("sk-ant-api03-", "EXAMPLEKEY", "EXAMPLEKEY"),
            concat!("ghp_", "TESTKEYTESTKEY", "TESTKEYTESTKEY", "000000"),
            concat!("hf_", "testtesttest", "testtest"),
            concat!("xoxb-", "1234-TEST-token"),
            "my_test_token_value",
            "myTestKeyValue42",
            concat!("sk_live_", "DummyValue12345678"),
            "FAKE_SECRET_9f3a1c7e",
            "Musterpasswort2026",
            "beispiel-schluessel-42",
            "sample_api_key_9f3a",
        ] {
            assert!(has_example_marker(value), "{value}");
        }
    }

    #[test]
    fn embedded_short_markers_and_stripe_modes_are_no_markers() {
        for value in [
            "aXtestQ9vLm2Rk7Wp4Zd",
            "q7FAKEm2Rk7Wp4Zd8Ln3",
            "Attestation2026!",
            "Contest-Winner-77",
            concat!("sk_test_", "Zq8Wm4Rk2Tn7", "Vb6Xc9Lp3Hd5Jf1"),
            concat!("rk_test_", "9f3a1c7e4b20", "d86f5ea9c317"),
            "Kx7!pQ2#vL9@rT4$",
            "resampler2026!",
            "Gegenbeispielhaft#77",
            "Ummusterung-Kx7q",
            "Xyzexamples9",
        ] {
            assert!(!has_example_marker(value), "{value}");
        }
    }

    #[test]
    fn long_markers_count_at_word_edges() {
        for value in [
            "Musterpasswort2026",
            "counterexample-2026",
            "Examples4All",
            "resampler-resampler",
        ] {
            assert!(has_example_marker(value), "{value}");
        }
    }

    #[test]
    fn single_sequential_runs_need_example_context() {
        for value in [
            concat!("AKIA", "1234567890", "ABCDEF"),
            concat!("ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "123456"),
            concat!("abcdefghijklmnopqrstuvwxyz", "1234567890", "ABCD"),
        ] {
            assert_eq!(low_variety(value), LowVariety::Sequential, "{value}");
            assert!(!is_example_value(value, true, || false), "{value}");
            assert!(is_example_value(value, true, || true), "{value}");
        }
        for value in [
            concat!("AKIA", "1234567890", "123456"),
            concat!("ghp_", "ABCDEFGH", "ABCDEFGH", "ABCDEFGH", "ABCDEFGH", "ABCD"),
        ] {
            assert_eq!(low_variety(value), LowVariety::Repeated, "{value}");
            assert!(is_example_value(value, true, || false), "{value}");
        }
    }

    #[test]
    fn markers_in_random_base62_do_not_trigger_by_chance() {
        let hits = (0..20_000)
            .filter(|seed| has_example_marker(&random_base62(*seed, 48)))
            .count();
        // A whole short word appears with a chance of about 1e-5 per value.
        assert!(hits <= 2, "{hits} random values carried a marker");
        let long = random_base62(7, 4096);
        assert!(!has_example_marker(&long));
    }

    #[test]
    fn low_variety_covers_repeats_runs_and_fills() {
        for value in [
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "1234567890123456789012345678901234567890",
            concat!(
                "0x",
                "1234567890abcdef",
                "1234567890abcdef",
                "1234567890abcdef",
                "1234567890abcdef"
            ),
            "abcabcabcabc",
            "00000000000000000000",
            concat!("AIza", "aaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaa"),
            concat!(
                "sk-",
                "aB12aB12aB12aB12aB12aB12",
                "aB12aB12aB12aB12aB12aB12"
            ),
            concat!("ASIA", "EXAMPLEKEY", "EXAMPL"),
            concat!(
                "-----BEGIN ",
                "PRIVATE KEY-----",
                "\\nTUlJQkVYQU1QTEVLRVlFWEFNUExFS0VZRVhBTVBMRUtFWUVYQU1QTEVLRVlFWEFNUExFS0VZ\\n"
            ),
        ] {
            assert!(is_low_variety(value), "{value}");
        }
    }

    #[test]
    fn random_values_and_short_repeats_are_not_low_variety() {
        for seed in 0..2_000 {
            let value = random_base62(seed, 40);
            assert!(!is_low_variety(&value), "{value}");
        }
        for value in [
            concat!("ghp_", "Zq7Zq7Zq7Zq7", "Wm4Rk8Tn2Vb6Xc9Lp3Hd5Jf1"),
            "Kx7pQ2vL1234567890abcdefRt4Mw8Zn3Bc6Hs9Jd",
            "s3cr3t",
            "Sommer2026!",
        ] {
            assert!(!is_low_variety(value), "{value}");
        }
    }

    #[test]
    fn example_context_is_explicit_and_ignores_host_names() {
        let text = "# Beispielwert aus der Doku\npassword=abcabcabcabc\n";
        let start = text.find("abc").unwrap();
        assert!(has_example_context(text, start, start + 12));
        let text = "Example config:\napi_key: 1234567890123456\n";
        let start = text.find("1234").unwrap();
        assert!(has_example_context(text, start, start + 16));
        let text = "# fixtures/auth.yaml\ntoken: deadbeefdeadbeef # dummy";
        let start = text.find("dead").unwrap();
        assert!(has_example_context(text, start, start + 16));

        for text in [
            "base_url: https://api.example.com/v2\npassword=abcabcabcabc",
            "see docs/setup.md\nsmtp: mail@example.org\npassword=abcabcabcabc",
            "# example\n\n\n\npassword=abcabcabcabc",
            "Example config:\nhost: db\nport: 5432\nuser: app\npassword=abcabcabcabc",
        ] {
            let start = text.find("abcabc").unwrap();
            assert!(!has_example_context(text, start, start + 12), "{text}");
        }
    }

    #[test]
    fn generic_values_need_context_for_low_variety_but_never_for_markers() {
        assert!(!is_example_value("abcabcabcabc", false, || false));
        assert!(is_example_value("abcabcabcabc", false, || true));
        assert!(is_example_value("abcabcabcabc", true, || false));
        assert!(!is_example_value(
            "Kx7pQ2vL1234567890abcdefRt4Mw8Zn3",
            false,
            || false
        ));
        assert!(is_example_value("example-password-1", false, || false));
        assert!(!is_example_value("Kx7!pQ2#vL9@rT4$", true, || true));
    }
}
