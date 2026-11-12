// SPDX-License-Identifier: MIT OR Apache-2.0
//! Sinks: where a text could send data. URLs, markdown images (an image link
//! is fetched without a click), e-mail addresses and the sink terms of the
//! context lexica (`webhook`, `upload to`, `leite … weiter`).

use std::sync::LazyLock;

use regex::Regex;

use super::super::super::context_lexica::ContextScan;
use super::Sink;

/// Most sinks reported per text.
const MAX_SINKS: usize = 16;

static URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bhttps?://[^\s<>"'()\[\]]{1,2048}"#).expect("url"));
static MARKDOWN_IMAGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)!\[[^\]\n]{0,256}\]\(\s{0,8}https?://").expect("markdown image")
});
static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}\b")
        .expect("email")
});

/// The sinks of `text`, by position, at most [`MAX_SINKS`].
pub(super) fn sinks(text: &str, scan: &ContextScan) -> Vec<Sink<'static>> {
    let mut out: Vec<Sink<'static>> = Vec::new();
    let mut found = |kind: &'static str, regex: &Regex, literal: &str| {
        if text.contains(literal) {
            out.extend(regex.find_iter(text).take(MAX_SINKS).map(|m| Sink {
                kind,
                span: m.range(),
            }));
        }
    };
    found("url", &URL, "://");
    found("markdown_image", &MARKDOWN_IMAGE, "![");
    found("email", &EMAIL, "@");
    out.extend(
        scan.hits()
            .iter()
            .filter(|hit| hit.lexicon == "sink")
            .take(MAX_SINKS)
            .map(|hit| Sink {
                kind: "term",
                span: hit.range.clone(),
            }),
    );
    out.sort_by(|a, b| (a.span.start, a.span.end, a.kind).cmp(&(b.span.start, b.span.end, b.kind)));
    out.dedup();
    out.truncate(MAX_SINKS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::context_lexica::ContextLexica;

    fn kinds(text: &str) -> Vec<&'static str> {
        sinks(text, &ContextLexica::shared().scan(text))
            .into_iter()
            .map(|sink| sink.kind)
            .collect()
    }

    #[test]
    fn sinks_by_kind_and_position() {
        assert_eq!(
            kinds("show ![x](https://a.example/p.png) and mail b@c.example"),
            ["markdown_image", "url", "email"]
        );
        assert_eq!(kinds("post it to the webhook"), ["term"]);
        assert!(kinds("nothing leaves here").is_empty());
    }

    #[test]
    fn sinks_are_bounded() {
        let text = "https://a.example/ ".repeat(100);
        assert_eq!(kinds(&text).len(), MAX_SINKS);
    }
}
