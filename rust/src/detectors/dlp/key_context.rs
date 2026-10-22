// SPDX-License-Identifier: GPL-3.0-only
//! F01: key context of wallet keys without a fixed prefix. A bare `0x` and 64
//! hex digits is as often a transaction or block hash, a Merkle/state root, a
//! storage slot or an event topic as an Ethereum private key, so
//! `dlp_eth_private_key` reports it only next to a key term (private key,
//! privkey, mnemonic, wallet, signer, Schlüssel …) and not where a hash, root
//! or ID term stands nearer.
//!
//! A term that labels the value decides: only separators stand between them
//! (`txHash: "…"`, `privateKey=…`, `Wallet transactions:` on the line above).
//! Without a label, a key term proper anywhere in the context supports the
//! value, so a hash or ID term elsewhere in a sentence does not veto it
//! (`the wallet private key for the event job: …`). Otherwise the nearest
//! term decides. The context is the value's line and up to five lines above
//! it, back to the previous value; a term after the value counts on its line
//! within a short gap and unless it names the next field (`…", "txHash": …`).
//! Wallet and signer terms count only on the value's line or as its label.
use regex::Regex;
use std::ops::Range;
use std::sync::LazyLock;

/// Characters before the value that a term may stand off.
const BEFORE_WINDOW: usize = 600;
/// Characters after the value that a term may stand off.
const AFTER_WINDOW: usize = 40;
/// Lines above the value's line searched for terms.
const LINES_ABOVE: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// A key term proper: supports the value also from a line above.
    Key,
    /// A wallet or signer term: supports the value on its own line only.
    Wallet,
    /// A hash, root, ID or public-key term: the value is no private key.
    Counter,
}

struct Term {
    pattern: &'static str,
    kind: Kind,
    /// Whether the term must stand as a word of its own (short terms).
    whole: bool,
}

const fn term(pattern: &'static str, kind: Kind, whole: bool) -> Term {
    Term {
        pattern,
        kind,
        whole,
    }
}

/// Terms in match priority: at one position the first matching term wins, so
/// compounds (`public key`, `storage key`) come before their parts.
static TERMS: &[Term] = &[
    // Public keys, storage and cache keys are no private keys.
    term(r"public[ _.-]?key", Kind::Counter, false),
    term(r"pub[ _.-]?key", Kind::Counter, false),
    term(
        r"(?:ö|oe)ffentliche[nrs]?[ _.-]?schl(?:ü|ue)ssel",
        Kind::Counter,
        false,
    ),
    term(r"storage[ _.-]?(?:key|slot)", Kind::Counter, false),
    term(r"cache[ _.-]?key", Kind::Counter, false),
    term(r"idempotency[ _.-]?key", Kind::Counter, false),
    // Key terms (EN/DE).
    term(r"private[ _.-]?key", Kind::Key, false),
    term(r"priv[ _.-]?key", Kind::Key, false),
    term(r"secret[ _.-]?key", Kind::Key, false),
    term(r"signing[ _.-]?key", Kind::Key, false),
    term(r"wallet[ _.-]?key", Kind::Key, false),
    term(r"seed[ _.-]?phrase", Kind::Key, false),
    term(r"mnemonic", Kind::Key, false),
    term(r"keystore", Kind::Key, false),
    term(
        r"privat(?:e[nrs]?)?[ _.-]?schl(?:ü|ue)ssel",
        Kind::Key,
        false,
    ),
    term(r"geheime[nrs]?[ _.-]?schl(?:ü|ue)ssel", Kind::Key, false),
    term(r"signatur[ _.-]?schl(?:ü|ue)ssel", Kind::Key, false),
    term(r"signier[ _.-]?schl(?:ü|ue)ssel", Kind::Key, false),
    term(r"wallet[ _.-]?schl(?:ü|ue)ssel", Kind::Key, false),
    // Hashes, roots, IDs and chain data.
    term(r"hash", Kind::Counter, false),
    term(r"digest", Kind::Counter, false),
    term(r"checksum", Kind::Counter, false),
    term(r"pr(?:ü|ue)fsumme", Kind::Counter, false),
    term(r"sha[ _-]?(?:1|224|256|384|512|3)", Kind::Counter, false),
    term(r"keccak", Kind::Counter, false),
    term(r"blake2?", Kind::Counter, false),
    term(r"md5", Kind::Counter, false),
    term(r"merkle", Kind::Counter, false),
    term(r"wurzel", Kind::Counter, false),
    term(r"fingerprint", Kind::Counter, false),
    term(r"fingerabdruck", Kind::Counter, false),
    term(r"integrity", Kind::Counter, false),
    term(r"transaction", Kind::Counter, false),
    term(r"transaktion", Kind::Counter, false),
    term(r"txid", Kind::Counter, false),
    term(r"receipt", Kind::Counter, false),
    term(r"keyhash", Kind::Counter, false),
    term(r"uuid", Kind::Counter, false),
    term(r"guid", Kind::Counter, false),
    term(r"tx", Kind::Counter, true),
    term(r"id", Kind::Counter, true),
    term(r"block", Kind::Counter, true),
    term(r"root", Kind::Counter, true),
    term(r"commit", Kind::Counter, true),
    term(r"nonce", Kind::Counter, true),
    term(r"salt", Kind::Counter, true),
    term(r"slot", Kind::Counter, true),
    term(r"topics?", Kind::Counter, true),
    term(r"event", Kind::Counter, true),
    term(r"address", Kind::Counter, true),
    term(r"adresse", Kind::Counter, true),
    // Wallet and signer terms, and key words of their own.
    term(r"wallets?", Kind::Wallet, false),
    term(r"signer", Kind::Wallet, true),
    term(r"signing", Kind::Wallet, true),
    term(r"accounts", Kind::Wallet, true),
    term(r"secret", Kind::Wallet, true),
    term(r"pk", Kind::Wallet, true),
    term(r"key", Kind::Wallet, true),
    term(r"schl(?:ü|ue)ssel", Kind::Wallet, true),
];

/// All terms as one case-insensitive alternation, one group per term.
static TERM_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    let alternation = TERMS
        .iter()
        .map(|term| format!("({})", term.pattern))
        .collect::<Vec<_>>()
        .join("|");
    Regex::new(&format!("(?i){alternation}")).unwrap()
});

/// A value of another field: a hex run of 16 or more digits.
static VALUE_RUN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[0-9A-Fa-f]{16,}").unwrap());

/// A term found in the text: its kind and byte range.
struct Found {
    kind: Kind,
    range: Range<usize>,
}

/// Whether a whole term at `range` stands as a word of its own: no letter or
/// digit before or after it, except where it starts or ends a camelCase part
/// (`relayerSigner`, `pkHex`). Longer terms match inside words
/// (`Blockhash`, `Hotwallet`).
fn at_boundary(text: &str, range: &Range<usize>, whole: bool) -> bool {
    if !whole {
        return true;
    }
    let found = &text[range.clone()];
    let first = found.chars().next();
    let last = found.chars().next_back();
    let before = text[..range.start].chars().next_back();
    let after = text[range.end..].chars().next();
    let starts = before.is_none_or(|ch| !ch.is_alphanumeric())
        || (first.is_some_and(char::is_uppercase)
            && before.is_some_and(|ch| ch.is_lowercase() || ch.is_ascii_digit()));
    let ends = after.is_none_or(|ch| !ch.is_alphanumeric())
        || (after.is_some_and(char::is_uppercase) && last.is_some_and(char::is_lowercase));
    starts && ends
}

/// Terms within `range` of `text`, in text order.
fn terms(text: &str, range: Range<usize>) -> Vec<Found> {
    TERM_REGEX
        .captures_iter(&text[range.clone()])
        .filter_map(|captures| {
            let (index, group) = captures
                .iter()
                .enumerate()
                .skip(1)
                .find_map(|(index, group)| group.map(|group| (index - 1, group)))?;
            let found = range.start + group.start()..range.start + group.end();
            let term = &TERMS[index];
            at_boundary(text, &found, term.whole).then_some(Found {
                kind: term.kind,
                range: found,
            })
        })
        .collect()
}

/// Byte index `chars` characters before `index`, not before `floor`.
fn back(text: &str, index: usize, chars: usize, floor: usize) -> usize {
    text[floor..index]
        .char_indices()
        .rev()
        .nth(chars.saturating_sub(1))
        .map_or(floor, |(offset, _)| floor + offset)
}

/// Byte index `chars` characters after `index`, not after `ceil`.
fn ahead(text: &str, index: usize, chars: usize, ceil: usize) -> usize {
    text[index..ceil]
        .char_indices()
        .nth(chars)
        .map_or(ceil, |(offset, _)| index + offset)
}

/// The rest of a field label after a term: the term's word, at most one more
/// word and quotes, then an assignment (`": `, ` hash:`, `Id=`).
static FIELD_LABEL_END: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^[\w-]*["' \t]*(?:[\w-]+["' \t]*)?[:=]"#).unwrap());

/// Whether a term after the value names the next field (`, "txHash": …`,
/// `; tx hash: …`). Punctuation before the term alone does not: in prose it
/// introduces an explanation (`0x…, this is the private key`).
fn names_next_field(text: &str, term_end: usize) -> bool {
    FIELD_LABEL_END.is_match(&text[term_end..])
}

/// Whether only separators stand between a term and the value it labels.
fn is_label_gap(gap: &str) -> bool {
    gap.chars().all(|ch| {
        ch.is_whitespace()
            || matches!(
                ch,
                '"' | '\''
                    | '`'
                    | ':'
                    | '='
                    | '('
                    | ')'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '<'
                    | '>'
                    | '|'
                    | '*'
                    | '#'
                    | '-'
                    | '_'
                    | '\\'
            )
    })
}

/// A term of the value's context.
struct Near {
    kind: Kind,
    /// Characters between the term and the value.
    distance: usize,
    /// Whether the term labels the value (`is_label_gap`).
    label: bool,
}

/// Start of the context before the value: its line and `LINES_ABOVE` lines
/// above, at most `BEFORE_WINDOW` characters, after the last other value.
fn context_start(text: &str, value_start: usize, line_start: usize) -> usize {
    let mut start = line_start;
    for _ in 0..LINES_ABOVE {
        if start == 0 {
            break;
        }
        start = text[..start - 1].rfind('\n').map_or(0, |index| index + 1);
    }
    let start = back(text, value_start, BEFORE_WINDOW, start);
    VALUE_RUN
        .find_iter(&text[start..value_start])
        .last()
        .map_or(start, |run| start + run.end())
}

/// Terms of the value's context with their distance and label flag.
fn context(text: &str, value: &Range<usize>, line: &Range<usize>) -> Vec<Near> {
    let start = context_start(text, value.start, line.start);
    let before = terms(text, start..value.start)
        .into_iter()
        .filter_map(|found| {
            let gap = &text[found.range.end..value.start];
            let label = is_label_gap(gap);
            // Wallet and signer terms above the value's line only as its label.
            (found.kind != Kind::Wallet || label || found.range.start >= line.start).then(|| Near {
                kind: found.kind,
                distance: gap.chars().count(),
                label,
            })
        });
    let end = ahead(text, value.end, AFTER_WINDOW, line.end);
    let after = terms(text, value.end..end)
        .into_iter()
        .filter(|found| !names_next_field(text, found.range.end))
        .map(|found| {
            let gap = &text[value.end..found.range.start];
            Near {
                kind: found.kind,
                distance: gap.chars().count(),
                label: is_label_gap(gap),
            }
        });
    before.chain(after).collect()
}

/// F01: whether the wallet key at `value` (byte range) of `text` stands in a
/// key context.
pub(super) fn has_key_context(text: &str, value: Range<usize>) -> bool {
    let line_start = text[..value.start].rfind('\n').map_or(0, |index| index + 1);
    let line_end = text[value.end..]
        .find('\n')
        .map_or(text.len(), |index| value.end + index);
    let near = context(text, &value, &(line_start..line_end));
    let nearest = |label_only: bool| {
        near.iter()
            .filter(|near| near.label || !label_only)
            .min_by_key(|near| near.distance)
            .map(|near| near.kind)
    };
    let kind = nearest(true).or_else(|| {
        if near.iter().any(|near| near.kind == Kind::Key) {
            Some(Kind::Key)
        } else {
            nearest(false)
        }
    });
    matches!(kind, Some(Kind::Key | Kind::Wallet))
}

#[cfg(test)]
mod tests {
    use super::has_key_context;

    // A test pattern, no key.
    const KEY: &str = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn context(template: &str) -> bool {
        let text = template.replace("{}", KEY);
        let start = text.find(KEY).unwrap();
        has_key_context(&text, start..start + KEY.len())
    }

    #[test]
    fn key_terms_on_the_line_support_the_value() {
        for template in [
            "WALLET_PRIVATE_KEY={}",
            "  walletPrivateKey: \"{}\",",
            "<add key=\"WalletPrivateKey\" value=\"{}\" />",
            "Privater Schlüssel des Hot-Wallets: {}",
            "Privatschlüssel: {}",
            "const signer = new Wallet(\"{}\");",
            "sepolia: { accounts: [\"{}\"] },",
            "DEPLOYER_PK={}",
            "  schluessel: {}",
            "Hotwallet-Export {}",
            "{} is the wallet's private key",
            "{\"address\": \"relayer\", \"privateKey\": \"{}\", \"chainId\": 11155111}",
            "{}, this is the private key",
            "{}; das ist der private Schlüssel der Wallet",
        ] {
            assert!(context(template), "{template}");
        }
    }

    #[test]
    fn key_terms_on_a_line_above_support_the_value() {
        assert!(context(
            "[09:41] maria: anyone have the wallet private key?\n[09:43] tom: here you go: {}\n"
        ));
        assert!(context(
            "anbei die Zugangsdaten (Wallet-Private-Key):\n\n{}\n\nBitte löschen."
        ));
        assert!(context(
            "[09:41] maria: the wallet private key for the event export?\n[09:42] tom: one sec\n[09:42] tom: which block?\n[09:43] tom: here: {}\n"
        ));
    }

    #[test]
    fn hash_terms_that_do_not_label_the_value_yield_to_key_terms() {
        for template in [
            "Note: the job still uses the old wallet private key from the last commit, current value: {}",
            "Wallet-Private-Key für die Event-Verarbeitung (Mandant 42) lautet {}",
            "here is the wallet private key for the transaction relayer:\n\n{}\n",
        ] {
            assert!(context(template), "{template}");
        }
    }

    #[test]
    fn hash_terms_or_no_term_reject_the_value() {
        for template in [
            "{}",
            "tx hash: {} confirmed",
            "{\"status\": \"ok\", \"transactionHash\": \"{}\"}",
            "Block 18 sealed, block hash {}",
            "The Merkle root {} matches the header.",
            "Transaktionshash: {} (bestätigt)",
            "Die Zustandswurzel {} stimmt.",
            "Wallet tx hash: {}",
            "Wallet-Export: Blockhash {}",
            "public key: {}",
            "storageKey: {}",
            "topics: [\"{}\"]",
            "{} (tx hash of the wallet funding)",
            "{\"privateKey\": \"0x1111222233334444\", \"blockHash\": \"{}\"}",
            "privateKey=0x1111222233334444aaaa data={}",
            "wallet private key: 0x1111222233334444aaaa\n{}",
            "Wallet transactions:\n{}",
            "Our wallet private key never leaves the HSM. Transaction hash:\n\n{}",
            "private key rotated; block hash {}",
            "monkey: {}",
            "{}, tx hash: pending",
            "{}; private key: rotated",
        ] {
            assert!(!context(template), "{template}");
        }
    }
}
