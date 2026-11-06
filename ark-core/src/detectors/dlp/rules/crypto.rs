// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key material: wallet keys, wallet seeds and PEM private keys.
use crate::detectors::dlp::key_context::has_key_context;
use crate::detectors::dlp::seed_phrase::{has_seed_context, is_seed_phrase, phrases};
use crate::detectors::dlp::{
    dlp::{DlpPattern, RuleMeta, SecretSubtype, ValidatorStrength},
    prefilter::ValueClass,
};
use crate::detectors::validators::{
    base58check_decode, bech32_decode_with_limit, convert_bits, crc32, Bech32Variant,
};
use regex::bytes::Regex;
use std::ops::Range;
use std::sync::LazyLock;

/// Order of the secp256k1 group, big-endian.
const SECP256K1_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// WIF version bytes: mainnet and testnet (also signet and regtest).
const WIF_MAINNET: u8 = 0x80;
const WIF_TESTNET: u8 = 0xef;

/// WIF: Base58Check with version byte 0x80 (`5…` uncompressed, `K…`/`L…`
/// compressed) or 0xef (`9…`, `c…`), a secp256k1 scalar and the 0x01 flag of
/// compressed keys.
fn is_btc_wif(value: &str) -> bool {
    let Some(payload) = base58check_decode(value) else {
        return false;
    };
    let scalar = match (payload.as_slice(), value.len()) {
        ([WIF_MAINNET | WIF_TESTNET, scalar @ ..], 51) if scalar.len() == 32 => scalar,
        ([WIF_MAINNET | WIF_TESTNET, scalar @ .., 0x01], 52) if scalar.len() == 32 => scalar,
        _ => return false,
    };
    is_secp256k1_scalar(scalar)
}

/// A private key in 1..n-1 of secp256k1, 32 bytes big-endian.
fn is_secp256k1_scalar(scalar: &[u8]) -> bool {
    scalar.len() == 32
        && scalar.iter().any(|byte| *byte != 0)
        && scalar < SECP256K1_ORDER.as_slice()
}

/// BIP 32 / SLIP-0132 version bytes of the extended private keys per prefix:
/// `xprv` (BIP 32), `yprv` (BIP 49), `zprv` (BIP 84) on mainnet and `tprv`,
/// `uprv`, `vprv` on testnet.
const EXTENDED_PRIVATE_VERSIONS: [(&str, [u8; 4]); 6] = [
    ("xprv", [0x04, 0x88, 0xad, 0xe4]),
    ("yprv", [0x04, 0x9d, 0x78, 0x78]),
    ("zprv", [0x04, 0xb2, 0x43, 0x0c]),
    ("tprv", [0x04, 0x35, 0x83, 0x94]),
    ("uprv", [0x04, 0x4a, 0x4e, 0x28]),
    ("vprv", [0x04, 0x5f, 0x18, 0xbc]),
];

/// C02: a serialized BIP 32 extended private key, Base58Check over 78 bytes:
/// the version of its prefix, depth, parent fingerprint and child number
/// (both zero for a master key at depth 0), chain code and `0x00` with a
/// secp256k1 scalar.
fn is_extended_private_key(value: &str) -> bool {
    let Some(version) = EXTENDED_PRIVATE_VERSIONS
        .iter()
        .find(|(prefix, _)| value.starts_with(prefix))
        .map(|(_, version)| version)
    else {
        return false;
    };
    let Some(payload) = base58check_decode(value) else {
        return false;
    };
    match payload.as_slice() {
        [v0, v1, v2, v3, depth, parent @ .., _] if payload.len() == 78 => {
            let (parent, rest) = parent.split_at(8);
            [*v0, *v1, *v2, *v3] == *version
                && (*depth != 0 || parent.iter().all(|byte| *byte == 0))
                && rest[32] == 0
                && is_secp256k1_scalar(&payload[46..])
        }
        _ => false,
    }
}

/// C03: an Ethereum keystore (Web3 Secret Storage v3) around the ciphertext:
/// the `kdf` (scrypt or pbkdf2) and the `mac` of the same `crypto` object
/// within a few hundred bytes. Other JSON with a `ciphertext` field (KMS,
/// JWE, Vault transit) has neither.
fn has_keystore_structure(text: &str, range: Range<usize>) -> bool {
    static KDF: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#""kdf"\s*:\s*"(?:scrypt|pbkdf2)""#).expect("valid regex"));
    static MAC: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#""mac"\s*:\s*"[0-9a-f]{64}""#).expect("valid regex"));
    const WINDOW: usize = 800;
    let window =
        &text.as_bytes()[range.start.saturating_sub(WINDOW)..(range.end + WINDOW).min(text.len())];
    KDF.is_match(window) && MAC.is_match(window)
}

/// C03: a Solana keypair as a JSON byte array (`solana-keygen` `id.json`,
/// `Keypair.fromSecretKey`): 64 numbers that are bytes and not one repeated
/// or counted filler.
fn is_solana_keypair(value: &str) -> bool {
    let mut seen = [false; 256];
    let mut count = 0;
    for number in value
        .trim_matches(['[', ']'])
        .split(',')
        .map(|number| number.trim().parse::<u16>())
    {
        match number {
            Ok(byte @ 0..=255) => seen[usize::from(byte)] = true,
            _ => return false,
        }
        count += 1;
    }
    count == 64 && seen.iter().filter(|seen| **seen).count() >= 24
}

/// The BIP39 English word list (2048 sorted words), also Electrum's default
/// word list for new seeds.
static BIP39_ENGLISH: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| include_str!("data/bip39_english.txt").lines().collect());

/// C-WALLET: an Electrum seed (version 2.0 and later): 12 words of the
/// English word list whose HMAC-SHA512 under the key `Seed version` starts
/// with the hex prefix of a seed type, `01` (standard), `100` (segwit), `101`
/// (2FA) or `102` (2FA segwit). The match is lowercase words with single
/// whitespace, already Electrum's normalized form once the runs are joined
/// by one space.
fn is_electrum_seed(value: &str) -> bool {
    let words: Vec<&str> = value.split_ascii_whitespace().collect();
    if words.len() != 12
        || !words
            .iter()
            .all(|word| BIP39_ENGLISH.binary_search(word).is_ok())
    {
        return false;
    }
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, b"Seed version");
    let tag = ring::hmac::sign(&key, words.join(" ").as_bytes());
    match tag.as_ref() {
        [0x01, ..] => true,
        [0x10, second, ..] => second >> 4 <= 2,
        _ => false,
    }
}

/// Seed terms (DE/EN) before a word-list seed, the prefilter keywords of the
/// seed rules and the term alternation of their patterns.
const SEED_TERMS: &[&str] = &[
    "electrum",
    "monero",
    "seed",
    "mnemonic",
    "recover",
    "wiederherstellung",
];

/// The Monero English word list (1626 sorted words with unique 3-letter
/// prefixes), `src/mnemonics/english.h`.
static MONERO_ENGLISH: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| include_str!("data/monero_english.txt").lines().collect());

/// C-WALLET: a Monero mnemonic seed, the text form of the private spend key:
/// 24 words of the English word list and a checksum word, the word at the
/// CRC-32 of the 3-letter prefixes of the 24 words modulo 24.
fn is_monero_seed(value: &str) -> bool {
    let words: Vec<&str> = value.split_ascii_whitespace().collect();
    if words.len() != 25
        || !words
            .iter()
            .all(|word| MONERO_ENGLISH.binary_search(word).is_ok())
    {
        return false;
    }
    let prefixes: String = words[..24].iter().map(|word| &word[..3]).collect();
    let index = crc32(prefixes.as_bytes()) as usize % 24;
    words[24][..3] == words[index][..3]
}

/// C-WALLET: a Cardano signing key in the Bech32 form of CIP-5: Bech32 (not
/// Bech32m) under a secret-key prefix, with the 32 bytes of an Ed25519 key,
/// the 64 bytes of an extended key or the 96 bytes of an extended key with
/// chain code (`_xsk`), and zero padding bits.
fn is_cardano_signing_key(value: &str) -> bool {
    bech32_decode_with_limit(value, 200).is_some_and(|decoded| {
        decoded.variant == Bech32Variant::Bech32
            && convert_bits(&decoded.data, 5, 8, false).is_some_and(|key| {
                if decoded.hrp.ends_with("_xsk") {
                    key.len() == 96
                } else {
                    matches!(key.len(), 32 | 64)
                }
            })
    })
}

/// Order of the secp256k1 group as 64 lowercase hex digits.
const SECP256K1_ORDER_HEX: &str =
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

/// Ethereum private key: a secp256k1 scalar in 1..n-1 as `0x` and 64
/// lowercase hex digits, which compare like the numbers they spell.
fn is_eth_private_key(value: &str) -> bool {
    value.strip_prefix("0x").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            && hex.bytes().any(|byte| byte != b'0')
            && hex < SECP256K1_ORDER_HEX
    })
}

pub(super) const RULES: &[DlpPattern] = &[
    // ── Crypto ───────────────────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_eth_private_key",
        pattern: r"0x[0-9a-f]{64}\b",
        entity_group: "CRYPTO_KEY",
        validator: Some(is_eth_private_key),
        span_group: None,
        base_score: 25,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://ethereum.org/en/developers/docs/accounts/",
            &["0x"],
        )
        .with_provider("ethereum")
        .with_min_entropy(3.0)
        .with_boundary("")
        // F01: tx/block hashes, roots and digests share the shape.
        .with_context_gate(has_key_context)
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_btc_wif",
        pattern: r"(?P<anchor_1>[59][1-9A-HJ-NP-Za-km-z]{50}|[KLc][1-9A-HJ-NP-Za-km-z]{51})",
        entity_group: "CRYPTO_KEY",
        validator: Some(is_btc_wif),
        span_group: None,
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::Checksum,
            "https://en.bitcoin.it/wiki/Wallet_import_format",
            &[],
        )
        .with_provider("bitcoin")
        // Testnet keys (version byte 0xef); mainnet keys never start so.
        .with_test_prefixes(&["9", "c"])
        .with_min_entropy(3.0)
        .with_value_run(ValueClass::Base58, 51)
        .with_boundary("")
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_bip32_extended_private_key",
        pattern: r"(?P<anchor_1>[xyztuv]prv)[1-9A-HJ-NP-Za-km-z]{107}",
        entity_group: "CRYPTO_KEY",
        validator: Some(is_extended_private_key),
        span_group: None,
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::Checksum,
            "https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format",
            &["xprv", "yprv", "zprv", "tprv", "uprv", "vprv"],
        )
        .with_provider("bitcoin")
        // Testnet versions (BIP 32 tprv, SLIP-0132 uprv/vprv).
        .with_test_prefixes(&["tprv", "uprv", "vprv"])
        .with_min_entropy(3.0)
        .with_boundary("")
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_eth_keystore_ciphertext",
        pattern: r#""ciphertext"\s*:\s*"([0-9a-f]{64})""#,
        entity_group: "CRYPTO_KEY",
        validator: None,
        span_group: Some(1),
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://ethereum.org/en/developers/docs/data-structures-and-encoding/web3-secret-storage/",
            &["ciphertext"],
        )
        .with_provider("ethereum")
        .with_min_entropy(3.0)
        .with_context_gate(has_keystore_structure)
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_solana_keypair",
        // A key term before the array: a bare list of 64 numbers is data.
        pattern: r"(?i)(?:keypair|secret[ _.-]?key|private[ _.-]?key|signer|id\.json)[^\[\]\n]{0,40}\n?[^\[\]\n]{0,10}(\[\s*(?:[0-9]{1,3}\s*,\s*){63}[0-9]{1,3}\s*\])",
        entity_group: "CRYPTO_KEY",
        validator: Some(is_solana_keypair),
        span_group: Some(1),
        base_score: 25,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://solana.com/docs/core/accounts#keypair",
            &["keypair", "secret", "private", "signer", "id.json"],
        )
        .with_provider("solana")
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_electrum_seed",
        // A seed term, then at most 80 characters on its line and exactly 12
        // lowercase words after punctuation or at the start of the next line,
        // not inside a longer run of words.
        pattern: r"(?m)(?i:electrum|monero|seed|mnemonic|recover|wiederherstellung)[^\n]{0,80}?(?:[^A-Za-z \t\r\n]|\r?\n)[ \t]*((?:[a-z]{3,8}[ \t]+){11}[a-z]{3,8})[ \t]*(?:$|[^A-Za-z \t])",
        entity_group: "CRYPTO_KEY",
        validator: Some(is_electrum_seed),
        span_group: Some(1),
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::Checksum,
            "https://electrum.readthedocs.io/en/latest/seedphrase.html",
            SEED_TERMS,
        )
        .with_provider("bitcoin")
        .with_subtype(SecretSubtype::SeedPhrase),
    },
    DlpPattern {
        name: "dlp_monero_seed",
        // The seed term and run of `dlp_electrum_seed` with 25 words, also
        // over line breaks (monero-wallet-cli prints the seed on several lines).
        pattern: r"(?m)(?i:electrum|monero|seed|mnemonic|recover|wiederherstellung)[^\n]{0,80}?(?:[^A-Za-z \t\r\n]|\r?\n)[ \t]*((?:[a-z]{4,12}(?:[ \t]+|[ \t]*\r?\n[ \t]*)){24}[a-z]{4,12})[ \t]*(?:$|[^A-Za-z \t])",
        entity_group: "CRYPTO_KEY",
        validator: Some(is_monero_seed),
        span_group: Some(1),
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::Checksum,
            "https://github.com/monero-project/monero/blob/master/src/mnemonics/electrum-words.cpp",
            SEED_TERMS,
        )
        .with_provider("monero")
        .with_subtype(SecretSubtype::SeedPhrase),
    },
    DlpPattern {
        name: "dlp_cardano_signing_key",
        pattern: r"(?P<anchor_1>(?:acct|addr|drep|policy|root|stake)_x?sk|ed25519e?_sk)1[02-9ac-hj-np-z]{58,160}",
        entity_group: "CRYPTO_KEY",
        validator: Some(is_cardano_signing_key),
        span_group: None,
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::Checksum,
            "https://cips.cardano.org/cip/CIP-0005",
            &["_sk1", "_xsk1"],
        )
        .with_provider("cardano")
        .with_boundary("")
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_bip39_seed_phrase",
        // C01: the words and their separators; `seed_phrase::phrases` finds
        // the phrases, the validator checks word lists and checksum.
        // A word has an ASCII letter among its letters, accented ones in NFC
        // or NFD (`año`, `a\u{303}o`); the finder checks the word lengths.
        pattern: r#"[\x{e0}-\x{ff}\x{300}-\x{36f}]{0,2}[a-z][a-z\x{e0}-\x{ff}\x{300}-\x{36f}]{1,17}(?:[\s0-9.):,"'-]{1,24}[\x{e0}-\x{ff}\x{300}-\x{36f}]{0,2}[a-z][a-z\x{e0}-\x{ff}\x{300}-\x{36f}]{1,17}){11,23}"#,
        entity_group: "CRYPTO_KEY",
        validator: Some(is_seed_phrase),
        span_group: None,
        base_score: 30,
        meta: RuleMeta::new(
            ValidatorStrength::Checksum,
            "https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki",
            &[],
        )
        // Every word has an ASCII letter (`año` in NFC no more than one);
        // the finder is the actual prefilter.
        .with_value_run(ValueClass::Alphanumeric, 1)
        .with_finder(phrases)
        // 12- and 15-word phrases carry a 4- or 5-bit checksum.
        .with_context_gate(has_seed_context)
        .with_subtype(SecretSubtype::SeedPhrase),
    },
    // ── Private key material ─────────────────────────────────────────────────
    DlpPattern {
        name: "dlp_private_key_block",
        pattern: r"(?s)-----BEGIN\s+(?P<anchor_2>RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----.*?-----END\s+(?P<anchor_1>RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
        entity_group: "PRIVATE_KEY",
        validator: None,
        span_group: None,
        base_score: 70,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:private-key",
            &["-----begin"],
        )
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_private_key_header",
        pattern: r"-----BEGIN\s+(?P<anchor_1>RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
        entity_group: "PRIVATE_KEY",
        validator: None,
        span_group: None,
        base_score: 50,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "gitleaks:private-key",
            &["-----begin"],
        )
        .with_subtype(SecretSubtype::PrivateKey),
    },
];
