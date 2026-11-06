// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key material: wallet keys, wallet seeds, PEM private keys, JWKs, VPN keys (C-KEYS) and
//! symmetric keys of frameworks and code.
use crate::detectors::dlp::key_context::has_key_context;
use crate::detectors::dlp::{
    dlp::{DlpPattern, RuleMeta, SecretSubtype, ValidatorStrength},
    prefilter::ValueClass,
};
use crate::detectors::validators::{
    base58check_decode, base64_decode, bech32_decode_with_limit, convert_bits, crc32, Base64Kind,
    Bech32Variant,
};
use regex::bytes::Regex;
use serde_json::Value;
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

/// C-KEYS: private JWK members of published test vectors (RFC 7517 A.2 EC
/// `d`, RFC 7517 A.3 AES `k`, RFC 8037 A.1 Ed25519 `d`); documentation
/// copies them verbatim.
const JWK_TEST_VECTORS: &[&str] = &[
    "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
    "GawgguFyGrWKav7AX4VKUg",
    "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
];

/// C-KEYS: a JSON Web Key (RFC 7517) that holds private key material: an
/// object with `kty` and its private member, `d` for RSA, EC and OKP keys
/// (RFC 7518 section 6, RFC 8037) or `k` for symmetric `oct` keys, as
/// base64url of at least 16 bytes. A public JWK has no such member. The
/// regex takes a flat object with `"kty"`, so a JWKS (`{"keys": [...]}`)
/// yields its keys one by one.
fn is_jwk_private_key(value: &str) -> bool {
    let Ok(Value::Object(jwk)) = serde_json::from_str::<Value>(value) else {
        return false;
    };
    let member = match jwk.get("kty").and_then(Value::as_str) {
        Some("RSA" | "EC" | "OKP") => "d",
        Some("oct") => "k",
        _ => return false,
    };
    jwk.get(member)
        .and_then(Value::as_str)
        .filter(|secret| !JWK_TEST_VECTORS.contains(secret))
        .and_then(|secret| base64_decode(secret, Base64Kind::UrlSafe))
        .is_some_and(|raw| raw.len() >= 16 && is_varied_key(&raw))
}

/// Key bytes that no placeholder or counter fills: at least half of the
/// bytes distinct and no run of consecutive values (`00 01 02 …`, FIPS-197).
fn is_varied_key(raw: &[u8]) -> bool {
    let mut seen = [false; 256];
    let mut distinct = 0;
    for byte in raw {
        if !std::mem::replace(&mut seen[usize::from(*byte)], true) {
            distinct += 1;
        }
    }
    distinct * 2 >= raw.len().min(64)
        && !raw
            .windows(2)
            .all(|pair| pair[1] == pair[0].wrapping_add(1))
}

/// C-KEYS: a WireGuard private or preshared key is the standard base64 of
/// 32 bytes (`wg genkey`, `wg genpsk`).
fn is_wireguard_key(value: &str) -> bool {
    base64_decode(value, Base64Kind::Standard)
        .is_some_and(|raw| raw.len() == 32 && is_varied_key(&raw))
}

/// C-KEYS: the 512 hex digits of an OpenVPN static key block decode to 256
/// varied bytes.
fn is_openvpn_static_key(value: &str) -> bool {
    let digits = value
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    hex_bytes(&digits).is_some_and(|raw| raw.len() == 256 && is_varied_key(&raw))
}

fn hex_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(hex.get(at..at + 2)?, 16).ok())
        .collect()
}

/// C-KEYS: AES keys of published test vectors (NIST SP 800-38A F.1, 128,
/// 192 and 256 bits) that tutorials and test suites copy.
const SYMMETRIC_TEST_VECTORS: &[&str] = &[
    "2b7e151628aed2a6abf7158809cf4f3c",
    "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
];

/// The bytes of a symmetric key constant: a `0x..` byte array, hex digits,
/// or standard or URL-safe base64 (Fernet keys keep their `=`).
fn symmetric_key_bytes(value: &str) -> Option<Vec<u8>> {
    if let Some(array) = value.strip_prefix(['[', '{']) {
        return array
            .split([',', ']', '}'])
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(|item| u8::from_str_radix(item.strip_prefix("0x")?, 16).ok())
            .collect();
    }
    if value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return hex_bytes(value);
    }
    base64_decode(value, Base64Kind::Standard)
        .or_else(|| base64_decode(value, Base64Kind::StandardUnpadded))
        .or_else(|| base64_decode(value.trim_end_matches('='), Base64Kind::UrlSafe))
}

/// C-KEYS: an AES or HMAC key of 128, 192 or 256 bits that is no published
/// test vector.
fn is_symmetric_key(value: &str) -> bool {
    symmetric_key_bytes(value).is_some_and(|raw| {
        matches!(raw.len(), 16 | 24 | 32)
            && is_varied_key(&raw)
            && !SYMMETRIC_TEST_VECTORS
                .iter()
                .any(|vector| hex_bytes(vector).is_some_and(|known| known == raw))
    })
}

/// C-KEYS: Laravel's `APP_KEY` is `base64:` and the base64 of a 16- or
/// 32-byte AES key (`php artisan key:generate`).
fn is_laravel_app_key(value: &str) -> bool {
    value
        .strip_prefix("base64:")
        .and_then(|key| base64_decode(key, Base64Kind::Standard))
        .is_some_and(|raw| matches!(raw.len(), 16 | 32) && is_varied_key(&raw))
}

/// C-KEYS: `get_random_secret_key()` draws 50 characters from lower-case
/// letters, digits and `!@#$%^&*(-_=+)`; a random key holds all three
/// kinds.
fn is_django_secret_key(value: &str) -> bool {
    let key = value.strip_prefix("django-insecure-").unwrap_or(value);
    key.bytes().any(|byte| byte.is_ascii_lowercase())
        && key.bytes().any(|byte| byte.is_ascii_digit())
        && key.bytes().any(|byte| b"!@#$%^&*(-_=+)".contains(&byte))
}

/// C-KEYS: `bin/rails secret` writes 64 random bytes as 128 hex digits.
fn is_rails_secret_key_base(value: &str) -> bool {
    hex_bytes(value).is_some_and(|raw| is_varied_key(&raw))
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
    // ── C-KEYS: key material in config and code ──────────────────────────────
    DlpPattern {
        name: "dlp_jwk_private_key",
        pattern: r#"\{[^{}]{0,4096}"kty"[^{}]{0,4096}\}"#,
        entity_group: "PRIVATE_KEY",
        validator: Some(is_jwk_private_key),
        span_group: None,
        base_score: 70,
        meta: RuleMeta::new(
            ValidatorStrength::Structure,
            "https://datatracker.ietf.org/doc/html/rfc7517",
            &["kty"],
        )
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_wireguard_private_key",
        pattern: concat!(
            r"(?i:(?-u:\b)(?:[a-z0-9]+[_-]){0,2}(?:private|preshared)[_-]?key",
            key_suffix!(),
            r")(?:=>|:=|[=:])[ \t]*\\?[\x22'`]?([A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=)(?:[^A-Za-z0-9+/=]|$)",
        ),
        entity_group: "PRIVATE_KEY",
        validator: Some(is_wireguard_key),
        span_group: Some(1),
        base_score: 50,
        meta: RuleMeta::new(
            ValidatorStrength::Structure,
            "https://www.wireguard.com/quickstart/",
            &[
                "privatekey",
                "private_key",
                "private-key",
                "presharedkey",
                "preshared_key",
                "preshared-key",
            ],
        )
        .with_provider("wireguard")
        .with_min_entropy(3.5)
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_openvpn_static_key",
        pattern: r"-----BEGIN OpenVPN Static key V1-----\s+(?:[0-9a-fA-F]{32}\s+){16}-----END OpenVPN Static key V1-----",
        entity_group: "CRYPTO_KEY",
        validator: Some(is_openvpn_static_key),
        span_group: None,
        base_score: 70,
        meta: RuleMeta::new(
            ValidatorStrength::Structure,
            "https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/",
            &["openvpn static key"],
        )
        .with_provider("openvpn")
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_ipsec_psk",
        pattern: r#":[ \t]*PSK[ \t]+\\?"([^"\\\s<>$%{}]{8,256})\\?""#,
        entity_group: "CRYPTO_KEY",
        validator: None,
        span_group: Some(1),
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::None,
            "https://docs.strongswan.org/docs/latest/config/ipsecSecrets.html",
            &["psk"],
        )
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_symmetric_key",
        pattern: concat!(
            r"(?i:(?-u:\b)(?:[a-z0-9]+[_-]){0,3}(?:aes|hmac|encryption|encrypt|enc|cipher|crypto|signing|fernet|symmetric)[_-]?(?:secret[_-]?)?key(?:\[\d{0,3}\])?",
            key_suffix!(),
            r")(?:\s*:\s*&?\[u8;\s*\d{1,3}\]\s*)?(?:=>|:=|[=:])[ \t]*",
            r"(?:[A-Za-z_][A-Za-z0-9_.:!]{0,40}\(\s*|new\s+byte\s*\[\s*\]\s*)?b?\\?[\x22'`]?",
            r"([0-9a-fA-F]{64}|[0-9a-fA-F]{48}|[0-9a-fA-F]{32}",
            r"|[A-Za-z0-9+/_-]{43}=|[A-Za-z0-9+/_-]{22}==|[A-Za-z0-9+/_-]{32}",
            r"|[\[{]\s*(?:0x[0-9a-fA-F]{2}\s*,\s*){15,31}0x[0-9a-fA-F]{2}\s*,?\s*[\]}])",
            r"(?:[^A-Za-z0-9+/=_-]|$)",
        ),
        entity_group: "CRYPTO_KEY",
        validator: Some(is_symmetric_key),
        span_group: Some(1),
        base_score: 40,
        meta: RuleMeta::new(
            ValidatorStrength::Structure,
            "https://docs.openssl.org/master/man1/openssl-rand/",
            &[
                "aes",
                "hmac",
                "enc",
                "cipher",
                "crypto",
                "signing",
                "fernet",
                "symmetric",
            ],
        )
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_laravel_app_key",
        pattern: r"(?:^|[^A-Za-z0-9+/_])(base64:(?:[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{22}==))(?:[^A-Za-z0-9+/=]|$)",
        entity_group: "CRYPTO_KEY",
        validator: Some(is_laravel_app_key),
        span_group: Some(1),
        base_score: 50,
        meta: RuleMeta::new(
            ValidatorStrength::Structure,
            "https://laravel.com/docs/encryption",
            &["base64:"],
        )
        .with_provider("laravel")
        .with_min_entropy(3.5)
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_django_secret_key",
        pattern: concat!(
            r"(?i:(?-u:\b)(?:django_)?secret_key",
            key_suffix!(),
            r")(?:=>|:=|[=:])[ \t]*(?:[A-Za-z_][A-Za-z0-9_.]{0,40}\([^,()\r\n]{0,80},[ \t]*)?\\?[\x22'`]?",
            r"((?:django-insecure-)?[a-z0-9!@#$%^&*(\-_=+)]{50})(?:[\x22'`\\\s]|$)",
        ),
        entity_group: "CRYPTO_KEY",
        validator: Some(is_django_secret_key),
        span_group: Some(1),
        base_score: 45,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://docs.djangoproject.com/en/stable/ref/settings/#secret-key",
            &["secret_key"],
        )
        .with_provider("django")
        // `startproject` writes `django-insecure-` keys for development.
        .with_test_prefixes(&["django-insecure-"])
        .with_min_entropy(3.5)
        .with_subtype(SecretSubtype::PrivateKey),
    },
    DlpPattern {
        name: "dlp_rails_secret_key_base",
        pattern: concat!(
            r"(?i:secret_key_base",
            key_suffix!(),
            r")(?:=>|:=|[=:])[ \t]*\\?[\x22'`]?([0-9a-f]{128})(?:[^0-9A-Za-z]|$)",
        ),
        entity_group: "CRYPTO_KEY",
        validator: Some(is_rails_secret_key_base),
        span_group: Some(1),
        base_score: 50,
        meta: RuleMeta::new(
            ValidatorStrength::Format,
            "https://guides.rubyonrails.org/security.html#custom-credentials",
            &["secret_key_base"],
        )
        .with_provider("rails")
        .with_min_entropy(3.0)
        .with_subtype(SecretSubtype::PrivateKey),
    },
];
