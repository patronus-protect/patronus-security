// SPDX-License-Identifier: GPL-3.0-only
//! K06: vendor-documented example values are no findings, publicly known test
//! keys are findings with `severity: test`, and the same shapes with other
//! values stay live findings. No documented value is stored in clear: tests
//! build them from the documented key bytes or claims (Base58Check, PKCS#8,
//! HMAC) or assemble them from pieces, and compare their SHA-256 with
//! `research/dlp/documented_values.yaml`.

use std::{collections::BTreeSet, path::PathBuf, sync::OnceLock};

use patronus_ark::{
    detectors::dlp::dlp::DLP_PATTERNS, SecurityCategory, SecurityGateway, SecurityLevel,
    SecurityScanResult,
};
use ring::{digest, hmac};

fn scan(text: &str) -> SecurityScanResult {
    static SCANNER: OnceLock<SecurityGateway> = OnceLock::new();
    SCANNER
        .get_or_init(|| {
            SecurityGateway::with_max_level(
                vec![SecurityCategory::Dlp],
                SecurityLevel::L1,
                None,
                false,
            )
        })
        .scan_category(SecurityCategory::Dlp, text)
        .into_iter()
        .find(|result| result.model == "native:dlp")
        .expect("native DLP result must be present")
}

/// `(rule_id, severity)` of every matched rule.
fn matched_rules(result: &SecurityScanResult) -> Vec<(String, Option<String>)> {
    result.layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .map(|rules| {
            rules
                .iter()
                .map(|rule| {
                    (
                        rule["rule_id"].as_str().unwrap().to_owned(),
                        rule["severity"].as_str().map(str::to_owned),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn assert_silent(text: &str) {
    let result = scan(text);
    assert!(
        result.evidence_spans.is_empty(),
        "documented example value reported in {text:?}: {:#?}",
        result.evidence_spans
    );
}

/// `rule_id` reports `value` with `severity`, and every other secret rule
/// that matched agrees on the severity.
fn assert_reported(text: &str, rule_id: &str, value: &str, severity: &str) {
    let result = scan(text);
    assert!(
        result.evidence_spans.iter().any(|span| span.text == value),
        "{rule_id}: missing {value:?} in {text:?}: {:#?}",
        result.evidence_spans
    );
    let rules = matched_rules(&result);
    assert!(
        rules.iter().any(|(rule, _)| rule == rule_id),
        "{rule_id}: rule did not fire on {text:?}: {rules:?}"
    );
    for (rule, found) in &rules {
        if let Some(found) = found {
            assert_eq!(found, severity, "{rule} on {text:?}");
        }
    }
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn base64(raw: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::new();
    for chunk in raw.chunks(3) {
        let bits = chunk.iter().enumerate().fold(0u32, |bits, (index, byte)| {
            bits | u32::from(*byte) << (16 - 8 * index)
        });
        for index in 0..=chunk.len() {
            out.push(alphabet[(bits >> (18 - 6 * index) & 63) as usize] as char);
        }
        if pad {
            out.push_str(&"=".repeat(3 - chunk.len()));
        }
    }
    out
}

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url(raw: &[u8]) -> String {
    base64(raw, URL_SAFE, false)
}

fn base64url_decode(text: &str) -> Vec<u8> {
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for byte in text.bytes() {
        bits = bits << 6 | URL_SAFE.iter().position(|c| *c == byte).unwrap() as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    out
}

fn base58check(payload: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let first = digest::digest(&digest::SHA256, payload);
    let second = digest::digest(&digest::SHA256, first.as_ref());
    let mut raw = payload.to_vec();
    raw.extend_from_slice(&second.as_ref()[..4]);
    let mut digits: Vec<u8> = Vec::new();
    for byte in &raw {
        let mut carry = u32::from(*byte);
        for digit in digits.iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = raw.iter().take_while(|byte| **byte == 0).count();
    "1".repeat(zeros)
        + &digits
            .iter()
            .rev()
            .map(|digit| ALPHABET[*digit as usize] as char)
            .collect::<String>()
}

/// Bitcoin wiki WIF example key and its uncompressed and compressed WIF.
const WIKI_WIF_KEY: &str = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";

fn wif(key: &[u8], compressed: bool) -> String {
    let mut payload = vec![0x80];
    payload.extend_from_slice(key);
    if compressed {
        payload.push(0x01);
    }
    base58check(&payload)
}

/// PKCS#8 Ed25519 private key (RFC 8410) as a base64 PEM body.
fn ed25519_pkcs8(key: &[u8]) -> String {
    let mut der = hex("302e020100300506032b657004220420");
    der.extend_from_slice(key);
    base64(&der, STANDARD, true)
}

/// RFC 8410 section 10.3 example private key.
const RFC8410_KEY: &str = "D4EE72DBF913584AD5B6D8F1F769F8AD3AFE7C28CBF1D4FBE097A88F44755842";

fn pem(body: &str) -> String {
    format!(
        concat!(
            "-----BEGIN ",
            "PRIVATE KEY-----\n{}\n-----END ",
            "PRIVATE KEY-----"
        ),
        body
    )
}

fn jws(header: &[u8], claims: &[u8], key: &[u8]) -> String {
    let signing_input = format!("{}.{}", base64url(header), base64url(claims));
    let tag = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, key),
        signing_input.as_bytes(),
    );
    format!("{signing_input}.{}", base64url(tag.as_ref()))
}

/// The jwt.io debugger's default HS256 token.
fn jwt_io_token() -> String {
    jws(
        br#"{"alg":"HS256","typ":"JWT"}"#,
        br#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#,
        b"your-256-bit-secret",
    )
}

/// RFC 7515 appendix A.1 (claims of RFC 7519 section 3.1), with the
/// documented JWK `k`.
fn rfc7515_token() -> String {
    jws(
        b"{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}",
        b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}",
        &base64url_decode(concat!(
            "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T",
            "-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
        )),
    )
}

const AWS_ACCESS_KEY_ID: &str = concat!("AKIA", "IOSFODNN7", "EXAMPLE");
const AWS_SECRET_ACCESS_KEY: &str = concat!("wJalrXUtnFEMI/", "K7MDENG/bPxRfiCY", "EXAMPLEKEY");

/// Hardhat Network / Foundry Anvil default accounts #0–#2.
const HARDHAT_KEYS: [&str; 3] = [
    concat!(
        "0xac0974bec39a17e3",
        "6ba4a6b4d238ff94",
        "4bacb478cbed5efc",
        "ae784d7bf4f2ff80"
    ),
    concat!(
        "0x59c6995e998f97a5",
        "a0044966f0945389",
        "dc9e86dae88c7a84",
        "12f4603b6b78690d"
    ),
    concat!(
        "0x5de4111afa1a4b94",
        "908f83103eb1f170",
        "6367c2e68ca870fc",
        "3fb9a804cdab365a"
    ),
];

/// Deterministic pseudo-random bytes (SplitMix64).
fn random_bytes(seed: u64, length: usize) -> Vec<u8> {
    let mut state = seed;
    (0..length)
        .map(|_| {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut mixed = state;
            mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            (mixed ^ (mixed >> 31)) as u8
        })
        .collect()
}

#[test]
fn documented_example_values_are_silent() {
    let key = hex(WIKI_WIF_KEY);
    let body = ed25519_pkcs8(&hex(RFC8410_KEY));
    for text in [
        format!("[default]\naws_access_key_id = {AWS_ACCESS_KEY_ID}\n"),
        format!("[default]\naws_secret_access_key = {AWS_SECRET_ACCESS_KEY}\n"),
        format!("wallet:\n  btc_wif: \"{}\"\n", wif(&key, false)),
        format!("WALLET_WIF={}\n", wif(&key, true)),
        format!("Schlüsseldatei (RFC 8410):\n{}\n", pem(&body)),
        format!(
            "{{\"signing_key\": \"{}\"}}",
            pem(&body).replace('\n', "\\n")
        ),
        format!(
            "GET /v1/me HTTP/1.1\nAuthorization: Bearer {}\n",
            jwt_io_token()
        ),
        format!("ID_TOKEN={}\n", jwt_io_token()),
        format!("Das Token aus der Doku: {}", jwt_io_token()),
        format!("{{\"access_token\": \"{}\"}}", rfc7515_token()),
    ] {
        assert_silent(&text);
    }
}

#[test]
fn documented_jwt_claims_are_silent_with_any_header_and_signature() {
    for (header, claims) in [
        (
            r#"{"alg":"RS256","typ":"JWT"}"#,
            r#"{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}"#,
        ),
        (
            r#"{"alg":"ES256","typ":"JWT"}"#,
            r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#,
        ),
        (
            r#"{"alg":"ES256"}"#,
            "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}",
        ),
    ] {
        let token = format!(
            "{}.{}.{}",
            base64url(header.as_bytes()),
            base64url(claims.as_bytes()),
            base64url(&random_bytes(7, 64))
        );
        assert_silent(&format!("Authorization: Bearer {token}"));
        assert_silent(&format!("const token = \"{token}\";"));
    }
}

#[test]
fn same_shapes_with_other_values_stay_live_findings() {
    let other_wif = wif(&random_bytes(11, 32), true);
    assert_reported(
        &format!("WALLET_WIF={other_wif}\n"),
        "dlp_btc_wif",
        &other_wif,
        "live",
    );
    let other_pem = pem(&ed25519_pkcs8(&random_bytes(12, 32)));
    assert_reported(
        &format!("{other_pem}\n"),
        "dlp_private_key_block",
        &other_pem,
        "live",
    );
    // Documented claims with one value changed are no example.
    for claims in [
        r#"{"sub":"1234567890","name":"Jane Roe","iat":1516239022}"#,
        r#"{"sub":"u-48151623","name":"John Doe","iat":1760000000}"#,
        r#"{"iss":"joe","exp":1900000000}"#,
    ] {
        let token = jws(
            br#"{"alg":"HS256","typ":"JWT"}"#,
            claims.as_bytes(),
            &random_bytes(13, 32),
        );
        assert_reported(
            &format!("ID_TOKEN={token}\n"),
            "dlp_jwt_token",
            &token,
            "live",
        );
    }
    let other_key = format!(
        "0x{}",
        random_bytes(14, 32)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    assert_reported(
        &format!("wallet private key: {other_key}"),
        "dlp_eth_private_key",
        &other_key,
        "live",
    );
}

#[test]
fn publicly_known_test_keys_report_severity_test() {
    for key in HARDHAT_KEYS {
        assert_reported(
            &format!("wallet private key: {key}"),
            "dlp_eth_private_key",
            key,
            "test",
        );
        assert_reported(
            &format!("# Hardhat-Konto für lokale Tests\nDEPLOYER_KEY={key}\n"),
            "dlp_eth_private_key",
            key,
            "test",
        );
    }
}

fn sha256_hex(text: &str) -> String {
    digest::digest(&digest::SHA256, text.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn documented_values_yaml_lists_exactly_the_built_values() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("research/dlp/documented_values.yaml");
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(yaml["schema"], "ark-dlp-documented-values-v1");
    let key = hex(WIKI_WIF_KEY);
    let built: BTreeSet<String> = [
        AWS_ACCESS_KEY_ID.to_owned(),
        AWS_SECRET_ACCESS_KEY.to_owned(),
        wif(&key, false),
        wif(&key, true),
        ed25519_pkcs8(&hex(RFC8410_KEY)),
    ]
    .into_iter()
    .chain(
        HARDHAT_KEYS
            .iter()
            .map(|key| key.trim_start_matches("0x").to_owned()),
    )
    .map(|value| sha256_hex(&value))
    .collect();
    let mut listed = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for entry in yaml["values"].as_sequence().unwrap() {
        let id = entry["id"].as_str().unwrap();
        assert!(ids.insert(id.to_owned()), "duplicate id {id}");
        let rule_id = entry["rule_id"].as_str().unwrap();
        assert!(
            DLP_PATTERNS.iter().any(|rule| rule.name == rule_id),
            "{id}: unknown rule {rule_id}"
        );
        assert!(
            matches!(entry["kind"].as_str(), Some("example" | "test")),
            "{id}"
        );
        assert!(
            entry["source"].as_str().unwrap().starts_with("https://"),
            "{id}"
        );
        let sha256 = entry["sha256"].as_str().unwrap();
        assert!(
            sha256.len() == 64
                && sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "{id}"
        );
        listed.insert(sha256.to_owned());
    }
    assert_eq!(listed, built);
    for entry in yaml["jwt_claims"].as_sequence().unwrap() {
        let id = entry["id"].as_str().unwrap();
        assert!(ids.insert(id.to_owned()), "duplicate id {id}");
        assert!(
            entry["claims"].as_mapping().unwrap().len() >= 2,
            "{id}: one claim alone is too weak"
        );
        assert!(
            entry["source"].as_str().unwrap().starts_with("https://"),
            "{id}"
        );
    }
}
