// SPDX-License-Identifier: GPL-3.0-only
//! dlp_btc_wif validates Base58Check: mainnet version byte 0x80, a secp256k1
//! scalar and, for compressed keys, the 0x01 flag. Keys come from the golden
//! generator; invalid vectors are built here and are no keys.

use std::path::Path;
use std::sync::OnceLock;

use patronus_ark::{
    detectors::validators::BASE58,
    golden_recipes::{materialize, GeneratorSet, SecretRecipe},
    SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

fn generators() -> &'static GeneratorSet {
    static GENERATORS: OnceLock<GeneratorSet> = OnceLock::new();
    GENERATORS.get_or_init(|| {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        GeneratorSet::load(root.join("python/patronus_ark/dlp_synth/generators.json"))
            .expect("generator spec must load")
    })
}

fn wif(gen: &str, seed: u64) -> String {
    let (text, _) = materialize(
        generators(),
        "<<secret:0>>",
        &[SecretRecipe::new(gen, seed)],
    )
    .expect("template must materialize");
    text
}

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

fn reports_key(text: &str, value: &str) -> bool {
    scan(text)
        .evidence_spans
        .iter()
        .any(|span| span.label == "CRYPTO_KEY" && span.text == value)
}

fn base58check_encode(payload: &[u8]) -> String {
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        ring::digest::digest(&ring::digest::SHA256, payload).as_ref(),
    );
    let mut raw = payload.to_vec();
    raw.extend_from_slice(&digest.as_ref()[..4]);
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
    let alphabet = BASE58.as_bytes();
    std::iter::repeat_n('1', zeros)
        .chain(
            digits
                .iter()
                .rev()
                .map(|digit| alphabet[*digit as usize] as char),
        )
        .collect()
}

const CARRIERS: &[&str] = &[
    "BTC_WIF_KEY={}\n",
    "wallet:\n  wif: \"{}\"\n",
    "{\"wif\": \"{}\"}\n",
    "Der WIF-Schlüssel des Wallets lautet {}.\n",
    "importprivkey {} \"cold\"\n",
];

#[test]
fn generated_wif_keys_are_reported_in_de_and_en_carriers() {
    for gen in ["btc_wif_mainnet_uncompressed", "btc_wif_mainnet_compressed"] {
        for seed in 0..16 {
            let value = wif(gen, seed);
            for carrier in CARRIERS {
                let text = carrier.replace("{}", &value);
                assert!(reports_key(&text, &value), "{gen}/{seed}: {text:?}");
            }
        }
    }
}

#[test]
fn a_wrong_checksum_character_is_no_key() {
    let alphabet: Vec<char> = BASE58.chars().collect();
    for gen in ["btc_wif_mainnet_uncompressed", "btc_wif_mainnet_compressed"] {
        for seed in 0..16 {
            let value = wif(gen, seed);
            for index in [10, value.len() - 1] {
                let mut chars: Vec<char> = value.chars().collect();
                let position = alphabet.iter().position(|c| *c == chars[index]).unwrap();
                chars[index] = alphabet[(position + 1) % alphabet.len()];
                let broken: String = chars.into_iter().collect();
                for carrier in CARRIERS {
                    let text = carrier.replace("{}", &broken);
                    assert!(scan(&text).evidence_spans.is_empty(), "{text:?}");
                }
            }
        }
    }
}

#[test]
fn checksum_valid_strings_without_a_mainnet_key_are_no_key() {
    let mut scalar = [0x5a_u8; 32];
    scalar[0] = 0x3c;
    let with = |version: u8, scalar: &[u8], flag: Option<u8>| {
        let mut payload = vec![version];
        payload.extend_from_slice(scalar);
        payload.extend(flag);
        base58check_encode(&payload)
    };
    let order = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    // The construction itself yields a key the rule reports.
    let valid = with(0x80, &scalar, Some(0x01));
    assert!(reports_key(&format!("wif: {valid}\n"), &valid));
    let invalid = [
        with(0x80, &scalar, Some(0x02)), // compression flag other than 0x01
        with(0x80, &[0; 32], None),      // zero scalar
        with(0x80, &[0; 32], Some(0x01)),
        with(0x80, &order, None), // scalar = group order
        with(0x80, &[0xff; 32], Some(0x01)),
    ];
    for value in invalid {
        assert!(matches!(value.len(), 51 | 52), "{value}");
        for carrier in CARRIERS {
            let text = carrier.replace("{}", &value);
            assert!(!reports_key(&text, &value), "{text:?}");
        }
    }
}
