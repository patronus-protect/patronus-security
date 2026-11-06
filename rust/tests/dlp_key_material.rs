// SPDX-License-Identifier: GPL-3.0-only
//! Key material in config and code (C-KEYS). `dlp_jwk_private_key`: a JSON
//! Web Key with `kty` and its private member (`d`, or `k` of `oct` keys,
//! RFC 7517/7518/8037); `dlp_wireguard_private_key`: a `PrivateKey` or
//! `PresharedKey` of 32 bytes in base64; `dlp_openvpn_static_key`: the
//! `--genkey secret` block of 16 lines of 32 hex digits;
//! `dlp_ipsec_psk`: the quoted `PSK` of an ipsec.secrets entry;
//! `dlp_symmetric_key`: an AES/HMAC/encryption key of 16, 24 or 32 bytes as
//! hex, base64 or a `0x` byte array; `dlp_laravel_app_key` (`base64:` and
//! 16 or 32 bytes), `dlp_django_secret_key` (50 characters of Django's
//! alphabet) and `dlp_rails_secret_key_base` (128 hex digits). Public JWKs,
//! WireGuard public keys and published test vectors are no secrets. Values
//! come from the golden generator or are built here at test time.

use std::path::Path;
use std::sync::OnceLock;

use patronus_ark::{
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

fn generated(gen: &str, seed: u64) -> String {
    materialize(
        generators(),
        "<<secret:0>>",
        &[SecretRecipe::new(gen, seed)],
    )
    .expect("template must materialize")
    .0
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

/// Whether `rule_id` reported a value in `text` (unsuppressed).
fn rule_hit(text: &str, rule_id: &str) -> bool {
    scan(text).layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .is_some_and(|rules| {
            rules
                .iter()
                .any(|rule| rule["rule_id"] == rule_id && rule.get("suppressed_by").is_none())
        })
}

/// Whether a span covers exactly `value`.
fn reports(text: &str, value: &str) -> bool {
    scan(text)
        .evidence_spans
        .iter()
        .any(|span| span.text == value)
}

/// Rules, generators and DE/EN carriers (`{}` is the value).
const CASES: &[(&str, &str, &[&str])] = &[
    (
        "dlp_jwk_private_key",
        "jwk_okp_private_key",
        &[
            "{\"keys\": [{}]}\n",
            "signing_jwk.json:\n{}\n",
            "# Signaturschlüssel für den Token-Dienst\nJWT_SIGNING_JWK='{}'\n",
            "const jwk = {};\nconst key = await importJWK(jwk, 'EdDSA');\n",
        ],
    ),
    (
        "dlp_jwk_private_key",
        "jwk_ec_private_key",
        &["{\"keys\": [{}]}\n", "Hier der JWK aus dem Vault: {}\n"],
    ),
    (
        "dlp_jwk_private_key",
        "jwk_rsa_private_key",
        &["{\"keys\": [{}]}\n", "auth:\n  jwk: '{}'\n"],
    ),
    (
        "dlp_wireguard_private_key",
        "wireguard_private_key",
        &[
            "[Interface]\nAddress = 10.8.0.2/24\nPrivateKey = {}\nListenPort = 51820\n",
            "[Peer]\nPublicKey = AAAA\nPresharedKey = {}\n",
            "wireguard:\n  # Schlüssel des Gateways\n  private_key: \"{}\"\n",
            "{\"wg\": {\"privateKey\": \"{}\"}}\n",
            "WG_PRIVATE_KEY={}\n",
        ],
    ),
    (
        "dlp_openvpn_static_key",
        "openvpn_static_key",
        &[
            "client\nremote vpn.example.net 1194\n<tls-auth>\n{}\n</tls-auth>\nkey-direction 1\n",
            "# ta.key, nicht weitergeben\n{}\n",
        ],
    ),
    (
        "dlp_ipsec_psk",
        "ipsec_psk",
        &[
            "# /etc/ipsec.secrets\n%any %any : PSK \"{}\"\n",
            "192.0.2.10 198.51.100.7 : PSK \"{}\"\n",
            "Der Tunnel nutzt: : PSK \"{}\"\n",
        ],
    ),
    (
        "dlp_symmetric_key",
        "aes256_hex_key",
        &[
            "ENCRYPTION_KEY={}\n",
            "AES_KEY = bytes.fromhex(\"{}\")\n",
            "{\"crypto\": {\"aes_key\": \"{}\"}}\n",
            "# HMAC-Schlüssel für Webhooks\nwebhook_hmac_key: {}\n",
        ],
    ),
    (
        "dlp_symmetric_key",
        "fernet_key",
        &[
            "FERNET_KEY={}\n",
            "cipher = Fernet(b\"{}\")\nfernet_key = \"{}\"\n",
        ],
    ),
    (
        "dlp_laravel_app_key",
        "laravel_app_key",
        &[
            "APP_NAME=Shop\nAPP_ENV=production\nAPP_KEY={}\n",
            "'key' => env('APP_KEY', '{}'),\n",
            "Hallo, der App-Key der Produktion ist {} – bitte rotieren.\n",
        ],
    ),
    (
        "dlp_django_secret_key",
        "django_secret_key",
        &[
            "SECRET_KEY = '{}'\nDEBUG = False\n",
            "DJANGO_SECRET_KEY={}\n",
            "SECRET_KEY = os.environ.get(\"DJANGO_SECRET_KEY\", \"{}\")\n",
        ],
    ),
    (
        "dlp_rails_secret_key_base",
        "rails_secret_key_base",
        &[
            "production:\n  secret_key_base: {}\n",
            "SECRET_KEY_BASE={}\n",
            "config.secret_key_base = \"{}\"\n",
        ],
    ),
];

#[test]
fn generated_keys_are_reported_whole_in_de_and_en_carriers() {
    for (rule_id, gen, carriers) in CASES {
        for seed in 0..6 {
            let value = generated(gen, seed);
            for (index, template) in carriers.iter().enumerate() {
                let text = template.replace("{}", &value);
                assert!(
                    rule_hit(&text, rule_id),
                    "{rule_id} {gen}/{seed}: carrier {index}"
                );
                assert!(
                    reports(&text, &value),
                    "{rule_id} {gen}/{seed}: carrier {index}"
                );
            }
        }
    }
}

/// Lookalike generators and the carriers their rule must stay silent in.
const LOOKALIKES: &[(&str, &str, &str)] = &[
    (
        "dlp_jwk_private_key",
        "jwk_okp_public_key",
        "{\"keys\": [{}]}\n",
    ),
    (
        "dlp_wireguard_private_key",
        "wireguard_private_key_short",
        "[Interface]\nPrivateKey = {}\n",
    ),
    (
        "dlp_openvpn_static_key",
        "openvpn_static_key_short",
        "<tls-auth>\n{}\n</tls-auth>\n",
    ),
    (
        "dlp_symmetric_key",
        "sha1_hex_digest",
        "ENCRYPTION_KEY={}\n",
    ),
];

#[test]
fn lookalikes_are_not_reported() {
    for (rule_id, gen, template) in LOOKALIKES {
        for seed in 0..8 {
            let text = template.replace("{}", &generated(gen, seed));
            assert!(!rule_hit(&text, rule_id), "{rule_id}: {gen}/{seed}");
        }
    }
}

#[test]
fn jwk_needs_kty_and_its_private_member() {
    let private = generated("jwk_ec_private_key", 3);
    assert!(rule_hit(&private, "dlp_jwk_private_key"));
    // A public JWK, a JWK without kty and an unknown kty hold no private key.
    let without_d = private.replace("\"d\":", "\"z\":");
    let without_kty = private.replace("\"kty\":\"EC\",", "");
    let unknown_kty = private.replace("\"kty\":\"EC\"", "\"kty\":\"XYZ\"");
    // An oct key holds its secret in k, not in d.
    let oct_with_d = private.replace("\"kty\":\"EC\"", "\"kty\":\"oct\"");
    // d must be base64url of at least 16 bytes.
    let short_d = r#"{"kty":"OKP","crv":"Ed25519","d":"c2hvcnQ","x":"c2hvcnQ"}"#;
    for (index, text) in [without_d, without_kty, unknown_kty, oct_with_d]
        .iter()
        .map(String::as_str)
        .chain([short_d])
        .enumerate()
    {
        assert!(!rule_hit(text, "dlp_jwk_private_key"), "case {index}");
    }
    // JWKS documents keep their private keys inside "keys".
    let okp = generated("jwk_okp_private_key", 5);
    let jwks = format!("{{\"keys\": [{okp}, {private}]}}");
    assert!(reports(&jwks, &okp) && reports(&jwks, &private));
}

#[test]
fn published_test_vectors_are_no_secrets() {
    for (index, text) in [
        // RFC 8037 A.1 (Ed25519) and RFC 7517 A.2 (P-256) private keys.
        r#"{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
        r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}"#,
        // RFC 7517 A.3 symmetric key.
        r#"{"kty":"oct","alg":"A128KW","k":"GawgguFyGrWKav7AX4VKUg"}"#,
        // NIST SP 800-38A and FIPS-197 AES keys.
        "AES_KEY = bytes.fromhex(\"2b7e151628aed2a6abf7158809cf4f3c\")\n",
        "aes_key = \"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4\"\n",
        "static const uint8_t aes_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};\n",
    ]
    .iter()
    .enumerate()
    {
        assert!(scan(text).evidence_spans.is_empty(), "vector {index}");
    }
}

#[test]
fn wireguard_public_keys_are_no_secret() {
    let key = generated("wireguard_private_key", 7);
    let text = format!(
        "[Peer]\nPublicKey = {key}\nAllowedIPs = 10.8.0.0/24\nEndpoint = vpn.example.net:51820\n"
    );
    assert!(!rule_hit(&text, "dlp_wireguard_private_key"));
    assert!(scan(&text).evidence_spans.is_empty());
}

#[test]
fn symmetric_keys_in_code_are_read_from_byte_arrays() {
    let hex = generated("aes256_hex_key", 9);
    let bytes = (0..32)
        .map(|at| format!("0x{}", &hex[2 * at..2 * at + 2]))
        .collect::<Vec<_>>()
        .join(", ");
    for (index, text) in [
        format!("static const uint8_t AES_KEY[32] = {{{bytes}}};\n"),
        format!("const HMAC_KEY: [u8; 32] = [{bytes}];\n"),
        format!("byte[] encryptionKey = new byte[] {{{bytes}}};\n"),
    ]
    .iter()
    .enumerate()
    {
        assert!(rule_hit(text, "dlp_symmetric_key"), "array {index}");
    }
    // 20 bytes are no AES key, and an array under a non-key name is data.
    let short = bytes.split(", ").take(20).collect::<Vec<_>>().join(", ");
    for (index, text) in [
        format!("static const uint8_t AES_KEY[20] = {{{short}}};\n"),
        format!("static const uint8_t SBOX_ROW[32] = {{{bytes}}};\n"),
    ]
    .iter()
    .enumerate()
    {
        assert!(!rule_hit(text, "dlp_symmetric_key"), "non-key {index}");
    }
}

#[test]
fn framework_key_shapes_are_checked() {
    let laravel = generated("laravel_app_key", 1);
    // base64 of 24 bytes is no Laravel key.
    let wrong_length = format!("APP_KEY=base64:{}\n", &laravel[7..39]);
    assert!(!rule_hit(&wrong_length, "dlp_laravel_app_key"));
    // A Django key without a symbol is no get_random_secret_key() output.
    let django = generated("django_secret_key", 2);
    let plain = django
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { 'x' })
        .collect::<String>();
    assert!(!rule_hit(
        &format!("SECRET_KEY = '{plain}'\n"),
        "dlp_django_secret_key"
    ));
    // Rails needs 128 hex digits, not a SHA-256 digest.
    let rails = generated("rails_secret_key_base", 3);
    assert!(!rule_hit(
        &format!("secret_key_base: {}\n", &rails[..64]),
        "dlp_rails_secret_key_base"
    ));
}

#[test]
fn references_and_placeholders_are_no_keys() {
    for (index, text) in [
        "APP_KEY=\n",
        "APP_KEY=${LARAVEL_APP_KEY}\n",
        "SECRET_KEY = os.environ[\"DJANGO_SECRET_KEY\"]\n",
        "secret_key_base: <%= ENV[\"SECRET_KEY_BASE\"] %>\n",
        "[Interface]\nPrivateKey = <your-private-key>\n",
        "PostUp = wg set %i private-key /etc/wireguard/private.key\n",
        "%any : PSK \"${IPSEC_PSK}\"\n",
        "ENCRYPTION_KEY={{ vault_encryption_key }}\n",
        "{\"kty\":\"RSA\",\"n\":\"…\",\"e\":\"AQAB\"}\n",
    ]
    .iter()
    .enumerate()
    {
        assert!(scan(text).evidence_spans.is_empty(), "reference {index}");
    }
}
