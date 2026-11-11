// SPDX-License-Identifier: GPL-3.0-only
//! JWT and PEM structure (F-STRUCT). `dlp_jwt_token` decodes the header to a
//! JSON object with `alg` and the claims to a JSON object; unsecured tokens
//! (`alg` `none`, empty signature) are reported with `jwt_alg` `none`, and
//! Supabase service-role and Firebase custom tokens name their provider.
//! `dlp_private_key_block` checks the body of every PEM type (PKCS#1, PKCS#8,
//! ENCRYPTED, EC, DSA, OPENSSH, PGP PRIVATE KEY BLOCK) and PuTTY PPK files
//! structurally and reports whether the key is encrypted (OpenSSH bcrypt
//! KDF). `dlp_private_key_header` keeps a bare header line but not armor
//! around a body that is no key. Values come from the golden generator or
//! are built here at test time.

use patronus_ark::detectors::score::ValidatorStrength;
use std::path::Path;
use std::sync::OnceLock;

use patronus_ark::{
    detectors::dlp::dlp::DLP_PATTERNS,
    golden_recipes::{materialize, GeneratorSet, SecretRecipe},
    SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};
use serde_json::Value;

/// Rules, their generators and lookalike generators (broken header or DER).
const RULES: &[(&str, &[&str], &[&str])] = &[
    (
        "dlp_jwt_token",
        &[
            "jwt_signed_hs256",
            "jwt_signed_rs256",
            "jwt_unsecured_none",
            "jwt_supabase_service_role",
            "jwt_firebase_custom_token",
        ],
        &[
            "jwt_header_no_alg",
            "jwt_claims_not_json",
            "jwt_empty_signature",
        ],
    ),
    (
        "dlp_private_key_block",
        &[
            "pem_pkcs8_ed25519_private_key",
            "pem_pkcs1_rsa_private_key",
            "pem_sec1_ec_private_key",
            "pem_dsa_private_key",
            "pem_openssh_ed25519_private_key",
            "pem_pkcs8_encrypted_private_key",
            "pem_openssh_ed25519_encrypted",
            "pgp_private_key_block",
            "putty_ppk_ed25519",
        ],
        &[
            "pem_pkcs1_rsa_bad_der",
            "pem_rsa_armor_ellipsis",
            "pem_openssh_armor_placeholder",
        ],
    ),
];

/// DE and EN carriers: .env, YAML, JSON (escaped line breaks), code, CLI, log
/// and prose. `true` marks carriers that hold the value as a JSON string.
const CARRIERS: &[(&str, bool)] = &[
    ("# Zugang für den Dienst\nSERVICE_SECRET={}\n", false),
    ("service:\n  secret: |\n{}\n", false),
    ("{\"service\": {\"secret\": \"{}\"}}\n", true),
    ("SERVICE_SECRET = \"\"\"\n{}\n\"\"\"\n", false),
    ("$ cat ./secrets/service\n{}\n$ ls\n", false),
    ("2026-11-07T06:12:44Z DEBUG svc: geladen\n{}\n", false),
    (
        "Das Geheimnis des Dienstes lautet:\n{}\nBitte im Tresor ablegen.\n",
        false,
    ),
    (
        "Hi Sam, here is the service secret:\n\n{}\n\nThanks!\n",
        false,
    ),
];

/// A carrier without a key name, where only the structure tells a value apart.
const NEUTRAL_CARRIER: &str = "2026-11-07T06:12:44Z WARN loader: rejected (wrong shape)\n{}\n";

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

/// The unsuppressed `matched_rules` entry of `rule_id` in `text`.
fn rule_entry(text: &str, rule_id: &str) -> Option<Value> {
    scan(text).layers[0]
        .details
        .get("matched_rules")
        .and_then(|rules| rules.as_array())
        .and_then(|rules| {
            rules
                .iter()
                .find(|rule| rule["rule_id"] == rule_id && rule.get("suppressed_by").is_none())
                .cloned()
        })
}

fn rule_hit(text: &str, rule_id: &str) -> bool {
    rule_entry(text, rule_id).is_some()
}

fn reports_any(text: &str) -> bool {
    !scan(text).evidence_spans.is_empty()
}

/// Whether a span covers exactly `value`.
fn reports(text: &str, value: &str) -> bool {
    scan(text)
        .evidence_spans
        .iter()
        .any(|span| span.text == value)
}

fn in_carrier(carrier: &(&str, bool), value: &str) -> (String, String) {
    let value = if carrier.1 {
        value.replace('\n', "\\n")
    } else {
        value.to_owned()
    };
    (carrier.0.replace("{}", &value), value)
}

#[test]
fn generated_values_are_reported_whole_in_de_and_en_carriers() {
    for (rule_id, gens, _) in RULES {
        for gen in *gens {
            for seed in 0..4 {
                let value = generated(gen, seed);
                for (index, carrier) in CARRIERS.iter().enumerate() {
                    let (text, value) = in_carrier(carrier, &value);
                    assert!(rule_hit(&text, rule_id), "{gen}/{seed}: carrier {index}");
                    assert!(reports(&text, &value), "{gen}/{seed}: carrier {index}");
                }
            }
        }
    }
}

#[test]
fn lookalikes_with_a_broken_header_or_der_are_not_reported() {
    for (rule_id, _, lookalikes) in RULES {
        for gen in *lookalikes {
            for seed in 0..6 {
                let value = generated(gen, seed);
                for (index, carrier) in CARRIERS.iter().enumerate() {
                    let (text, _) = in_carrier(carrier, &value);
                    assert!(!rule_hit(&text, rule_id), "{gen}/{seed}: carrier {index}");
                }
                // Without a key name no other rule takes the value either.
                let text = NEUTRAL_CARRIER.replace("{}", &value);
                assert!(!reports_any(&text), "{gen}/{seed}: neutral carrier");
            }
        }
    }
}

#[test]
fn structure_rules_declare_validator_strength_structure() {
    for rule_id in ["dlp_jwt_token", "dlp_private_key_block"] {
        let rule = DLP_PATTERNS
            .iter()
            .find(|rule| rule.name == rule_id)
            .expect("rule exists");
        assert_eq!(
            rule.meta.validator_strength,
            ValidatorStrength::Structure,
            "{rule_id}"
        );
    }
}

/// Base64url without padding.
fn base64url(bytes: &[u8]) -> String {
    base64_with(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        bytes,
    )
}

/// Standard base64 with padding.
fn base64(bytes: &[u8]) -> String {
    let mut out = base64_with(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        bytes,
    );
    while !out.len().is_multiple_of(4) {
        out.push('=');
    }
    out
}

fn base64_with(alphabet: &[u8; 64], bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(alphabet[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// A JWT with `header` and `claims` JSON and the signature of a generated
/// HS256 token.
fn jwt(header: &str, claims: &str) -> String {
    let template = generated("jwt_signed_hs256", 2);
    let signature = template.rsplit('.').next().unwrap();
    format!(
        "{}.{}.{signature}",
        base64url(header.as_bytes()),
        base64url(claims.as_bytes())
    )
}

#[test]
fn jwt_header_shapes() {
    let claims = r#"{"sub":"4711","iat":1762495200}"#;
    let carrier = |token: &str| format!("id_token={token}\n");
    // Valid: any JOSE header with a string alg and JSON object claims.
    for header in [
        r#"{"alg":"HS256","typ":"JWT"}"#,
        r#"{"alg":"RS256"}"#,
        r#"{"typ":"at+jwt","alg":"ES256","kid":"k1"}"#,
        r#"{"alg":"EdDSA","typ":"JWT"}"#,
    ] {
        let token = jwt(header, claims);
        assert!(rule_hit(&carrier(&token), "dlp_jwt_token"), "{header}");
    }
    // Invalid: no alg, a non-string alg, a header that is no object or no
    // JSON, claims that are no object.
    for (header, claims) in [
        (r#"{"typ":"JWT"}"#, claims),
        (r#"{"alg":256,"typ":"JWT"}"#, claims),
        (r#"["alg","HS256"]"#, claims),
        (r#"{"alg":"HS256","typ":"JWT"}!"#, claims),
        (r#"{"alg":"HS256","typ":"JWT"}"#, r#"["sub","4711"]"#),
    ] {
        let token = jwt(header, claims);
        assert!(!rule_hit(&carrier(&token), "dlp_jwt_token"), "{header}");
    }
}

#[test]
fn unsecured_jwts_are_flagged_and_need_alg_none_for_an_empty_signature() {
    let value = generated("jwt_unsecured_none", 1);
    let text = format!("2026-11-07 WARN auth: accepted token {value} for /admin\n");
    let entry = rule_entry(&text, "dlp_jwt_token").expect("alg none token is reported");
    assert_eq!(entry["jwt_alg"], "none");
    assert!(reports(&text, &value));

    let signed = generated("jwt_signed_hs256", 1);
    let entry = rule_entry(&format!("id_token={signed}\n"), "dlp_jwt_token").expect("signed");
    assert_eq!(entry["jwt_alg"], "HS256");

    // A signed algorithm with the signature cut off is no issued token.
    let (unsigned, _) = signed.rsplit_once('.').unwrap();
    assert!(!rule_hit(
        &format!("id_token={unsigned}.\n"),
        "dlp_jwt_token"
    ));
}

#[test]
fn supabase_and_firebase_service_jwts_name_their_provider() {
    for (gen, provider) in [
        ("jwt_supabase_service_role", "supabase"),
        ("jwt_firebase_custom_token", "firebase"),
    ] {
        let value = generated(gen, 3);
        let entry = rule_entry(&format!("SERVICE_TOKEN={value}\n"), "dlp_jwt_token")
            .unwrap_or_else(|| panic!("{gen} is reported"));
        assert_eq!(entry["provider"], provider, "{gen}");
    }
    let plain = generated("jwt_signed_rs256", 3);
    let entry = rule_entry(&format!("id_token={plain}\n"), "dlp_jwt_token").expect("reported");
    assert!(entry.get("provider").is_none());
}

#[test]
fn private_keys_report_whether_they_are_encrypted() {
    for (gen, encrypted) in [
        ("pem_openssh_ed25519_private_key", false),
        ("pem_openssh_ed25519_encrypted", true),
        ("pem_pkcs8_ed25519_private_key", false),
        ("pem_pkcs8_encrypted_private_key", true),
        ("pem_pkcs1_rsa_private_key", false),
        ("putty_ppk_ed25519", false),
    ] {
        let value = generated(gen, 1);
        let entry = rule_entry(&format!("key:\n{value}\n"), "dlp_private_key_block")
            .unwrap_or_else(|| panic!("{gen} is reported"));
        assert_eq!(entry["key_encrypted"], encrypted, "{gen}");
    }
    // Legacy OpenSSL encryption of PKCS#1 keys: Proc-Type/DEK-Info headers.
    let rsa = generated("pem_pkcs1_rsa_private_key", 1);
    let (head, body) = rsa.split_once('\n').unwrap();
    let legacy = format!(
        "{head}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n\n{body}"
    );
    let entry = rule_entry(&format!("key:\n{legacy}\n"), "dlp_private_key_block")
        .expect("legacy encrypted RSA key is reported");
    assert_eq!(entry["key_encrypted"], true);
}

#[test]
fn public_keys_and_armor_without_a_key_body_are_not_reported() {
    for text in [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHB1YmxpYyBoYWxmIG9mIGEgZGVwbG95IGtleSBvbmx5 deploy@ci\n",
        "git.example.de,10.0.4.12 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGhvc3Qga2V5IG9mIHRoZSBnaXQgbWlycm9yLCBwdWIu\n",
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcHVibGljIGhhbGYgb2YgYSBzaWduaW5nIGtleSBvayE=\n-----END PUBLIC KEY-----\n",
        // Armor split with concat! so no committed line holds a whole private key block.
        concat!("-----BEGIN RSA ", "PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n"),
        concat!(
            "-----BEGIN OPENSSH ",
            "PRIVATE KEY-----\n<hier den privaten Schlüssel einfügen>\n-----END OPENSSH PRIVATE KEY-----\n"
        ),
        concat!(
            "-----BEGIN ",
            "PRIVATE KEY-----\nTUlJRXZnSUJBREFOQmdrcWhraUc5dzBCQVFFRkFBU0NCS2d3Z2dTa0FnRUFBb0lC\n-----END PRIVATE KEY-----\n"
        ),
        "Die Datei beginnt mit PuTTY-User-Key-File-3 und endet mit Private-MAC.\n",
    ] {
        assert!(!reports_any(text), "{text}");
    }
}

#[test]
fn a_bare_header_line_stays_a_fragment() {
    for text in [
        concat!(
            "effective config: ssh_private_key=-----BEGIN OPENSSH ",
            "PRIVATE KEY----- retries=3\n"
        ),
        concat!("Schlüsseldatei:\n-----BEGIN RSA ", "PRIVATE KEY-----\n"),
    ] {
        assert!(rule_hit(text, "dlp_private_key_header"), "{text}");
    }
}

#[test]
fn key_blocks_in_notebook_strings_with_doubly_escaped_line_breaks() {
    for gen in [
        "pem_pkcs8_ed25519_private_key",
        "pem_openssh_ed25519_private_key",
    ] {
        let value = generated(gen, 2).replace('\n', "\\\\n");
        let text = format!(
            "   \"source\": [\n    \"tls_private_key = \\\"{value}\\\"\\n\",\n    \"client.connect()\"\n   ]\n"
        );
        assert!(rule_hit(&text, "dlp_private_key_block"), "{gen}");
    }
}

/// A PEM block of `label` around `raw`, wrapped at 70 characters.
fn pem(label: &str, raw: &[u8]) -> String {
    let encoded = base64(raw);
    let body: Vec<&str> = encoded
        .as_bytes()
        .chunks(70)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect();
    // Armor built with format! so no committed line holds a private key block.
    format!(
        "-----BEGIN {label} {}-----\n{}\n-----END {label} {}-----",
        "PRIVATE KEY",
        body.join("\n"),
        "PRIVATE KEY"
    )
}

/// Pseudo-random key octets (xorshift).
fn key_octets(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 32) as u8
        })
        .collect()
}

fn ssh_string(value: &[u8]) -> Vec<u8> {
    [&(value.len() as u32).to_be_bytes()[..], value].concat()
}

/// An unencrypted `openssh-key-v1` ssh-ed25519 key (OpenSSH PROTOCOL.key).
fn openssh_ed25519(public: &[u8], secret: &[u8], comment: &[u8]) -> Vec<u8> {
    let key_type = ssh_string(b"ssh-ed25519");
    let mut private = [7u8, 7, 7, 7, 7, 7, 7, 7].to_vec();
    private.extend(&key_type);
    private.extend(ssh_string(public));
    private.extend(ssh_string(&[secret, public].concat()));
    private.extend(ssh_string(comment));
    let mut pad = 1;
    while !private.len().is_multiple_of(8) {
        private.push(pad);
        pad += 1;
    }
    let mut raw = b"openssh-key-v1\0".to_vec();
    for field in [&b"none"[..], b"none", b""] {
        raw.extend(ssh_string(field));
    }
    raw.extend(1u32.to_be_bytes());
    raw.extend(ssh_string(&[key_type, ssh_string(public)].concat()));
    raw.extend(ssh_string(&private));
    raw
}

#[test]
fn a_repeated_fill_in_the_key_comment_does_not_make_a_key_an_example() {
    // H01: the fill check reads key octets only, not the OpenSSH comment or
    // a PGP User ID.
    let comment = b"abcabcabcabcabcabc";
    for seed in 1..=20 {
        let openssh = pem(
            "OPENSSH",
            &openssh_ed25519(&key_octets(seed, 32), &key_octets(!seed, 32), comment),
        );
        // Secret-key packet (tag 5) and User ID packet (tag 13), new format.
        let mut pgp = vec![0xc5, 100, 4];
        pgp.extend(key_octets(seed, 99));
        pgp.extend([0xcd, 25]);
        pgp.extend(b"abcabcabcabc <ab@abc.abc>");
        let pgp = pem("PGP", &pgp).replace("PRIVATE KEY-----", "PRIVATE KEY BLOCK-----");
        for key in [openssh, pgp] {
            for template in [
                "Schlüssel des Abgleichdienstes:\n{}\n",
                "here is the key for the handover box:\n{}\n",
            ] {
                let text = template.replace("{}", &key);
                assert!(rule_hit(&text, "dlp_private_key_block"), "seed {seed}");
            }
        }
    }
    // A fill of the key octets stays a documentation example.
    let fill = |len| {
        b"EXAMPLEKEY"
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect::<Vec<_>>()
    };
    let example = pem(
        "OPENSSH",
        &openssh_ed25519(&fill(32), &fill(32), b"ci@host"),
    );
    assert!(!rule_hit(
        &format!("key:\n{example}\n"),
        "dlp_private_key_block"
    ));
}
