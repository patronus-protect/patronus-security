// SPDX-License-Identifier: MIT OR Apache-2.0
//! F-STRUCT: structure of JWTs and private key blocks.
//!
//! A JWT is reported only when its header decodes to a JSON object with a
//! string `alg` and its claims to a JSON object (`jwt_parse`); an empty
//! signature only for an unsecured token (`alg` `none`, RFC 7519 section 6),
//! which the result flags with `jwt_alg`. Supabase and Firebase service
//! tokens name their provider from the claims.
//!
//! A private key block is reported only when its body decodes to the
//! structure its armor names: the DER of PKCS#1 RSA, DSA, SEC1 EC, PKCS#8
//! and encrypted PKCS#8 keys (RFC 7468), an `openssh-key-v1` blob (OpenSSH
//! PROTOCOL.key), a secret-key packet (RFC 4880) or the key lines of a
//! PuTTY PPK file. The result reports whether the key is encrypted (OpenSSH
//! cipher with bcrypt KDF, encrypted PKCS#8, OpenSSL `Proc-Type` headers,
//! PPK `Encryption`).
use std::ops::Range;

use crate::detectors::validators::{
    base64_decode, der_integer_ok, der_parse, der_sequence, jwt_parse, Base64Kind, DerElement, Jwt,
};

/// The JWT that `dlp_jwt_token` reports for `value`: a parsed compact JWS
/// whose signature is present or whose `alg` is `none`.
pub(super) fn jwt_token(value: &str) -> Option<Jwt> {
    jwt_parse(value).filter(|jwt| !jwt.signature.is_empty() || jwt.header.is_unsecured())
}

pub(super) fn is_jwt_token(value: &str) -> bool {
    jwt_token(value).is_some()
}

/// Audience of Firebase custom tokens (Admin SDK `createCustomToken`).
const FIREBASE_CUSTOM_TOKEN_AUD: &str =
    "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";
/// Issuer prefix of Firebase ID tokens.
const FIREBASE_ID_TOKEN_ISS: &str = "https://securetoken.google.com/";

/// Provider of a service JWT from its claims: Supabase API keys carry
/// `iss` `supabase`, Firebase custom tokens the Identity Toolkit audience
/// and ID tokens the securetoken issuer.
fn jwt_provider(jwt: &Jwt) -> Option<&'static str> {
    let claim = |name: &str| jwt.claims.get(name).and_then(|value| value.as_str());
    if claim("iss") == Some("supabase") {
        Some("supabase")
    } else if claim("aud") == Some(FIREBASE_CUSTOM_TOKEN_AUD)
        || claim("iss").is_some_and(|iss| iss.starts_with(FIREBASE_ID_TOKEN_ISS))
    {
        Some("firebase")
    } else {
        None
    }
}

/// What a private key block holds beyond its armor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct KeyFacts {
    /// Whether the key material is encrypted; `None` where the format does
    /// not tell it without parsing the key itself (PGP).
    pub encrypted: Option<bool>,
}

const UNENCRYPTED: Option<KeyFacts> = Some(KeyFacts {
    encrypted: Some(false),
});
const ENCRYPTED: Option<KeyFacts> = Some(KeyFacts {
    encrypted: Some(true),
});

/// Upper bound of a key block the checks read (a 16384-bit RSA key in PEM
/// is about 13 KiB).
const MAX_BLOCK: usize = 32 * 1024;

/// The structure of a `dlp_private_key_block` match: a PEM block or a PuTTY
/// PPK file.
pub(super) fn private_key(block: &str) -> Option<KeyFacts> {
    if block.len() > MAX_BLOCK {
        return None;
    }
    if block.starts_with("PuTTY-User-Key-File-") {
        return putty_key(block);
    }
    let rest = block.strip_prefix("-----BEGIN")?;
    let (label, rest) = rest.split_once("-----")?;
    let (body, _) = rest.split_once("-----END")?;
    let label = label.split_whitespace().collect::<Vec<_>>().join(" ");
    let (data, encrypted_headers) = body_data(body, label == "PGP PRIVATE KEY BLOCK");
    let der = base64_decode(&data, Base64Kind::Standard)?;
    if encrypted_headers {
        return (matches!(
            label.as_str(),
            "RSA PRIVATE KEY" | "DSA PRIVATE KEY" | "EC PRIVATE KEY"
        ) && der.len() >= 16)
            .then_some(KeyFacts {
                encrypted: Some(true),
            });
    }
    match label.as_str() {
        "RSA PRIVATE KEY" => integer_sequence(&der, 9),
        "DSA PRIVATE KEY" => integer_sequence(&der, 6),
        "EC PRIVATE KEY" => sec1_key(&der),
        "PRIVATE KEY" => pkcs8_key(&der),
        "ENCRYPTED PRIVATE KEY" => encrypted_pkcs8_key(&der),
        "OPENSSH PRIVATE KEY" => openssh_key(&der),
        "PGP PRIVATE KEY BLOCK" => pgp_secret_key(&der),
        _ => None,
    }
}

/// H01: the decoded body of a PEM private key block (DER, OpenSSH or PGP
/// packets) given without its armor lines, for the example check on the key
/// octets.
pub(super) fn private_key_payload(body: &str) -> Option<Vec<u8>> {
    if body.len() > MAX_BLOCK {
        return None;
    }
    base64_decode(&body_data(body, true).0, Base64Kind::Standard)
}

/// The base64 data of a PEM body with real or escaped line breaks and
/// whether RFC 1421 headers mark it as encrypted; `pgp` drops the CRC-24
/// line of an ASCII armor.
fn body_data(body: &str, pgp: bool) -> (String, bool) {
    let mut encrypted_headers = false;
    let mut data = String::with_capacity(body.len());
    for line in lines(body) {
        if let Some((name, value)) = line.split_once(':') {
            // RFC 1421 headers of OpenSSL-encrypted keys, RFC 4880 armor headers.
            encrypted_headers |= name.trim() == "Proc-Type" && value.contains("ENCRYPTED");
        } else if pgp && line.starts_with('=') && line.len() == 5 {
            // RFC 4880 section 6.2: the CRC-24 line closes the armor body.
        } else {
            data.push_str(line);
        }
    }
    (data, encrypted_headers)
}

/// Lines of a body with real or JSON-escaped line breaks (also doubly
/// escaped in notebooks), without the indentation, quotes and separators of
/// a string literal around them.
fn lines(body: &str) -> impl Iterator<Item = &str> {
    body.split(['\n', '\r'])
        .flat_map(|line| line.split("\\n"))
        .flat_map(|line| line.split("\\r"))
        .map(|line| {
            line.trim_matches(|c: char| {
                c.is_whitespace() || matches!(c, '"' | '\'' | '`' | ',' | ';' | '\\')
            })
        })
        .filter(|line| !line.is_empty())
}

/// PKCS#1 RSAPrivateKey (RFC 8017, two-prime: 9 INTEGERs, multi-prime with
/// version 1: more) and OpenSSL DSAPrivateKey (6 INTEGERs), version first.
fn integer_sequence(der: &[u8], count: usize) -> Option<KeyFacts> {
    let fields = der_sequence(der)?;
    let version_ok = matches!(fields.first()?.content, [0] | [1]);
    (fields.len() >= count
        && version_ok
        && fields
            .iter()
            .take(count)
            .all(|field| field.tag == 0x02 && der_integer_ok(field.content)))
    .then_some(KeyFacts {
        encrypted: Some(false),
    })
}

/// RFC 5915 ECPrivateKey: version 1 and the private key OCTET STRING.
fn sec1_key(der: &[u8]) -> Option<KeyFacts> {
    match der_sequence(der)?.as_slice() {
        [DerElement {
            tag: 0x02,
            content: [1],
        }, DerElement {
            tag: 0x04,
            content: key,
        }, ..]
            if !key.is_empty() =>
        {
            UNENCRYPTED
        }
        _ => None,
    }
}

/// RFC 5958 OneAsymmetricKey: version 0 or 1, AlgorithmIdentifier with an
/// OID and the private key OCTET STRING.
fn pkcs8_key(der: &[u8]) -> Option<KeyFacts> {
    match der_sequence(der)?.as_slice() {
        [DerElement {
            tag: 0x02,
            content: [0] | [1],
        }, DerElement {
            tag: 0x30,
            content: algorithm,
        }, DerElement {
            tag: 0x04,
            content: key,
        }, ..]
            if has_oid(algorithm) && !key.is_empty() =>
        {
            UNENCRYPTED
        }
        _ => None,
    }
}

/// RFC 5958 EncryptedPrivateKeyInfo: AlgorithmIdentifier and ciphertext.
fn encrypted_pkcs8_key(der: &[u8]) -> Option<KeyFacts> {
    match der_sequence(der)?.as_slice() {
        [DerElement {
            tag: 0x30,
            content: algorithm,
        }, DerElement {
            tag: 0x04,
            content: ciphertext,
        }] if has_oid(algorithm) && !ciphertext.is_empty() => ENCRYPTED,
        _ => None,
    }
}

/// Whether an AlgorithmIdentifier's content starts with an OID.
fn has_oid(algorithm: &[u8]) -> bool {
    der_parse(algorithm).is_some_and(|fields| fields.first().is_some_and(|field| field.tag == 0x06))
}

/// OpenSSH PROTOCOL.key: `openssh-key-v1\0`, cipher, KDF and KDF options as
/// strings, at least one key. A key with cipher `none` needs KDF `none`;
/// an encrypted one a KDF (`bcrypt`).
fn openssh_key(raw: &[u8]) -> Option<KeyFacts> {
    let mut rest = raw.strip_prefix(b"openssh-key-v1\0")?;
    let cipher = ssh_string(&mut rest)?;
    let kdf = ssh_string(&mut rest)?;
    ssh_string(&mut rest)?;
    let keys = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?);
    if keys == 0 {
        return None;
    }
    match (cipher, kdf) {
        (b"none", b"none") => UNENCRYPTED,
        (b"none", _) | (_, b"none") => None,
        _ => ENCRYPTED,
    }
}

/// An SSH `string`: a big-endian u32 length and that many bytes.
fn ssh_string<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let length = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
    let value = rest.get(4..4usize.checked_add(length)?)?;
    *rest = &rest[4 + length..];
    Some(value)
}

/// RFC 4880 section 4.2: the first packet is a secret-key packet (tag 5)
/// whose length fits the data.
fn pgp_secret_key(raw: &[u8]) -> Option<KeyFacts> {
    let (&first, rest) = raw.split_first()?;
    let (tag, length) = if first & 0xc0 == 0xc0 {
        // New format: one-, two- or five-octet length.
        let length = match *rest.first()? {
            octet @ 0..=191 => usize::from(octet) + 2,
            octet @ 192..=223 => {
                ((usize::from(octet) - 192) << 8) + usize::from(*rest.get(1)?) + 192 + 3
            }
            255 => u32::from_be_bytes(rest.get(1..5)?.try_into().ok()?) as usize + 6,
            _ => return None,
        };
        (first & 0x3f, length)
    } else if first & 0x80 != 0 {
        // Old format: the length type in the low two bits.
        let octets = match first & 0x03 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => return None,
        };
        let length = rest
            .get(..octets)?
            .iter()
            .fold(0usize, |length, octet| (length << 8) | usize::from(*octet));
        ((first >> 2) & 0x0f, length + 1 + octets)
    } else {
        return None;
    };
    (tag == 5 && length <= raw.len()).then_some(KeyFacts { encrypted: None })
}

/// PuTTY PPK v2/v3: `Public-Lines` and `Private-Lines` counts of base64
/// lines that decode, and `Encryption` `none` or a cipher.
fn putty_key(file: &str) -> Option<KeyFacts> {
    let mut lines = lines(file);
    let mut encryption = None;
    let mut decoded = [false; 2];
    while let Some(line) = lines.next() {
        let Some((name, value)) = line.split_once(": ") else {
            continue;
        };
        let slot = match name {
            "Encryption" => {
                encryption = Some(value != "none");
                continue;
            }
            "Public-Lines" => 0,
            "Private-Lines" => 1,
            _ => continue,
        };
        let count: usize = value
            .parse()
            .ok()
            .filter(|count| (1..=64).contains(count))?;
        let data: String = lines.by_ref().take(count).collect();
        decoded[slot] =
            base64_decode(&data, Base64Kind::Standard).is_some_and(|key| !key.is_empty());
    }
    (decoded == [true, true]).then_some(KeyFacts {
        encrypted: Some(encryption?),
    })
}

/// `dlp_private_key_header`: a header line alone is a fragment of a key; a
/// header that opens a block (an END line follows) needs a key body, which
/// `dlp_private_key_block` then reports.
pub(super) fn is_key_header(text: &str, range: Range<usize>) -> bool {
    let rest = &text[range.end..];
    let mut window = rest.len().min(MAX_BLOCK);
    while !rest.is_char_boundary(window) {
        window -= 1;
    }
    let rest = &rest[..window];
    let Some(end) = rest.find("-----END") else {
        return true;
    };
    if rest[..end].contains("-----BEGIN") {
        return true;
    }
    let close = rest[end + 8..]
        .find("-----")
        .map_or(rest.len(), |offset| end + 8 + offset + 5);
    private_key(&text[range.start..range.end + close]).is_some()
}

/// Facts the result reports beyond the rule's metadata.
pub(super) fn details(rule_id: &str, value: &str) -> Vec<(&'static str, serde_json::Value)> {
    match rule_id {
        "dlp_jwt_token" => jwt_token(value).map_or_else(Vec::new, |jwt| {
            let mut details = vec![("jwt_alg", jwt.header.alg.clone().into())];
            if let Some(provider) = jwt_provider(&jwt) {
                details.push(("provider", provider.into()));
            }
            details
        }),
        "dlp_private_key_block" => private_key(value)
            .and_then(|facts| facts.encrypted)
            .map_or_else(Vec::new, |encrypted| {
                vec![("key_encrypted", encrypted.into())]
            }),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssh_string(value: &[u8]) -> Vec<u8> {
        let mut out = (value.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(value);
        out
    }

    fn openssh(cipher: &[u8], kdf: &[u8], keys: u32) -> Vec<u8> {
        let mut raw = b"openssh-key-v1\0".to_vec();
        raw.extend(ssh_string(cipher));
        raw.extend(ssh_string(kdf));
        raw.extend(ssh_string(b""));
        raw.extend(keys.to_be_bytes());
        raw
    }

    #[test]
    fn openssh_cipher_and_kdf_decide_encryption() {
        assert_eq!(openssh_key(&openssh(b"none", b"none", 1)), UNENCRYPTED);
        assert_eq!(
            openssh_key(&openssh(b"aes256-ctr", b"bcrypt", 1)),
            ENCRYPTED
        );
        assert_eq!(openssh_key(&openssh(b"none", b"bcrypt", 1)), None);
        assert_eq!(openssh_key(&openssh(b"aes256-ctr", b"none", 1)), None);
        assert_eq!(openssh_key(&openssh(b"none", b"none", 0)), None);
        assert_eq!(openssh_key(b"openssh-key-v2\0"), None);
    }

    #[test]
    fn pgp_needs_a_secret_key_packet_that_fits() {
        // New format (0xc5) and old format (0x95, two-octet length).
        assert!(pgp_secret_key(&[0xc5, 2, 4, 0]).is_some());
        assert!(pgp_secret_key(&[0x95, 0, 2, 4, 0]).is_some());
        // Public-key packet (tag 6), a length beyond the data, no packet.
        assert!(pgp_secret_key(&[0xc6, 2, 4, 0]).is_none());
        assert!(pgp_secret_key(&[0xc5, 9, 4, 0]).is_none());
        assert!(pgp_secret_key(&[0x05, 2, 4, 0]).is_none());
    }

    #[test]
    fn der_shapes_per_pem_type() {
        // SEQUENCE { INTEGER 1, OCTET STRING } (SEC1) and the same as a SET.
        assert_eq!(sec1_key(&[0x30, 6, 2, 1, 1, 4, 1, 7]), UNENCRYPTED);
        assert_eq!(sec1_key(&[0x31, 6, 2, 1, 1, 4, 1, 7]), None);
        // PKCS#8: version, AlgorithmIdentifier with an OID, key.
        let pkcs8 = [0x30, 12, 2, 1, 0, 0x30, 4, 6, 2, 0x2b, 0x65, 4, 1, 7];
        assert_eq!(pkcs8_key(&pkcs8), UNENCRYPTED);
        assert_eq!(pkcs8_key(&pkcs8[..13]), None);
        // EncryptedPrivateKeyInfo: AlgorithmIdentifier and ciphertext only.
        let encrypted = [0x30, 9, 0x30, 4, 6, 2, 0x2b, 0x65, 4, 1, 7];
        assert_eq!(encrypted_pkcs8_key(&encrypted), ENCRYPTED);
        assert_eq!(encrypted_pkcs8_key(&pkcs8), None);
        // RSA needs nine minimal non-negative INTEGERs, version 0 first.
        let mut rsa = vec![0x30, 27];
        (0..9).for_each(|_| rsa.extend([2, 1, 0]));
        assert_eq!(integer_sequence(&rsa, 9), UNENCRYPTED);
        assert_eq!(integer_sequence(&rsa[..26], 9), None);
        rsa[4] = 0x80;
        assert_eq!(integer_sequence(&rsa, 9), None);
    }

    #[test]
    fn body_lines_drop_escapes_quotes_and_armor_headers() {
        let collected: Vec<&str> =
            lines("\\nAAAA\\n  \"BBBB\",\r\n  CCCC==\n\\\\nDDDD\\\\n").collect();
        assert_eq!(collected, ["AAAA", "BBBB", "CCCC==", "DDDD"]);
    }

    #[test]
    fn private_key_payload_decodes_wrapped_and_escaped_bodies() {
        let raw = openssh(b"none", b"none", 1);
        // Base64 of `raw`, wrapped after 20 characters below.
        let (head, tail) = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB".split_at(20);
        for body in [
            format!("\n{head}\n{tail}\n"),
            format!("\\n{head}\\n{tail}\\n"),
        ] {
            assert_eq!(private_key_payload(&body), Some(raw.clone()), "{body}");
        }
        assert_eq!(private_key_payload("\n...\n"), None);
    }
}
