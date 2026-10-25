// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bitcoin Base58 and Base58Check.

use super::charset::BASE58;

/// Decode Bitcoin Base58; leading `1` characters become zero bytes.
pub fn base58_decode(value: &str) -> Option<Vec<u8>> {
    let leading_zeros = value.bytes().take_while(|byte| *byte == b'1').count();
    // Little-endian base-256 digits, built by repeated multiply-add.
    let mut bytes: Vec<u8> = Vec::with_capacity(value.len());
    for byte in value.bytes() {
        let mut carry = BASE58.bytes().position(|digit| digit == byte)? as u32;
        for digit in bytes.iter_mut() {
            carry += u32::from(*digit) * 58;
            *digit = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut decoded = vec![0u8; leading_zeros];
    decoded.extend(bytes.iter().rev());
    Some(decoded)
}

/// Payload of a Base58Check string whose last four bytes are the first four
/// bytes of the double SHA-256 of the payload; `None` otherwise.
pub fn base58check_decode(value: &str) -> Option<Vec<u8>> {
    let mut raw = base58_decode(value)?;
    if raw.len() < 5 {
        return None;
    }
    let checksum = raw.split_off(raw.len() - 4);
    let digest = ring::digest::digest(
        &ring::digest::SHA256,
        ring::digest::digest(&ring::digest::SHA256, &raw).as_ref(),
    );
    (digest.as_ref()[..4] == checksum[..]).then_some(raw)
}
