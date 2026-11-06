// SPDX-License-Identifier: GPL-3.0-only
//! Base58Check encoding (double SHA-256) for the key vectors of the wallet
//! key tests.

use patronus_ark::detectors::validators::BASE58;

pub fn base58check_encode(payload: &[u8]) -> String {
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
