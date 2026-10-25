// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bech32 (BIP 173) and Bech32m (BIP 350).

use super::charset::BECH32;

/// Maximum string length of BIP 173 (segwit addresses). Longer formats such as
/// Lightning invoices pass their own limit to [`bech32_decode_with_limit`].
pub const BECH32_MAX_LENGTH: usize = 90;

/// Maximum length of the human-readable part (BIP 173), whatever the total limit.
const BECH32_MAX_HRP_LENGTH: usize = 83;

const BECH32M_CONSTANT: u32 = 0x2bc8_30a3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bech32Variant {
    Bech32,
    Bech32m,
}

/// A decoded Bech32 string: lowercase human-readable part, 5-bit data words
/// without the six checksum words, and the checksum variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bech32 {
    pub hrp: String,
    pub data: Vec<u8>,
    pub variant: Bech32Variant,
}

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    const GENERATOR: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut checksum = 1u32;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x1ff_ffff) << 5) ^ u32::from(value);
        for (bit, generator) in GENERATOR.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

/// Decode a Bech32 or Bech32m string of at most [`BECH32_MAX_LENGTH`] characters.
pub fn bech32_decode(value: &str) -> Option<Bech32> {
    bech32_decode_with_limit(value, BECH32_MAX_LENGTH)
}

/// Decode a Bech32 or Bech32m string of at most `max_length` characters:
/// printable ASCII, not mixed case, a non-empty HRP of at most 83 characters
/// before the last `1` and at least six data characters that carry a valid checksum.
pub fn bech32_decode_with_limit(value: &str, max_length: usize) -> Option<Bech32> {
    if value.len() > max_length || !value.bytes().all(|byte| (33..=126).contains(&byte)) {
        return None;
    }
    let has_lower = value.bytes().any(|byte| byte.is_ascii_lowercase());
    let has_upper = value.bytes().any(|byte| byte.is_ascii_uppercase());
    if has_lower && has_upper {
        return None;
    }
    let value = value.to_ascii_lowercase();
    let separator = value.rfind('1')?;
    if separator == 0 || separator > BECH32_MAX_HRP_LENGTH || separator + 7 > value.len() {
        return None;
    }
    let (hrp, data) = (&value[..separator], &value[separator + 1..]);
    let data = data
        .bytes()
        .map(|byte| {
            BECH32
                .bytes()
                .position(|digit| digit == byte)
                .map(|v| v as u8)
        })
        .collect::<Option<Vec<u8>>>()?;
    let expanded = hrp
        .bytes()
        .map(|byte| byte >> 5)
        .chain(std::iter::once(0))
        .chain(hrp.bytes().map(|byte| byte & 31))
        .chain(data.iter().copied());
    let variant = match polymod(expanded) {
        1 => Bech32Variant::Bech32,
        BECH32M_CONSTANT => Bech32Variant::Bech32m,
        _ => return None,
    };
    Some(Bech32 {
        hrp: hrp.to_owned(),
        data: data[..data.len() - 6].to_vec(),
        variant,
    })
}

impl Bech32 {
    /// The data words regrouped into bytes (BIP 173 `convertbits(data, 5, 8, False)`).
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        convert_bits(&self.data, 5, 8, false)
    }
}

/// Regroup `from`-bit words into `to`-bit words (BIP 173 `convertbits`). With
/// `pad` the last word is zero-padded; without it, leftover bits must be zero
/// and fewer than `from`. Word sizes outside 1..=8 bits are rejected.
pub fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    if !(1..=8).contains(&from) || !(1..=8).contains(&to) {
        return None;
    }
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    let mut converted = Vec::with_capacity(data.len() * from as usize / to as usize + 1);
    let max_value = (1u32 << to) - 1;
    for value in data {
        let value = u32::from(*value);
        if value >> from != 0 {
            return None;
        }
        accumulator = (accumulator << from) | value;
        bits += from;
        while bits >= to {
            bits -= to;
            converted.push(((accumulator >> bits) & max_value) as u8);
        }
        accumulator &= (1 << bits) - 1;
    }
    if pad {
        if bits > 0 {
            converted.push(((accumulator << (to - bits)) & max_value) as u8);
        }
    } else if bits >= from || accumulator != 0 {
        return None;
    }
    Some(converted)
}
