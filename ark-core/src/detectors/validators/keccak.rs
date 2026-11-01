// SPDX-License-Identifier: MIT OR Apache-2.0
//! Keccak-256, the original Keccak padding (`0x01`) that Ethereum uses, not
//! the SHA3-256 padding (`0x06`) of FIPS 202.

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets of the rho step, indexed by lane `x + 5 * y`.
const ROTATIONS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// Bytes absorbed per permutation for a 256-bit digest.
const RATE: usize = 136;

fn keccak_f(state: &mut [u64; 25]) {
    for round_constant in ROUND_CONSTANTS {
        let mut parity = [0u64; 5];
        for (x, column) in parity.iter_mut().enumerate() {
            *column = (0..5).fold(0, |acc, y| acc ^ state[x + 5 * y]);
        }
        for x in 0..5 {
            let d = parity[(x + 4) % 5] ^ parity[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }
        let mut rotated = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] =
                    state[x + 5 * y].rotate_left(ROTATIONS[x + 5 * y]);
            }
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] = rotated[x + 5 * y]
                    ^ (!rotated[(x + 1) % 5 + 5 * y] & rotated[(x + 2) % 5 + 5 * y]);
            }
        }
        state[0] ^= round_constant;
    }
}

/// Keccak-256 digest of `data`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut state = [0u64; 25];
    let mut absorb = |block: &[u8; RATE]| {
        for (lane, word) in state.iter_mut().zip(block.chunks_exact(8)) {
            *lane ^= u64::from_le_bytes(word.try_into().unwrap());
        }
        keccak_f(&mut state);
    };
    let mut blocks = data.chunks_exact(RATE);
    for block in &mut blocks {
        absorb(block.try_into().unwrap());
    }
    let rest = blocks.remainder();
    let mut last = [0u8; RATE];
    last[..rest.len()].copy_from_slice(rest);
    last[rest.len()] ^= 0x01;
    last[RATE - 1] ^= 0x80;
    absorb(&last);
    let mut digest = [0u8; 32];
    for (out, lane) in digest.chunks_exact_mut(8).zip(state) {
        out.copy_from_slice(&lane.to_le_bytes());
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::keccak256;

    fn hex(bytes: [u8; 32]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn known_digests() {
        assert_eq!(
            hex(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex(keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
        // Exactly one block less one byte, one block and more than one block.
        assert_eq!(
            hex(keccak256(&[b'a'; 135])),
            "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446"
        );
        assert_eq!(
            hex(keccak256(&[b'a'; 136])),
            "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e"
        );
        assert_eq!(
            hex(keccak256(&[b'a'; 200])),
            "96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d"
        );
    }
}
