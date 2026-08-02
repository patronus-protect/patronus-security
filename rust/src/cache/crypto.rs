// SPDX-License-Identifier: GPL-3.0-only
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};

use super::{CacheEncryptionConfig, CacheError};

const ENCRYPTED_MAGIC: &[u8; 8] = b"ARKENC01";
const AES_256_GCM_ALGORITHM: u8 = 1;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = ENCRYPTED_MAGIC.len() + 1 + NONCE_LEN + 8 + 8;

pub(crate) struct CacheCrypto {
    value_key: LessSafeKey,
    index_key: [u8; 32],
    fingerprint: [u8; 32],
}

impl CacheCrypto {
    pub(crate) fn new(config: &CacheEncryptionConfig) -> Result<Self, CacheError> {
        let value_key_bytes = blake3::derive_key(
            "patronus ark persistent cache value encryption key v1",
            &config.key,
        );
        let index_key = blake3::derive_key(
            "patronus ark persistent cache index keyed hash key v1",
            &config.key,
        );
        let fingerprint = blake3::derive_key(
            "patronus ark persistent cache open registry fingerprint v1",
            &config.key,
        );
        let unbound = UnboundKey::new(&aead::AES_256_GCM, &value_key_bytes)
            .map_err(|_| CacheError::Storage("invalid cache encryption key".to_string()))?;
        Ok(Self {
            value_key: LessSafeKey::new(unbound),
            index_key,
            fingerprint,
        })
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub(crate) fn encrypt(
        &self,
        aad_domain: &[u8],
        aad_key: &[u8],
        created_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CacheError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| CacheError::Storage("failed to generate cache nonce".to_string()))?;

        let mut bytes =
            Vec::with_capacity(HEADER_LEN + plaintext.len() + aead::AES_256_GCM.tag_len());
        bytes.extend_from_slice(ENCRYPTED_MAGIC);
        bytes.push(AES_256_GCM_ALGORITHM);
        bytes.extend_from_slice(&nonce_bytes);
        bytes.extend_from_slice(&created_at_unix_ms.to_le_bytes());
        bytes.extend_from_slice(&expires_at_unix_ms.to_le_bytes());

        let aad = aad(aad_domain, aad_key, &bytes[..HEADER_LEN]);
        let mut body = plaintext.to_vec();
        self.value_key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(aad.as_slice()),
                &mut body,
            )
            .map_err(|_| CacheError::Storage("failed to encrypt cache record".to_string()))?;
        bytes.extend_from_slice(&body);
        Ok(bytes)
    }

    pub(crate) fn decrypt(
        &self,
        aad_domain: &[u8],
        aad_key: &[u8],
        bytes: &[u8],
    ) -> Result<Vec<u8>, CacheError> {
        if bytes.len() < HEADER_LEN + aead::AES_256_GCM.tag_len() {
            return Err(CacheError::InvalidRecord(
                "encrypted cache record is truncated".to_string(),
            ));
        }
        if &bytes[..ENCRYPTED_MAGIC.len()] != ENCRYPTED_MAGIC {
            return Err(CacheError::InvalidRecord(
                "cache record is not encrypted".to_string(),
            ));
        }
        if bytes[ENCRYPTED_MAGIC.len()] != AES_256_GCM_ALGORITHM {
            return Err(CacheError::InvalidRecord(
                "unsupported cache encryption algorithm".to_string(),
            ));
        }
        let nonce_start = ENCRYPTED_MAGIC.len() + 1;
        let nonce_end = nonce_start + NONCE_LEN;
        let nonce_bytes: [u8; NONCE_LEN] = bytes[nonce_start..nonce_end]
            .try_into()
            .expect("nonce slice has fixed length");

        let aad = aad(aad_domain, aad_key, &bytes[..HEADER_LEN]);
        let mut plaintext = bytes[HEADER_LEN..].to_vec();
        let plaintext = self
            .value_key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(aad.as_slice()),
                &mut plaintext,
            )
            .map_err(|_| CacheError::InvalidRecord("cache record decrypt failed".to_string()))?;
        Ok(plaintext.to_vec())
    }

    pub(crate) fn envelope_times(bytes: &[u8]) -> Result<(u64, u64), CacheError> {
        if bytes.len() < HEADER_LEN {
            return Err(CacheError::InvalidRecord(
                "encrypted cache record is truncated".to_string(),
            ));
        }
        if &bytes[..ENCRYPTED_MAGIC.len()] != ENCRYPTED_MAGIC {
            return Err(CacheError::InvalidRecord(
                "cache record is not encrypted".to_string(),
            ));
        }
        if bytes[ENCRYPTED_MAGIC.len()] != AES_256_GCM_ALGORITHM {
            return Err(CacheError::InvalidRecord(
                "unsupported cache encryption algorithm".to_string(),
            ));
        }
        let created_start = ENCRYPTED_MAGIC.len() + 1 + NONCE_LEN;
        let expires_start = created_start + 8;
        let created_at_unix_ms =
            u64::from_le_bytes(bytes[created_start..expires_start].try_into().unwrap());
        let expires_at_unix_ms =
            u64::from_le_bytes(bytes[expires_start..expires_start + 8].try_into().unwrap());
        Ok((created_at_unix_ms, expires_at_unix_ms))
    }

    pub(crate) fn index_keyed_hash(&self, value: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(&self.index_key, value).as_bytes()
    }
}

fn aad(domain: &[u8], key: &[u8], header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(domain.len() + key.len() + header.len() + 16);
    aad.extend_from_slice(&(domain.len() as u64).to_le_bytes());
    aad.extend_from_slice(domain);
    aad.extend_from_slice(&(key.len() as u64).to_le_bytes());
    aad.extend_from_slice(key);
    aad.extend_from_slice(header);
    aad
}
