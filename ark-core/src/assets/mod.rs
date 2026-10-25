//! Shared model asset preparation; network access requires the `download` feature.
pub mod compact_tokenizer;
#[cfg(feature = "download")]
pub mod download;
pub mod mmbert_tokenizer;
