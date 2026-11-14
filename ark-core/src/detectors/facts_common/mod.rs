// SPDX-License-Identifier: MIT OR Apache-2.0
//! The contracts every facts document shares: shell commands
//! (`patronus.facts/1`, [`super::shell`]) and texts (`patronus.text_facts/1`,
//! [`super::text`]).
//!
//! - [`pyjson`]: the canonical JSON form, byte for byte as the Python
//!   reference writes it.
//! - [`fields`]: strict reading of a facts document back from JSON.
//! - [`tokens`]: facts flattened into model tokens (`F:<key>=<value>`) and the
//!   token list of an analyzer.
//! - [`model`]: the K26 model form (char_wb TF-IDF + analyzer tokens -> LR)
//!   shared by the shell-risk model and the text category models.
//! - [`cedar`]: loading the Cedar schema a facts document is checked against.

pub mod cedar;
pub(crate) mod fields;
pub mod model;
pub mod pyjson;
pub mod tokens;
