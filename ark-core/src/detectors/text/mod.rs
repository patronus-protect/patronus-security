// SPDX-License-Identifier: MIT OR Apache-2.0
//! `patronus.text_facts/1`: versioned, deterministic facts per text, the
//! common input of the category models and policies. Shaped like the
//! `patronus.facts/1` of a shell command ([`super::shell`]) and sharing its
//! contracts ([`super::facts_common`]): a canonical JSON form with a Python
//! reference (`scripts/l1_threat/text_facts.py`), a token analyzer ([`tf1`],
//! like `kf1`) and a Cedar schema (`data/text.cedarschema`).
//!
//! - [`facts`]: the facts of one text: the pattern findings with their
//!   modifiers, the carrier read from the text structure, the addressee, the
//!   sinks, the data references of PII/DLP hits, the obfuscation and decoding
//!   the normalisation pre-pass undid, the context terms and the language.
//! - [`tf1`]: lowercased word tokens plus the flattened facts.
//! - [`schema`]: the Cedar schema and the request context of a text.
//!
//! Only the text is read: request metadata (role, source) never feeds the
//! facts. Deterministic, no I/O.

pub mod facts;
mod schema;
mod tf1;

pub use facts::{data_refs, extract, DataRef, Finding, FindingFacts, Sink, TextFacts};
pub use schema::schema;
pub use tf1::{tf1, visit_tf1};
