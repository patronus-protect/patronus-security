// SPDX-License-Identifier: MIT OR Apache-2.0
mod detection;
mod obfuscation;
mod patterns;
mod prepared;
mod util;

pub use detection::*;

pub use prepared::{HiddenView, NativeText};

pub(crate) use obfuscation::{confusable_ascii, token_contains_unicode_confusable};
pub use obfuscation::{percent_decode_lossy, slash_unicode_decode_lossy};
