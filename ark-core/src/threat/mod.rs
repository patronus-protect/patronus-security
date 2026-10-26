// SPDX-License-Identifier: MIT OR Apache-2.0
mod detection;
mod obfuscation;
mod patterns;
mod prepared;
mod util;

pub use detection::*;

pub use prepared::NativeText;

pub use obfuscation::{base64_decode_text, percent_decode_lossy, slash_unicode_decode_lossy};
