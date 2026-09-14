// SPDX-License-Identifier: GPL-3.0-only
mod detection;
mod obfuscation;
mod patterns;
mod prepared;
mod util;

pub(crate) use detection::*;

pub(crate) use prepared::NativeText;

pub(crate) use obfuscation::{base64_decode_text, slash_unicode_decode_lossy};
