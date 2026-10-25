// SPDX-License-Identifier: MIT OR Apache-2.0

/// A NANP extension right after the number (F18): `x4587` without a space after
/// the `x`, `ext 123`, `ext. 123`, `extension 12`, in any letter case. Letters
/// without digits are no extension, so a closing `\b` ends the span before them.
macro_rules! nanp_extension {
    () => {
        r"[ \t]?(?i:x|ext(?:ension)?\.?[ \t]?)\d{1,6}"
    };
}

mod au;
mod common;
pub mod context;
mod context_anchors;
mod de;
mod driver_license;
mod identifiers;
mod intl;
pub mod overlap;
#[allow(clippy::module_inception)]
pub mod pii;
pub mod score;
mod sg;
mod uk;
mod us;
pub mod validators;
mod vat;
