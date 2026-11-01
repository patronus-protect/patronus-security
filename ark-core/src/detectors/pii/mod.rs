// SPDX-License-Identifier: MIT OR Apache-2.0

/// A NANP extension right after the number (F18): `x4587` without a space after
/// the `x`, `ext 123`, `ext. 123`, `extension 12`, in any letter case. Letters
/// without digits are no extension, so a closing `\b` ends the span before them.
macro_rules! nanp_extension {
    () => {
        r"[ \t]?(?i:x|ext(?:ension)?\.?[ \t]?)\d{1,6}"
    };
}

mod at;
mod au;
mod be;
mod ca;
mod ch;
mod common;
pub mod context;
mod context_anchors;
mod de;
mod device;
mod driver_license;
mod es;
mod fin;
mod fr;
mod identifiers;
mod ie;
mod india;
mod intl;
mod it;
mod kr;
mod licence_plate;
mod nl;
mod nordic;
pub mod overlap;
#[allow(clippy::module_inception)]
pub mod pii;
mod pl;
mod pt;
pub mod score;
mod sg;
mod tr;
mod uk;
mod us;
pub mod validators;
mod vat;
mod za;
