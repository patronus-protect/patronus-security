// SPDX-License-Identifier: GPL-3.0-only
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
