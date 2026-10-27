// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::detectors::{dlp::score::DlpMode, pii::score::PiiMode};

/// Per-call native policy. Hosts can adapt their existing gates without copying them.
pub trait NativePolicy {
    fn allows_model(&self, id: &str) -> bool;
    fn allows_rule(&self, id: &str) -> bool;
    fn explain(&self) -> bool;
    fn pii_mode(&self) -> PiiMode;
    fn dlp_mode(&self) -> DlpMode;
}
