// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reusable native producers shared by synchronous scanners and host adapters.
//! Hosts retain category selection, result mapping, aggregation and failure policy.
mod engine;
mod policy;
mod registry;

pub use engine::{NativeEngine, NativeProducerOutcome, NATIVE_CATEGORIES};
pub use policy::{default_rule_enabled, NativeGates, ScoreMode};
pub use registry::NativeProducerSpec;
