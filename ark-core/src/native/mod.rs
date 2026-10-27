// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reusable native producers shared by synchronous scanners and host adapters.
//! Hosts retain category selection, result mapping, aggregation and failure policy.
mod engine;
mod policy;
mod registry;

pub use engine::{NativeEngine, NativeProducerOutcome};
pub use policy::NativePolicy;
pub use registry::NativeProducerSpec;
