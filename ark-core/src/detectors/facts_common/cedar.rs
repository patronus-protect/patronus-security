// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Cedar schemas of the facts documents (`.cedarschema` next to each
//! detector's data), parsed once.

use cedar_policy::Schema;

/// Parse a compiled-in `.cedarschema`; `what` names it in the panic message of
/// a broken build.
pub fn schema(source: &str, what: &str) -> Schema {
    Schema::from_cedarschema_str(source)
        .unwrap_or_else(|error| panic!("{what} Cedar schema: {error}"))
        .0
}
