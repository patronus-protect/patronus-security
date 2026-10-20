// SPDX-License-Identifier: GPL-3.0-only
//! Country-neutral contact and network identifiers: e-mail, IP and MAC addresses, E.164 phone numbers.
use super::{pii::PiiPattern, score::ValidatorStrength, validators};

// ── Email ────────────────────────────────────────────────────────────────
pub(super) const EMAIL: PiiPattern = PiiPattern {
    name: "pii_email",
    pattern: r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    entity_group: "EMAIL",
    validator: None,
    strength: ValidatorStrength::None,
    base_score: 70,
    captured_value: false,
    requires_context: false,
};

// ── IP-Adressen ─────────────────────────────────────────────────────────
pub(super) const IPV4: PiiPattern = PiiPattern {
    name: "pii_ipv4",
    pattern: r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    entity_group: "IP_ADDRESS",
    validator: Some(validators::ip_address),
    strength: ValidatorStrength::Format,
    base_score: 50,
    captured_value: false,
    requires_context: false,
};

pub(super) const IPV6_FULL: PiiPattern = PiiPattern {
    name: "pii_ipv6_full",
    pattern: r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b",
    entity_group: "IP_ADDRESS",
    validator: Some(validators::ip_address),
    strength: ValidatorStrength::Format,
    base_score: 50,
    captured_value: false,
    requires_context: false,
};

pub(super) const IPV6_COMPRESSED: PiiPattern = PiiPattern {
    name: "pii_ipv6_compressed",
    pattern: r"\b(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?\b",
    entity_group: "IP_ADDRESS",
    validator: Some(validators::ip_address),
    strength: ValidatorStrength::Format,
    base_score: 50,
    captured_value: false,
    requires_context: false,
};

pub(super) const IPV6_LOOPBACK: PiiPattern = PiiPattern {
    name: "pii_ipv6_loopback",
    pattern: r"::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?\b",
    entity_group: "IP_ADDRESS",
    validator: Some(validators::ip_address),
    strength: ValidatorStrength::Format,
    base_score: 40,
    captured_value: false,
    requires_context: false,
};

// ── Telefon ──────────────────────────────────────────────────────────────
pub(super) const PHONE_INTERNATIONAL: PiiPattern = PiiPattern {
    name: "pii_phone_international",
    pattern: r"\+[1-9](?:[\s./()\-]*\d){6,14}\b",
    entity_group: "PHONE",
    validator: Some(validators::unanchored_phone),
    strength: ValidatorStrength::Format,
    base_score: 40,
    captured_value: false,
    requires_context: false,
};

// ── MAC-Adresse ─────────────────────────────────────────────────────────
pub(super) const MAC_ADDRESS: PiiPattern = PiiPattern {
    name: "pii_mac_address",
    pattern: r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b|\b(?:[0-9a-f]{2}-){5}[0-9a-f]{2}\b",
    entity_group: "MAC_ADDRESS",
    validator: Some(validators::mac_address),
    strength: ValidatorStrength::Format,
    base_score: 55,
    captured_value: false,
    requires_context: false,
};
