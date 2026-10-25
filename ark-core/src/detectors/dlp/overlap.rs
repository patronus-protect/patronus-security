// SPDX-License-Identifier: MIT OR Apache-2.0
//! K08: overlap resolution between secret findings.
//!
//! Where secret matches overlap, one span stays. Before the tiers decide, two
//! pair rules remove spans that describe the same value worse:
//!
//! - A span of the same tier that only adds quotes or a trailing `;`/`,` to a
//!   tighter span gives way to it (`'value'` from `dlp_env_var_secret` against
//!   `value` from the assignment rule).
//! - A substring artefact gives way to the value it lies in: a fixed-format
//!   match strictly inside a longer fixed-format value of another rule (a
//!   WIF-shaped Base58 run inside a Stripe key or a JWT), or a match of a rule
//!   without keywords strictly inside any longer secret value.
//!
//! Then the remaining spans are taken by tier ([`OverlapTier`]), validator
//! strength and registry order; a span that overlaps a taken one is
//! suppressed. Suppressed matches stay in `matched_rules` and name the rule
//! they gave way to in `suppressed_by`. Identifier and content rules have no
//! tier and keep overlapping spans as before (the first match per label).

use std::collections::BTreeMap;
use std::ops::Range;

use crate::detectors::first_match_per_range;
use crate::EvidenceSpan;

use super::dlp::{RuleMeta, ValidatorStrength};

/// Overlap tier of a secret rule; a lower tier keeps its span.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OverlapTier {
    /// Provider-bound formats and key material (providers, crypto, PEM).
    Provider,
    /// Platform-format tokens: JWT, bearer, CSRF, session cookie, URL signature.
    Token,
    /// Password hashes.
    Hash,
    /// Structural credentials: URL userinfo and parameters, Basic auth,
    /// connection strings and LDAP bind passwords (G01).
    Credential,
    /// Any value under a secret-like key or variable name.
    Generic,
}

impl OverlapTier {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Token => "token",
            Self::Hash => "hash",
            Self::Credential => "credential",
            Self::Generic => "generic",
        }
    }

    /// Fixed-format tiers prove the value's boundaries by its format.
    const fn is_fixed_format(self) -> bool {
        matches!(self, Self::Provider | Self::Token | Self::Hash)
    }
}

const fn strength_rank(strength: ValidatorStrength) -> u8 {
    match strength {
        ValidatorStrength::Checksum => 0,
        ValidatorStrength::Structure => 1,
        ValidatorStrength::Format => 2,
        ValidatorStrength::None => 3,
    }
}

/// Per-rule inputs of the resolution, indexed like the rule registry.
pub struct OverlapRules<'a> {
    pub rule_ids: &'a [&'static str],
    pub tiers: &'a [Option<OverlapTier>],
    pub metas: &'a [RuleMeta],
}

struct Secret {
    /// Position in the candidate list (= `matched_rules` index).
    position: usize,
    rule: usize,
    tier: OverlapTier,
    range: Range<usize>,
}

/// The spans that stay, in candidate order; marks suppressed secret matches in
/// `matched_rules` (same order as `candidates`).
pub fn resolve(
    text: &str,
    rules: &OverlapRules<'_>,
    candidates: Vec<(usize, EvidenceSpan)>,
    matched_rules: &mut [serde_json::Value],
) -> Vec<EvidenceSpan> {
    let mut secrets = Vec::new();
    let mut others = Vec::new();
    for (position, (rule, span)) in candidates.iter().enumerate() {
        match rules.tiers[*rule] {
            Some(tier) => secrets.push(Secret {
                position,
                rule: *rule,
                tier,
                range: span.start_byte..span.end_byte,
            }),
            None => others.push(position),
        }
    }
    let mut suppressed_by = vec![None; candidates.len()];
    resolve_secrets(text, rules, &mut secrets, &mut suppressed_by);

    for (position, winner) in suppressed_by.iter().enumerate() {
        if let (Some(winner), Some(entry)) = (winner, matched_rules.get_mut(position)) {
            entry["suppressed_by"] = rules.rule_ids[candidates[*winner].0].into();
        }
    }
    let mut kept_others = first_match_per_range(
        others
            .iter()
            .map(|&position| candidates[position].1.clone()),
        true,
    )
    .into_iter();
    let mut next_other = kept_others.next();
    let mut kept = Vec::with_capacity(candidates.len());
    for (position, (rule, span)) in candidates.into_iter().enumerate() {
        if rules.tiers[rule].is_some() {
            if suppressed_by[position].is_none() {
                kept.push(span);
            }
        } else if next_other.as_ref() == Some(&span) {
            kept.push(span);
            next_other = kept_others.next();
        }
    }
    kept
}

fn resolve_secrets(
    text: &str,
    rules: &OverlapRules<'_>,
    secrets: &mut [Secret],
    suppressed_by: &mut [Option<usize>],
) {
    secrets.sort_by_key(|secret| (secret.range.start, std::cmp::Reverse(secret.range.end)));
    // Pair rules over every overlapping pair; `secrets` is sorted by start.
    for a in 0..secrets.len() {
        for b in a + 1..secrets.len() {
            if secrets[b].range.start >= secrets[a].range.end {
                break;
            }
            let (first, second) = (&secrets[a], &secrets[b]);
            for (outer, inner) in [(first, second), (second, first)] {
                if !contains(&outer.range, &inner.range) {
                    continue;
                }
                let extra = [
                    &text[outer.range.start..inner.range.start],
                    &text[inner.range.end..outer.range.end],
                ];
                if outer.tier == inner.tier
                    && extra.iter().all(|part| part.chars().all(is_delimiter))
                {
                    // `'value'` gives way to `value`.
                    suppress(suppressed_by, outer.position, inner.position);
                } else if outer.rule != inner.rule
                    && extra
                        .iter()
                        .any(|part| part.chars().any(char::is_alphanumeric))
                    && (rules.metas[inner.rule].keywords.is_empty()
                        || (outer.tier.is_fixed_format() && inner.tier.is_fixed_format()))
                {
                    // A run inside a longer value is part of that value.
                    suppress(suppressed_by, inner.position, outer.position);
                }
            }
        }
    }

    // Tier, validator strength and registry order decide among the rest.
    let mut order = (0..secrets.len())
        .filter(|&index| suppressed_by[secrets[index].position].is_none())
        .collect::<Vec<_>>();
    order.sort_by_key(|&index| {
        let secret = &secrets[index];
        (
            secret.tier,
            strength_rank(rules.metas[secret.rule].validator_strength),
            secret.position,
        )
    });
    let mut taken = BTreeMap::<usize, (usize, usize)>::new();
    for index in order {
        let secret = &secrets[index];
        let overlapping = taken
            .range(..secret.range.end)
            .next_back()
            .filter(|(_, &(end, _))| end > secret.range.start)
            .map(|(_, &(_, position))| position);
        match overlapping {
            Some(winner) => suppressed_by[secret.position] = Some(winner),
            None => {
                taken.insert(secret.range.start, (secret.range.end, secret.position));
            }
        }
    }
}

/// Whether `outer` contains `inner` and is longer.
fn contains(outer: &Range<usize>, inner: &Range<usize>) -> bool {
    outer.start <= inner.start && inner.end <= outer.end && outer.len() > inner.len()
}

fn is_delimiter(c: char) -> bool {
    matches!(c, '"' | '\'' | '`' | ';' | ',')
}

fn suppress(suppressed_by: &mut [Option<usize>], loser: usize, winner: usize) {
    suppressed_by[loser].get_or_insert(winner);
}
