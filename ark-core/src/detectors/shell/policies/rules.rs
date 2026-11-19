// SPDX-License-Identifier: MIT OR Apache-2.0
//! Loading policies: Cedar sources in the `core.cedar` format (core and user
//! tiers) and the translated DefenseClaw rules at their gated level.

use std::collections::HashMap;

use cedar_policy::{Policy, PolicyId};

use super::{DcRule, Decision, Rule, Tier, DC_RULES_JSON, RULE_PREFIX, USER_ID};
use crate::detectors::facts_common::cedar::{parse_annotated, CedarRule};

/// Policies of a Cedar source in the `core.cedar` format, ordered by id:
/// `core.*` ids in the core tier, `user.*` ids in the user tier.
pub(super) fn parse_cedar(
    source: &str,
    tier: Tier,
    levels: Option<&HashMap<String, String>>,
) -> Result<Vec<Rule>, String> {
    parse_annotated(
        source,
        tier,
        levels,
        |id| match tier {
            Tier::User => USER_ID.is_match(id),
            _ => id.starts_with("core."),
        },
        RULE_PREFIX,
    )
}

/// The translated DefenseClaw rules that ship (`status == translated`, not the
/// held-out test bucket) at their gated level, in file order.
pub(super) fn dc_rules(levels: &HashMap<String, String>) -> Result<Vec<Rule>, String> {
    let records: Vec<DcRule> =
        serde_json::from_str(DC_RULES_JSON).map_err(|error| format!("dc_rules.json: {error}"))?;
    let mut rules = Vec::new();
    for record in records {
        if record.status != "translated" || record.bucket == "test" {
            continue;
        }
        let Some(level) = levels
            .get(&record.id)
            .and_then(|l| Decision::parse_level(l))
        else {
            continue;
        };
        if !matches!(
            record.tier.as_deref(),
            None | Some("") | Some("bundle-default")
        ) {
            return Err(format!("{}: unexpected tier", record.id));
        }
        let action = record.scope.as_deref().unwrap_or("segment");
        let condition = record
            .condition
            .ok_or_else(|| format!("{}: translated rule without condition", record.id))?;
        let text = format!(
            r#"forbid(principal, action == Action::"{action}", resource) when {{ {condition} }};"#
        );
        let policy = Policy::parse(Some(PolicyId::new(&record.id)), text)
            .map_err(|error| format!("{}: {error}", record.id))?;
        rules.push(CedarRule::new(
            RULE_PREFIX,
            Tier::BundleDefault,
            record
                .title
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| record.id.clone()),
            level,
            policy,
            record.pattern.filter(|p| !p.is_empty()),
        )?);
    }
    Ok(rules)
}
