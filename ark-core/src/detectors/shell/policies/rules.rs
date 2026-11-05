// SPDX-License-Identifier: MIT OR Apache-2.0
//! Loading policies: Cedar sources in the `core.cedar` format (core and user
//! tiers) and the translated DefenseClaw rules at their gated level.

use std::collections::HashMap;
use std::str::FromStr;

use cedar_policy::{
    ActionConstraint, Effect, Policy, PolicyId, PolicySet, PrincipalConstraint, ResourceConstraint,
    ValidationMode, Validator,
};

use super::{
    DcRule, Decision, Rule, Scope, Tier, CEDAR_SCHEMA, COMMAND_ACTION, DC_RULES_JSON,
    SEGMENT_ACTION, USER_ID,
};

fn scope_of(policy: &Policy) -> Option<Scope> {
    match policy.action_constraint() {
        ActionConstraint::Eq(action) if action == *SEGMENT_ACTION => Some(Scope::Segment),
        ActionConstraint::Eq(action) if action == *COMMAND_ACTION => Some(Scope::Command),
        _ => None,
    }
}

/// Policies of a Cedar source in the `core.cedar` format, ordered by id.
pub(super) fn parse_cedar(
    source: &str,
    tier: Tier,
    levels: Option<&HashMap<String, String>>,
) -> Result<Vec<Rule>, String> {
    let set = PolicySet::from_str(source).map_err(|error| format!("does not parse: {error}"))?;
    if set.templates().next().is_some() {
        return Err("templates are not allowed".to_string());
    }
    let mut rules = Vec::new();
    for policy in set.policies() {
        let id = policy
            .annotation("id")
            .ok_or_else(|| format!("policy {} has no @id", policy.id()))?
            .to_string();
        let well_named = match tier {
            Tier::User => USER_ID.is_match(&id),
            _ => id.starts_with("core."),
        };
        if !well_named {
            return Err(format!(
                "policy id {id:?} is not allowed in tier {}",
                tier.as_str()
            ));
        }
        let cap = policy
            .annotation("decision")
            .and_then(Decision::parse_level)
            .ok_or_else(|| format!("{id}: @decision must be block or ask"))?;
        let scope = scope_of(policy).ok_or_else(|| {
            format!("{id}: must apply to action == Action::\"segment\" or Action::\"command\"")
        })?;
        if policy.effect() != Effect::Forbid
            || policy.principal_constraint() != PrincipalConstraint::Any
            || policy.resource_constraint() != ResourceConstraint::Any
        {
            return Err(format!(
                "{id}: must be forbid(principal, action == …, resource)"
            ));
        }
        let level = match levels {
            // Core levels come from the release's validation gate.
            Some(levels) => match levels.get(&id).and_then(|l| Decision::parse_level(l)) {
                Some(level) => level,
                None => continue,
            },
            None => cap,
        };
        rules.push(Rule::new(
            tier,
            policy.annotation("title").unwrap_or(&id).to_string(),
            scope,
            level,
            policy.new_id(PolicyId::new(&id)),
            None,
        ));
    }
    rules.sort_by(|a, b| a.id().cmp(b.id()));
    if let Some(pair) = rules.windows(2).find(|pair| pair[0].id() == pair[1].id()) {
        return Err(format!("policy id {} is not unique", pair[0].id()));
    }
    Ok(rules)
}

pub(super) fn policy_set<'a>(
    rules: impl IntoIterator<Item = &'a Rule>,
) -> Result<PolicySet, String> {
    PolicySet::from_policies(rules.into_iter().map(|rule| rule.policy.clone()))
        .map_err(|error| error.to_string())
}

pub(super) fn validate(rules: &[Rule]) -> Result<(), String> {
    let result =
        Validator::new(CEDAR_SCHEMA.clone()).validate(&policy_set(rules)?, ValidationMode::Strict);
    if result.validation_passed() {
        return Ok(());
    }
    let errors: Vec<String> = result
        .validation_errors()
        .take(2)
        .map(ToString::to_string)
        .collect();
    Err(format!("schema validation failed: {errors:?}"))
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
        let scope = scope_of(&policy).ok_or_else(|| format!("{}: unknown scope", record.id))?;
        rules.push(Rule::new(
            Tier::BundleDefault,
            record
                .title
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| record.id.clone()),
            scope,
            level,
            policy,
            record.pattern.filter(|p| !p.is_empty()),
        ));
    }
    Ok(rules)
}
