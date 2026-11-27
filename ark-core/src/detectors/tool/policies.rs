// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cedar policies over `patronus.tool_facts/1`: one `call` request per tool
//! call (`data/tool.cedarschema`), the core policies (`data/core.cedar`, the
//! reference's default set, compiled in) and user policies from the runtime
//! configuration in the same format: `forbid` only, `@id("user.*")`,
//! `@decision("block"|"ask")`, optional `@title`, `action == Action::"call"`,
//! validated against the schema. The format, tiers and evaluation are the
//! generic ones of [`crate::detectors::facts_common::cedar`], as for Cat.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;
use std::sync::LazyLock;

use cedar_policy::{EntityUid, RestrictedExpression, Schema};
use regex::Regex;

use super::facts::ToolFacts;
use crate::detectors::facts_common::cedar::{
    self, CedarPolicies, CedarRule, ContextPairs, PolicyScope,
};
pub use crate::detectors::facts_common::cedar::{Decision, PolicyHit, Tier};

const CORE_POLICIES: &str = include_str!("data/core.cedar");
pub(crate) const SCHEMA: &str = include_str!("data/tool.cedarschema");

static CEDAR_SCHEMA: LazyLock<Schema> = LazyLock::new(|| cedar::schema(SCHEMA, "tool facts"));
static PRINCIPAL: LazyLock<EntityUid> =
    LazyLock::new(|| EntityUid::from_str(r#"Agent::"agent""#).expect("principal"));
static RESOURCE: LazyLock<EntityUid> =
    LazyLock::new(|| EntityUid::from_str(r#"Tool::"tool""#).expect("resource"));
static CALL_ACTION: LazyLock<EntityUid> =
    LazyLock::new(|| EntityUid::from_str(r#"Action::"call""#).expect("action"));
static USER_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^user\.[A-Za-z0-9_.-]{1,64}$").expect("user id"));

/// Prefix of tool policy ids in the shared L1 `rules` gates:
/// `tool.core.secret_to_egress`, `tool.user.new_recipient`.
pub const RULE_PREFIX: &str = "tool.";

/// The one request scope: a tool call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Call;

impl PolicyScope for Call {
    const ALL: &'static [Self] = &[Call];

    fn action(self) -> &'static EntityUid {
        &CALL_ACTION
    }
}

type Rule = CedarRule<Call>;

/// The Cedar schema of the `call` requests.
pub fn schema() -> &'static Schema {
    &CEDAR_SCHEMA
}

fn parse(source: &str, tier: Tier) -> Result<Vec<Rule>, String> {
    cedar::parse_annotated(
        source,
        tier,
        None,
        |id| match tier {
            Tier::User => USER_ID.is_match(id),
            _ => id.starts_with("core."),
        },
        RULE_PREFIX,
    )
}

/// User policies from the runtime configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ToolPolicyConfig {
    /// Cedar sources of user policies; one source may hold several policies.
    pub user_policies: Vec<String>,
}

impl ToolPolicyConfig {
    /// Add the `*.cedar` files of `dir`, in file-name order.
    pub fn add_cedar_dir(&mut self, dir: &Path) -> Result<(), String> {
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .map_err(|error| format!("failed to read {}: {error}", dir.display()))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.extension().is_some_and(|ext| ext == "cedar"))
            .collect();
        files.sort();
        for file in files {
            self.user_policies.push(
                std::fs::read_to_string(&file)
                    .map_err(|error| format!("failed to read {}: {error}", file.display()))?,
            );
        }
        Ok(())
    }
}

/// The loaded policies: the core set plus the configured user policies.
pub struct ToolPolicies {
    policies: CedarPolicies<Call>,
}

impl ToolPolicies {
    /// The core policies alone.
    pub fn core() -> Result<Self, String> {
        Self::with_config(&ToolPolicyConfig::default())
    }

    /// The compiled-in core policies and the user policies of `config`.
    pub fn with_config(config: &ToolPolicyConfig) -> Result<Self, String> {
        Self::with_core(CORE_POLICIES, config)
    }

    /// The core policies of a block (`core.cedar`, `core.*` ids) and the user
    /// policies of `config`.
    pub fn with_core(core: &str, config: &ToolPolicyConfig) -> Result<Self, String> {
        let mut rules = parse(core, Tier::Core)?;
        for source in &config.user_policies {
            for rule in parse(source, Tier::User)? {
                cedar::validate(&CEDAR_SCHEMA, std::slice::from_ref(&rule))
                    .map_err(|error| format!("{}: {error}", rule.id()))?;
                if rules.iter().any(|r| r.id() == rule.id()) {
                    return Err(format!("policy id {} is not unique", rule.id()));
                }
                rules.push(rule);
            }
        }
        let policies = CedarPolicies::build(
            &CEDAR_SCHEMA,
            rules,
            BTreeMap::new(),
            PRINCIPAL.clone(),
            RESOURCE.clone(),
        )?;
        Ok(Self { policies })
    }

    /// Number of loaded policies.
    pub fn len(&self) -> usize {
        self.policies.rules().len()
    }

    /// Whether no policy is loaded.
    pub fn is_empty(&self) -> bool {
        self.policies.rules().is_empty()
    }

    /// The loaded policies: id, tier, decision and title.
    pub fn list(&self) -> Vec<(String, Tier, Decision, String)> {
        self.policies
            .rules()
            .iter()
            .map(|r| (r.id().to_string(), r.tier, r.level, r.title.clone()))
            .collect()
    }

    /// The fired policies, strongest first, and the decision. `known_targets`
    /// are receivers the host approved before (for user policies on new
    /// receivers). A policy whose id `allows_rule` refuses never fires.
    pub fn evaluate(
        &self,
        facts: &ToolFacts,
        known_targets: &[String],
        allows_rule: impl Fn(&str) -> bool,
    ) -> Result<(Decision, Vec<PolicyHit>), String> {
        let request = ("call".to_string(), Call, context(facts, known_targets));
        let (hits, _) = self.policies.evaluate([request], &[], allows_rule)?;
        let decision = hits
            .iter()
            .map(|h| h.decision)
            .max()
            .unwrap_or(Decision::Allow);
        Ok((decision, hits))
    }
}

fn set<'a>(items: impl IntoIterator<Item = &'a str>) -> RestrictedExpression {
    let unique: BTreeSet<&str> = items.into_iter().collect();
    RestrictedExpression::new_set(
        unique
            .into_iter()
            .map(|s| RestrictedExpression::new_string(s.to_string())),
    )
}

/// The context of the `call` request (`CallContext` of the schema).
pub fn context(facts: &ToolFacts, known_targets: &[String]) -> ContextPairs {
    let m = &facts.model;
    let flows: Vec<String> = facts
        .flows
        .iter()
        .flat_map(|f| {
            [
                format!("{}>{}", f.data, f.sink),
                format!("{}>{}>{}", f.data, f.sink, f.via),
            ]
        })
        .collect();
    let objects: Vec<String> = facts
        .objects
        .iter()
        .filter_map(|o| o.access.as_ref().map(|a| format!("{a}@{}", o.class)))
        .collect();
    // the call reaches outside: a public host, a recipient, or a publish sink
    let external = facts.network.iter().any(|n| n.scope == "PUBLIC")
        || !facts.recipients.is_empty()
        || m.sinks.iter().any(|s| s == "publish");
    let s = |v: &str| RestrictedExpression::new_string(v.to_string());
    vec![
        ("tool".into(), s(&facts.tool.name)),
        ("server".into(), s(&facts.tool.server)),
        ("paw".into(), s(m.paw.as_deref().unwrap_or(""))),
        ("sight".into(), s(m.sight.as_deref().unwrap_or(""))),
        ("sinks".into(), set(m.sinks.iter().map(String::as_str))),
        ("sources".into(), set(m.sources.iter().map(String::as_str))),
        ("objects".into(), set(objects.iter().map(String::as_str))),
        (
            "classes".into(),
            set(facts.objects.iter().map(|o| o.class.as_str())),
        ),
        (
            "hosts".into(),
            set(facts.network.iter().map(|n| n.host.as_str())),
        ),
        (
            "net_scopes".into(),
            set(facts.network.iter().map(|n| n.scope.as_str())),
        ),
        (
            "recipient_kinds".into(),
            set(facts.recipients.iter().map(|r| r.kind.as_str())),
        ),
        (
            "recipient_domains".into(),
            set(facts
                .recipients
                .iter()
                .map(|r| r.domain.as_str())
                .filter(|d| !d.is_empty())),
        ),
        ("atoms".into(), set(facts.atoms.iter().map(String::as_str))),
        ("flows".into(), set(flows.iter().map(String::as_str))),
        ("shell".into(), RestrictedExpression::new_bool(facts.shell)),
        ("external".into(), RestrictedExpression::new_bool(external)),
        (
            "session_sources".into(),
            set(facts.session.sources.iter().map(String::as_str)),
        ),
        (
            "session_tool_sources".into(),
            set(facts.session.tool_sources.iter().map(String::as_str)),
        ),
        (
            "session_objects".into(),
            set(facts.session.objects.iter().map(String::as_str)),
        ),
        (
            "linked".into(),
            set(facts.linked.iter().map(String::as_str)),
        ),
        (
            "targets".into(),
            set(facts.targets.iter().map(String::as_str)),
        ),
        (
            "known_targets".into(),
            set(known_targets.iter().map(String::as_str)),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_policies_compile_and_validate() {
        let p = ToolPolicies::core().unwrap();
        assert_eq!(p.len(), 20);
        assert!(p
            .list()
            .iter()
            .all(|(id, tier, _, _)| id.starts_with("core.") && *tier == Tier::Core));
    }

    #[test]
    fn user_policies_need_user_ids_and_the_schema() {
        let ok = r#"@id("user.no_github_delete") @decision("block")
            forbid (principal, action == Action::"call", resource)
            when { context.server == "github" && context.paw == "delete" };"#;
        let config = ToolPolicyConfig {
            user_policies: vec![ok.into()],
        };
        assert_eq!(ToolPolicies::with_config(&config).unwrap().len(), 21);
        let bad_id = ok.replace("user.no_github_delete", "core.mine");
        assert!(ToolPolicies::with_config(&ToolPolicyConfig {
            user_policies: vec![bad_id]
        })
        .is_err());
        let bad_field = ok.replace("context.server", "context.nope");
        assert!(ToolPolicies::with_config(&ToolPolicyConfig {
            user_policies: vec![bad_field]
        })
        .is_err());
    }
}
