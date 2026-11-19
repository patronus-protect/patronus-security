// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cedar policies over a facts document, independent of the detector: the
//! schema, the annotated policy format, the policy tiers and the evaluation.
//! A detector supplies its schema, its request scopes (one Cedar action each)
//! and the requests of one input; Cat's shell policies
//! ([`crate::detectors::shell::policies`]) are the first such policy set.
//!
//! Policy format (`core.cedar`, user files): `forbid` only, any principal and
//! resource, `action ==` one scope action, `@id`, `@decision("block"|"ask")`
//! and optional `@title`. Every policy is validated against the schema. A
//! policy fires when its forbid is satisfied; its decision is its level, a
//! `bundle-default` `block` that the allowlist names drops to `ask`. A policy
//! may carry a regex `pattern` that the detector checks on the input first:
//! such a policy is evaluated alone, and only when its pattern matched.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr;

use cedar_policy::{
    ActionConstraint, Authorizer, Context, Effect, Entities, EntityUid, Policy, PolicyId,
    PolicySet, PrincipalConstraint, Request, ResourceConstraint, RestrictedExpression, Schema,
    ValidationMode, Validator,
};

/// Parse a compiled-in `.cedarschema`; `what` names it in the panic message of
/// a broken build.
pub fn schema(source: &str, what: &str) -> Schema {
    Schema::from_cedarschema_str(source)
        .unwrap_or_else(|error| panic!("{what} Cedar schema: {error}"))
        .0
}

/// A decision on `allow < ask < block`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Decision {
    Allow,
    Ask,
    Block,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Ask => "ask",
            Decision::Block => "block",
        }
    }

    /// The level of a policy: `block` or `ask`.
    pub(crate) fn parse_level(level: &str) -> Option<Self> {
        match level {
            "block" => Some(Decision::Block),
            "ask" => Some(Decision::Ask),
            _ => None,
        }
    }
}

/// Policy tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Core,
    BundleDefault,
    User,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Core => "core",
            Tier::BundleDefault => "bundle-default",
            Tier::User => "user",
        }
    }
}

/// The request scopes of a detector's schema: one Cedar action each.
pub trait PolicyScope: Copy + Eq + 'static {
    /// The scopes, in evaluation order.
    const ALL: &'static [Self];
    /// The Cedar action of the scope.
    fn action(self) -> &'static EntityUid;
}

/// The scope whose action a policy is constrained to.
fn scope_of<S: PolicyScope>(policy: &Policy) -> Option<S> {
    match policy.action_constraint() {
        ActionConstraint::Eq(action) => S::ALL.iter().copied().find(|s| *s.action() == action),
        _ => None,
    }
}

/// One loaded policy.
#[derive(Clone, Debug)]
pub struct CedarRule<S> {
    pub tier: Tier,
    pub title: String,
    pub scope: S,
    pub level: Decision,
    /// The Cedar policy, with the policy id as its Cedar id.
    pub policy: Policy,
    /// `<prefix><policy id>`: the id in the shared L1 `rules` gates.
    pub rule_id: String,
    /// Regex the detector checks on the input before the policy is evaluated.
    pub pattern: Option<String>,
}

impl<S: PolicyScope> CedarRule<S> {
    /// A rule from a policy whose action is one of the scopes.
    pub fn new(
        rule_prefix: &str,
        tier: Tier,
        title: String,
        level: Decision,
        policy: Policy,
        pattern: Option<String>,
    ) -> Result<Self, String> {
        let scope = scope_of(&policy).ok_or_else(|| format!("{}: unknown scope", policy.id()))?;
        Ok(Self {
            rule_id: format!("{rule_prefix}{}", policy.id()),
            tier,
            title,
            scope,
            level,
            policy,
            pattern,
        })
    }
}

impl<S> CedarRule<S> {
    pub fn id(&self) -> &str {
        self.policy.id().as_ref()
    }
}

/// Policies of a Cedar source in the annotated format, ordered by id. A policy
/// id must pass `well_named`. With `levels` (a release's validation gate) a
/// policy takes the level listed for its id and is dropped without one;
/// otherwise its `@decision` is its level.
pub fn parse_annotated<S: PolicyScope>(
    source: &str,
    tier: Tier,
    levels: Option<&HashMap<String, String>>,
    well_named: impl Fn(&str) -> bool,
    rule_prefix: &str,
) -> Result<Vec<CedarRule<S>>, String> {
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
        if !well_named(&id) {
            return Err(format!(
                "policy id {id:?} is not allowed in tier {}",
                tier.as_str()
            ));
        }
        let cap = policy
            .annotation("decision")
            .and_then(Decision::parse_level)
            .ok_or_else(|| format!("{id}: @decision must be block or ask"))?;
        if scope_of::<S>(policy).is_none() {
            let actions: Vec<String> = S::ALL.iter().map(|s| s.action().to_string()).collect();
            return Err(format!(
                "{id}: must apply to action == {}",
                actions.join(" or ")
            ));
        }
        if policy.effect() != Effect::Forbid
            || policy.principal_constraint() != PrincipalConstraint::Any
            || policy.resource_constraint() != ResourceConstraint::Any
        {
            return Err(format!(
                "{id}: must be forbid(principal, action == …, resource)"
            ));
        }
        let level = match levels {
            Some(levels) => match levels.get(&id).and_then(|l| Decision::parse_level(l)) {
                Some(level) => level,
                None => continue,
            },
            None => cap,
        };
        rules.push(CedarRule::new(
            rule_prefix,
            tier,
            policy.annotation("title").unwrap_or(&id).to_string(),
            level,
            policy.new_id(PolicyId::new(&id)),
            None,
        )?);
    }
    rules.sort_by(|a, b| a.id().cmp(b.id()));
    if let Some(pair) = rules.windows(2).find(|pair| pair[0].id() == pair[1].id()) {
        return Err(format!("policy id {} is not unique", pair[0].id()));
    }
    Ok(rules)
}

fn policy_set<'a, S: 'a>(
    rules: impl IntoIterator<Item = &'a CedarRule<S>>,
) -> Result<PolicySet, String> {
    PolicySet::from_policies(rules.into_iter().map(|rule| rule.policy.clone()))
        .map_err(|error| error.to_string())
}

/// Validate `rules` against `schema` (strict mode).
pub fn validate<S>(schema: &Schema, rules: &[CedarRule<S>]) -> Result<(), String> {
    let result = Validator::new(schema.clone()).validate(&policy_set(rules)?, ValidationMode::Strict);
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

/// A fired policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyHit {
    pub id: String,
    pub tier: Tier,
    pub title: String,
    pub decision: Decision,
    /// The places of the requests it fired on, sorted.
    pub r#where: Vec<String>,
}

/// A bundle-default policy the allowlist lowered from block to ask.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lowered {
    pub id: String,
}

/// Cedar context pairs of one request.
pub type ContextPairs = Vec<(String, RestrictedExpression)>;

/// A validated policy set, ready to evaluate requests: the policies without a
/// pattern in one set per scope, each pattern policy in a set of its own.
pub struct CedarPolicies<S> {
    rules: Vec<CedarRule<S>>,
    by_id: HashMap<String, usize>,
    unpatterned: Vec<(S, PolicySet)>,
    /// Per pattern policy, in rule order: its rule and a set holding only it.
    pattern_rules: Vec<(usize, PolicySet)>,
    allowlist: BTreeMap<String, String>,
    principal: EntityUid,
    resource: EntityUid,
}

impl<S: PolicyScope> CedarPolicies<S> {
    /// Validate `rules` against `schema` and build their sets; requests run
    /// as `principal` on `resource`. `allowlist` maps bundle-default policy
    /// ids to `"ask"`.
    pub fn build(
        schema: &Schema,
        rules: Vec<CedarRule<S>>,
        allowlist: BTreeMap<String, String>,
        principal: EntityUid,
        resource: EntityUid,
    ) -> Result<Self, String> {
        validate(schema, &rules)?;
        let pattern_rules = rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule.pattern.is_some())
            .map(|(index, rule)| Ok((index, policy_set([rule])?)))
            .collect::<Result<_, String>>()?;
        let unpatterned = S::ALL
            .iter()
            .map(|&scope| {
                let rules = rules
                    .iter()
                    .filter(|r| r.pattern.is_none() && r.scope == scope);
                Ok((scope, policy_set(rules)?))
            })
            .collect::<Result<_, String>>()?;
        Ok(Self {
            by_id: rules
                .iter()
                .enumerate()
                .map(|(i, r)| (r.id().to_string(), i))
                .collect(),
            rules,
            unpatterned,
            pattern_rules,
            allowlist,
            principal,
            resource,
        })
    }

    /// The loaded policies.
    pub fn rules(&self) -> &[CedarRule<S>] {
        &self.rules
    }

    /// The pattern policies' rule indices, in the order their patterns are
    /// numbered in [`Self::evaluate`].
    pub fn pattern_rules(&self) -> impl Iterator<Item = usize> + '_ {
        self.pattern_rules.iter().map(|(rule, _)| *rule)
    }

    /// The fired policies, strongest first, and the allowlisted ones.
    /// `requests` are (place, scope, context); `matched` numbers the pattern
    /// policies whose pattern matched the input. A policy whose `rule_id`
    /// `allows_rule` refuses never fires.
    pub fn evaluate(
        &self,
        requests: impl IntoIterator<Item = (String, S, ContextPairs)>,
        matched: &[usize],
        allows_rule: impl Fn(&str) -> bool,
    ) -> Result<(Vec<PolicyHit>, Vec<Lowered>), String> {
        if self.rules.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let authorizer = Authorizer::new();
        let entities = Entities::empty();
        let mut fired: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
        for (place, scope, pairs) in requests {
            let context = Context::from_pairs(pairs).map_err(|e| e.to_string())?;
            let request = Request::new(
                self.principal.clone(),
                scope.action().clone(),
                self.resource.clone(),
                context,
                None,
            )
            .map_err(|e| e.to_string())?;
            let unpatterned = self
                .unpatterned
                .iter()
                .filter(|(s, _)| *s == scope)
                .map(|(_, set)| set);
            let candidates = unpatterned.chain(
                matched
                    .iter()
                    .map(|&k| &self.pattern_rules[k])
                    .filter(|(rule, _)| self.rules[*rule].scope == scope)
                    .map(|(_, set)| set),
            );
            for set in candidates {
                // Forbids only: the satisfied ones are the reasons of the denial.
                let response = authorizer.is_authorized(&request, set, &entities);
                if let Some(error) = response.diagnostics().errors().next() {
                    return Err(error.to_string());
                }
                for id in response.diagnostics().reason() {
                    let rule = self.by_id[AsRef::<str>::as_ref(id)];
                    fired.entry(rule).or_default().insert(place.clone());
                }
            }
        }
        let mut hits = Vec::new();
        let mut lowered = Vec::new();
        for (index, places) in fired {
            let rule = &self.rules[index];
            if !allows_rule(&rule.rule_id) {
                continue;
            }
            let mut decision = rule.level;
            if rule.tier == Tier::BundleDefault
                && self.allowlist.get(rule.id()).map(String::as_str) == Some("ask")
                && decision == Decision::Block
            {
                lowered.push(Lowered {
                    id: rule.id().to_string(),
                });
                decision = Decision::Ask;
            }
            hits.push(PolicyHit {
                id: rule.id().to_string(),
                tier: rule.tier,
                title: rule.title.clone(),
                decision,
                r#where: places.into_iter().collect(),
            });
        }
        hits.sort_by(|a, b| {
            (std::cmp::Reverse(a.decision), a.tier != Tier::Core, &a.id).cmp(&(
                std::cmp::Reverse(b.decision),
                b.tier != Tier::Core,
                &b.id,
            ))
        });
        lowered.sort_by(|a, b| a.id.cmp(&b.id));
        Ok((hits, lowered))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    const SCHEMA: &str = r#"
        entity Agent; entity Target;
        action "text" appliesTo { principal: Agent, resource: Target,
            context: { sinks: Set<String>, addressee: String } };"#;

    static TEXT: LazyLock<EntityUid> =
        LazyLock::new(|| EntityUid::from_str(r#"Action::"text""#).unwrap());

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Text;

    impl PolicyScope for Text {
        const ALL: &'static [Self] = &[Text];
        fn action(self) -> &'static EntityUid {
            &TEXT
        }
    }

    const POLICIES: &str = r#"
        @id("core.mail_out") @decision("block") @title("Mail to an outside sink")
        forbid (principal, action == Action::"text", resource)
        when { context.sinks.contains("mail") };
        @id("core.assistant") @decision("ask")
        forbid (principal, action == Action::"text", resource)
        when { context.addressee == "assistant" };"#;

    fn policies(source: &str, allowlist: &[(&str, &str)]) -> Result<CedarPolicies<Text>, String> {
        let rules = parse_annotated(source, Tier::Core, None, |id| id.starts_with("core."), "t.")?;
        CedarPolicies::build(
            &schema(SCHEMA, "test"),
            rules,
            allowlist
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            EntityUid::from_str(r#"Agent::"text""#).unwrap(),
            EntityUid::from_str(r#"Target::"text""#).unwrap(),
        )
    }

    fn request(sinks: &[&str], addressee: &str) -> (String, Text, ContextPairs) {
        let sinks = RestrictedExpression::new_set(
            sinks
                .iter()
                .map(|s| RestrictedExpression::new_string(s.to_string())),
        );
        (
            "text".to_string(),
            Text,
            vec![
                ("sinks".to_string(), sinks),
                (
                    "addressee".to_string(),
                    RestrictedExpression::new_string(addressee.to_string()),
                ),
            ],
        )
    }

    #[test]
    fn evaluates_a_generic_policy_set_strongest_first() {
        let policies = policies(POLICIES, &[]).unwrap();
        assert_eq!(policies.rules().len(), 2);
        assert_eq!(policies.rules()[0].rule_id, "t.core.assistant");
        let (hits, lowered) = policies
            .evaluate([request(&["mail"], "assistant")], &[], |_| true)
            .unwrap();
        let fired: Vec<_> = hits.iter().map(|h| (h.id.as_str(), h.decision)).collect();
        assert_eq!(
            fired,
            [
                ("core.mail_out", Decision::Block),
                ("core.assistant", Decision::Ask)
            ]
        );
        assert_eq!(hits[0].title, "Mail to an outside sink");
        assert_eq!(hits[0].r#where, ["text"]);
        assert!(lowered.is_empty());
        let (hits, _) = policies
            .evaluate([request(&["file"], "user")], &[], |_| true)
            .unwrap();
        assert!(hits.is_empty());
        let (hits, _) = policies
            .evaluate([request(&["mail"], "user")], &[], |id| {
                id != "t.core.mail_out"
            })
            .unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn refuses_policies_outside_the_format_or_schema() {
        for bad in [
            POLICIES.replace(r#"@decision("ask")"#, r#"@decision("allow")"#),
            POLICIES.replace("core.assistant", "user.assistant"),
            POLICIES.replace(r#"Action::"text""#, r#"Action::"file""#),
            POLICIES.replace("context.addressee", "context.nope"),
            POLICIES.replace("forbid", "permit"),
        ] {
            assert!(policies(&bad, &[]).is_err(), "{bad}");
        }
    }

    #[test]
    fn levels_override_the_annotation_and_drop_unlisted_policies() {
        let levels = HashMap::from([("core.mail_out".to_string(), "ask".to_string())]);
        let rules: Vec<CedarRule<Text>> =
            parse_annotated(POLICIES, Tier::Core, Some(&levels), |_| true, "t.").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!((rules[0].id(), rules[0].level), ("core.mail_out", Decision::Ask));
    }
}
