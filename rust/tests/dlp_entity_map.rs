// SPDX-License-Identifier: GPL-3.0-only
use patronus_ark::detectors::dlp::dlp::{SecretSubtype, DLP_PATTERNS};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// Native DLP producers outside `DLP_PATTERNS` that still own a public `dlp_*` rule id.
const NATIVE_PRODUCER_RULES: &[&str] = &[
    "dlp_sensitive_material",
    "dlp_secret_transfer",
    "dlp_mcp_runtime_risk",
    "dlp_mcp_policy",
    "dlp_destructive_operation",
];

const SCOPES: &[&str] = &["shared", "ark_only", "baseline_only", "out_of_scope"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntityMap {
    schema: String,
    baselines: BTreeMap<String, Baseline>,
    taxonomy: BTreeMap<String, Group>,
    subtypes: BTreeMap<String, Subtype>,
    entities: Vec<Entity>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Baseline {
    version: String,
    source: String,
    #[serde(default)]
    inventory: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    family: String,
    #[serde(default)]
    planned: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Subtype {
    groups: Vec<String>,
    #[serde(default)]
    planned: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entity {
    id: String,
    scope: String,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    subtype: Option<String>,
    #[serde(default)]
    ark: Vec<String>,
    #[serde(default)]
    gitleaks: Vec<String>,
    #[serde(default)]
    trufflehog: Vec<String>,
    #[serde(default)]
    detect_secrets: Vec<String>,
    #[serde(default)]
    google_dlp: Vec<String>,
    #[serde(default)]
    backlog: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

impl Entity {
    fn baseline_ids(&self) -> impl Iterator<Item = &String> {
        self.gitleaks
            .iter()
            .chain(&self.trufflehog)
            .chain(&self.detect_secrets)
            .chain(&self.google_dlp)
    }
}

fn research_file(name: &str) -> String {
    let path = format!("{}/../research/dlp/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{path}: {err}"))
}

fn load() -> EntityMap {
    serde_yaml::from_str(&research_file("entity_map.yaml")).unwrap()
}

#[test]
fn every_dlp_rule_is_mapped_exactly_once_with_its_entity_group() {
    let map = load();
    assert_eq!(map.schema, "ark-dlp-entity-map-v1");
    let mut owner = BTreeMap::new();
    for entity in &map.entities {
        for rule in &entity.ark {
            assert!(
                owner.insert(rule.as_str(), entity).is_none(),
                "{rule} is mapped twice"
            );
        }
    }
    let expected: BTreeSet<_> = DLP_PATTERNS
        .iter()
        .map(|p| p.name)
        .chain(NATIVE_PRODUCER_RULES.iter().copied())
        .collect();
    let mapped: BTreeSet<_> = owner.keys().copied().collect();
    assert_eq!(
        mapped, expected,
        "entity_map.yaml must map every dlp_* rule"
    );
    for pattern in DLP_PATTERNS {
        let entity = owner[pattern.name];
        assert_eq!(
            entity.group.as_deref(),
            Some(pattern.entity_group),
            "{} sits in {}",
            pattern.name,
            entity.id
        );
        assert_ne!(entity.scope, "out_of_scope", "{}", pattern.name);
    }
    for rule in NATIVE_PRODUCER_RULES {
        assert_eq!(owner[rule].scope, "out_of_scope", "{rule}");
    }
}

#[test]
fn scopes_match_the_mapped_tools() {
    let map = load();
    let mut ids = BTreeSet::new();
    for entity in &map.entities {
        assert!(ids.insert(&entity.id), "duplicate entity {}", entity.id);
        assert!(SCOPES.contains(&entity.scope.as_str()), "{}", entity.id);
        let has_ark = !entity.ark.is_empty();
        let has_baseline = entity.baseline_ids().next().is_some();
        match entity.scope.as_str() {
            "shared" => assert!(has_ark && has_baseline, "{}", entity.id),
            "ark_only" => assert!(has_ark && !has_baseline, "{}", entity.id),
            "baseline_only" => assert!(
                !has_ark && has_baseline && entity.backlog.is_some(),
                "{} needs a baseline id and a backlog task",
                entity.id
            ),
            _ => assert!(
                entity
                    .reason
                    .as_deref()
                    .is_some_and(|r| !r.trim().is_empty()),
                "{} needs a reason",
                entity.id
            ),
        }
        match &entity.group {
            Some(group) => assert!(map.taxonomy.contains_key(group), "{}", entity.id),
            None => assert_eq!(entity.scope, "out_of_scope", "{}", entity.id),
        }
    }
    for (name, group) in &map.taxonomy {
        assert!(!group.family.is_empty(), "{name}");
        let used_by_ark = map
            .entities
            .iter()
            .any(|e| !e.ark.is_empty() && e.group.as_ref() == Some(name));
        assert_eq!(group.planned, !used_by_ark, "planned flag of {name}");
    }
}

#[test]
fn subtypes_match_the_rule_metadata() {
    let map = load();
    let declared: BTreeMap<_, _> = SecretSubtype::ALL
        .iter()
        .map(|subtype| (subtype.as_str().to_string(), subtype.groups()))
        .collect();
    assert_eq!(
        map.subtypes.keys().collect::<Vec<_>>(),
        declared.keys().collect::<Vec<_>>(),
        "subtypes of entity_map.yaml vs. SecretSubtype::ALL"
    );
    for (name, subtype) in &map.subtypes {
        assert_eq!(subtype.groups, declared[name], "groups of {name}");
        for group in &subtype.groups {
            assert!(map.taxonomy.contains_key(group), "{name}: {group}");
        }
        let used = DLP_PATTERNS
            .iter()
            .any(|rule| rule.meta.subtype.map(SecretSubtype::as_str) == Some(name.as_str()));
        assert_eq!(subtype.planned, !used, "planned flag of subtype {name}");
    }
    // K09: the new kinds are subtypes, not groups of their own.
    for kind in [
        "connection_string",
        "webhook_url",
        "auth_url",
        "otp_secret",
        "seed_phrase",
    ] {
        assert!(map.subtypes.contains_key(kind), "{kind} must be a subtype");
        assert!(
            !map.taxonomy.contains_key(&kind.to_ascii_uppercase()),
            "{kind} must not be a group"
        );
    }
    for entity in &map.entities {
        let Some(name) = &entity.subtype else {
            continue;
        };
        let subtype = map
            .subtypes
            .get(name)
            .unwrap_or_else(|| panic!("{}: unknown subtype {name}", entity.id));
        let group = entity.group.as_ref().expect("a subtype needs a group");
        assert!(subtype.groups.contains(group), "{}: {group}", entity.id);
        for rule in &entity.ark {
            let pattern = DLP_PATTERNS.iter().find(|p| p.name == rule).unwrap();
            assert_eq!(
                pattern.meta.subtype.map(SecretSubtype::as_str),
                Some(name.as_str()),
                "{}: {rule}",
                entity.id
            );
        }
    }
}

#[test]
fn baseline_inventories_are_fully_mapped() {
    let map = load();
    let tools: BTreeSet<_> = map.baselines.keys().map(String::as_str).collect();
    assert_eq!(
        tools,
        BTreeSet::from(["detect_secrets", "gitleaks", "google_dlp", "trufflehog"])
    );
    assert_eq!(map.baselines["gitleaks"].version, "8.30.1");
    assert_eq!(map.baselines["detect_secrets"].version, "1.5.0");
    assert_eq!(map.baselines["trufflehog"].version, "3.97.9");
    assert_eq!(map.baselines["gitleaks"].inventory.len(), 222);
    assert_eq!(map.baselines["detect_secrets"].inventory.len(), 27);
    for (tool, baseline) in &map.baselines {
        assert!(!baseline.source.is_empty(), "{tool}");
        let inventory: BTreeSet<_> = baseline.inventory.iter().collect();
        assert_eq!(inventory.len(), baseline.inventory.len(), "{tool} dup");
        let mapped: Vec<_> = map
            .entities
            .iter()
            .flat_map(|e| match tool.as_str() {
                "gitleaks" => &e.gitleaks,
                "trufflehog" => &e.trufflehog,
                "detect_secrets" => &e.detect_secrets,
                _ => &e.google_dlp,
            })
            .collect();
        if tool == "gitleaks" {
            let unique: BTreeSet<_> = mapped.iter().collect();
            assert_eq!(unique.len(), mapped.len(), "gitleaks rule mapped twice");
        }
        if inventory.is_empty() {
            continue;
        }
        let mapped: BTreeSet<_> = mapped.into_iter().collect();
        assert_eq!(mapped, inventory, "{tool} inventory vs. entities");
    }
}

#[test]
fn backlog_references_exist() {
    let backlog = research_file("backlog.yaml");
    let tasks: BTreeSet<_> = backlog
        .lines()
        .filter_map(|line| {
            let rest = line.trim_start().trim_start_matches("- ");
            let rest = rest.strip_prefix("{id: ").or(rest.strip_prefix("id: "))?;
            Some(rest.split([',', ' ']).next()?.to_string())
        })
        .collect();
    assert!(tasks.contains("E01") && tasks.contains("P12"));
    for entity in load().entities {
        if let Some(task) = entity.backlog {
            assert!(tasks.contains(&task), "{}: unknown task {task}", entity.id);
        }
    }
}
