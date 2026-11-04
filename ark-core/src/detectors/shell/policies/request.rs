// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cedar requests of one command: one `segment` request per segment plus one
//! `command` request, with the pre-joined sets of the schema.

use std::collections::BTreeSet;

use cedar_policy::RestrictedExpression;

use crate::detectors::shell::facts::Facts;

use super::{Scope, HKCU, HKLM, SLASHES};

/// DefenseClaw-style normalized path: forward slashes, registry roots shortened.
fn norm_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let path = HKLM.replace(&path, "HKLM${2}");
    let path = HKCU.replace(&path, "HKCU${2}");
    SLASHES.replace_all(&path, "/").into_owned()
}

type Pairs = Vec<(String, RestrictedExpression)>;

/// A Cedar set of strings (Cedar sets are unordered and de-duplicated).
fn set<I: IntoIterator<Item = String>>(items: I) -> RestrictedExpression {
    RestrictedExpression::new_set(items.into_iter().map(RestrictedExpression::new_string))
}

fn text(value: &str) -> RestrictedExpression {
    RestrictedExpression::new_string(value.to_string())
}

fn strings<'a, I: IntoIterator<Item = &'a str>>(items: I) -> RestrictedExpression {
    set(items.into_iter().map(str::to_string))
}

/// Cedar requests (place, scope, context) for one command (`requests`).
pub(super) fn requests(facts: &Facts, patterns: &[String]) -> Vec<(String, Scope, Pairs)> {
    let pairs = |items: Vec<(&str, RestrictedExpression)>| -> Pairs {
        items.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    };
    let mut out: Vec<(String, Scope, Pairs)> = Vec::new();
    for s in &facts.segments {
        let mut values = BTreeSet::new();
        let mut paths = BTreeSet::new();
        let mut objects = BTreeSet::new();
        for object in &s.objects {
            let mut vs = BTreeSet::from([norm_path(object.value.as_deref().unwrap_or(""))]);
            if let Some(abs) = object.abs.as_ref().filter(|a| !a.is_empty()) {
                vs.insert(abs.clone());
            }
            if let Some(access) = object.access {
                paths.extend(vs.iter().map(|v| format!("{access}:{v}")));
                objects.insert(format!("{access}@{}", object.class));
            }
            values.extend(vs);
        }
        let context = pairs(vec![
            ("program", text(&s.program)),
            ("verb", text(s.verb.unwrap_or(""))),
            ("role", text(s.role.unwrap_or(""))),
            (
                "sensitive_read",
                RestrictedExpression::new_bool(s.sensitive),
            ),
            ("nested", text(s.nested.unwrap_or(""))),
            ("sql", strings(s.sql.iter().copied())),
            ("ops", strings(s.ops.iter().copied())),
            ("access", strings(s.objects.iter().filter_map(|o| o.access))),
            ("classes", strings(s.objects.iter().map(|o| o.class))),
            ("objects", set(objects)),
            ("paths", set(paths)),
            ("values", set(values)),
            ("argv", set(s.argv.iter().cloned())),
            (
                "settings",
                set(s
                    .settings
                    .iter()
                    .map(|x| format!("{}:{}", x.domain, x.polarity))),
            ),
            ("grants", strings(s.grants.iter().copied())),
            (
                "host_root_mount",
                RestrictedExpression::new_bool(s.host_root_mount),
            ),
            ("privileged", RestrictedExpression::new_bool(s.privileged)),
            ("fixture", RestrictedExpression::new_bool(s.fixture)),
            ("hosts", set(s.network.iter().map(|n| n.host.clone()))),
            ("net_scopes", strings(s.network.iter().map(|n| n.scope))),
            ("dialect", text(&facts.dialect)),
            ("patterns", set(patterns.iter().cloned())),
        ]);
        out.push((format!("segment:{}", s.id), Scope::Segment, context));
    }
    let flows = facts.flows.iter().flat_map(|f| {
        [
            format!("{}>{}", f.data, f.sink),
            format!("{}>{}>{}", f.data, f.sink, f.via),
        ]
    });
    let segments = &facts.segments;
    let context = pairs(vec![
        ("flows", set(flows)),
        ("objects", strings(facts.objects.iter().map(|o| o.class))),
        ("atoms", set(facts.atoms.iter().cloned())),
        ("programs", set(segments.iter().map(|s| s.program.clone()))),
        (
            "ops",
            strings(segments.iter().flat_map(|s| s.ops.iter().copied())),
        ),
        (
            "settings",
            set(segments.iter().flat_map(|s| {
                s.settings
                    .iter()
                    .map(|x| format!("{}:{}", x.domain, x.polarity))
            })),
        ),
        (
            "hosts",
            set(segments
                .iter()
                .flat_map(|s| s.network.iter().map(|n| n.host.clone()))),
        ),
        (
            "net_scopes",
            strings(
                segments
                    .iter()
                    .flat_map(|s| s.network.iter().map(|n| n.scope)),
            ),
        ),
        ("dialect", text(&facts.dialect)),
        (
            "segments",
            RestrictedExpression::new_long(segments.len() as i64),
        ),
        ("patterns", set(patterns.iter().cloned())),
    ]);
    out.push(("command".to_string(), Scope::Command, context));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_path_shortens_registry_roots() {
        assert_eq!(norm_path("HKEY_LOCAL_MACHINE\\SAM"), "HKLM/SAM");
        assert_eq!(norm_path("hkcu:\\Software\\\\x"), "HKCU/Software/x");
        assert_eq!(norm_path("/etc//shadow"), "/etc/shadow");
    }
}
