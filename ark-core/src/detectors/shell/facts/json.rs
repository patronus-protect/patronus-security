// SPDX-License-Identifier: MIT OR Apache-2.0
//! `patronus.facts/1` as JSON: the documents the reference builds, and their
//! canonical form (`schema.dumps`).

use serde_json::{json, Map, Value};

use crate::detectors::shell::pyjson;

use super::{Facts, Flow, LegacyClass, Object, Segment, ShellContext, FACTS_VERSION};

impl ShellContext {
    fn to_json(&self) -> Value {
        let mut map = Map::new();
        for (key, value) in [
            ("cwd", &self.cwd),
            ("home", &self.home),
            ("repo_root", &self.repo_root),
            ("dialect", &self.dialect),
        ] {
            if let Some(value) = value {
                map.insert(key.to_string(), json!(value));
            }
        }
        Value::Object(map)
    }
}

impl Object {
    fn to_json(&self) -> Value {
        let mut map = Map::new();
        map.insert("value".into(), json!(self.value));
        map.insert("class".into(), json!(self.class));
        map.insert("access".into(), json!(self.access));
        map.insert("abs".into(), json!(self.abs));
        match self.legacy_class {
            LegacyClass::Absent => {}
            LegacyClass::Null => {
                map.insert("legacy_class".into(), Value::Null);
            }
            LegacyClass::Class(class) => {
                map.insert("legacy_class".into(), json!(class));
            }
        }
        Value::Object(map)
    }
}

fn flow_json(flow: &Flow) -> Value {
    json!({"data": flow.data, "sink": flow.sink, "via": flow.via})
}

impl Segment {
    fn to_json(&self) -> Value {
        let mut value = json!({
            "id": self.id,
            "head": self.head,
            "program": self.program,
            "verb": self.verb,
            "role": self.role,
            "sensitive": self.sensitive,
            "vocab": self.vocab,
            "ops": self.ops,
            "objects": self.objects.iter().map(Object::to_json).collect::<Vec<_>>(),
            "kv": self.kv,
            "settings": self.settings.iter()
                .map(|s| json!({"domain": s.domain, "polarity": s.polarity}))
                .collect::<Vec<_>>(),
            "secctl": self.secctl,
            "grants": self.grants,
            "container": {"host_root_mount": self.host_root_mount, "privileged": self.privileged},
            "fixture": self.fixture,
            "redirected": self.redirected,
            "network": self.network.iter()
                .map(|n| json!({"host": n.host, "scope": n.scope}))
                .collect::<Vec<_>>(),
            "argv": self.argv,
            "sql": self.sql,
        });
        if let Some(nested) = self.nested {
            value["nested"] = json!(nested);
        }
        if let Some(parent) = self.parent {
            value["parent"] = json!(parent);
        }
        value
    }
}

impl Facts {
    /// The facts document as the Python reference builds it (key order and
    /// list order not yet canonical).
    pub fn to_json(&self) -> Value {
        json!({
            "v": FACTS_VERSION,
            "mode": "fixed",
            "dialect": self.dialect,
            "parse_status": self.parse_status,
            "context": self.context.as_ref().map(ShellContext::to_json),
            "segments": self.segments.iter().map(Segment::to_json).collect::<Vec<_>>(),
            "flows": self.flows.iter().map(flow_json).collect::<Vec<_>>(),
            "objects": self.objects.iter().map(Object::to_json).collect::<Vec<_>>(),
            "atoms": self.atoms,
            "writes": self.writes.iter()
                .map(|w| json!({"path": w.path, "data": w.data}))
                .collect::<Vec<_>>(),
            "downloads": self.downloads,
        })
    }

    /// Canonical JSON (`schema.dumps`): sorted keys, sorted lists except
    /// `segments`, compact separators, UTF-8.
    pub fn canonical_json(&self) -> String {
        let mut value = self.to_json();
        pyjson::canonical(&mut value);
        pyjson::dumps_compact(&value)
    }
}
