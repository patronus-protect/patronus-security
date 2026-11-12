// SPDX-License-Identifier: MIT OR Apache-2.0
//! `patronus.facts/1` as JSON: the documents the reference builds, their
//! canonical form (`schema.dumps`), and the way back for `prior_facts` that a
//! caller kept as JSON.

use serde_json::{json, Map, Value};

use crate::detectors::facts_common::fields::Fields;
use crate::detectors::facts_common::pyjson;

use super::{
    Analysis, Facts, Flow, LegacyClass, Network, Object, Segment, Setting, ShellContext, Write,
    FACTS_VERSION,
};

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

impl Object<'_> {
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

fn flow_json(flow: &Flow<'_>) -> Value {
    json!({"data": flow.data, "sink": flow.sink, "via": flow.via})
}

impl Segment<'_> {
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

impl Facts<'_> {
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

    /// The facts document in canonical order (`schema.canonical`): sorted
    /// lists except `segments`, which keeps the command order.
    pub fn canonical_value(&self) -> Value {
        let mut value = self.to_json();
        pyjson::canonical(&mut value, &["segments"]);
        value
    }

    /// Canonical JSON (`schema.dumps`): sorted keys, sorted lists except
    /// `segments`, compact separators, UTF-8.
    pub fn canonical_json(&self) -> String {
        pyjson::dumps_compact(&self.canonical_value())
    }
}

fn context_from_json(value: &Value) -> Result<ShellContext, String> {
    let mut f = Fields::of(value, "context")?;
    let mut field = |key: &str| -> Result<Option<String>, String> {
        f.optional(key)
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("context.{key} must be a string"))
            })
            .transpose()
    };
    let context = ShellContext {
        cwd: field("cwd")?,
        home: field("home")?,
        repo_root: field("repo_root")?,
        dialect: field("dialect")?,
    };
    f.finish()?;
    Ok(context)
}

fn object_from_json(value: &Value) -> Result<Object<'_>, String> {
    let mut f = Fields::of(value, "object")?;
    let object = Object {
        value: f.opt_str("value")?.map(str::to_string),
        class: f.str("class")?,
        access: f.opt_str("access")?,
        abs: f.opt_str("abs")?.map(str::to_string),
        legacy_class: match f.optional("legacy_class") {
            None => LegacyClass::Absent,
            Some(Value::Null) => LegacyClass::Null,
            Some(Value::String(class)) => LegacyClass::Class(class),
            Some(_) => return Err("object.legacy_class must be a string or null".into()),
        },
    };
    f.finish()?;
    Ok(object)
}

fn flow_from_json(value: &Value) -> Result<Flow<'_>, String> {
    let mut f = Fields::of(value, "flow")?;
    let flow = Flow::new(f.str("data")?, f.str("sink")?, f.str("via")?);
    f.finish()?;
    Ok(flow)
}

fn segment_from_json(value: &Value) -> Result<Segment<'_>, String> {
    let mut f = Fields::of(value, "segment")?;
    let mut container = Fields::of(f.get("container")?, "segment.container")?;
    let (host_root_mount, privileged) = (
        container.bool("host_root_mount")?,
        container.bool("privileged")?,
    );
    container.finish()?;
    let segment = Segment {
        id: Fields::index(f.get("id")?, "segment.id")?,
        head: f.str("head")?.to_string(),
        program: f.str("program")?.to_string(),
        verb: f.opt_str("verb")?,
        role: f.opt_str("role")?,
        sensitive: f.bool("sensitive")?,
        vocab: f.opt_str("vocab")?,
        ops: f.strs("ops")?,
        objects: f.list("objects", object_from_json)?,
        kv: f.strings("kv")?,
        settings: f.list("settings", |v| {
            let mut s = Fields::of(v, "setting")?;
            let setting = Setting {
                domain: s.str("domain")?,
                polarity: s.str("polarity")?,
            };
            s.finish().map(|()| setting)
        })?,
        secctl: f.bool("secctl")?,
        grants: f.strs("grants")?,
        host_root_mount,
        privileged,
        fixture: f.bool("fixture")?,
        redirected: f.bool("redirected")?,
        network: f.list("network", |v| {
            let mut n = Fields::of(v, "network")?;
            let network = Network {
                host: n.str("host")?.to_string(),
                scope: n.str("scope")?,
            };
            n.finish().map(|()| network)
        })?,
        argv: f.strings("argv")?,
        sql: f.strs("sql")?,
        nested: f
            .optional("nested")
            .map(|v| v.as_str().ok_or("segment.nested must be a string"))
            .transpose()?,
        parent: f
            .optional("parent")
            .map(|v| Fields::index(v, "segment.parent"))
            .transpose()?,
        rest_raw: Vec::new(),
    };
    f.finish()?;
    Ok(segment)
}

impl<'a> Facts<'a> {
    /// Facts from their JSON document ([`Self::to_json`] or the canonical
    /// form, e.g. the `facts` of a verdict kept as `prior_facts`); the strings
    /// borrow from `value`. Refuses another version, missing and unknown keys.
    pub fn from_json(value: &'a Value) -> Result<Self, String> {
        let mut f = Fields::of(value, "facts")?;
        if f.str("v")? != FACTS_VERSION || f.str("mode")? != "fixed" {
            return Err(format!(
                "facts must be patronus.facts/1 v {FACTS_VERSION} in fixed mode"
            ));
        }
        let facts = Facts {
            dialect: f.str("dialect")?.to_string(),
            parse_status: f.str("parse_status")?,
            context: match f.get("context")? {
                Value::Null => None,
                context => Some(context_from_json(context)?),
            },
            segments: f.list("segments", segment_from_json)?,
            flows: f.list("flows", flow_from_json)?,
            objects: f.list("objects", object_from_json)?,
            atoms: f.strings("atoms")?,
            writes: f.list("writes", |v| {
                let mut w = Fields::of(v, "write")?;
                let write = Write {
                    path: w.str("path")?.to_string(),
                    data: w.str("data")?,
                };
                w.finish().map(|()| write)
            })?,
            downloads: f.strings("downloads")?,
            analysis: Analysis::default(),
        };
        f.finish()?;
        Ok(facts)
    }
}
