// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tool-call arguments as JSON in their original key order. The reference
//! walks the arguments as Python's `json.loads` builds them (insertion order,
//! a repeated key keeps its first position and its last value), and its
//! limits (`[:40]` keys, `[:20]` items) and the model's code text depend on
//! that order; `serde_json::Map` sorts keys in this crate.

use std::fmt;

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Number, Value};

/// A JSON value with object keys in document order.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    /// Parse JSON text.
    pub fn parse(text: &str) -> Result<Self, String> {
        serde_json::from_str(text).map_err(|error| error.to_string())
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    /// The value of `key` in an object.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Python truthiness.
    pub fn truthy(&self) -> bool {
        match self {
            Json::Null => false,
            Json::Bool(b) => *b,
            Json::Number(n) => n.as_f64() != Some(0.0),
            Json::String(s) => !s.is_empty(),
            Json::Array(a) => !a.is_empty(),
            Json::Object(o) => !o.is_empty(),
        }
    }

    /// Python `str()` of the value as `json.loads` would have built it.
    pub fn py_str(&self) -> String {
        self.py_repr(true)
    }

    fn py_repr(&self, top: bool) -> String {
        match self {
            Json::Null => "None".into(),
            Json::Bool(b) => (if *b { "True" } else { "False" }).into(),
            Json::Number(n) => n.to_string(),
            Json::String(s) if top => s.clone(),
            Json::String(s) => format!("'{s}'"),
            Json::Array(a) => format!(
                "[{}]",
                a.iter()
                    .map(|x| x.py_repr(false))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Json::Object(o) => format!(
                "{{{}}}",
                o.iter()
                    .map(|(k, x)| format!("'{k}': {}", x.py_repr(false)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    /// Compact JSON text in document order.
    pub fn to_text(&self) -> String {
        serde_json::to_string(&self.to_value_ordered()).unwrap_or_default()
    }

    /// As a `serde_json::Value` (keys sorted, as `serde_json::Map` keeps them).
    pub fn to_value(&self) -> Value {
        match self {
            Json::Null => Value::Null,
            Json::Bool(b) => Value::Bool(*b),
            Json::Number(n) => Value::Number(n.clone()),
            Json::String(s) => Value::String(s.clone()),
            Json::Array(a) => Value::Array(a.iter().map(Json::to_value).collect()),
            Json::Object(o) => {
                Value::Object(o.iter().map(|(k, v)| (k.clone(), v.to_value())).collect())
            }
        }
    }

    fn to_value_ordered(&self) -> OrderedValue<'_> {
        OrderedValue(self)
    }
}

/// Serializes a [`Json`] with its keys in document order.
struct OrderedValue<'a>(&'a Json);

impl serde::Serialize for OrderedValue<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeSeq};
        match self.0 {
            Json::Null => serializer.serialize_unit(),
            Json::Bool(b) => serializer.serialize_bool(*b),
            Json::Number(n) => n.serialize(serializer),
            Json::String(s) => serializer.serialize_str(s),
            Json::Array(a) => {
                let mut seq = serializer.serialize_seq(Some(a.len()))?;
                for x in a {
                    seq.serialize_element(&OrderedValue(x))?;
                }
                seq.end()
            }
            Json::Object(o) => {
                let mut map = serializer.serialize_map(Some(o.len()))?;
                for (k, v) in o {
                    map.serialize_entry(k, &OrderedValue(v))?;
                }
                map.end()
            }
        }
    }
}

impl From<&Value> for Json {
    fn from(value: &Value) -> Self {
        match value {
            Value::Null => Json::Null,
            Value::Bool(b) => Json::Bool(*b),
            Value::Number(n) => Json::Number(n.clone()),
            Value::String(s) => Json::String(s.clone()),
            Value::Array(a) => Json::Array(a.iter().map(Json::from).collect()),
            Value::Object(o) => {
                Json::Object(o.iter().map(|(k, v)| (k.clone(), Json::from(v))).collect())
            }
        }
    }
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Json;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Json, E> {
        Ok(Json::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Json, E> {
        Ok(Json::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Json, E> {
        Ok(Json::Number(v.into()))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Json, E> {
        Ok(Number::from_f64(v).map_or(Json::Null, Json::Number))
    }

    fn visit_str<E>(self, v: &str) -> Result<Json, E> {
        Ok(Json::String(v.to_string()))
    }

    fn visit_string<E>(self, v: String) -> Result<Json, E> {
        Ok(Json::String(v))
    }

    fn visit_unit<E>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_none<E>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Json, D::Error> {
        Json::deserialize(d)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        let mut out = Vec::new();
        while let Some(x) = seq.next_element()? {
            out.push(x);
        }
        Ok(Json::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let mut out: Vec<(String, Json)> = Vec::new();
        while let Some((k, v)) = map.next_entry::<String, Json>()? {
            match out.iter_mut().find(|(key, _)| *key == k) {
                Some(slot) => slot.1 = v,
                None => out.push((k, v)),
            }
        }
        Ok(Json::Object(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_key_order_and_python_duplicates() {
        let j = Json::parse(r#"{"b": 1, "a": [true, null], "b": 2.5}"#).unwrap();
        let Json::Object(pairs) = &j else { panic!() };
        assert_eq!(
            pairs.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
            ["b", "a"]
        );
        assert_eq!(j.get("b").unwrap().py_str(), "2.5");
        assert_eq!(j.get("a").unwrap().py_str(), "[True, None]");
        assert_eq!(j.to_text(), r#"{"b":2.5,"a":[true,null]}"#);
    }
}
