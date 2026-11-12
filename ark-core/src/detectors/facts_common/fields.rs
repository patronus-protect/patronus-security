// SPDX-License-Identifier: MIT OR Apache-2.0
//! Strict reading of facts documents: every key is taken once, missing and
//! unknown keys are errors.

use serde_json::{Map, Value};

/// The fields of one JSON object, taken one by one; [`Self::finish`] refuses
/// keys nobody took.
pub(crate) struct Fields<'a> {
    what: &'static str,
    map: &'a Map<String, Value>,
    taken: usize,
}

impl<'a> Fields<'a> {
    pub(crate) fn of(value: &'a Value, what: &'static str) -> Result<Self, String> {
        let map = value
            .as_object()
            .ok_or_else(|| format!("{what} must be an object"))?;
        Ok(Self {
            what,
            map,
            taken: 0,
        })
    }

    pub(crate) fn optional(&mut self, key: &str) -> Option<&'a Value> {
        let value = self.map.get(key);
        self.taken += usize::from(value.is_some());
        value
    }

    pub(crate) fn get(&mut self, key: &str) -> Result<&'a Value, String> {
        let what = self.what;
        self.optional(key)
            .ok_or_else(|| format!("{what}.{key} is missing"))
    }

    pub(crate) fn str(&mut self, key: &str) -> Result<&'a str, String> {
        let what = self.what;
        self.get(key)?
            .as_str()
            .ok_or_else(|| format!("{what}.{key} must be a string"))
    }

    pub(crate) fn opt_str(&mut self, key: &str) -> Result<Option<&'a str>, String> {
        let what = self.what;
        match self.get(key)? {
            Value::Null => Ok(None),
            value => value
                .as_str()
                .map(Some)
                .ok_or_else(|| format!("{what}.{key} must be a string or null")),
        }
    }

    pub(crate) fn bool(&mut self, key: &str) -> Result<bool, String> {
        let what = self.what;
        self.get(key)?
            .as_bool()
            .ok_or_else(|| format!("{what}.{key} must be a boolean"))
    }

    pub(crate) fn index(value: &Value, what: &str) -> Result<usize, String> {
        value
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| format!("{what} must be a non-negative integer"))
    }

    pub(crate) fn list<T>(
        &mut self,
        key: &str,
        item: impl Fn(&'a Value) -> Result<T, String>,
    ) -> Result<Vec<T>, String> {
        let what = self.what;
        self.get(key)?
            .as_array()
            .ok_or_else(|| format!("{what}.{key} must be a list"))?
            .iter()
            .map(item)
            .collect()
    }

    pub(crate) fn strs(&mut self, key: &str) -> Result<Vec<&'a str>, String> {
        let what = self.what;
        self.list(key, |v| {
            v.as_str()
                .ok_or_else(|| format!("{what}.{key} must hold strings"))
        })
    }

    pub(crate) fn strings(&mut self, key: &str) -> Result<Vec<String>, String> {
        Ok(self.strs(key)?.into_iter().map(str::to_string).collect())
    }

    pub(crate) fn finish(self) -> Result<(), String> {
        if self.taken == self.map.len() {
            return Ok(());
        }
        let mut unknown: Vec<&str> = self.map.keys().map(String::as_str).collect();
        unknown.sort_unstable();
        Err(format!("{} has unknown keys among {unknown:?}", self.what))
    }
}
