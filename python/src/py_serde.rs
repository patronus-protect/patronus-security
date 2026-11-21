// SPDX-License-Identifier: GPL-3.0-only
//! A `serde` serializer that builds the Python objects `json.loads` makes of
//! `serde_json::to_string(value)`, without the JSON text: a JSON text round
//! trip cost more than the scan on large texts (H06-2). The public result dicts
//! come from the Rust types' own `Serialize` implementations through it.
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyList, PyString};
use rustc_hash::FxHashMap;
use serde::ser::{self, Serialize};

/// Shares one string object per distinct short text: the keys and most
/// string values (`rule_id`, `span_precision`, …) repeat in every
/// `matched_rules` entry, and creating and freeing a string per occurrence
/// cost about a third of the details of a 100 KiB scan (H06-3). A shared
/// string is equal and immutable, so the objects are the ones `json.loads`
/// makes. The cache hashes with Fx: SipHash cost about a fifth of the details
/// of a 100 KiB scan (H06-5).
pub(crate) struct PyStrings<'py> {
    py: Python<'py>,
    strings: FxHashMap<Box<str>, Bound<'py, PyString>>,
}

/// Longer texts (scanned text in spans and details) are rarely repeated and
/// are not worth a cache entry.
const CACHED_STRING_MAX_BYTES: usize = 64;

impl<'py> PyStrings<'py> {
    pub(crate) fn new(py: Python<'py>) -> Self {
        Self {
            py,
            strings: FxHashMap::default(),
        }
    }

    /// A dict key, interned like the keys `json.loads` memoizes.
    fn key(&mut self, text: &str) -> Bound<'py, PyString> {
        if let Some(string) = self.strings.get(text) {
            return string.clone();
        }
        let string = PyString::intern_bound(self.py, text);
        self.strings.insert(text.into(), string.clone());
        string
    }

    /// A string value; not interned, as it may hold scanned text.
    fn value(&mut self, text: &str) -> Bound<'py, PyString> {
        if text.len() > CACHED_STRING_MAX_BYTES {
            return PyString::new_bound(self.py, text);
        }
        if let Some(string) = self.strings.get(text) {
            return string.clone();
        }
        let string = PyString::new_bound(self.py, text);
        self.strings.insert(text.into(), string.clone());
        string
    }
}

/// `value` as Python objects, sharing `strings` across calls.
pub(crate) fn to_py<'py, T: Serialize + ?Sized>(
    strings: &mut PyStrings<'py>,
    value: &T,
) -> PyResult<Bound<'py, PyAny>> {
    value
        .serialize(PySerializer {
            strings,
            key: false,
        })
        .map_err(|error| error.0)
}

#[derive(Debug)]
pub(crate) struct Error(PyErr);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Error {}

impl ser::Error for Error {
    fn custom<T: std::fmt::Display>(message: T) -> Self {
        Self(PyValueError::new_err(message.to_string()))
    }
}

impl From<PyErr> for Error {
    fn from(error: PyErr) -> Self {
        Self(error)
    }
}

struct PySerializer<'s, 'py> {
    strings: &'s mut PyStrings<'py>,
    /// A map key: strings are interned and numbers become strings, as JSON
    /// object keys are.
    key: bool,
}

impl<'s, 'py> PySerializer<'s, 'py> {
    fn py(&self) -> Python<'py> {
        self.strings.py
    }

    fn number<N: IntoPy<PyObject> + ToString>(self, number: N) -> Result<Bound<'py, PyAny>, Error> {
        if self.key {
            return Ok(self.strings.key(&number.to_string()).into_any());
        }
        let py = self.py();
        Ok(number.into_py(py).into_bound(py))
    }

    /// `{variant: value}`, serde's external enum tagging as `serde_json` writes it.
    fn tagged(
        strings: &mut PyStrings<'py>,
        variant: &'static str,
        value: Bound<'py, PyAny>,
    ) -> Result<Bound<'py, PyAny>, Error> {
        let dict = PyDict::new_bound(strings.py);
        dict.set_item(strings.key(variant), value)?;
        Ok(dict.into_any())
    }
}

impl<'s, 'py> ser::Serializer for PySerializer<'s, 'py> {
    type Ok = Bound<'py, PyAny>;
    type Error = Error;
    type SerializeSeq = SeqBuilder<'s, 'py>;
    type SerializeTuple = SeqBuilder<'s, 'py>;
    type SerializeTupleStruct = SeqBuilder<'s, 'py>;
    type SerializeTupleVariant = SeqBuilder<'s, 'py>;
    type SerializeMap = MapBuilder<'s, 'py>;
    type SerializeStruct = MapBuilder<'s, 'py>;
    type SerializeStructVariant = MapBuilder<'s, 'py>;

    fn serialize_bool(self, value: bool) -> Result<Self::Ok, Error> {
        if self.key {
            return Ok(self
                .strings
                .key(if value { "true" } else { "false" })
                .into_any());
        }
        Ok(PyBool::new_bound(self.py(), value).to_owned().into_any())
    }

    fn serialize_i8(self, value: i8) -> Result<Self::Ok, Error> {
        self.number(value)
    }

    fn serialize_i16(self, value: i16) -> Result<Self::Ok, Error> {
        self.number(value)
    }

    fn serialize_i32(self, value: i32) -> Result<Self::Ok, Error> {
        self.number(value)
    }

    fn serialize_i64(self, value: i64) -> Result<Self::Ok, Error> {
        self.number(value)
    }

    fn serialize_u8(self, value: u8) -> Result<Self::Ok, Error> {
        self.number(value)
    }

    fn serialize_u16(self, value: u16) -> Result<Self::Ok, Error> {
        self.number(value)
    }

    fn serialize_u32(self, value: u32) -> Result<Self::Ok, Error> {
        self.number(value)
    }

    fn serialize_u64(self, value: u64) -> Result<Self::Ok, Error> {
        self.number(value)
    }

    fn serialize_f32(self, value: f32) -> Result<Self::Ok, Error> {
        self.serialize_f64(f64::from(value))
    }

    fn serialize_f64(self, value: f64) -> Result<Self::Ok, Error> {
        if self.key {
            return Err(ser::Error::custom("float map keys are not supported"));
        }
        Ok(PyFloat::new_bound(self.py(), value).into_any())
    }

    fn serialize_char(self, value: char) -> Result<Self::Ok, Error> {
        self.serialize_str(value.encode_utf8(&mut [0; 4]))
    }

    fn serialize_str(self, value: &str) -> Result<Self::Ok, Error> {
        Ok(if self.key {
            self.strings.key(value)
        } else {
            self.strings.value(value)
        }
        .into_any())
    }

    fn serialize_bytes(self, value: &[u8]) -> Result<Self::Ok, Error> {
        let py = self.py();
        Ok(PyList::new_bound(py, value).into_any())
    }

    fn serialize_none(self) -> Result<Self::Ok, Error> {
        Ok(self.py().None().into_bound(self.py()))
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Self::Ok, Error> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Error> {
        self.serialize_none()
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Error> {
        self.serialize_none()
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Error> {
        self.serialize_str(variant)
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Error> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Error> {
        let inner = value.serialize(PySerializer {
            strings: &mut *self.strings,
            key: false,
        })?;
        Self::tagged(self.strings, variant, inner)
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<SeqBuilder<'s, 'py>, Error> {
        Ok(SeqBuilder {
            list: PyList::empty_bound(self.py()),
            strings: self.strings,
            variant: None,
        })
    }

    fn serialize_tuple(self, len: usize) -> Result<SeqBuilder<'s, 'py>, Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<SeqBuilder<'s, 'py>, Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<SeqBuilder<'s, 'py>, Error> {
        let mut builder = self.serialize_seq(Some(len))?;
        builder.variant = Some(variant);
        Ok(builder)
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<MapBuilder<'s, 'py>, Error> {
        Ok(MapBuilder {
            dict: PyDict::new_bound(self.py()),
            strings: self.strings,
            key: None,
            variant: None,
        })
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<MapBuilder<'s, 'py>, Error> {
        self.serialize_map(Some(len))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<MapBuilder<'s, 'py>, Error> {
        let mut builder = self.serialize_map(Some(len))?;
        builder.variant = Some(variant);
        Ok(builder)
    }
}

pub(crate) struct SeqBuilder<'s, 'py> {
    list: Bound<'py, PyList>,
    strings: &'s mut PyStrings<'py>,
    variant: Option<&'static str>,
}

impl<'s, 'py> SeqBuilder<'s, 'py> {
    fn push<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        let item = value.serialize(PySerializer {
            strings: &mut *self.strings,
            key: false,
        })?;
        self.list.append(item)?;
        Ok(())
    }

    fn finish(self) -> Result<Bound<'py, PyAny>, Error> {
        match self.variant {
            Some(variant) => PySerializer::tagged(self.strings, variant, self.list.into_any()),
            None => Ok(self.list.into_any()),
        }
    }
}

impl<'s, 'py> ser::SerializeSeq for SeqBuilder<'s, 'py> {
    type Ok = Bound<'py, PyAny>;
    type Error = Error;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.push(value)
    }

    fn end(self) -> Result<Self::Ok, Error> {
        self.finish()
    }
}

impl<'s, 'py> ser::SerializeTuple for SeqBuilder<'s, 'py> {
    type Ok = Bound<'py, PyAny>;
    type Error = Error;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.push(value)
    }

    fn end(self) -> Result<Self::Ok, Error> {
        self.finish()
    }
}

impl<'s, 'py> ser::SerializeTupleStruct for SeqBuilder<'s, 'py> {
    type Ok = Bound<'py, PyAny>;
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.push(value)
    }

    fn end(self) -> Result<Self::Ok, Error> {
        self.finish()
    }
}

impl<'s, 'py> ser::SerializeTupleVariant for SeqBuilder<'s, 'py> {
    type Ok = Bound<'py, PyAny>;
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.push(value)
    }

    fn end(self) -> Result<Self::Ok, Error> {
        self.finish()
    }
}

pub(crate) struct MapBuilder<'s, 'py> {
    dict: Bound<'py, PyDict>,
    strings: &'s mut PyStrings<'py>,
    key: Option<Bound<'py, PyAny>>,
    variant: Option<&'static str>,
}

impl<'s, 'py> MapBuilder<'s, 'py> {
    fn value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<Bound<'py, PyAny>, Error> {
        value.serialize(PySerializer {
            strings: &mut *self.strings,
            key: false,
        })
    }

    fn finish(self) -> Result<Bound<'py, PyAny>, Error> {
        match self.variant {
            Some(variant) => PySerializer::tagged(self.strings, variant, self.dict.into_any()),
            None => Ok(self.dict.into_any()),
        }
    }
}

impl<'s, 'py> ser::SerializeMap for MapBuilder<'s, 'py> {
    type Ok = Bound<'py, PyAny>;
    type Error = Error;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Error> {
        self.key = Some(key.serialize(PySerializer {
            strings: &mut *self.strings,
            key: true,
        })?);
        Ok(())
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        let key = self
            .key
            .take()
            .ok_or_else(|| <Error as ser::Error>::custom("map value without a key"))?;
        let value = self.value(value)?;
        self.dict.set_item(key, value)?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Error> {
        self.finish()
    }
}

impl<'s, 'py> ser::SerializeStruct for MapBuilder<'s, 'py> {
    type Ok = Bound<'py, PyAny>;
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        let value = self.value(value)?;
        self.dict.set_item(self.strings.key(key), value)?;
        Ok(())
    }

    fn end(self) -> Result<Self::Ok, Error> {
        self.finish()
    }
}

impl<'s, 'py> ser::SerializeStructVariant for MapBuilder<'s, 'py> {
    type Ok = Bound<'py, PyAny>;
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        ser::SerializeStruct::serialize_field(self, key, value)
    }

    fn end(self) -> Result<Self::Ok, Error> {
        self.finish()
    }
}
