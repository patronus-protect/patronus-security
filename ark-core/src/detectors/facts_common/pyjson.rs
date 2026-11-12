// SPDX-License-Identifier: MIT OR Apache-2.0
//! Python `json.dumps` and float formatting, byte for byte.
//!
//! `patronus.facts/1`, `patronus.text_facts/1` and `patronus.verdict/1` are
//! defined by the canonical JSON the Python reference writes, so the port
//! writes the same bytes: sorted keys, `repr` floats (`1e-05`, `2.0`), Python's
//! string escapes, and the canonical list order of `schema.canonical`.

use serde_json::Value;

/// `json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)`.
pub fn dumps_compact(value: &Value) -> String {
    let mut out = String::new();
    write(value, &mut out, false, (",", ":"));
    out
}

/// `json.dumps(value, sort_keys=True)`: default separators, ASCII escapes. It is
/// the sort key of `schema.canonical`.
fn dumps_sort_key(value: &Value) -> String {
    let mut out = String::new();
    write(value, &mut out, true, (", ", ": "));
    out
}

fn write(value: &Value, out: &mut String, ascii: bool, separators: (&str, &str)) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => match number.as_f64() {
            Some(float) if number.is_f64() => out.push_str(&float_repr(float)),
            _ => out.push_str(&number.to_string()),
        },
        Value::String(text) => write_str(text, out, ascii),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(separators.0);
                }
                write(item, out, ascii, separators);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push_str(separators.0);
                }
                write_str(key, out, ascii);
                out.push_str(separators.1);
                write(&map[key], out, ascii, separators);
            }
            out.push('}');
        }
    }
}

fn write_str(text: &str, out: &mut String, ascii: bool) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if ascii && !c.is_ascii() => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Python `repr(float)`: the shortest round-trip digits, positional for
/// decimal exponents -4..16, else `d.ddde+XX`.
pub fn float_repr(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_string();
    }
    // `{:e}` gives the shortest round-trip digits as `d.ddde[-]x`.
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific.split_once('e').expect("exponent");
    let exponent: i32 = exponent.parse().expect("exponent digits");
    let (sign, mantissa) = match mantissa.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", mantissa),
    };
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let point = exponent + 1; // digits are 0.d1d2… × 10^point
    if !(-4 < point && point <= 16) {
        let tail = if digits.len() > 1 {
            format!("{}.{}", &digits[..1], &digits[1..])
        } else {
            digits.clone()
        };
        let exp_sign = if exponent < 0 { '-' } else { '+' };
        return format!("{sign}{tail}e{exp_sign}{:02}", exponent.abs());
    }
    if point <= 0 {
        return format!("{sign}0.{}{digits}", "0".repeat((-point) as usize));
    }
    let point = point as usize;
    if digits.len() <= point {
        format!("{sign}{digits}{}.0", "0".repeat(point - digits.len()))
    } else {
        format!("{sign}{}.{}", &digits[..point], &digits[point..])
    }
}

/// Python `round(value, ndigits)`: correctly rounded, ties to even on the
/// exact binary value (Rust's fixed-precision formatting does the same).
pub fn py_round(value: f64, ndigits: usize) -> f64 {
    if !value.is_finite() {
        return value;
    }
    format!("{value:.ndigits$}")
        .parse()
        .expect("formatted float")
}

/// `schema.canonical`: every list sorted by its `json.dumps(sort_keys=True)`
/// form, except the lists under a key in `ordered` (the `segments` of a
/// command), which keep their order.
pub fn canonical(value: &mut Value, ordered: &[&str]) {
    match value {
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                match item {
                    Value::Array(items) if ordered.contains(&key.as_str()) => {
                        items.iter_mut().for_each(|item| canonical(item, ordered))
                    }
                    item => canonical(item, ordered),
                }
            }
        }
        Value::Array(items) => {
            items.iter_mut().for_each(|item| canonical(item, ordered));
            let mut keyed: Vec<(String, Value)> = items
                .drain(..)
                .map(|item| (dumps_sort_key(&item), item))
                .collect();
            keyed.sort_by(|left, right| left.0.cmp(&right.0));
            items.extend(keyed.into_iter().map(|(_, item)| item));
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn float_repr_matches_python() {
        for (value, expected) in [
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (2.0, "2.0"),
            (0.1, "0.1"),
            (1e-4, "0.0001"),
            (1e-5, "1e-05"),
            (1.5e-7, "1.5e-07"),
            (1e15, "1000000000000000.0"),
            (1e16, "1e+16"),
            (123456.789, "123456.789"),
            (0.34768833740155536, "0.34768833740155536"),
            (-3.0531749725341797, "-3.0531749725341797"),
        ] {
            assert_eq!(float_repr(value), expected, "{value}");
        }
    }

    #[test]
    fn round_is_correctly_rounded() {
        assert_eq!(py_round(2.675, 2), 2.67); // binary value is below the tie
        assert_eq!(py_round(0.125, 2), 0.12); // exact tie goes to even
        assert_eq!(py_round(4.29603232068, 4), 4.296);
        assert_eq!(py_round(-0.00004, 4), -0.0);
    }

    #[test]
    fn dumps_sorts_keys_and_escapes_like_python() {
        let value = json!({"b": [1, 2.5, "é\"\u{1}"], "a": null, "c": true});
        assert_eq!(
            dumps_compact(&value),
            "{\"a\":null,\"b\":[1,2.5,\"é\\\"\\u0001\"],\"c\":true}"
        );
        assert_eq!(
            dumps_sort_key(&json!(["é", "😀"])),
            "[\"\\u00e9\", \"\\ud83d\\ude00\"]"
        );
    }

    #[test]
    fn canonical_sorts_lists_but_not_segments() {
        let mut value = json!({
            "segments": [{"argv": ["b", "a"]}, {"argv": []}],
            "atoms": ["Z", "A"],
            "flows": [{"data": "b"}, {"data": "a"}]
        });
        canonical(&mut value, &["segments"]);
        assert_eq!(
            dumps_compact(&value),
            r#"{"atoms":["A","Z"],"flows":[{"data":"a"},{"data":"b"}],"segments":[{"argv":["a","b"]},{"argv":[]}]}"#
        );
    }
}
