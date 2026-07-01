use serde_json::Value;

pub(crate) fn schema_strings(value: &Value) -> Vec<String> {
    let mut strings = Vec::new();
    collect_schema_strings(value, None, &mut strings);
    strings
}

fn collect_schema_strings(value: &Value, key: Option<&str>, strings: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            if key.map(is_schema_text_key).unwrap_or(false) {
                strings.push(text.clone());
            }
        }
        Value::Array(items) => {
            if key.map(is_schema_text_key).unwrap_or(false) {
                for item in items {
                    collect_all_strings(item, strings);
                }
                return;
            }
            for item in items {
                collect_schema_strings(item, None, strings);
            }
        }
        Value::Object(map) => {
            for (next_key, item) in map {
                collect_schema_strings(item, Some(next_key), strings);
            }
        }
        _ => {}
    }
}

fn collect_all_strings(value: &Value, strings: &mut Vec<String>) {
    match value {
        Value::String(text) => strings.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                collect_all_strings(item, strings);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                collect_all_strings(item, strings);
            }
        }
        _ => {}
    }
}

fn is_schema_text_key(key: &str) -> bool {
    matches!(
        key,
        "description" | "title" | "$comment" | "examples" | "default" | "enum"
    )
}
