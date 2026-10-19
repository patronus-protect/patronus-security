// SPDX-License-Identifier: GPL-3.0-only
//! T07: placeholders and environment/template references in the value of
//! value-capturing credential rules. General code expressions as values
//! (function calls, member access, type annotations) are left to T03.
use regex::Regex;
use std::{ops::Range, sync::OnceLock};

/// Text after the value start that is checked for a reference: captures stop
/// at `(`, `[` or `}`, so `os.environ[…]`, `ENV.fetch(…)` and `{{var}}` are
/// only visible in the text that follows the value.
const REFERENCE_WINDOW: usize = 256;

/// Placeholder values in any case, compared without `_`, `-` and `.`.
const PLACEHOLDER_VALUES: &[&str] = &[
    "changeme",
    "replaceme",
    "todo",
    "tbd",
    "fixme",
    "placeholder",
    "platzhalter",
    "bitteaendern",
    "bitteändern",
];

/// Words that make an all-upper or all-lower word sequence a placeholder
/// wherever they stand (`YOUR_API_TOKEN`, `dein-api-token`, `TOKEN_TODO`).
const PLACEHOLDER_WORDS: &[&str] = &[
    "your",
    "yours",
    "dein",
    "deine",
    "deinen",
    "deinem",
    "deiner",
    "placeholder",
    "platzhalter",
    "changeme",
    "replaceme",
    "todo",
    "fixme",
    "tbd",
];

/// Words that make such a sequence a placeholder as its first word
/// (`INSERT_TOKEN_HERE`, `HIER_…`, `BITTE_AENDERN`, `IHR_API_SCHLUESSEL`).
const PLACEHOLDER_FIRST_WORDS: &[&str] = &[
    "insert", "enter", "replace", "hier", "bitte", "ihr", "ihre", "ihren",
];

/// Words that make such a sequence a placeholder as its last word
/// (`…_HERE`, `…_EINTRAGEN`, `PASSWORT_HIER_EINFUEGEN`).
const PLACEHOLDER_LAST_WORDS: &[&str] = &[
    "here",
    "hier",
    "eintragen",
    "einfuegen",
    "einfügen",
    "ersetzen",
    "aendern",
    "ändern",
    "setzen",
    "angeben",
];

/// T07 decision for one match: the value at `range` of `text` is a
/// placeholder or a reference to the environment, a template variable or a
/// Terraform value rather than a secret.
pub(crate) fn is_placeholder_match(text: &str, range: Range<usize>) -> bool {
    let line_end = text[range.start..]
        .find(['\n', '\r'])
        .map_or(text.len(), |index| range.start + index);
    let end = floor_char_boundary(text, line_end.min(range.start + REFERENCE_WINDOW));
    let head = trim_leading_quotes(&text[range.start..end.max(range.end)]);
    is_reference(head) || is_placeholder_value(&text[range])
}

/// Environment accessors and template/interpolation openers at the start of
/// the value: `${…}`, `$(…)`, `${{ … }}`, `{{…}}`, `{%…`, `#{…}`, `$env:X`,
/// `os.environ[…]`, `os.getenv(…)`, `os.Getenv(…)`, `System.getenv(…)`,
/// `Environment.GetEnvironmentVariable(…)`, `ENV.fetch(…)`, `ENV[…]`,
/// `process.env.X`, `import.meta.env.X`, `env::var(…)`, `env!(…)`,
/// `getenv(…)`, `env(…)`, `$_ENV[…]`.
pub(crate) fn is_reference(head: &str) -> bool {
    static REFERENCE: OnceLock<Regex> = OnceLock::new();
    REFERENCE
        .get_or_init(|| {
            Regex::new(concat!(
                r"^(?:\$\{|\$\(|\{\{|\{%|#\{|\$env:[A-Za-z_]",
                r"|(?:os\.)?environ\b",
                r"|(?:os|syscall)\.(?:getenv|Getenv|LookupEnv)\s*\(",
                r"|(?i:system\.getenv)\s*\(",
                r"|Environment\.(?:GetEnvironmentVariable|getenv)\s*\(",
                r"|ENV(?:\.fetch\b|\s*\[)",
                r"|(?:import\.meta|process)\.env\b",
                r"|Deno\.env\.get\s*\(",
                r"|(?:std::)?env::var(?:_os)?\s*\(",
                r"|(?:option_)?env!\s*\(",
                r"|(?i:getenv)\s*\(",
                r"|env\s*\(",
                r"|\$_(?:ENV|SERVER)\s*\[",
                r#"|(?:var|local|module|data)\.[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*|\[[^\]\s]*\]?)*(?:[\s,;)}"'\\]|$)"#,
                r")",
            ))
            .unwrap()
        })
        .is_match(head)
}

/// Placeholder values (T07): `<…>`/`&lt;…&gt;`, masks (`********`,
/// `xxxx-xxxx`), shell and Windows variables (`$VAR`, `%VAR%`), the values of
/// [`PLACEHOLDER_VALUES`] and all-upper or all-lower word sequences such as
/// `YOUR_…_HERE`, `HIER_…_EINTRAGEN` or `your-api-token`. Mixed-case values
/// (`YourDog2026!`), words without a placeholder word (`ORANGE_TRAIN_4711`)
/// and `$` followed by a word with digits (`$ecret2026`) stay secrets.
pub(crate) fn is_placeholder_value(value: &str) -> bool {
    let value = trim_leading_quotes(value);
    let value = value
        .find(['"', '\'', '`', '\\'])
        .map_or(value, |end| &value[..end])
        .trim_end_matches([';', ',', '.', ':']);
    if value.is_empty() {
        return false;
    }
    if value.starts_with('<') || value.starts_with("&lt;") || value.starts_with('[') {
        return true;
    }
    if value
        .chars()
        .all(|character| matches!(character, '*' | '•' | '●' | 'x' | 'X' | '-' | '_' | '.'))
    {
        return true;
    }
    if let Some(name) = value.strip_prefix('$') {
        return is_variable_name(name);
    }
    if let Some(name) = value
        .strip_prefix('%')
        .and_then(|rest| rest.strip_suffix('%'))
    {
        return is_identifier(name);
    }
    is_placeholder_words(value)
}

/// `$name` is a shell, PHP or template variable unless the name looks like
/// the rest of a password: a mixed-case or lower-case word with digits and
/// without `_` (`$ecret2026`, `$kqztrwx4711`).
fn is_variable_name(name: &str) -> bool {
    if !is_identifier(name) {
        return false;
    }
    let has_digit = name.bytes().any(|byte| byte.is_ascii_digit());
    !has_digit || name.contains('_') || !name.bytes().any(|byte| byte.is_ascii_lowercase())
}

fn is_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn is_placeholder_words(value: &str) -> bool {
    let words: Vec<&str> = value.split(['_', '-', '.']).collect();
    if words
        .iter()
        .any(|word| word.is_empty() || !word.chars().all(char::is_alphanumeric))
    {
        return false;
    }
    let joined: String = words.concat().to_lowercase();
    if PLACEHOLDER_VALUES.contains(&joined.as_str()) {
        return true;
    }
    let upper = value.chars().any(char::is_uppercase);
    let lower = value.chars().any(char::is_lowercase);
    if upper == lower {
        // Mixed case (`YourDog`) or no letters at all.
        return false;
    }
    let words: Vec<String> = words.iter().map(|word| word.to_lowercase()).collect();
    let first = words.first().map(String::as_str).unwrap_or_default();
    let last = words.last().map(String::as_str).unwrap_or_default();
    words
        .iter()
        .any(|word| PLACEHOLDER_WORDS.contains(&word.as_str()))
        || PLACEHOLDER_FIRST_WORDS.contains(&first)
        || PLACEHOLDER_LAST_WORDS.contains(&last)
}

/// Quotes and escape backslashes before a value (`"…"`, `\"…\"` in JSON).
fn trim_leading_quotes(value: &str) -> &str {
    value.trim_start_matches(['"', '\'', '`', '\\'])
}

fn floor_char_boundary(text: &str, mut index: usize) -> usize {
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

#[cfg(test)]
mod tests {
    use super::{is_placeholder_match, is_placeholder_value, is_reference};

    #[test]
    fn placeholder_words_in_de_and_en() {
        for value in [
            "YOUR_DB_PASSWORD_HERE",
            "\"YOUR_DB_PASSWORD_HERE\";",
            "'BITTE_AENDERN'",
            "HIER_GITLAB_TOKEN_EINTRAGEN",
            "\"HIER_STRIPE_WEBHOOK_SECRET_EINTRAGEN\";",
            "YOUR-API-TOKEN",
            "your-api-token-here",
            "dein-api-token",
            "IHR_API_SCHLUESSEL",
            "PASSWORT_HIER_EINFÜGEN",
            "INSERT_TOKEN_HERE",
            "REPLACE_WITH_YOUR_TOKEN",
            "REPLACE_ME",
            "TODO",
            "TODO.",
            "ChangeMe",
            "change-me",
            "PLACEHOLDER",
            "<your-token>",
            "&lt;dein-database-url&gt;",
            "[REDACTED]",
            "********",
            "********\\",
            "\"xxxxxxxxxxxxxxxxxxxxxxxx\";",
            "xxxx-xxxx-xxxx",
            "$CLIENT_SECRET",
            "\"$VAULT_SERVICE_TOKEN\"",
            "$db_password",
            "$dbPassword;",
            "%CLIENT_SECRET%",
            "YOUR_DB_PASSWORD_HERE\\n\",\"negative_reason\":\"x\"",
        ] {
            assert!(is_placeholder_value(value), "{value}");
        }
    }

    #[test]
    fn real_values_are_no_placeholders() {
        for value in [
            "Kx7pQ2vL9rT4",
            "YourDog2026!",
            "Here4711Now",
            "ORANGE_KQZTRWX_4711",
            "TODOLIST_KQZTRW_4711",
            "correct-horse-battery-staple",
            "HEREFORD_CATTLE_99",
            "$kqztrwx4711",
            "$ecret2026",
            "%CLIENT_SECRET",
            "x7xX-9xxx",
            "f4fcba1c3696bf9b564c7dac9b0062f5097331f9",
            "B2B6Hwjm1-l_Jt~xzC",
            "r_RP7Jvq4TzDpgn2ey8Zq1WGZKzXDWpMaXsAEBZyTyU",
        ] {
            assert!(!is_placeholder_value(value), "{value}");
        }
    }

    #[test]
    fn environment_and_template_references() {
        for head in [
            "${CLIENT_SECRET}",
            "${{ secrets.CLIENT_SECRET }}",
            "$(pass show ci/token)",
            "{{clientSecret}}",
            "{{ client_secret }}",
            "{% raw %}",
            "#{CLIENT_SECRET}",
            "$env:CLIENT_SECRET",
            "os.environ[\"CLIENT_SECRET\"]",
            "os.environ.get(\"CLIENT_SECRET\")",
            "os.environ[\\\"CLIENT_SECRET\\\"]\\n\",",
            "environ[\"CLIENT_SECRET\"]",
            "os.getenv(\"CLIENT_SECRET\")",
            "os.Getenv(\"CLIENT_SECRET\")",
            "System.getenv(\"CSRF_TOKEN\");",
            "Environment.GetEnvironmentVariable(\"CLIENT_SECRET\");",
            "ENV.fetch(\"CLIENT_SECRET\")",
            "ENV[\"API_TOKEN\"]",
            "process.env.CLIENT_SECRET",
            "import.meta.env.VITE_CLIENT_SECRET;",
            "Deno.env.get(\"TOKEN\")",
            "std::env::var(\"TOKEN\")?;",
            "env!(\"CLIENT_SECRET\");",
            "getenv('DB_PASSWORD');",
            "env('DB_PASSWORD'),",
            "$_ENV['DB_PASSWORD']",
            "var.client_secret",
            "var.client_secret\n}",
            "var.client_secret\\n}\\n\",",
            "local.db_password",
            "data.vault_generic_secret.api.data[\"key\"]",
            "module.secrets.token",
        ] {
            assert!(is_reference(head), "{head}");
        }
    }

    #[test]
    fn values_that_only_resemble_references() {
        for head in [
            "Kx7pQ2vL9rT4",
            "variable.kqztrwx4711",
            "envoy-7Kq2LmX9",
            "environment9Kq2",
            "ENVELOPE_KQZT_42",
            "var.Kx7!pQ2#",
            "$kqztrwx4711",
            "{kqztrwx4711}",
            "datastore4711Kq",
        ] {
            assert!(!is_reference(head), "{head}");
        }
    }

    #[test]
    fn truncated_captures_see_the_following_text() {
        for (text, value) in [
            ("csrf_token = os.environ[\"CSRF_TOKEN\"]", "os.environ"),
            ("csrf_token = ENV.fetch(\"CSRF_TOKEN\")", "ENV.fetch"),
            (
                "ClientSecret = Environment.GetEnvironmentVariable(\"CLIENT_SECRET\");",
                "Environment.GetEnvironmentVariable(",
            ),
            ("Client-Secret: {{clientSecret}}", "{{clientSecret"),
            (
                "\"client_secret = os.environ[\\\"X\\\"]\\n\",",
                "os.environ[\\",
            ),
        ] {
            let start = text.find(value).unwrap();
            assert!(
                is_placeholder_match(text, start..start + value.len()),
                "{text}"
            );
        }
        let text = "token = Kx7pQ2vL9rT4 # was ${TOKEN}";
        let start = text.find("Kx7").unwrap();
        assert!(!is_placeholder_match(text, start..start + 12));
        let text = "Passwort: Grüße-2026-Kq\nNächste Zeile: ${X}";
        let start = text.find("Grüße").unwrap();
        assert!(!is_placeholder_match(
            text,
            start..start + "Grüße-2026-Kq".len()
        ));
    }
}
