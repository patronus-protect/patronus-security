// SPDX-License-Identifier: GPL-3.0-only
//! T07: placeholders and environment/template references in the value of
//! value-capturing credential rules. K06 adds template syntaxes (`%(name)s`,
//! `{name}`, `@name@`, `__NAME__`, `((name))` …), secret-manager references,
//! DE/EN placeholders and values that only name the credential. General code
//! expressions as values (function calls, member access, type annotations)
//! are left to T03.
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
    // K06: empty values and documented defaults (JKS `changeit`).
    "null",
    "nil",
    "none",
    "undefined",
    "changeit",
    "setme",
    "fillme",
];

/// Redaction words (K06), as the whole value or inside a mask
/// (`***REMOVED***`, `***ENTFERNT***`).
const REDACTION_WORDS: &[&str] = &[
    "redacted",
    "removed",
    "masked",
    "hidden",
    "omitted",
    "geschwaerzt",
    "geschwärzt",
    "entfernt",
    "maskiert",
    "ausgeblendet",
];

/// Credential nouns (K06) of values that only name the credential
/// (`my-access-token`, `SECRET_PASSWORD`, `MEIN_PASSWORT`).
const CREDENTIAL_NOUNS: &[&str] = &[
    "password",
    "passwort",
    "kennwort",
    "passwd",
    "pwd",
    "pass",
    "secret",
    "token",
    "key",
    "apikey",
    "credential",
    "credentials",
    "geheimnis",
    "schluessel",
    "schlüssel",
    "zugangsdaten",
];

/// Words that may stand next to a credential noun in such a name.
const CREDENTIAL_NAME_WORDS: &[&str] = &[
    "my",
    "mein",
    "meine",
    "the",
    "api",
    "access",
    "refresh",
    "private",
    "client",
    "app",
    "db",
    "database",
    "datenbank",
    "user",
    "admin",
    "root",
    "service",
    "bearer",
    "session",
    "auth",
    "signing",
    "webhook",
    "master",
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
    "eingeben",
    "ausfuellen",
    "ausfüllen",
    "einsetzen",
    "hinterlegen",
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
    is_reference(head)
        || is_delimited_variable(head)
        || is_secret_manager_reference(head)
        || is_secret_manager_reference(enclosing_token(text, range.start, end))
        || is_placeholder_value(&text[range])
}

/// K06: secret-manager references: 1Password `op://`, vals `ref+…://`, Azure
/// `@Microsoft.KeyVault(…)`, AWS Secrets Manager/SSM ARNs, GCP Secret Manager
/// resource names and mounted Docker/Kubernetes secret files.
pub(crate) fn is_secret_manager_reference(head: &str) -> bool {
    static SECRET_MANAGER: OnceLock<Regex> = OnceLock::new();
    SECRET_MANAGER
        .get_or_init(|| {
            Regex::new(concat!(
                r"^(?:op://[^\s/]+/",
                r"|ref\+[a-z0-9]+://",
                r"|@Microsoft\.KeyVault\(",
                r"|arn:aws[a-z-]*:(?:secretsmanager|ssm):",
                r"|projects/[A-Za-z0-9_-]+/secrets/[A-Za-z0-9_-]+",
                r"|(?:/var)?/run/secrets/)",
            ))
            .unwrap()
        })
        .is_match(head)
}

/// The text from the start of the token that holds `start` (after the last
/// whitespace, quote, `=` or `,` on its line, at most [`REFERENCE_WINDOW`]
/// bytes back) up to `end`: a value captured inside an ARN
/// (`…:secret:prod/…`) belongs to the ARN.
fn enclosing_token(text: &str, start: usize, end: usize) -> &str {
    let floor = floor_char_boundary(text, start.saturating_sub(REFERENCE_WINDOW));
    let token_start = text[floor..start]
        .rfind(|character: char| {
            character.is_whitespace() || matches!(character, '"' | '\'' | '`' | '=' | ',')
        })
        .map_or(floor, |index| floor + index + 1);
    &text[token_start..end.max(start)]
}

/// K06: a variable name between template delimiters at the start of the
/// value: `{name}`, `{0}`, `{name!r}`, `{env:NAME}` (str.format, f-strings,
/// .NET), `@name@` (Maven/Gradle/autoconf filters), `__NAME__` (replace
/// tokens) and `!NAME!` (cmd delayed expansion). As for `$name`, a name that
/// looks like the rest of a password (`{kqztrwx4711}`, `__Kx7pQ2vL9__`) is no
/// variable.
pub(crate) fn is_delimited_variable(head: &str) -> bool {
    static DELIMITED: OnceLock<Regex> = OnceLock::new();
    let Some(captures) = DELIMITED
        .get_or_init(|| {
            Regex::new(concat!(
                r"^(?:\{(?P<brace>[A-Za-z_][A-Za-z0-9_.]*|[0-9]*)(?:[!:][^{}\s]*)?\}",
                r"|@(?P<at>[A-Za-z_][A-Za-z0-9_.-]*)@",
                r"|__(?P<underscore>[A-Za-z0-9_]+?)__(?:[^A-Za-z0-9_]|$)",
                r"|!(?P<bang>[A-Za-z_][A-Za-z0-9_]*)!)",
            ))
            .unwrap()
        })
        .captures(head)
    else {
        return false;
    };
    if let Some(name) = captures.name("brace") {
        let name = name.as_str();
        return name.bytes().all(|byte| byte.is_ascii_digit())
            || is_variable_name(&name.replace('.', "_"));
    }
    ["at", "underscore", "bang"]
        .iter()
        .filter_map(|group| captures.name(group))
        .any(|name| is_variable_name(&name.as_str().replace(['.', '-'], "_")))
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
                // K06: Python `%(name)s`, Ruby/Puppet/Logstash `%{name}`,
                // Concourse/BOSH `((name))`, YAML tags of Home Assistant,
                // ESPHome, Ansible and CloudFormation.
                r"|%\([A-Za-z_][A-Za-z0-9_.-]*\)",
                r"|%\{\[?[A-Za-z_]",
                r"|\(\(\s*[A-Za-z_][A-Za-z0-9_./-]*\s*\)\)",
                r"|!(?:Ref|Sub|GetAtt|ImportValue|FindInMap|Join|Select|If|Base64|secret|env_var|vault)\s",
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
        // Terminators and closing delimiters of call-style carriers such as
        // `Client(api_key=YOUR_API_KEY_HERE)` that the capture includes.
        .trim_end_matches([';', ',', '.', ':', ')', ']', '}']);
    if value.is_empty() {
        return false;
    }
    if value.starts_with('<') || value.starts_with("&lt;") || value.starts_with('[') {
        return true;
    }
    // K06: a word inside a mask (`***REMOVED***`, `**None**`).
    let unmasked = value.trim_matches('*');
    if unmasked.len() < value.len() && !unmasked.is_empty() {
        return is_placeholder_value(unmasked);
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
pub(crate) fn is_variable_name(name: &str) -> bool {
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
    if PLACEHOLDER_VALUES.contains(&joined.as_str()) || REDACTION_WORDS.contains(&joined.as_str()) {
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
        || is_credential_name(&words)
}

/// K06: two or more words that only name a credential: credential nouns and
/// the words of [`CREDENTIAL_NAME_WORDS`], at least one noun
/// (`my-access-token`, `SECRET_PASSWORD`; not `actual-secret`).
fn is_credential_name(words: &[String]) -> bool {
    words.len() >= 2
        && words
            .iter()
            .any(|word| CREDENTIAL_NOUNS.contains(&word.as_str()))
        && words.iter().all(|word| {
            CREDENTIAL_NOUNS.contains(&word.as_str())
                || CREDENTIAL_NAME_WORDS.contains(&word.as_str())
        })
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
    use super::{
        is_delimited_variable, is_placeholder_match, is_placeholder_value, is_reference,
        is_secret_manager_reference,
    };

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
    fn closing_delimiters_of_call_carriers_are_trimmed() {
        for (text, value) in [
            (
                "client = Client(api_key=YOUR_API_KEY_HERE)",
                "YOUR_API_KEY_HERE)",
            ),
            ("db = connect(password=$DB_PASSWORD)", "$DB_PASSWORD)"),
            ("cfg = {password: $DB_PASSWORD}", "$DB_PASSWORD}"),
            ("args[password=REPLACE_ME]", "REPLACE_ME]"),
            ("connect(password=$DB_PASSWORD));", "$DB_PASSWORD));"),
        ] {
            let start = text.find(value).unwrap();
            assert!(
                is_placeholder_match(text, start..start + value.len()),
                "{text}"
            );
        }
        for (text, value) in [
            ("conn = connect(password=Kx7pQ2vL9rT4)", "Kx7pQ2vL9rT4)"),
            (
                "client = Client(api_key=f4fcba1c3696bf9b564c7dac9b0062f5097331f9)",
                "f4fcba1c3696bf9b564c7dac9b0062f5097331f9)",
            ),
            ("connect(password=$ecret2026)", "$ecret2026)"),
            (
                "connect(password=ORANGE_KQZTRWX_4711)",
                "ORANGE_KQZTRWX_4711)",
            ),
        ] {
            let start = text.find(value).unwrap();
            assert!(
                !is_placeholder_match(text, start..start + value.len()),
                "{text}"
            );
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

    #[test]
    fn k06_placeholders_redactions_and_credential_names() {
        for value in [
            "PASSWORT_HIER_EINGEBEN",
            "BITTE_AUSFUELLEN",
            "TOKEN_EINSETZEN",
            "SCHLUESSEL_HIER_HINTERLEGEN",
            "null",
            "None)",
            "undefined",
            "changeit",
            "REDACTED",
            "GESCHWAERZT",
            "***REMOVED***",
            "***ENTFERNT***",
            "\"**None**\"",
            "my-access-token",
            "secret_token",
            "SECRET_PASSWORD",
            "MEIN_PASSWORT",
            "auth.password",
            "api-key",
        ] {
            assert!(is_placeholder_value(value), "{value}");
        }
        for value in [
            "actual-secret",
            "my-dog-rex-2026",
            "secret-sauce-4711",
            "password",
            "nullpointer4711",
            "*Kx7pQ2vL9rT4*",
            "Secret_Token",
            "TOKEN_KQZTRW_4711",
        ] {
            assert!(!is_placeholder_value(value), "{value}");
        }
    }

    #[test]
    fn k06_delimited_variables() {
        for head in [
            "{password}",
            "{db_password}@db.internal:5432/app\"",
            "{0};\"",
            "{}",
            "{password!r}\"",
            "{pw:>12}",
            "{env:DB_PASSWORD}",
            "{settings.db_password}",
            "@db.passwort@",
            "@DB_PASSWORD@",
            "@db-password@\n",
            "__DB_PASSWORD__",
            "__ACCESS_TOKEN__\n",
            "__password__;",
            "!DB_PASSWORD!",
        ] {
            assert!(is_delimited_variable(head), "{head}");
        }
        for head in [
            "{kqztrwx4711}",
            "{Kx7pQ2vL9}",
            "{password",
            "@kqztrwx4711@",
            "@Kx7pQ2vL9@",
            "__Kx7pQ2vL9rT4__",
            "__DB_PASSWORD__x",
            "!Kx7pQ2vL9rT4!",
            "Kx7pQ2vL9rT4",
        ] {
            assert!(!is_delimited_variable(head), "{head}");
        }
    }

    #[test]
    fn k06_template_syntaxes_and_secret_manager_references() {
        for head in [
            "%(db_password)s",
            "%(passwort)s@db.intern",
            "%{db_password}",
            "%{[secrets][db]}",
            "((lager.db_passwort))",
            "(( db_password ))",
            "!secret wlan_passwort",
            "!Ref DbPassword",
            "!Sub '{{resolve:secretsmanager:x}}'",
            "!vault |",
        ] {
            assert!(is_reference(head), "{head}");
        }
        for head in [
            "%Kx7(pQ2)vL9",
            "%{",
            "((Kx7!pQ2))",
            "!Reference2026Kq",
            "!secretKx7pQ2",
        ] {
            assert!(!is_reference(head), "{head}");
        }
        for head in [
            "op://Production/postgres/password",
            "ref+vault://secret/data/app#db_password",
            "ref+awssecrets://prod/api#token",
            "@Microsoft.KeyVault(SecretUri=https://kv.vault.azure.net/secrets/db/)",
            "arn:aws:secretsmanager:eu-central-1:123456789012:secret:prod/api-AbCdEf",
            "arn:aws-us-gov:ssm:us-gov-west-1:123456789012:parameter/db",
            "projects/lager-prod/secrets/db-password/versions/latest",
            "/run/secrets/db_password",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
        ] {
            assert!(is_secret_manager_reference(head), "{head}");
        }
        for head in [
            "opal://Kx7pQ2vL9rT4",
            "op://",
            "ref+://x",
            "arn:aws:s3:::bucket/key",
            "projects4711Kq/x",
            "/run/secretsKx7",
        ] {
            assert!(!is_secret_manager_reference(head), "{head}");
        }
    }

    #[test]
    fn k06_values_inside_a_secret_manager_reference() {
        let text = "SERVICE_TOKEN=arn:aws:secretsmanager:eu-central-1:123456789012:secret:prod/api-AbCdEf\n";
        let start = text.find("prod/").unwrap();
        assert!(is_placeholder_match(text, start..text.len() - 1));
        let text = "token = arn-like secret:prod/Kx7pQ2vL9rT4";
        let start = text.find("prod/").unwrap();
        assert!(!is_placeholder_match(text, start..text.len()));
    }
}
