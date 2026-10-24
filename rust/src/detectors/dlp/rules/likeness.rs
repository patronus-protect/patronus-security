// SPDX-License-Identifier: GPL-3.0-only
//! F-GEN1: password likeness of the values of the generic credential rules
//! (F11, T03, T10). A key such as `password` or `token` says nothing about
//! the text after it: in code it is followed by expressions and types
//! (`token = get_token()`, `password: Option<&str>`, `Token::Literal(c)`), in
//! prose by ordinary words („Passwort ist falsch“, "token is embedded"), in
//! test suites by credential names and stand-ins (`password: "password"`,
//! `https://user:secret@…`). A value counts only if it could be a chosen
//! secret:
//!
//! - no code expression: no call, index or member access, no `::` path, no
//!   type annotation, no format placeholder and no file path (only for
//!   values without quotes, apart from paths: a string literal is a value);
//! - the key is no shell variable (`$PWD:/work` in a `docker -v` mount);
//! - no word sequence of the DE/EN dictionary or its word forms (`falsch`,
//!   `stored`, `implemented`) and no name of a credential (`GIT_PASSWORD`,
//!   `passwordGenerator`, `"mySecret"`, `realtoken`), no metasyntactic
//!   stand-in (`foo001`, `bar002`).
//!
//! Character classes decide which checks apply: a value with a digit or a
//! symbol other than an identifier separator is never a word or a name, so
//! weak but real passwords such as `Sommer2026!`, `hunter2`, `P@ssw0rd` or
//! `letmein` (no dictionary word) stay secrets. A token in the username of a
//! URL (`https://<token>:x-oauth-basic@…`) needs two character classes and
//! token entropy as well.
use super::credentials::{low_variety, LowVariety};
use crate::detectors::validators::{shannon_entropy, CharClasses};
use regex::Regex;
use std::{ops::Range, sync::LazyLock};

/// Credential nouns: a value that is or contains one of them as a word
/// names a credential rather than holding it.
const CREDENTIAL_NOUNS: &[&str] = &[
    "password",
    "passwords",
    "passwort",
    "passwoerter",
    "passwörter",
    "kennwort",
    "passwd",
    "pwd",
    "pass",
    "passphrase",
    "secret",
    "secrets",
    "geheimnis",
    "token",
    "tokens",
    "apikey",
    "credential",
    "credentials",
    "zugangsdaten",
    "schluessel",
    "schlüssel",
];

/// Words that stand next to a credential noun in a quoted stand-in value
/// (`"mySecret"`, `"topSecret"`, `"realtoken"`, `"supersecret"`).
const STAND_IN_WORDS: &[&str] = &[
    "my", "mein", "meine", "your", "dein", "deine", "the", "a", "some", "top", "super", "real",
    "fake", "test", "dummy", "default", "sample", "new", "old", "other", "another", "wrong", "bad",
    "good", "valid", "invalid", "secret", "geheim", "geheimes", "neues", "altes", "falsches",
    "user", "admin", "api", "access", "auth",
];

/// Metasyntactic stand-ins of test suites, optionally followed by digits
/// (`foo001:bar002`).
const METASYNTACTIC: &[&str] = &[
    "foo", "bar", "baz", "qux", "quux", "corge", "grault", "garply", "waldo", "fred", "plugh",
    "xyzzy", "thud", "hoge", "fuga", "piyo",
];

/// Pseudo-passwords of token-in-username URLs: the token is the username,
/// the password a constant (GitHub `https://<token>:x-oauth-basic@github.com`).
pub(crate) const PSEUDO_PASSWORDS: &[&str] = &["x-oauth-basic"];

/// Common DE/EN words that follow `password is`, `Passwort ist`, `token:` in
/// prose, docs and schema files, and words of code identifiers. Inflected
/// forms are covered by [`is_word_form`].
const DICTIONARY: &[&str] = &[
    // EN function words and adverbs
    "about",
    "again",
    "also",
    "always",
    "and",
    "any",
    "anyway",
    "both",
    "but",
    "case",
    "does",
    "done",
    "each",
    "else",
    "even",
    "ever",
    "for",
    "from",
    "here",
    "into",
    "just",
    "less",
    "like",
    "more",
    "most",
    "much",
    "must",
    "never",
    "next",
    "none",
    "not",
    "now",
    "only",
    "other",
    "same",
    "should",
    "since",
    "still",
    "such",
    "than",
    "that",
    "then",
    "there",
    "these",
    "this",
    "those",
    "through",
    "too",
    "under",
    "until",
    "very",
    "what",
    "when",
    "where",
    "which",
    "while",
    "will",
    "with",
    "within",
    "without",
    "would",
    "yet",
    // EN adjectives and participles after "is"
    "active",
    "bad",
    "blank",
    "broken",
    "correct",
    "empty",
    "false",
    "fine",
    "free",
    "good",
    "great",
    "hard",
    "known",
    "long",
    "lost",
    "mandatory",
    "missing",
    "new",
    "old",
    "open",
    "optional",
    "plain",
    "present",
    "random",
    "ready",
    "right",
    "safe",
    "secure",
    "short",
    "simple",
    "strong",
    "sure",
    "taken",
    "true",
    "unknown",
    "unset",
    "valid",
    "invalid",
    "weak",
    "wrong",
    "set",
    "sent",
    "shown",
    "given",
    "hidden",
    "written",
    "known",
    "unique",
    "different",
    "available",
    "visible",
    "sensitive",
    "insecure",
    "incorrect",
    "stale",
    "expired",
    "revoked",
    "rotated",
    "leaked",
    "reset",
    "same",
    "first",
    "last",
    "own",
    "required",
    "default",
    "generic",
    "global",
    "local",
    "static",
    "dynamic",
    "internal",
    "external",
    "public",
    "private",
    "temporary",
    "permanent",
    // EN nouns of code identifiers
    "access",
    "account",
    "api",
    "app",
    "auth",
    "admin",
    "basic",
    "bearer",
    "body",
    "client",
    "code",
    "config",
    "context",
    "current",
    "data",
    "db",
    "entry",
    "error",
    "field",
    "file",
    "flag",
    "form",
    "github",
    "gitlab",
    "bitbucket",
    "group",
    "hash",
    "header",
    "id",
    "info",
    "input",
    "item",
    "key",
    "length",
    "list",
    "login",
    "manager",
    "map",
    "message",
    "mode",
    "name",
    "node",
    "oauth",
    "option",
    "options",
    "output",
    "owner",
    "param",
    "params",
    "path",
    "provider",
    "query",
    "refresh",
    "repo",
    "request",
    "response",
    "result",
    "root",
    "scope",
    "server",
    "service",
    "session",
    "source",
    "state",
    "store",
    "string",
    "table",
    "text",
    "type",
    "user",
    "username",
    "value",
    "values",
    "generator",
    "validator",
    "strength",
    "policy",
    "prompt",
    "dialog",
    "label",
    "hint",
    "placeholder",
    "rule",
    "rules",
    "my",
    "your",
    "the",
    "get",
    "put",
    "from",
    "to",
    "new",
    "is",
    "has",
    "on",
    "of",
    "in",
    "by",
    "or",
    "at",
    // DE function words and adverbs
    "aber",
    "abgelaufen",
    "auch",
    "bereits",
    "bitte",
    "dann",
    "darf",
    "dort",
    "doch",
    "eben",
    "eine",
    "einer",
    "einfach",
    "falsch",
    "gleich",
    "hier",
    "immer",
    "jetzt",
    "kein",
    "keine",
    "leer",
    "mehr",
    "muss",
    "nicht",
    "nie",
    "noch",
    "nur",
    "oder",
    "schon",
    "sehr",
    "sind",
    "soll",
    "und",
    "weg",
    "wieder",
    "zu",
    "zwar",
    // DE adjectives and participles after „ist“
    "alt",
    "neu",
    "richtig",
    "korrekt",
    "inkorrekt",
    "ungueltig",
    "ungültig",
    "gueltig",
    "gültig",
    "sicher",
    "unsicher",
    "schwach",
    "stark",
    "kurz",
    "lang",
    "bekannt",
    "unbekannt",
    "geheim",
    "vertraulich",
    "abgelaufen",
    "gesperrt",
    "erforderlich",
    "optional",
    "pflicht",
    "notwendig",
    "vergeben",
    "identisch",
    "anders",
    "veraltet",
    "zufaellig",
    "zufällig",
    "gleich",
    "derselbe",
    "dasselbe",
    "leer",
    "gut",
    "schlecht",
    "fest",
    "frei",
    // DE nouns of identifiers
    "benutzer",
    "konto",
    "daten",
    "datenbank",
    "dienst",
    "wert",
    "feld",
    "zugang",
];

/// Value types of Rust, Python, TS/JS, Go, PHP, Java/C# and JSON schema
/// annotations (`token: Option<&str>`, `password: str)`,
/// `@return array{password: string|null}`).
static TYPE_ANNOTATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:&(?:'[A-Za-z_]+\s*)?(?:mut\s*)?|\?|\*|\[\])?",
        r"(?:str|string|String|bytes|byte|int|integer|i8|i16|i32|i64|u8|u16|u32|u64|usize|isize",
        r"|bool|boolean|number|any|unknown|object|mixed|char|float|double|long|void|never",
        r"|Option|Optional|Arc|Box|Rc|Vec|Cow|Secret|SecretString|SecretBox|SecretVec|Zeroizing",
        r"|Mutex|RwLock|SecureString|Sensitive|Masked|Promise|Result|List|Dict|Map|Record|Array",
        r"|array|list|dict|Sequence|Union|Literal|Readonly|Partial|Nullable|Maybe|CharSequence",
        r"|NSString|non-empty-string|positive-int|callable)",
        r"(?:[<\[|)>,;:?=&]|$)",
    ))
    .unwrap()
});

/// A call or index access at the start of the value: `get_token()`,
/// `os.environ[…]`, `$this->io->askAndHideAnswer(`, `.$e->getMessage()`,
/// `values[1]`, `Object.assign({`.
static CALL_OR_INDEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^\.?[$@]?[A-Za-z_][A-Za-z0-9_$]*(?:(?:\.|->|::|\?\.|!\.)[$]?[A-Za-z_][A-Za-z0-9_$]*)*!?\s*[(\[]",
    )
    .unwrap()
});

/// Member access: two or more digit-free identifier segments
/// (`this._input.value`, `password.length`, `Y.username`, `_.password`).
static MEMBER_ACCESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[$]?[A-Za-z_$]+(?:(?:\.|->|\?\.|!\.)[A-Za-z_$]+)+(?:[^A-Za-z0-9_$]|$)").unwrap()
});

/// ABNF repetition (`1*(tchar)`, `*DIGIT`) of grammar listings.
static ABNF_REPETITION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9]*\*[0-9]*(?:\(|[A-Z]{3,})").unwrap());

/// printf/format placeholders at the start of the value (`%s`, `%v`, `%-8s`,
/// `{}`).
static FORMAT_PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:%[-+ #0]*[0-9]*(?:\.[0-9]+)?[sdvqxXfiruS](?:[^A-Za-z0-9]|$)|\{\})").unwrap()
});

/// Unix, home-relative and Windows paths (`/run/secrets/db`, `./token.txt`,
/// `~/.pgpass`, `C:\keys\db.txt`). A single absolute segment counts only
/// as a lower-case word without digits (`/work`, `/apps-dir`).
static PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:(?:~|\.{1,2})/[A-Za-z0-9._/-]*",
        r"|/[A-Za-z0-9._-]+/[A-Za-z0-9._/-]*",
        r"|/[a-z][a-z._-]*",
        r"|[A-Za-z]:\\[^\s]*)$",
    ))
    .unwrap()
});

/// T09: an identifier in one naming convention: lower, upper, snake, kebab,
/// dotted, camelCase or PascalCase words (`github-copilot`, `prefixItems`,
/// `ExtensionKeywords`), unlike random mixed case (`QDaKkIyIVKw`).
static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:[a-z]+(?:[-_.][a-z]+)*|[A-Z]+(?:[-_.][A-Z]+)*",
        r"|[a-z]+(?:[A-Z][a-z]+)+|[A-Z][a-z]+(?:[-_.]?[A-Z][a-z]+)*)$",
    ))
    .unwrap()
});

/// T09: a package version or range (`^1.0.0`, `~2.3.4`, `>=5.2.3`).
static VERSION_RANGE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[\^~<>=]*v?\d+\.\d+\.\d+(?:[-+.][0-9A-Za-z.-]*)?$").unwrap());

/// T09: the XML `value` attribute after the key's closing quote, as the
/// rules match it (`" value="`).
static XML_VALUE_SEPARATOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["']\s+value\s*=\s*["']?$"#).unwrap());

/// T09: a key in a `key` or `name` attribute followed by the quoted value
/// (`<add key="DbPassword" value="`, `<property name="password" value="`).
static XML_KEY_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:key|name)\s*=\s*["'][^"'<>\r\n]*["']\s+value\s*=\s*["']$"#).unwrap()
});

/// T09: code at the start of a value: a cast or parameter list
/// (`(string) $x`, `()=>f`), an arrow function (`e=>({…})`), a comparison
/// (`===C`) or a negated call (`!empty($uri[…])`).
static CODE_START: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*\s*=>|[=>]|!\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\()",
    )
    .unwrap()
});

/// How the key separates its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Separator {
    /// `=`, `:` or a template/URL delimiter.
    Symbol,
    /// `is`, `ist`, `lautet` in prose.
    Prose,
}

/// F11/T03: whether the value at `range` of `text`, which
/// `dlp_password_assignment` or `dlp_generic_credential_assignment` matched
/// after its key, looks like a chosen secret.
pub(crate) fn is_assignment_value(text: &str, range: Range<usize>) -> bool {
    let value = &text[range.clone()];
    let before = &text[..range.start];
    let quoted = before.ends_with(['"', '\'']);
    if quoted && closes_string(before) {
        return false;
    }
    // T09: XML `key="…" value="…"` holds the key in a `key`/`name` attribute
    // and the value in quotes (not `placeholder="API key" value={…}`).
    let xml_value = XML_VALUE_SEPARATOR.is_match(before);
    if xml_value && !(quoted && XML_KEY_VALUE.is_match(before)) {
        return false;
    }
    let Some((separator, key_end)) = separator(before) else {
        return true;
    };
    // T09: a quoted key (`"password":`, `'password' =>`, `["DB_PASSWORD"] =`)
    // is a field of JSON, a dict or an array: an unquoted value is code
    // (`{"password": pwd}`, `case"apiKey":u=…`, `'password' => !empty(…)`),
    // as after `=>`, and a quoted one must suit a field.
    let quoted_key = xml_value
        || before[..key_end]
            .trim_end_matches(']')
            .ends_with(['"', '\''])
        || before[key_end..].trim_start().starts_with("=>");
    if quoted_key && !quoted {
        return false;
    }
    if quoted_key && !suits_field_key(value) {
        return false;
    }
    // `$PWD:/work` (a `docker -v` mount): the key is a shell variable.
    let key_start = before[..key_end]
        .trim_end_matches(|c: char| c.is_alphanumeric() || c == '_')
        .len();
    if before[..key_start].ends_with('$') && before[key_end..].trim_start().starts_with(':') {
        return false;
    }
    if is_path(value) {
        return false;
    }
    // `<key>:<token>:x-oauth-basic@host`: the userinfo of a token URL belongs
    // to `dlp_url_userinfo_token`.
    if PSEUDO_PASSWORDS
        .iter()
        .any(|pseudo| value.contains(&format!(":{pseudo}@")))
    {
        return false;
    }
    // After a closing quote, `.`/`+` concatenate (`"…token: ".$e->getMessage()`).
    let concatenated = quoted && value.starts_with(['.', '+']);
    if (!quoted || concatenated) && (is_code_expression(value) || value.ends_with(':')) {
        return false;
    }
    if value.contains(char::is_whitespace) {
        return is_passphrase(value);
    }
    let bare = trim_trailing_punctuation(value.trim_start_matches('`'));
    if is_metasyntactic(bare) {
        return false;
    }
    if !is_word_like(bare) {
        return true;
    }
    if quoted && separator == Separator::Symbol {
        // A string literal holds a value; only stand-ins are none.
        return !is_stand_in(bare);
    }
    !(is_stand_in(bare) || names_a_credential(bare) || is_word_sequence(bare))
}

/// K05B: whether an item of an array or sequence under a credential key
/// (`api_keys: [ … ]`, `tokens:` with `- …` lines) could be a secret. Its
/// key stands apart, so the item must show it on its own, more strictly
/// than a value after its key: printable ASCII without blanks, a digit or
/// both cases among at least two of lower case, upper case, digits and
/// symbols, no template characters (`<|endoftext|>`, `{name}`; a `}` alone
/// belongs to a password), and as a field value no identifier, word, name,
/// stand-in, version or code ([`suits_field_key`]), path or metasyntactic
/// word. Scopes (`read:org`), words and tokenizer entries are no items of a
/// credential list.
pub(crate) fn is_item_value(value: &str) -> bool {
    let bare = value.trim();
    let classes = [
        bare.bytes().any(|byte| byte.is_ascii_lowercase()),
        bare.bytes().any(|byte| byte.is_ascii_uppercase()),
        bare.bytes().any(|byte| byte.is_ascii_digit()),
        bare.bytes().any(|byte| byte.is_ascii_punctuation()),
    ];
    !bare.is_empty()
        && bare.bytes().all(|byte| byte.is_ascii_graphic())
        && classes.iter().filter(|&&class| class).count() >= 2
        && (classes[2] || (classes[0] && classes[1]))
        && !bare.contains(['<', '>', '{', '|'])
        && !is_word_like(bare)
        && suits_field_key(bare)
        && !is_path(bare)
        && !is_metasyntactic(bare)
}

/// F-GEN2 (T08): whether the value at `range` of `text`, which
/// `dlp_env_var_secret` matched after an upper-case variable name, could be
/// a secret. A constant such as `DATA_API_KEY = '.data-api'` or
/// `AUTH_FLOW_PASSWORD = "password"` names something instead: word-like
/// values are checked as words, credential names and stand-ins also inside
/// quotes. Bare values must not be a call or index access (`os.environ[…]`,
/// `getenv(…)`), a format placeholder or a path. Member access is not
/// checked: `.env` values such as `wPF.DZs~Brb…` hold dots.
pub(crate) fn is_env_value(text: &str, range: Range<usize>) -> bool {
    let value = &text[range.clone()];
    let before = &text[..range.start];
    let quoted = before.ends_with(['"', '\'']);
    // An escaped quote (`KEY=\"value\"` inside a serialized string) opens the
    // value; it cannot close the surrounding string.
    let escaped = before.ends_with("\\\"") || before.ends_with("\\'");
    if (quoted && !escaped && closes_string(before))
        || is_path(value)
        || (!quoted && (CALL_OR_INDEX.is_match(value) || FORMAT_PLACEHOLDER.is_match(value)))
    {
        return false;
    }
    if value.contains(char::is_whitespace) {
        return is_passphrase(value);
    }
    let bare = trim_trailing_punctuation(value);
    !is_metasyntactic(bare)
        && (!is_word_like(bare)
            || !(is_stand_in(bare) || names_a_credential(bare) || is_word_sequence(bare)))
}

/// Prefix words of a compound `…token` key whose value is no credential:
/// pagination and stream cursors (`nextPageToken`, `continuation_token`),
/// JSON pointer segments (`pathToken`),
/// cancellation and sync handles, token counts of models and lexers
/// (`max_token`, `prompt_token`) and the CSRF token, which
/// `dlp_csrf_token` reports.
const NON_SECRET_TOKEN_PREFIXES: &[&str] = &[
    "page",
    "next",
    "prev",
    "previous",
    "cursor",
    "path",
    "continuation",
    "cancel",
    "cancellation",
    "sync",
    "resume",
    "max",
    "min",
    "total",
    "input",
    "output",
    "prompt",
    "completion",
    "start",
    "end",
    "eof",
    "lexer",
    "parser",
    "csrf",
    "xsrf",
];

/// Prefix words of a compound `…secret` key that names a Kubernetes or Helm
/// secret object rather than holding a secret (`existingSecret`,
/// `imagePullSecret`, `tls_secret`).
const SECRET_OBJECT_PREFIXES: &[&str] = &["existing", "pull", "tls"];

/// Bytes before the credential noun searched for a compound-key prefix.
const MAX_KEY_PREFIX: usize = 64;

/// T09: the shape of a key whose credential noun starts at `key_start`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyShape<'a> {
    /// The noun stands alone or after `.`/`-` (`password`, `app.db.password`,
    /// `X-Api-Key`), as before T09.
    Simple,
    /// A compound or camelCase key with its prefix (`db_` of `db_password`,
    /// `service` of `serviceSecret`).
    Compound(&'a str),
    /// The noun ends a word without a naming-convention break
    /// (`mypassword`, `DBPASSWORD`, `Benutzerkennwort`): no key.
    Word,
}

/// T09: the key shape at `key_start`. After `_` the prefix is the
/// identifier before it (`DB_`, `lager_db_`); after a letter or digit the
/// key is camelCase only where a lower-case letter or digit meets a capital
/// noun (`dbPassword`, `DbPassword`, `adminDbPassword`).
fn key_shape(text: &str, key_start: usize) -> KeyShape<'_> {
    let before = &text[..key_start];
    let Some(last) = before.chars().next_back() else {
        return KeyShape::Simple;
    };
    let mut floor = key_start.saturating_sub(MAX_KEY_PREFIX);
    while !text.is_char_boundary(floor) {
        floor += 1;
    }
    let window = &before[floor..];
    let head = &window[window
        .trim_end_matches(|c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        .len()..];
    if last == '_' {
        return if words(head).is_empty() {
            KeyShape::Simple
        } else {
            KeyShape::Compound(head)
        };
    }
    // A letter outside ASCII (`Maßpasswort`) continues the word, as
    // under the Unicode `\b` before T09.
    if !last.is_alphanumeric() {
        return KeyShape::Simple;
    }
    let capital_noun = text[key_start..]
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_uppercase());
    if capital_noun && (last.is_ascii_lowercase() || last.is_ascii_digit()) {
        KeyShape::Compound(head)
    } else {
        KeyShape::Word
    }
}

/// T09: whether the key whose credential noun starts at `key_start` has the
/// shape of a key ([`key_shape`]) and the value at `value` suits it. A
/// compound key names a field, so its value must suit one
/// ([`suits_field_key`], `forgotPassword: "forgot-password"`).
pub(crate) fn is_key_prefix(text: &str, key_start: usize, value: Range<usize>) -> bool {
    match key_shape(text, key_start) {
        KeyShape::Simple => true,
        KeyShape::Compound(_) => suits_field_key(&text[value]),
        KeyShape::Word => false,
    }
}

/// T09: whether a quoted `value` suits a field key (a compound or quoted
/// key) as a secret: no identifier in a naming convention, word, name or
/// stand-in (`"github-copilot"`, `"prefixItems"`, `"alpha"`), no version
/// range (`"^1.0.0"`), no code (`"IPython.core.magics.osm:OSMagics"`), and
/// a passphrase with a capital, digit or symbol beyond lower-case words
/// (`'little green men'` in a test array).
fn suits_field_key(value: &str) -> bool {
    let bare = trim_trailing_punctuation(value.trim());
    if bare.contains(char::is_whitespace) {
        return bare
            .chars()
            .any(|c| !(c.is_lowercase() || c.is_whitespace()));
    }
    !(VERSION_RANGE.is_match(bare)
        || is_code_expression(bare)
        || (is_word_like(bare)
            && (IDENTIFIER.is_match(bare)
                || is_stand_in(bare)
                || names_a_credential(bare)
                || is_word_sequence(bare))))
}

/// T09: [`is_assignment_key`] for `dlp_generic_credential_assignment`, and
/// no compound `…token` key of a cursor, handle or count and no `…secret`
/// key of a secret object (see [`NON_SECRET_TOKEN_PREFIXES`],
/// [`SECRET_OBJECT_PREFIXES`]).
pub(crate) fn is_credential_key(text: &str, key_start: usize, value: Range<usize>) -> bool {
    if let KeyShape::Compound(head) = key_shape(text, key_start) {
        let noun: String = text[key_start..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | ' '))
            .collect::<String>()
            .trim_end()
            .to_lowercase();
        let prefix_words = words(head);
        let excluded = |list: &[&str]| {
            prefix_words
                .iter()
                .any(|word| list.contains(&word.as_str()))
        };
        // K05B: a plural key (`nextTokens`, `pullSecrets`) binds list items.
        let noun = noun.strip_suffix('s').unwrap_or(&noun);
        if (noun.ends_with("token") && excluded(NON_SECRET_TOKEN_PREFIXES))
            || (noun == "secret" && excluded(SECRET_OBJECT_PREFIXES))
        {
            return false;
        }
    }
    is_assignment_key(text, key_start, value)
}

/// T09: [`is_key_prefix`] for the assignment rules, whose bare value stops
/// after 150 characters: a value cut there (`id_token=eyJ…` with a long
/// example JWT) is no whole value, and its example markers may lie beyond
/// the cut.
pub(crate) fn is_assignment_key(text: &str, key_start: usize, value: Range<usize>) -> bool {
    let truncated = text[value.end..].chars().next().is_some_and(|c| {
        !(c.is_whitespace() || matches!(c, '"' | '\'' | ';' | ',' | '}' | ']' | '\\'))
    });
    !truncated && is_key_prefix(text, key_start, value)
}

/// T09: whether the value at `range` of `text`, which `dlp_csrf_token`
/// matched after its key, could be a token: no word sequence and no name
/// with a credential noun (`"X-CSRF-Token"`, `csrf_token`) and, without
/// quotes, no member access
/// (`request.form.csrf`).
pub(crate) fn is_token_value(text: &str, range: Range<usize>) -> bool {
    let value = &text[range.clone()];
    let quoted = text[..range.start].ends_with(['"', '\'']);
    if !quoted && MEMBER_ACCESS.is_match(value) {
        return false;
    }
    let bare = trim_trailing_punctuation(value);
    !is_metasyntactic(bare)
        && !(is_word_like(bare)
            && (words(bare)
                .iter()
                .any(|word| is_credential_noun(word) || matches!(word.as_str(), "csrf" | "xsrf"))
                || is_word_sequence(bare)))
}

/// F-GEN2: whether the quote that `before` ends with closes a string rather
/// than opening the value: key and separator are a string of their own
/// (`"Password:"),d?i.createElement(` in minified code, where the key is a
/// label), or the line holds an odd number of that quote before it. Escaped
/// quotes and apostrophes inside words (`it's`) do not count.
fn closes_string(before: &str) -> bool {
    let Some(quote) = before.chars().next_back() else {
        return false;
    };
    let head = &before[..before.len() - 1];
    // T09: an escaped quote (`= \"…` in a JSON string or notebook cell) opens
    // a value inside the outer string; it closes one after an odd number of
    // escaped quotes on the line.
    if let Some(head) = head.strip_suffix('\\') {
        let line = &head[head.rfind('\n').map_or(0, |index| index + 1)..];
        return line.matches(&format!("\\{quote}")).count() % 2 == 1;
    }
    // A label holds the key inside the string (`"Password:"`); a quoted key
    // (`{"password":"…`) closes before its separator, and an XML attribute
    // (`key="DbPassword" value="…`) follows a space.
    let label = head
        .strip_suffix([':', '='])
        .map(|head| {
            let opening = head
                .trim_end_matches(|c: char| c.is_alphanumeric() || matches!(c, '_' | '-' | ' '));
            (opening, &head[opening.len()..])
        })
        .is_some_and(|(opening, label)| {
            opening.ends_with(quote) && label.starts_with(|c: char| !c.is_whitespace())
        });
    if label {
        return true;
    }
    let line = &before[before[..before.len() - 1]
        .rfind('\n')
        .map_or(0, |index| index + 1)..];
    let bytes = line.as_bytes();
    let quote = quote as u8;
    let opening = bytes.len() - 1;
    (0..opening)
        .filter(|&index| {
            bytes[index] == quote
                && (index == 0 || bytes[index - 1] != b'\\')
                && !(quote == b'\''
                    && index > 0
                    && bytes[index - 1].is_ascii_alphabetic()
                    && bytes[index + 1].is_ascii_alphabetic())
        })
        .count()
        % 2
        == 1
}

/// F-GEN2 (T04): a quoted value with spaces is a passphrase unless it reads
/// as text: a label or message that names the credential („Passwort
/// eingeben“, "Enter your token"), only dictionary words ("too short"), a
/// sentence (function words such as `the`, `bitte`, a closing `.`, `?` or
/// `:`, more than six words), a placeholder (`change me`) or a format or
/// template string (`%s`, `{0}`, `${…}`).
fn is_passphrase(value: &str) -> bool {
    let value = value.trim();
    let parts: Vec<&str> = value.split_whitespace().collect();
    let words = words(value);
    if parts.len() > MAX_PASSPHRASE_WORDS
        || value.ends_with(['.', '?', ':', ',', ';', '…'])
        || is_template(value)
        || words.is_empty()
    {
        return false;
    }
    let names_credential = words
        .iter()
        .any(|word| is_credential_noun(word) || CREDENTIAL_LABEL_WORDS.contains(&word.as_str()));
    let sentence = words
        .iter()
        .any(|word| FUNCTION_WORDS.contains(&word.as_str()));
    let only_dictionary = parts.iter().all(|part| {
        let part = trim_trailing_punctuation(part);
        is_word_like(part) && is_word_sequence(part)
    });
    let joined: String = parts.concat();
    !(names_credential
        || sentence
        || only_dictionary
        || super::placeholders::is_placeholder_value(&joined))
}

/// A format or template string: `{…}`, `<…>`, `${…}`, `$(…)` or a printf
/// placeholder anywhere in the value.
fn is_template(value: &str) -> bool {
    value.contains(['{', '<', '>'])
        || value.contains("${")
        || value.contains("$(")
        || value
            .match_indices('%')
            .any(|(index, _)| FORMAT_PLACEHOLDER.is_match(&value[index..]))
}

/// More words than a passphrase has: a sentence.
const MAX_PASSPHRASE_WORDS: usize = 6;

/// Words of labels and messages about a credential besides the nouns.
const CREDENTIAL_LABEL_WORDS: &[&str] = &["login", "anmeldung", "username", "benutzername"];

/// DE/EN function words of sentences and UI messages; diceware passphrases
/// are content words.
const FUNCTION_WORDS: &[&str] = &[
    "a", "an", "the", "to", "of", "for", "be", "is", "are", "was", "at", "in", "on", "with",
    "your", "you", "please", "must", "not", "and", "or", "this", "that", "it", "enter", "der",
    "die", "das", "ein", "eine", "einen", "und", "oder", "zu", "mit", "ist", "sind", "nicht",
    "sie", "ihr", "ihre", "bitte", "muss", "eingeben", "geben",
];

/// T10: whether the password of a URL userinfo (`scheme://user:<value>@`)
/// looks like a chosen secret: no pseudo-password of a token-in-username
/// URL, no credential name or stand-in (`user:pass`, `user:secret`,
/// `token:MY_GITHUB_TOKEN`, `foo001:bar002`, `gitlab-ci-token:realtoken`).
pub(crate) fn is_userinfo_password(text: &str, range: Range<usize>) -> bool {
    let value = &text[range];
    // The password is the part after the last `:` of the userinfo.
    let password = value.rsplit(':').next().unwrap_or(value);
    if PSEUDO_PASSWORDS
        .iter()
        .any(|pseudo| password.eq_ignore_ascii_case(pseudo))
    {
        return false;
    }
    !is_metasyntactic(value)
        && (!is_word_like(value) || !(is_stand_in(value) || names_a_credential(value)))
}

/// T10: whether the username of a token-in-username URL
/// (`https://<value>:x-oauth-basic@…`) looks like a token, see
/// [`is_token_like`].
pub(crate) fn is_userinfo_token(text: &str, range: Range<usize>) -> bool {
    is_token_like(&text[range])
}

/// T10, F-HTTP: whether `value` looks like a machine-issued token: no word,
/// name or stand-in, two character classes, at least 3 bits of entropy per
/// character and no hand-typed runs: a token covered by sequential or
/// repeated runs (`ghp_1234567890abcdef…`, `DEADBEEFDEADBEEF…`) is a demo
/// value.
pub(super) fn is_token_like(value: &str) -> bool {
    if low_variety(value) != LowVariety::No {
        return false;
    }
    let classes = CharClasses::of(value);
    let alphanumeric_classes = [classes.lower, classes.upper, classes.digit]
        .iter()
        .filter(|count| **count > 0)
        .count();
    // A word or name with a numeric suffix only (`johnsmith42`,
    // `jane.doe2026`) is a handle: its digits are no token evidence.
    let head = value.trim_end_matches(|c: char| c.is_ascii_digit());
    if head.len() < value.len() && is_word_like(head) {
        return false;
    }
    alphanumeric_classes >= 2
        && shannon_entropy(value) >= 3.0
        && !is_metasyntactic(value)
        && !(is_word_like(value)
            && (is_stand_in(value) || names_a_credential(value) || is_word_sequence(value)))
}

/// F-HTTP: an identifier in one naming convention (`zugangstoken_lager`,
/// `accessTokenFromVault`, `YOUR_ACCESS_TOKEN`) rather than a token.
pub(super) fn is_identifier(value: &str) -> bool {
    is_word_like(value) && IDENTIFIER.is_match(value)
}

/// F-HTTP: whether the password of a decoded Basic `user:password` pair
/// (RFC 7617) is a chosen one: not the user-id again (`admin:admin`), no
/// metasyntactic stand-in (`foo:bar`) and, read without leetspeak digits and
/// symbols (`p@ss`, `s3cr3t`), no credential name or stand-in
/// (`user:password`, `application:secret`, `confidentialApplication:topSecret`)
/// and no word sequence.
pub(super) fn is_chosen_password(user: &str, password: &str) -> bool {
    !password.eq_ignore_ascii_case(user) && is_chosen_secret(password)
}

/// G01: whether the password of a connection string or LDAP bind
/// (`Password=<value>;`, `ldapsearch … -w <value>`) is a chosen one, as for
/// [`is_chosen_password`]: `Password=password;`, `Pwd=s3cr3t;` and `-w secret`
/// are stand-ins; code (`BindCredential = configuration["…"]`) holds no value.
pub(crate) fn is_connection_password(text: &str, range: Range<usize>) -> bool {
    let value = &text[range];
    !is_code_expression(value) && is_chosen_secret(value)
}

/// [`is_chosen_password`] without the user-id.
fn is_chosen_secret(password: &str) -> bool {
    let plain: String = password
        .chars()
        .map(|c| match c {
            '@' | '4' => 'a',
            '3' => 'e',
            '1' | '!' => 'i',
            '0' => 'o',
            '$' | '5' => 's',
            '7' => 't',
            c => c,
        })
        .collect();
    !is_metasyntactic(password)
        && !(is_word_like(&plain)
            && (is_stand_in(&plain) || names_a_credential(&plain) || is_word_sequence(&plain)))
}

/// The separator before a value and the byte offset where the key ends, or
/// `None` if `before` does not end in a key and separator.
fn separator(before: &str) -> Option<(Separator, usize)> {
    let head = before
        .trim_end_matches(['"', '\''])
        .trim_end_matches('\\')
        .trim_end();
    if let Some(found) = XML_VALUE_SEPARATOR.find(before) {
        let key = before[..found.start()].trim_end_matches('\\');
        return Some((Separator::Symbol, key.len()));
    }
    if let Some(rest) = head.strip_suffix("=>") {
        return Some((Separator::Symbol, rest.trim_end().len()));
    }
    if let Some(rest) = head.strip_suffix(['=', ':']) {
        return Some((Separator::Symbol, rest.trim_end().len()));
    }
    let word_start = head
        .trim_end_matches(|c: char| c.is_ascii_alphabetic())
        .len();
    let word = head[word_start..].to_ascii_lowercase();
    matches!(word.as_str(), "is" | "ist" | "lautet")
        .then(|| (Separator::Prose, head[..word_start].trim_end().len()))
}

/// T03: code that computes or annotates a value instead of holding it.
fn is_code_expression(value: &str) -> bool {
    let value = value.trim_start_matches('`');
    value.starts_with(':')
        || value.starts_with("--")
        || CODE_START.is_match(value)
        || ABNF_REPETITION.is_match(value)
        || CALL_OR_INDEX.is_match(value)
        || MEMBER_ACCESS.is_match(value)
        || TYPE_ANNOTATION.is_match(value)
        || FORMAT_PLACEHOLDER.is_match(value)
}

pub(super) fn is_path(value: &str) -> bool {
    PATH.is_match(trim_trailing_punctuation(value))
}

/// Only letters and the identifier separators `_`, `-`, `.`: a value with a
/// digit or another symbol is no word, name or stand-in.
pub(super) fn is_word_like(value: &str) -> bool {
    !value.is_empty()
        && value.chars().any(char::is_alphabetic)
        && value
            .chars()
            .all(|c| c.is_alphabetic() || matches!(c, '_' | '-' | '.'))
}

/// A metasyntactic word with optional digits (`foo`, `bar002`).
fn is_metasyntactic(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    METASYNTACTIC.contains(&lower.trim_end_matches(|c: char| c.is_ascii_digit()))
}

/// A credential noun with stand-in words only (`password`, `"topSecret"`,
/// `realtoken`, `my-secret`) or the pseudo-password of a token URL. Called
/// for word-like values only: `Secret2026!` is a password.
fn is_stand_in(value: &str) -> bool {
    if PSEUDO_PASSWORDS.contains(&value.to_ascii_lowercase().as_str()) {
        return true;
    }
    let words = words(value);
    words.iter().any(|word| is_credential_noun(word))
        && words
            .iter()
            .all(|word| is_credential_noun(word) || STAND_IN_WORDS.contains(&word.as_str()))
}

/// An identifier in one naming convention with a credential noun as one of
/// its words names the credential (`GIT_PASSWORD`, `passwordGenerator`,
/// `MY_BITBUCKET_TOKEN`, `clientSecret`). Separators with mixed case
/// (`ghp_shortButRealPassword`) are no naming convention.
fn names_a_credential(value: &str) -> bool {
    let single_case =
        !(value.chars().any(char::is_uppercase) && value.chars().any(char::is_lowercase));
    (single_case || !value.contains(['_', '-', '.']))
        && words(value).iter().any(|word| is_credential_noun(word))
}

/// A credential noun, also behind stand-in prefixes written as one word
/// (`realtoken`, `supersecret`, `mypassword`).
fn is_credential_noun(word: &str) -> bool {
    let mut rest = word;
    loop {
        if CREDENTIAL_NOUNS.contains(&rest) {
            return true;
        }
        match STAND_IN_WORDS
            .iter()
            .find_map(|prefix| rest.strip_prefix(prefix).filter(|rest| rest.len() >= 3))
        {
            Some(stripped) => rest = stripped,
            None => return false,
        }
    }
}

/// F11: every word is a DE/EN dictionary word or a word form
/// („falsch“, "stored", "case-sensitive", "abgelaufen").
fn is_word_sequence(value: &str) -> bool {
    let words = words(value);
    !words.is_empty()
        && words
            .iter()
            .all(|word| DICTIONARY.contains(&word.as_str()) || is_word_form(word))
}

/// Inflected and derived DE/EN word forms: EN participles and derivations
/// (`configured`, `missing`, `problematic`, `sensitive`), DE derivations and
/// participles (`erforderlich`, `gesetzt`, `hinterlegt`, `abgelaufen`). A
/// suffix or participle shape alone is no evidence (`kqztrwxing`): the stem
/// must be a dictionary word (`stored`, `configured`) or read like one.
fn is_word_form(word: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        "ed", "ing", "able", "ible", "tion", "sion", "ment", "ness", "less", "ful", "ous", "ive",
        "ic", "ical", "ally", "lich", "isch", "ung", "heit", "keit", "bar", "los",
    ];
    static PARTICIPLE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(concat!(
            r"^(?:(?:ab|an|auf|aus|ein|mit|vor|zu|zurück|zurueck|weg|fest)?ge\p{Ll}{2,}(?:t|en)",
            r"|(?:ver|be|er|ent|zer|hinter|über|ueber|unter)\p{Ll}{3,}t)$",
        ))
        .unwrap()
    });
    if word.chars().count() < 5 {
        return false;
    }
    SUFFIXES.iter().any(|suffix| {
        word.strip_suffix(suffix)
            .is_some_and(|stem| is_known_stem(stem) || reads_like_word(stem))
    }) || (PARTICIPLE.is_match(word) && reads_like_word(word))
}

/// A dictionary word behind an inflection: the stem itself, with a dropped
/// `e` (`stor|ed`), a doubled final consonant (`stopp|ed`) or `y` → `i`
/// (`carri|ed`).
fn is_known_stem(stem: &str) -> bool {
    let mut candidates = vec![stem.to_string(), format!("{stem}e")];
    let mut chars = stem.chars().rev();
    if let (Some(last), Some(previous)) = (chars.next(), chars.next()) {
        if last == previous {
            candidates.push(stem[..stem.len() - last.len_utf8()].to_string());
        }
    }
    if let Some(rest) = stem.strip_suffix('i') {
        candidates.push(format!("{rest}y"));
    }
    candidates
        .iter()
        .any(|candidate| DICTIONARY.contains(&candidate.as_str()))
}

/// Letters that alternate like DE/EN words: at least a quarter vowels and
/// no run of more than three consonants, `sch`/`ch` counting as one
/// (`problemat`, `verschlüssel`); random letters fail (`kqztrwx`).
fn reads_like_word(letters: &str) -> bool {
    let letters = letters.replace("sch", "s").replace("ch", "c");
    let is_vowel = |c: char| "aeiouyäöü".contains(c);
    let total = letters.chars().count();
    let vowels = letters.chars().filter(|c| is_vowel(*c)).count();
    let longest_consonant_run = letters
        .split(is_vowel)
        .map(|run| run.chars().count())
        .max()
        .unwrap_or(0);
    total > 0 && vowels * 4 >= total && longest_consonant_run <= 3
}

/// Lower-case words of an identifier or phrase, split at `_`, `-`, `.` and
/// lower→upper changes (`passwordGenerator`, `MY_GITHUB_TOKEN`).
fn words(value: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut previous_lower = false;
    for c in value.chars() {
        if !c.is_alphabetic() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            previous_lower = false;
            continue;
        }
        if c.is_uppercase() && previous_lower {
            words.push(std::mem::take(&mut current));
        }
        previous_lower = c.is_lowercase();
        current.extend(c.to_lowercase());
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// Closing punctuation of prose and code that the capture includes
/// (`falsch.`, `set)`, `string):`).
fn trim_trailing_punctuation(value: &str) -> &str {
    value.trim_end_matches(['.', ',', ':', ';', '!', '?', ')', '`'])
}

#[cfg(test)]
mod tests {
    use super::{
        closes_string, is_assignment_value, is_connection_password, is_env_value, is_passphrase,
        is_userinfo_password, is_userinfo_token, key_shape, suits_field_key, KeyShape,
    };

    /// The value after the last `{v}` marker position of `template`.
    fn assignment(template: &str, value: &str) -> bool {
        let start = template.find("{v}").unwrap();
        let text = template.replace("{v}", value);
        is_assignment_value(&text, start..start + value.len())
    }

    fn userinfo(
        template: &str,
        value: &str,
        check: fn(&str, std::ops::Range<usize>) -> bool,
    ) -> bool {
        let start = template.find("{v}").unwrap();
        let text = template.replace("{v}", value);
        check(&text, start..start + value.len())
    }

    #[test]
    fn code_expressions_are_no_values() {
        for (template, value) in [
            ("token = {v}", "get_token()"),
            ("password = {v}", "os.environ[\"DB\"]"),
            ("token: {v}", "Option<&str>"),
            ("pub token: {v}", "Arc<str>,"),
            ("def f(password: {v}", "str)"),
            ("scorer: ((password: {v}", "string)"),
            ("array{password: {v}", "string|null}"),
            ("Token:{v}", ":Literal(c)"),
            ("$token = {v}", "$authTokens[$originUrl"),
            ("$password = {v}", "$this->io->askAndHideAnswer("),
            ("access token: \"{v}", ".$e->getMessage())"),
            ("token          = {v}", "1*(tchar)"),
            ("const password = {v}", "this._input!.value"),
            ("password: {v}", "password.length"),
            ("password:{v}", "e.length>0?"),
            ("password = {v}", "%s&user=%s"),
            ("password:\n  {v}", "type:"),
            ("the fill color token is {v}", "`--range-track-fill-bg`."),
        ] {
            assert!(!assignment(template, value), "{template} / {value}");
        }
    }

    #[test]
    fn paths_and_shell_variable_keys_are_no_values() {
        assert!(!assignment("docker run -v \"$PWD:{v}\"", "/work"));
        assert!(!assignment("  - $PWD:{v}", "/usr/src/app"));
        assert!(!assignment(
            "token_file = \"x\"\npassword: {v}",
            "/run/secrets/db"
        ));
        assert!(!assignment("password: \"{v}\"", "~/.pgpass"));
    }

    #[test]
    fn words_and_credential_names_are_no_values() {
        for (template, value) in [
            ("Das Passwort ist {v}", "falsch"),
            ("Das Passwort ist {v}", "abgelaufen."),
            ("the password is {v}", "stored"),
            ("the password is {v}", "case-sensitive"),
            ("Token is {v}", "problematic"),
            ("password = {v}", "token"),
            ("password={v}", "GIT_PASSWORD,"),
            ("password: {v}", "passwordGenerator,"),
            ("client_secret: {v}", "clientSecret,"),
            ("password: \"{v}\"", "password"),
            ("password: \"{v}\"", "pass"),
            ("clientSecret: \"{v}\"", "topSecret"),
            ("clientSecret: \"{v}\"", "mySecret"),
        ] {
            assert!(!assignment(template, value), "{template} / {value}");
        }
    }

    #[test]
    fn weak_but_real_passwords_stay_values() {
        for (template, value) in [
            ("password: {v}", "hunter2"),
            ("password = {v}", "letmein"),
            ("Passwort: {v}", "abcabcabcabc"),
            ("Das Passwort lautet {v}", "Sommer2026!"),
            ("password: \"{v}\"", "sunshine"),
            ("password: {v}", "P@ssw0rd"),
            ("password={v}", "$kqztrwx4711"),
            ("password = {v}", "{kqztrwx4711}"),
            ("password=%{v}", "Kx7(pQ2)vL9"),
            ("passwort: {v}", "ORANGE_KQZTRWX_4711"),
            ("password: {v}", "my-dog-rex-2026"),
            ("password = {v}", "ghp_shortButRealPassword"),
            (
                "api_key = \"{v}\"",
                "f4fcba1c3696bf9b564c7dac9b0062f5097331f9",
            ),
        ] {
            assert!(assignment(template, value), "{template} / {value}");
        }
    }

    #[test]
    fn suffix_endings_of_random_letters_are_no_word_forms() {
        // Review PR #129: a suffix alone (`-ing`, `-ed`, `-ic`) is no word
        // form; the stem must be a dictionary word or read like one.
        for value in ["kqztrwxing", "zvbxqtmed", "wqxzrkplic"] {
            assert!(assignment("password = {v}", value), "{value}");
        }
        for value in [
            "stored",
            "configured",
            "missing",
            "problematic",
            "verschlüsselung",
        ] {
            assert!(!assignment("the password is {v}", value), "{value}");
        }
    }

    #[test]
    fn userinfo_stand_ins_are_no_passwords() {
        for value in [
            "pass",
            "secret",
            "x-oauth-basic",
            "MY_GITHUB_TOKEN",
            "realtoken",
            "bar002",
        ] {
            assert!(
                !userinfo("https://user:{v}@example.org/", value, is_userinfo_password),
                "{value}"
            );
        }
        for value in ["Kx7pQ2vL9rT4", "B2B6Hwjm1-l_Jt~xzC", "letmein", "hunter2"] {
            assert!(
                userinfo("https://user:{v}@example.org/", value, is_userinfo_password),
                "{value}"
            );
        }
    }

    #[test]
    fn userinfo_tokens_need_token_likeness() {
        for value in [
            "myusername",
            "TOKEN",
            "github_token",
            "abcdefgh",
            "johnsmith42",
            "jane.doe2026",
            concat!("ghp_", "1234567890abcdefghijklmnopqrstuvwxyz", "AB"),
        ] {
            assert!(
                !userinfo(
                    "https://{v}:x-oauth-basic@github.com/",
                    value,
                    is_userinfo_token
                ),
                "{value}"
            );
        }
        assert!(userinfo(
            "https://{v}:x-oauth-basic@github.com/",
            "4fe210f1c90defd5f704f7ff182304b24a615234",
            is_userinfo_token
        ));
    }

    fn env(template: &str, value: &str) -> bool {
        let start = template.find("{v}").unwrap();
        let text = template.replace("{v}", value);
        is_env_value(&text, start..start + value.len())
    }

    #[test]
    fn passphrases_are_content_words() {
        for value in [
            "blau Drache 47 Zaun",
            "correct horse battery 42",
            "Jabmrq xilats rdrzr 22",
            "Kx7 pQ2;vL9",
            "Kx7, pQ2}vL9",
        ] {
            assert!(is_passphrase(value), "{value}");
        }
    }

    #[test]
    fn messages_labels_and_templates_are_no_passphrases() {
        for value in [
            "Enter your password",
            "Bitte Passwort eingeben",
            "Bitte geben Sie ein Passwort ein",
            "too short",
            "Passwort ist falsch",
            "change me",
            "Invalid token: %s",
            "{{ .Values.lager.token }}",
            "$(cat /run/secrets/db)",
            "${DB_PASSWORD} fallback",
            "<your client secret>",
            "Must be at least eight characters long.",
            "one two three four five six seven",
            "Username or login",
        ] {
            assert!(!is_passphrase(value), "{value}");
        }
    }

    #[test]
    fn quotes_that_close_a_string_open_no_value() {
        assert!(closes_string(
            r#"i.createElement("label",{htmlFor:"pw"},"Password:""#
        ));
        assert!(closes_string(r#"t("client_secret:""#));
        assert!(closes_string(r#"msg = "the password is ""#));
        assert!(!closes_string(r#"password: ""#));
        assert!(!closes_string(r#"conn = connect(host="db", password=""#));
        assert!(!closes_string("it's password: '"));
    }

    #[test]
    fn env_values_reject_constants_calls_and_paths() {
        for (template, value) in [
            ("const DATA_API_KEY = '{v}'", ".data-api"),
            ("const AUTH_FLOW_PASSWORD = \"{v}\"", "password"),
            ("LOGIN_FORM_PASSWORD = '{v}'", "passwordField"),
            ("ADMIN_TOKEN = \"{v}\"", "MY_ADMIN_TOKEN"),
            ("SECRET_KEY = {v}", "config.get(\"secret\")"),
            ("SERVICE_SECRET = {v}", "os.environ[\"SERVICE_SECRET\"]"),
            ("DB_PASSWORD_FILE_SECRET={v}", "/run/secrets/db_password"),
            ("API_TOKEN={v}", "%s"),
            ("DB_PASSWORD=\"{v}\"", "Enter the database password"),
            (
                "e.createElement(\"label\",{},\"DB_PASSWORD:\"{v}\"",
                "),d?e.x(",
            ),
        ] {
            assert!(!env(template, value), "{template} / {value}");
        }
    }

    #[test]
    fn env_values_keep_real_secrets() {
        for (template, value) in [
            ("DB_PASSWORD={v}", "wPF.DZs~BrbDYmfvGE"),
            ("DB_PASSWORD={v}", "Kx7;pQ2vL9"),
            ("SERVICE_SECRET = \"{v}\"", "Otaoqkq1952*"),
            (
                "export API_TOKEN='{v}'",
                "26254c0665131707f3991d8526485850dbcd9646",
            ),
            ("      DB_PASSWORD: \"{v}\"", "blau Drache 47 Zaun"),
            ("DB_PASSWORD={v}", "XkqPwzLmRtVb"),
        ] {
            assert!(env(template, value), "{template} / {value}");
        }
    }

    #[test]
    fn quoted_assignment_values_with_spaces_need_passphrase_likeness() {
        assert!(assignment("password = \"{v}\"", "blau Drache 47 Zaun"));
        assert!(assignment("token: '{v}'", "kq;Ab3xZq,42}QX"));
        assert!(!assignment("password: \"{v}\"", "Enter your password"));
        assert!(!assignment(
            "i.createElement(\"label\",{},\"Password:\"{v}\"",
            "),d?i.createElement("
        ));
    }

    /// The shape of the key whose noun starts at `noun` in `text`.
    fn shape<'a>(text: &'a str, noun: &str) -> KeyShape<'a> {
        key_shape(text, text.find(noun).unwrap())
    }

    #[test]
    fn compound_and_camel_case_keys_have_their_prefix() {
        assert_eq!(shape("password = x", "password"), KeyShape::Simple);
        assert_eq!(shape("app.db.password=x", "password"), KeyShape::Simple);
        assert_eq!(shape("X-Api-Key: x", "Api"), KeyShape::Simple);
        assert_eq!(shape("_password = x", "password"), KeyShape::Simple);
        assert_eq!(
            shape("db_password = x", "password"),
            KeyShape::Compound("db_")
        );
        assert_eq!(
            shape("LAGER_DB_PASSWORD=x", "PASSWORD"),
            KeyShape::Compound("LAGER_DB_")
        );
        assert_eq!(shape("dbPassword: x", "Password"), KeyShape::Compound("db"));
        assert_eq!(
            shape("<add key=\"AdminDbPassword\"", "Password"),
            KeyShape::Compound("AdminDb")
        );
        assert_eq!(
            shape("oauth2Secret = x", "Secret"),
            KeyShape::Compound("oauth2")
        );
        for (text, noun) in [
            ("mypassword = x", "password"),
            ("DBPASSWORD=x", "PASSWORD"),
            ("Benutzerkennwort: x", "kennwort"),
            ("Maßpasswort: x", "passwort"),
        ] {
            assert_eq!(shape(text, noun), KeyShape::Word, "{text}");
        }
    }

    #[test]
    fn field_keys_need_more_than_identifiers_words_and_versions() {
        for value in [
            "Kx7!pQ2#vL9",
            "QDaKkIyIVKwWKJSRDK",
            "Blau Drache 47 Zaun",
            "ab;Kx7pQ,42}Zr",
        ] {
            assert!(suits_field_key(value), "{value}");
        }
        for value in [
            "github-copilot",
            "prefixItems",
            "ExtensionKeywords",
            "alpha",
            "SERVICE_NAME",
            "^1.0.0",
            ">=5.2.3",
            "IPython.core.magics.osm:OSMagics",
            "string",
            "little green men",
            "confirmPassword",
        ] {
            assert!(!suits_field_key(value), "{value}");
        }
    }

    #[test]
    fn escaped_quotes_open_values_inside_a_string() {
        assert!(!closes_string("    \"db_password = \\\""));
        assert!(!closes_string("{\"config\": \"{\\\"password\\\": \\\""));
        assert!(closes_string("    \"print(\\\"Password: \\\""));
        // A quoted JSON key closes before its separator; an XML attribute
        // follows a space.
        assert!(!closes_string("{\"password\":\""));
        assert!(!closes_string("<add key=\"DbPassword\" value=\""));
    }

    #[test]
    fn connection_passwords_are_chosen_ones() {
        let chosen = |value: &str| is_connection_password(value, 0..value.len());
        for value in ["Kx7pQ2vL9!", "Tr0ub4dor & 3", "Sommer2026!", "hunter22"] {
            assert!(chosen(value), "{value}");
        }
        for value in [
            "password",
            "Pa55w0rd",
            "s3cr3t",
            "myPassword",
            "secret",
            "foo",
            "configuration[",
            "getPassword(",
        ] {
            assert!(!chosen(value), "{value}");
        }
    }
}
