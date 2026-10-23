// SPDX-License-Identifier: GPL-3.0-only
//! Document structure: values and the keys that name them (K04).
//!
//! A JSON key, a `key: value` or `key=value` line (YAML, INI, forms), an XML/HTML
//! element or attribute, a CSV header or the header of a Markdown/HTML table names
//! the value it holds, just as a field name right before the value does. [`Fields`]
//! finds those fields in a text; a detector decides which keys name which label.
//! Every value lies on one line; keys are normalized with [`normalize_key`].
use std::{collections::HashMap, ops::Range, sync::LazyLock};

use regex::Regex;

/// Where a field was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// `"key": "value"`, `'key': 'value'`, `"key": 123`.
    Json,
    /// `key: value` or `key=value` as the whole line (YAML, INI, forms).
    KeyValue,
    /// `<key>value</key>`, `<element key="value">`.
    Xml,
    /// A cell below a header line of `;`, `,`, tab or `|` separated values.
    Csv,
    /// A Markdown or HTML table cell below its header or next to its key cell.
    Table,
}

impl Carrier {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::KeyValue => "kv",
            Self::Xml => "xml",
            Self::Csv => "csv",
            Self::Table => "table",
        }
    }
}

/// One value and the key that names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// Byte range of the key (header cell, element or attribute name), trimmed and
    /// without quotes.
    pub key: Range<usize>,
    /// Byte range of the value, trimmed and without quotes.
    pub value: Range<usize>,
    /// Indexes into [`Fields::names`], most specific first: the key, and for XML the
    /// key qualified by its parent element (`<customer id=…>` → `customer id`).
    pub names: Vec<usize>,
    pub carrier: Carrier,
}

/// The fields of one text, ordered by value position.
#[derive(Debug, Default)]
pub struct Fields {
    names: Vec<String>,
    fields: Vec<Field>,
}

/// Longest key in characters; longer "keys" are sentences.
const MAX_KEY_CHARS: usize = 48;

impl Fields {
    pub fn parse(text: &str) -> Self {
        let mut builder = Builder::default();
        json(text, &mut builder);
        key_value_lines(text, &mut builder);
        xml(text, &mut builder);
        markdown_tables(text, &mut builder);
        html_tables(text, &mut builder);
        csv(text, &mut builder);
        builder.finish()
    }

    /// Normalized key names; [`Field::names`] point here.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    pub fn iter(&self) -> impl Iterator<Item = &Field> {
        self.fields.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Fields whose value is exactly `value` (byte offsets). A key names its
    /// whole value, not a number inside it.
    pub fn at(&self, value: Range<usize>) -> impl Iterator<Item = &Field> {
        let start = self.fields.partition_point(|field| {
            (field.value.start, field.value.end) < (value.start, value.end)
        });
        self.fields[start..]
            .iter()
            .take_while(move |field| field.value == value)
    }
}

#[derive(Default)]
struct Builder {
    names: Vec<String>,
    index: HashMap<String, usize>,
    fields: Vec<Field>,
}

impl Builder {
    fn name(&mut self, name: String) -> Option<usize> {
        if name.is_empty() {
            return None;
        }
        if let Some(&index) = self.index.get(&name) {
            return Some(index);
        }
        self.names.push(name.clone());
        self.index.insert(name, self.names.len() - 1);
        Some(self.names.len() - 1)
    }

    /// Add `value` named by `key` (and `parent key`), trimmed and unquoted.
    fn push(
        &mut self,
        text: &str,
        key: Range<usize>,
        parent: Option<&str>,
        value: Range<usize>,
        carrier: Carrier,
    ) {
        let Some(key) = trim_value(text, key) else {
            return;
        };
        let raw_key = &text[key.clone()];
        if raw_key.chars().count() > MAX_KEY_CHARS {
            return;
        }
        let Some(value) = trim_value(text, value) else {
            return;
        };
        let local = normalize_key(raw_key);
        let mut names = Vec::with_capacity(2);
        if let Some(parent) = parent {
            let qualified = format!("{} {local}", normalize_key(parent));
            names.extend(self.name(local));
            names.extend(self.name(qualified));
        } else {
            names.extend(self.name(local));
        }
        if names.is_empty() {
            return;
        }
        self.fields.push(Field {
            key,
            value,
            names,
            carrier,
        });
    }

    fn finish(mut self) -> Fields {
        self.fields
            .sort_by_key(|field| (field.value.start, field.value.end, field.key.start));
        self.fields
            .dedup_by(|a, b| a.key == b.key && a.value == b.value && a.names == b.names);
        Fields {
            names: self.names,
            fields: self.fields,
        }
    }
}

/// Lowercase words of a key: `customerId`, `customer_id`, `Customer-ID` and
/// `Customer ID:` all become `customer id`. Letters, digits, `'` and `#` stay;
/// every other run of characters becomes one space.
pub fn normalize_key(key: &str) -> String {
    let mut normalized = String::with_capacity(key.len());
    let mut previous: Option<char> = None;
    for ch in key.chars() {
        if ch.is_alphanumeric() || matches!(ch, '\'' | '#') {
            if ch.is_uppercase()
                && previous.is_some_and(char::is_lowercase)
                && !normalized.ends_with(' ')
            {
                normalized.push(' ');
            }
            normalized.extend(ch.to_lowercase());
        } else if !normalized.is_empty() && !normalized.ends_with(' ') {
            normalized.push(' ');
        }
        previous = Some(ch);
    }
    let trimmed = normalized.trim_end().len();
    normalized.truncate(trimmed);
    normalized
}

/// The value without surrounding blanks and one pair of matching quotes; `None`
/// when nothing is left or the value spans lines.
fn trim_value(text: &str, value: Range<usize>) -> Option<Range<usize>> {
    let raw = &text[value.clone()];
    let start = value.start + (raw.len() - raw.trim_start().len());
    let end = value.start + raw.trim_end().len();
    if start >= end {
        return None;
    }
    let mut range = start..end;
    let inner = &text[range.clone()];
    if inner.len() >= 2
        && ((inner.starts_with('"') && inner.ends_with('"'))
            || (inner.starts_with('\'') && inner.ends_with('\'')))
    {
        range = trim_value(text, range.start + 1..range.end - 1)?;
    }
    (!text[range.clone()].contains(['\n', '\r'])).then_some(range)
}

fn json(text: &str, builder: &mut Builder) {
    static PAIR: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?:"((?:[^"\\\r\n]|\\.){1,64})"|'((?:[^'\\\r\n]|\\.){1,64})')[ \t]*:[ \t]*(?:"((?:[^"\\\r\n]|\\.)*)"|'((?:[^'\\\r\n]|\\.)*)'|(-?[0-9][0-9.]*)(?:[ \t]*[,}\]]|[ \t]*\r?$))"#,
        )
        .unwrap()
    });
    if !text.contains(':') {
        return;
    }
    for captures in PAIR.captures_iter(text) {
        let key = captures.get(1).or_else(|| captures.get(2)).unwrap();
        let Some(value) = captures
            .get(3)
            .or_else(|| captures.get(4))
            .or_else(|| captures.get(5))
        else {
            continue;
        };
        builder.push(text, key.range(), None, value.range(), Carrier::Json);
    }
}

/// A `key: value` or `key=value` line: the key, the separator and the raw value.
static KEY_VALUE_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^[ \t]*(?:[-*+][ \t]+)?(\p{L}[\p{L}\p{N} ._'/#()&+\-]{0,47}?)[ \t]*[:=][ \t]*([^\r\n]+?)[ \t]*\r?$",
    )
    .unwrap()
});

/// One line of `text` read as a [`Carrier::KeyValue`] field (DLP K05): the
/// byte ranges of the key and of the raw value, untrimmed of quotes and
/// comments, so that a caller can apply the quoting rules of its format.
/// `None` if `line` is no `key: value` or `key=value` line.
pub(crate) fn key_value_line(
    text: &str,
    line: Range<usize>,
) -> Option<(Range<usize>, Range<usize>)> {
    let captures = KEY_VALUE_LINE.captures(&text[line.clone()])?;
    let key = captures.get(1)?;
    let value = captures.get(2)?;
    Some((
        line.start + key.start()..line.start + key.end(),
        line.start + value.start()..line.start + value.end(),
    ))
}

fn key_value_lines(text: &str, builder: &mut Builder) {
    if !text.contains([':', '=']) {
        return;
    }
    for captures in KEY_VALUE_LINE.captures_iter(text) {
        let key = captures.get(1).unwrap();
        let value = captures.get(2).unwrap();
        builder.push(text, key.range(), None, value.range(), Carrier::KeyValue);
    }
}

fn xml(text: &str, builder: &mut Builder) {
    static TAG: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"<(/?)(?:[A-Za-z_][\w.\-]*:)?([A-Za-z_][\w.\-]*)((?:[ \t\r\n]+[^<>]*?)?)[ \t\r\n]*(/?)>")
            .unwrap()
    });
    static ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?:[A-Za-z_][\w.\-]*:)?([A-Za-z_][\w.\-]*)[ \t\r\n]*=[ \t\r\n]*(?:"([^"\r\n]*)"|'([^'\r\n]*)')"#)
            .unwrap()
    });
    if !text.contains('<') {
        return;
    }
    // Open elements: name range and the end of the open tag.
    let mut open: Vec<(Range<usize>, usize)> = Vec::new();
    // The open tag that the next text belongs to, if no tag came in between.
    let mut last_open: Option<(Range<usize>, usize)> = None;
    for captures in TAG.captures_iter(text) {
        let whole = captures.get(0).unwrap();
        let name = captures.get(2).unwrap();
        let closing = !captures[1].is_empty();
        if closing {
            if let Some((open_name, content_start)) = last_open.take() {
                if text[open_name.clone()] == *name.as_str() {
                    let parent = open
                        .iter()
                        .rev()
                        .nth(1)
                        .map(|(parent, _)| &text[parent.clone()]);
                    builder.push(
                        text,
                        open_name,
                        parent,
                        content_start..whole.start(),
                        Carrier::Xml,
                    );
                }
            }
            if let Some(position) = open
                .iter()
                .rposition(|(open_name, _)| text[open_name.clone()] == *name.as_str())
            {
                open.truncate(position);
            }
            continue;
        }
        let element = &text[name.range()];
        if let Some(attributes) = captures.get(3) {
            for attribute in ATTRIBUTE.captures_iter(attributes.as_str()) {
                let key = attribute.get(1).unwrap();
                let value = attribute.get(2).or_else(|| attribute.get(3)).unwrap();
                let offset = attributes.start();
                builder.push(
                    text,
                    offset + key.start()..offset + key.end(),
                    Some(element),
                    offset + value.start()..offset + value.end(),
                    Carrier::Xml,
                );
            }
        }
        if captures[4].is_empty() {
            open.push((name.range(), whole.end()));
            last_open = Some((name.range(), whole.end()));
        } else {
            last_open = None;
        }
    }
}

/// Byte ranges of the lines of `text`, without line terminators.
fn lines(text: &str) -> impl Iterator<Item = Range<usize>> + '_ {
    let mut start = 0;
    text.split_inclusive('\n').map(move |line| {
        let range = start..start + line.trim_end_matches(['\n', '\r']).len();
        start += line.len();
        range
    })
}

/// Cells of `line` split at `delimiter` outside double quotes.
fn split_cells(text: &str, line: Range<usize>, delimiter: u8) -> Vec<Range<usize>> {
    let bytes = text.as_bytes();
    let mut cells = Vec::new();
    let mut start = line.start;
    let mut quoted = false;
    for index in line.clone() {
        match bytes[index] {
            b'"' => quoted = !quoted,
            byte if byte == delimiter && !quoted => {
                cells.push(start..index);
                start = index + 1;
            }
            _ => {}
        }
    }
    cells.push(start..line.end);
    cells
}

/// Cells of a Markdown table row; `None` if the line is not one.
fn table_row(text: &str, line: Range<usize>) -> Option<Vec<Range<usize>>> {
    let raw = &text[line.clone()];
    let trimmed = raw.trim();
    if !trimmed.starts_with('|') || trimmed.len() < 3 {
        return None;
    }
    let start = line.start + (raw.len() - raw.trim_start().len());
    let end = start + trimmed.len();
    let mut cells = split_cells(text, start + 1..end, b'|');
    if trimmed.ends_with('|') {
        cells.pop();
    }
    Some(cells)
}

fn is_separator_row(text: &str, cells: &[Range<usize>]) -> bool {
    cells.iter().all(|cell| {
        let cell = text[cell.clone()].trim();
        let dashes = cell.trim_start_matches(':').trim_end_matches(':');
        !dashes.is_empty() && dashes.bytes().all(|byte| byte == b'-')
    })
}

fn markdown_tables(text: &str, builder: &mut Builder) {
    if !text.contains('|') {
        return;
    }
    let mut block: Vec<Vec<Range<usize>>> = Vec::new();
    for line in lines(text).chain(std::iter::once(text.len()..text.len())) {
        match table_row(text, line) {
            Some(cells) => block.push(cells),
            None if !block.is_empty() => table_block(text, &std::mem::take(&mut block), builder),
            None => {}
        }
    }
}

fn table_block(text: &str, rows: &[Vec<Range<usize>>], builder: &mut Builder) {
    if rows.len() >= 2 && is_separator_row(text, &rows[1]) {
        let header = &rows[0];
        for row in &rows[2..] {
            for (key, value) in header.iter().zip(row) {
                builder.push(text, key.clone(), None, value.clone(), Carrier::Table);
            }
        }
        return;
    }
    // Without a header, a row of key and value cells: `| Kundennummer | KD-1 |`.
    for row in rows {
        if row.len().is_multiple_of(2) && !is_separator_row(text, row) {
            for pair in row.chunks(2) {
                builder.push(text, pair[0].clone(), None, pair[1].clone(), Carrier::Table);
            }
        }
    }
}

fn html_tables(text: &str, builder: &mut Builder) {
    static TABLE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)<table\b[^>]*>(.*?)</table>").unwrap());
    static ROW: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)<tr\b[^>]*>(.*?)</tr>").unwrap());
    static CELL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?is)<(th|td)\b[^>]*>([^<]*)</(?:th|td)>").unwrap());
    if !text.contains("<t") && !text.contains("<T") {
        return;
    }
    for table in TABLE.captures_iter(text) {
        let body = table.get(1).unwrap();
        let mut header: Option<Vec<Range<usize>>> = None;
        for row in ROW.captures_iter(body.as_str()) {
            let row_start = body.start() + row.get(1).unwrap().start();
            let cells: Vec<(bool, Range<usize>)> = CELL
                .captures_iter(row.get(1).unwrap().as_str())
                .map(|cell| {
                    let content = cell.get(2).unwrap();
                    (
                        cell[1].eq_ignore_ascii_case("th"),
                        row_start + content.start()..row_start + content.end(),
                    )
                })
                .collect();
            if cells.is_empty() {
                continue;
            }
            if cells.iter().all(|(heading, _)| *heading) {
                if header.is_none() && cells.len() >= 2 {
                    header = Some(cells.into_iter().map(|(_, range)| range).collect());
                }
                continue;
            }
            let pairs = cells.len().is_multiple_of(2)
                && cells.chunks(2).all(|pair| pair[0].0 && !pair[1].0);
            if pairs {
                for pair in cells.chunks(2) {
                    builder.push(
                        text,
                        pair[0].1.clone(),
                        None,
                        pair[1].1.clone(),
                        Carrier::Table,
                    );
                }
            } else if let Some(header) = &header {
                for (key, (_, value)) in header.iter().zip(&cells) {
                    builder.push(text, key.clone(), None, value.clone(), Carrier::Table);
                }
            }
        }
    }
}

/// A header cell names a column: it holds a letter, no digit and is not quoted prose.
fn is_header_cell(text: &str, cell: &Range<usize>) -> bool {
    let cell = text[cell.clone()].trim().trim_matches('"').trim();
    !cell.is_empty()
        && cell.chars().count() <= MAX_KEY_CHARS
        && cell.chars().any(char::is_alphabetic)
        && !cell.chars().any(|ch| ch.is_ascii_digit())
}

fn csv(text: &str, builder: &mut Builder) {
    let all: Vec<Range<usize>> = lines(text).collect();
    if all.len() < 2 {
        return;
    }
    for delimiter in *b";\t,|" {
        if !text.as_bytes().contains(&delimiter) {
            continue;
        }
        let mut run: Vec<Vec<Range<usize>>> = Vec::new();
        let mut flush = |run: &mut Vec<Vec<Range<usize>>>| {
            if run.len() >= 2 && run[0].iter().all(|cell| is_header_cell(text, cell)) {
                for row in &run[1..] {
                    for (key, value) in run[0].iter().zip(row) {
                        builder.push(text, key.clone(), None, value.clone(), Carrier::Csv);
                    }
                }
            }
            run.clear();
        };
        for line in &all {
            let raw = &text[line.clone()];
            let cells = if raw.trim().is_empty()
                || (delimiter == b'|' && raw.trim_start().starts_with('|'))
            {
                Vec::new()
            } else {
                split_cells(text, line.clone(), delimiter)
            };
            if cells.len() < 2 || run.first().is_some_and(|first| first.len() != cells.len()) {
                flush(&mut run);
            }
            if cells.len() >= 2 {
                run.push(cells);
            }
        }
        flush(&mut run);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(names, value)` of every field.
    fn fields(text: &str) -> Vec<(Vec<String>, &str, Carrier)> {
        let fields = Fields::parse(text);
        fields
            .iter()
            .map(|field| {
                (
                    field
                        .names
                        .iter()
                        .map(|&name| fields.names()[name].clone())
                        .collect(),
                    &text[field.value.clone()],
                    field.carrier,
                )
            })
            .collect()
    }

    fn has(text: &str, name: &str, value: &str, carrier: Carrier) -> bool {
        fields(text).iter().any(|(names, found, found_carrier)| {
            names.iter().any(|known| known == name) && *found == value && *found_carrier == carrier
        })
    }

    #[test]
    fn normalizes_case_separators_and_camel_case() {
        assert_eq!(normalize_key("customerId"), "customer id");
        assert_eq!(normalize_key("customer_ID"), "customer id");
        assert_eq!(normalize_key("Kunden-Nr.:"), "kunden nr");
        assert_eq!(normalize_key("  St.-Nr. "), "st nr");
        assert_eq!(normalize_key("E-Mail"), "e mail");
        assert_eq!(normalize_key("driver's licence no."), "driver's licence no");
        assert_eq!(normalize_key("Führerschein"), "führerschein");
    }

    #[test]
    fn json_keys_name_string_and_number_values() {
        let text = r#"{"kundennummer": "KD-99120", 'taxId': '31415926539', "age": 41, "x": ""}"#;
        assert!(has(text, "kundennummer", "KD-99120", Carrier::Json));
        assert!(has(text, "tax id", "31415926539", Carrier::Json));
        assert!(has(text, "age", "41", Carrier::Json));
        assert!(!fields(text).iter().any(|(names, _, _)| names[0] == "x"));
    }

    #[test]
    fn key_value_lines_cover_yaml_ini_and_forms() {
        let text = "customer:\n  customer_id: C-104882\n- passnummer = \"C4J7K9L2N\"\nSt.-Nr.: 93815/08152\r\nkein Feld hier\n";
        assert!(has(text, "customer id", "C-104882", Carrier::KeyValue));
        assert!(has(text, "passnummer", "C4J7K9L2N", Carrier::KeyValue));
        assert!(has(text, "st nr", "93815/08152", Carrier::KeyValue));
        assert!(!fields(text)
            .iter()
            .any(|(names, _, _)| names[0] == "customer"));
    }

    #[test]
    fn xml_elements_and_attributes_with_parent_names() {
        let text = r#"<employee><id>E-77121</id></employee><customer id="CUST-9001"/><ns:bank><ns:bic>BARCGB22</ns:bic></ns:bank>"#;
        assert!(has(text, "employee id", "E-77121", Carrier::Xml));
        assert!(has(text, "customer id", "CUST-9001", Carrier::Xml));
        assert!(has(text, "bic", "BARCGB22", Carrier::Xml));
        // Mixed content is not one value.
        assert!(fields("<p>Telefon <b>030</b> 123</p>")
            .iter()
            .all(|(names, _, _)| names[0] == "b"));
    }

    #[test]
    fn markdown_tables_by_header_and_by_key_cell() {
        let text =
            "| MRN | Ward |\n|---|:---:|\n| MRN-981134 | 7 |\n\n| Kundennummer | KD-99121 |\n";
        assert!(has(text, "mrn", "MRN-981134", Carrier::Table));
        assert!(has(text, "ward", "7", Carrier::Table));
        assert!(has(text, "kundennummer", "KD-99121", Carrier::Table));
        // The header row is not a key/value row.
        assert!(!has(text, "mrn", "Ward", Carrier::Table));
    }

    #[test]
    fn html_tables_by_header_and_by_heading_cell() {
        let text = "<table><tr><th>Name</th><th>Telefon</th></tr><tr><td>Anna</td><td>030 1234567</td></tr></table>\n<table><tr><th>SSN</th><td>219-09-9997</td></tr></table>";
        assert!(has(text, "telefon", "030 1234567", Carrier::Table));
        assert!(has(text, "ssn", "219-09-9997", Carrier::Table));
    }

    #[test]
    fn csv_cells_take_their_header() {
        let text = "Name;Matrikelnummer\nLea Brandt;4718205\n\"Roth, Jana\";4718206\n";
        assert!(has(text, "matrikelnummer", "4718205", Carrier::Csv));
        assert!(has(text, "matrikelnummer", "4718206", Carrier::Csv));
        // A header needs letters without digits; a single line is no table.
        assert!(!fields("2024;2025\n17;18\n")
            .iter()
            .any(|(_, _, carrier)| *carrier == Carrier::Csv));
        assert!(fields("Name;Telefon").is_empty());
    }

    #[test]
    fn a_key_names_its_whole_value_only() {
        let text = "a: 1\nTelefon: 030 1234567 privat\nFax: 030 7654321\n";
        let fields = Fields::parse(text);
        let part = text.find("030").unwrap();
        assert_eq!(fields.at(part..part + 11).count(), 0);
        let whole = text.find("030 7654321").unwrap();
        let found: Vec<_> = fields.at(whole..whole + 11).collect();
        assert_eq!(found.len(), 1);
        assert_eq!(fields.names()[found[0].names[0]], "fax");
    }
}
