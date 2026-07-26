// SPDX-License-Identifier: GPL-3.0-only
use unicode_normalization::UnicodeNormalization;

const HTML_ENTITY_MAX_DEPTH: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextNormalizationConfig {
    pub html_entities: bool,
    pub nfkc: bool,
    pub confusables: bool,
    pub format_characters: bool,
    pub whitespace: bool,
    pub trim: bool,
}

impl Default for TextNormalizationConfig {
    fn default() -> Self {
        Self {
            html_entities: true,
            nfkc: true,
            confusables: true,
            format_characters: true,
            whitespace: true,
            trim: true,
        }
    }
}

pub fn normalize_text(text: &str, config: &TextNormalizationConfig) -> String {
    let mut normalized = text.to_string();
    if config.html_entities {
        normalized = decode_html_entities_recursive(&normalized, HTML_ENTITY_MAX_DEPTH);
    }
    if config.nfkc {
        normalized = normalized.nfkc().collect();
    }
    if config.confusables {
        normalized = normalize_confusables(&normalized);
    }
    if config.format_characters {
        normalized = remove_format_characters(&normalized);
    }
    if config.whitespace {
        normalized = collapse_whitespace(&normalized);
    }
    if config.trim {
        normalized = normalized.trim().to_string();
    }
    normalized
}

pub fn canonical_security_text_v1(text: &str) -> String {
    normalize_text(text, &TextNormalizationConfig::default())
}

fn decode_html_entities_recursive(text: &str, max_depth: usize) -> String {
    let mut current = text.to_string();
    for _ in 0..max_depth {
        let decoded = decode_html_entities_once(&current);
        if decoded == current {
            break;
        }
        current = decoded;
    }
    current
}

fn decode_html_entities_once(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('&') {
        output.push_str(&rest[..start]);
        let candidate = &rest[start..];
        if let Some(end) = candidate.find(';') {
            let entity = &candidate[1..end];
            if entity.len() <= 32 {
                if let Some(decoded) = decode_html_entity(entity) {
                    output.push(decoded);
                    rest = &candidate[end + 1..];
                    continue;
                }
            }
        }
        output.push('&');
        rest = &candidate[1..];
    }
    output.push_str(rest);
    output
}

fn decode_html_entity(entity: &str) -> Option<char> {
    if let Some(decimal) = entity.strip_prefix('#') {
        let value = if let Some(hex) = decimal
            .strip_prefix('x')
            .or_else(|| decimal.strip_prefix('X'))
        {
            u32::from_str_radix(hex, 16).ok()?
        } else {
            decimal.parse::<u32>().ok()?
        };
        return char::from_u32(value);
    }

    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        "ensp" => Some(' '),
        "emsp" => Some(' '),
        "thinsp" => Some(' '),
        "Tab" => Some('\t'),
        "NewLine" => Some('\n'),
        "colon" => Some(':'),
        "semi" => Some(';'),
        "comma" => Some(','),
        "period" => Some('.'),
        "sol" => Some('/'),
        "bsol" => Some('\\'),
        "lpar" => Some('('),
        "rpar" => Some(')'),
        "lsqb" => Some('['),
        "rsqb" => Some(']'),
        "lcub" => Some('{'),
        "rcub" => Some('}'),
        "num" => Some('#'),
        "equals" => Some('='),
        "plus" => Some('+'),
        "minus" => Some('-'),
        "ast" => Some('*'),
        "commat" => Some('@'),
        "excl" => Some('!'),
        "quest" => Some('?'),
        "grave" => Some('`'),
        "lrm" => Some('\u{200e}'),
        "rlm" => Some('\u{200f}'),
        "zwj" => Some('\u{200d}'),
        "zwnj" => Some('\u{200c}'),
        _ => None,
    }
}

fn normalize_confusables(text: &str) -> String {
    text.chars()
        .map(|ch| confusable_ascii(ch).unwrap_or(ch))
        .collect()
}

fn confusable_ascii(ch: char) -> Option<char> {
    match ch {
        'А' | 'Α' | 'Ꭺ' | 'ᗅ' | 'ꓮ' => Some('A'),
        'а' | 'ɑ' | 'α' | 'Ꭿ' | '⍺' => Some('a'),
        'В' | 'Β' | 'Ᏼ' | 'ᗷ' | 'ꓐ' => Some('B'),
        'Ь' | 'Ꮟ' => Some('b'),
        'С' | 'Ϲ' | 'Ꮯ' | 'Ⅽ' | 'ꓚ' => Some('C'),
        'с' | 'ϲ' | 'ⅽ' => Some('c'),
        'ԁ' | 'ⅾ' => Some('d'),
        'Е' | 'Ε' | 'Ꭼ' | 'ꓰ' => Some('E'),
        'е' | '℮' | 'ℯ' | 'ⅇ' | 'ε' => Some('e'),
        'Ғ' => Some('F'),
        'ɡ' | 'ց' => Some('g'),
        'Η' | 'Н' | 'Ꮋ' | 'ꓧ' => Some('H'),
        'һ' | 'հ' => Some('h'),
        'І' | 'Ι' | 'Ӏ' | 'Ⅰ' | 'ᛁ' | 'ꓲ' => Some('I'),
        'і' | 'ι' | 'ı' | 'ⅼ' => Some('i'),
        'Ј' | 'Ϳ' | 'Ꭻ' | 'ꓙ' => Some('J'),
        'ј' | 'ϳ' => Some('j'),
        'Κ' | 'К' | 'Ꮶ' | 'ꓗ' => Some('K'),
        'κ' | 'к' => Some('k'),
        'Ꮮ' | 'Ⅼ' | 'ꓡ' => Some('L'),
        'ӏ' | 'ℓ' => Some('l'),
        'Μ' | 'М' | 'Ꮇ' | 'Ⅿ' | 'ꓟ' => Some('M'),
        'м' | 'ⅿ' => Some('m'),
        'Ν' | 'Ⲛ' | 'ꓠ' => Some('N'),
        'ո' | 'ռ' => Some('n'),
        'Ο' | 'О' | 'Օ' | 'Ⲟ' | 'ꓳ' => Some('O'),
        'ο' | 'о' | 'օ' | 'ⲟ' | 'σ' => Some('o'),
        'Ρ' | 'Р' | 'Ꮲ' | 'ꓑ' => Some('P'),
        'ρ' | 'р' => Some('p'),
        'ԛ' => Some('q'),
        'Ꭱ' | 'ꓣ' => Some('R'),
        'г' => Some('r'),
        'Ѕ' | 'Տ' | 'Ⴝ' | 'Ꮪ' | 'ꓢ' => Some('S'),
        'ѕ' | 'ꜱ' => Some('s'),
        'Τ' | 'Т' | 'Ꭲ' | 'ꓔ' => Some('T'),
        'т' => Some('t'),
        'υ' | 'ս' | 'ᴜ' => Some('u'),
        'Ѵ' | 'Ⅴ' | 'Ꮩ' | 'ꓦ' => Some('V'),
        'ν' | 'ѵ' | 'ⅴ' => Some('v'),
        'Ԝ' | 'Ꮃ' | 'ꓪ' => Some('W'),
        'ԝ' | 'ա' => Some('w'),
        'Χ' | 'Х' | 'Ⅹ' | '᙭' | 'ꓫ' => Some('X'),
        'χ' | 'х' | 'ⅹ' => Some('x'),
        'Υ' | 'Ү' | 'Ꭹ' | 'ꓬ' => Some('Y'),
        'у' | 'γ' | 'ү' => Some('y'),
        'Ζ' | 'Ꮓ' | 'ꓜ' => Some('Z'),
        'ζ' => Some('z'),
        'З' => Some('3'),
        _ => None,
    }
}

fn remove_format_characters(text: &str) -> String {
    text.chars()
        .filter(|ch| !is_unicode_format_character(*ch))
        .collect()
}

fn is_unicode_format_character(ch: char) -> bool {
    matches!(
        ch as u32,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

fn collapse_whitespace(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut in_whitespace = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !in_whitespace {
                output.push(' ');
                in_whitespace = true;
            }
        } else {
            output.push(ch);
            in_whitespace = false;
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_security_text_v1_applies_all_steps_in_order() {
        let text = "  &amp;#x69;gnor\u{200b}e\u{00a0}\u{202e}  Ρrеνіоus　  ";

        assert_eq!(canonical_security_text_v1(text), "ignore Previous");
    }

    #[test]
    fn normalize_text_respects_step_gates() {
        let config = TextNormalizationConfig {
            confusables: false,
            format_characters: false,
            ..TextNormalizationConfig::default()
        };

        assert_eq!(
            normalize_text(" &amp;#x41;\u{200b} Ρ ", &config),
            "A\u{200b} Ρ"
        );
    }
}
