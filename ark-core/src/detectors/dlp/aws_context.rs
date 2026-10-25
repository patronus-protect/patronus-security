// SPDX-License-Identifier: MIT OR Apache-2.0
//! F05: structural context of AWS secret access keys. The secret is 40
//! base64 characters without a prefix, so its shape is no proof: a value only
//! counts next to an AWS anchor. The rule's regex finds three anchors:
//!
//! - an AWS key name or label (`aws_secret_access_key`, `AwsSecretAccessKey`,
//!   `aws.secretKey`, `AWS-Secret-Access-Key`, „AWS secret access key“ in
//!   prose, `SecretAccessKey` in STS/IAM output), also with the value up to
//!   two lines further down in chats and mails;
//! - an access key ID right before the value (`"AKIA…", "…"` in SDK calls,
//!   `AKIA…,…` in the IAM credentials CSV, `mc alias set … AKIA… …`);
//! - a generic secret key name (`secret_key`, `secret-key`, `secretKey`,
//!   `SecretKey`), as in Terraform `provider "aws"` blocks, `.s3cfg` or Spring
//!   `cloud.aws.credentials.secret-key`.
//!
//! The first two are AWS anchors of their own. The generic key name counts
//! only with AWS context: an access key ID or an `access_key`/`accessKeyId`
//! key, a Terraform `provider "aws"` or `backend "s3"` block, an
//! `amazonaws.com` host, or `aws` as a word or name part (`cloud.aws.…`,
//! `aws:` above a nested `secret-key:`, `~/.aws/credentials`), in the value's
//! line, up to five lines above or two lines below. A Django or Flask
//! `SECRET_KEY` is no anchor at all.
use regex::Regex;
use std::ops::Range;
use std::sync::LazyLock;

/// Lines above the value searched for the anchor of its match.
const ANCHOR_LINES: usize = 3;
/// Lines above and below the value searched for AWS context.
const CONTEXT_LINES_ABOVE: usize = 5;
const CONTEXT_LINES_BELOW: usize = 2;
/// Bytes a context window reaches before or after the value at most.
const WINDOW_BYTES: usize = 600;

/// AWS access key IDs: the credential prefixes of the IAM unique-ID table
/// (`AKIA` long-term, `ASIA` temporary, `ABIA` STS service bearer token,
/// `ACCA` context-specific credential, legacy `A3T…`) and 16 upper-case
/// letters or digits: Base32 today, legacy IDs also hold 0, 1, 8 and 9
/// (gitleaks aws-access-token).
pub const ACCESS_KEY_ID: &str = r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}";

/// The AWS anchors of their own: an AWS secret key name or label, or an
/// access key ID.
static AWS_ANCHOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?i:aws[\s_.-]?secret[\s_.-]?(?:access[\s_.-]?)?key|secret[\s_.-]?access[\s_.-]?key)|{ACCESS_KEY_ID}"
    ))
    .unwrap()
});

/// AWS context of a generic secret key name.
static AWS_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"{ACCESS_KEY_ID}|(?i:access[_.-]?key|provider\s*"aws"|backend\s*"s3"|amazonaws\.com)"#
    ))
    .unwrap()
});

static AWS_WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)aws").unwrap());

/// An AWS secret access key: 40 base64 characters without padding, with upper
/// and lower case letters. A random key lacks one of them with a chance below
/// 10⁻⁸; hex digests (SHA-1, git object IDs), repeated example fills and
/// single-case words do.
pub fn is_aws_secret_value(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'/' || byte == b'+')
        && value.bytes().any(|byte| byte.is_ascii_uppercase())
        && value.bytes().any(|byte| byte.is_ascii_lowercase())
}

/// Byte index of the start of the line `lines` lines above the line of
/// `index`, not more than `WINDOW_BYTES` before it.
fn lines_above(text: &str, index: usize, lines: usize) -> usize {
    let mut start = text[..index].rfind('\n').map_or(0, |newline| newline + 1);
    for _ in 0..lines {
        if start == 0 {
            break;
        }
        start = text[..start - 1]
            .rfind('\n')
            .map_or(0, |newline| newline + 1);
    }
    let mut floor = index.saturating_sub(WINDOW_BYTES);
    while !text.is_char_boundary(floor) {
        floor += 1;
    }
    start.max(floor)
}

/// Byte index of the end of the line `lines` lines below the line of
/// `index`, not more than `WINDOW_BYTES` after it.
fn lines_below(text: &str, index: usize, lines: usize) -> usize {
    let mut end = text[index..]
        .find('\n')
        .map_or(text.len(), |newline| index + newline);
    for _ in 0..lines {
        if end == text.len() {
            break;
        }
        end = text[end + 1..]
            .find('\n')
            .map_or(text.len(), |newline| end + 1 + newline);
    }
    let mut ceil = (index + WINDOW_BYTES).min(text.len());
    while !text.is_char_boundary(ceil) {
        ceil -= 1;
    }
    end.min(ceil)
}

/// Whether `aws` stands as a word or name part in `text` (`provider "aws"`,
/// `cloud.aws.credentials`, `AWS_REGION`, `awsSecret`), not inside a word
/// (`laws`, `awesome`).
fn has_aws_word(text: &str) -> bool {
    AWS_WORD.find_iter(text).any(|found| {
        let before = text[..found.start()].chars().next_back();
        let after = text[found.end()..].chars().next();
        before.is_none_or(|ch| !ch.is_ascii_alphabetic())
            && after.is_none_or(|ch| !ch.is_ascii_lowercase())
    })
}

/// F05: whether the 40-character value at `value` stands in AWS context (see
/// the module docs).
pub(super) fn has_aws_secret_context(text: &str, value: Range<usize>) -> bool {
    let anchor_start = lines_above(text, value.start, ANCHOR_LINES);
    if AWS_ANCHOR.is_match(&text[anchor_start..value.start]) {
        return true;
    }
    let context_start = lines_above(text, value.start, CONTEXT_LINES_ABOVE);
    let context_end = lines_below(text, value.end, CONTEXT_LINES_BELOW);
    [
        &text[context_start..value.start],
        &text[value.end..context_end],
    ]
    .iter()
    .any(|part| AWS_CONTEXT.is_match(part) || has_aws_word(part))
}

#[cfg(test)]
mod tests {
    use super::{has_aws_secret_context, is_aws_secret_value};

    /// A 40-character base64 value assembled at test time.
    fn value() -> String {
        ["Zq7Lm2Xc9Vb", "Np4/Rt8Wy+Hk", "3Gd6Fs1Jo5Ea", "Ui0Tw"].concat()
    }

    fn context(before: &str, after: &str) -> bool {
        let text = format!("{before}{}{after}", value());
        has_aws_secret_context(&text, before.len()..before.len() + 40)
    }

    #[test]
    fn value_needs_forty_base64_characters_in_both_cases() {
        assert!(is_aws_secret_value(&value()));
        assert!(!is_aws_secret_value(&value()[..39]));
        assert!(!is_aws_secret_value(&format!("{}A", value())));
        assert!(!is_aws_secret_value(&value().to_lowercase()));
        assert!(!is_aws_secret_value(&value().to_uppercase()));
        assert!(!is_aws_secret_value(&value().replace('/', "=")));
        assert!(!is_aws_secret_value(&"0123456789abcdef".repeat(3)[..40]));
    }

    #[test]
    fn aws_anchors_need_no_further_context() {
        assert!(context("aws_secret_access_key = ", "\n"));
        assert!(context("<add key=\"AwsSecretAccessKey\" value=\"", "\" />"));
        assert!(context("the AWS secret access key for the job:\n\n", "\n"));
        assert!(context(
            &[
                "new BasicAWSCredentials(\"AKIA",
                "ZQ7LM2XC4VBNP4RT",
                "\", \""
            ]
            .concat(),
            "\");"
        ));
    }

    #[test]
    fn generic_secret_keys_need_aws_context() {
        assert!(!context("secret_key = \"", "\"\n"));
        assert!(!context("# Django\nSECRET_KEY = \"", "\"\n"));
        assert!(context(
            "provider \"aws\" {\n  region = \"eu-central-1\"\n  secret_key = \"",
            "\"\n}"
        ));
        assert!(context(
            &[
                "[default]\naccess_key = AKIA",
                "ZQ7LM2XC4VBNP4RT",
                "\nsecret_key = "
            ]
            .concat(),
            "\n"
        ));
        assert!(context("cloud.aws.credentials.secret-key=", "\n"));
        assert!(context("secretKey: \"", "\"\naccessKeyId: from-vault\n"));
        assert!(context(
            "cloud:\n  aws:\n    credentials:\n      secret-key: ",
            "\n"
        ));
        assert!(!context("laws:\n  secret_key: ", "\n"));
        assert!(!context("awesome:\n  secretKey: ", "\n"));
    }
}
