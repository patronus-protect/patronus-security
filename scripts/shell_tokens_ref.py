# SPDX-License-Identifier: GPL-3.0-only
"""Reference shell-token analyzer for the `cat-shell-risk-commander` A1 model.

This is the source of truth that `rust/src/detectors/shell/shell_tokens.rs`
re-implements bit-for-bit. It is vendored here so
`scripts/generate_shell_command_v2_parity_fixtures.py` can build the synthetic
`format_version: 2` parity model without the (gitignored, 4 MB) model release.

Text is never executed: it is tokenised, normalised and turned into TF-IDF
feature strings only. Kept deliberately small so the Rust port can match it
exactly: one regex tokenizer, a fixed normalisation table, unigrams + bigrams +
three structural markers (command head, pipe target, redirect target).
"""
import re

TOKEN = re.compile(r"""'[^']*'|"(?:\\.|[^"\\])*"|\$\(|\|\||&&|>>|\d*>&\d*|[|;&<>()]|[^\s|;&<>()'"]+""")
OPERATORS = {'|', '||', '&&', ';', '&', '(', ')', '$(', '<', '>', '>>'}
URL = re.compile(r'^[a-z][a-z0-9+.-]*://', re.I)
IPV4 = re.compile(r'^\d{1,3}(\.\d{1,3}){3}(:\d+)?$')
NUM = re.compile(r'^-?\d+$')
HOSTPORT = re.compile(r'^[a-z0-9.-]+\.[a-z]{2,}:\d+$', re.I)


def tokens(text):
    return TOKEN.findall(text)


def normalise(token):
    if token in OPERATORS or re.fullmatch(r'\d*>&\d*', token):
        return token
    if token[:1] in '\'"' and len(token) > 1:
        return '<STR>'
    if URL.match(token):
        return '<URL>'
    if IPV4.match(token):
        return '<IP>'
    if HOSTPORT.match(token):
        return '<HOSTPORT>'
    if NUM.match(token):
        return '<NUM>' if not token.startswith('-') else '-<NUM>'
    return token.lower()


def head(token):
    """Command name without directory, e.g. /usr/bin/python3 -> python3."""
    return token.rsplit('/', 1)[-1]


def features(text):
    raw = tokens(text)
    norm = [normalise(t) for t in raw]
    out = list(norm)
    out += [a + ' ' + b for a, b in zip(norm, norm[1:])]
    at_start = True
    after = None
    for token, value in zip(raw, norm):
        if value in OPERATORS or value.endswith('>&') or re.fullmatch(r'\d*>&\d*', value):
            at_start = value in {'|', '||', '&&', ';', '&', '(', '$('}
            after = value if value in {'|', '>', '>>', '<'} else None
            continue
        if after == '|':
            out.append('PIPE->' + head(value))
        elif after in {'>', '>>'}:
            out.append('REDIR->' + ('/dev/null' if value == '/dev/null' else
                                    '<DEV>' if value.startswith('/dev/') else '<FILE>'))
        if at_start:
            out.append('CMD=' + head(value))
        at_start = False
        after = None
    return out
