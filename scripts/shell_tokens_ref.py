# SPDX-License-Identifier: GPL-3.0-only
"""Reference shell-token analyzer for the `cat-shell-risk-commander` A1 model.

This is the source of truth that `rust/src/detectors/shell/shell_tokens.rs`
re-implements bit-for-bit. It is vendored here so
`scripts/generate_shell_command_parity_fixtures.py` can build the synthetic
`format_version: 2` parity model without the (gitignored, 4 MB) model release.

Text is never executed: it is tokenised, normalised and turned into TF-IDF
feature strings only. Kept deliberately small so the Rust port can match it
exactly: one regex tokenizer, a fixed normalisation table, unigrams + bigrams +
three structural markers (command head, pipe target, redirect target), plus the
issue #159 relation markers (does a download flow into an interpreter?), with
heredoc bodies that are code (python/node/ruby/perl, or cat/tee into a code file)
masked before tokenising.
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


# ---- Heredoc bodies for non-shell interpreters (issue: Python read as shell) ----
# `python - <<'PY' … PY` feeds Python, not shell, so its body must not be tokenised as
# shell: list syntax like ['ssh','-o',…] would turn into `[`, `,`, `CMD=[` tokens that only
# attacks carried in training. The body is replaced by one `heredoc_body` line for this
# block; the char_wb block still sees the raw text.
HEREDOC_INTERPRETERS = ('node', 'ruby', 'perl')
HEREDOC_OP = re.compile(r"<<-?[ \t]*(?:'([^'\\\n]+)'|\"([^\"\\\n]+)\"|([^\s;&|()<>'\"\\]+))(?=$|[\s;&|()<>])")
# `cat <<'EOF' > fix.py` writes code or data, not shell: same treatment when the owning
# command's output file has one of these extensions. Shell scripts (`> run.sh`) stay shell.
HEREDOC_WRITERS = ('cat', 'tee')
HEREDOC_PREFIXES = ('sudo', 'doas', 'env', 'exec', 'command', 'nohup', 'time')
HEREDOC_FILE = re.compile(
    r'(?:>>?|\btee(?:\s+-a)?)\s*[\'"]?[^\s;&|()<>\'"]+\.(?:py|pyi|js|mjs|cjs|ts|tsx|jsx|rb|pl|pm|php|r|jl|json|ya?ml|toml|ini|cfg)'
    r'[\'"]?(?=[\s;&|()<>]|$)', re.I)
HEREDOC_MASK = 'heredoc_body'


def heredoc_segments(line):
    """Top-level command segments as (start, end), splitting on `; | & && ||` outside any
    `$( … )` / `( … )` / backticks / quotes. A heredoc belongs to the segment that contains
    its `<<`, so `echo python; cat f <<EOF` attributes `<<EOF` to `cat f`, not the earlier
    `python`, and `python -- "$(cat <<OLD)"` keeps `<<OLD` with `python`."""
    depth = 0; backtick = False; quote = None; start = 0; i = 0; n = len(line)
    while i < n:
        c = line[i]
        if quote is not None:
            if c == quote:
                quote = None
            i += 1; continue
        if c in '\'"':
            quote = c; i += 1; continue
        if c == '`':
            backtick = not backtick; i += 1; continue
        if line[i:i + 2] == '$(' or c == '(':
            depth += 1; i += 2 if c == '$' else 1; continue
        if c == ')':
            depth = max(0, depth - 1); i += 1; continue
        if depth == 0 and not backtick:
            if line[i:i + 2] in ('&&', '||'):
                yield start, i; start = i + 2; i += 2; continue
            if c in ';|&':
                yield start, i; start = i + 1; i += 1; continue
        i += 1
    yield start, n


def _segment_head(segment):
    """Lowercase basename of the command head of `segment`, skipping assignments, flags and
    sudo/env prefixes; '' when it has none."""
    for token in segment.split():
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*=.*', token) or token.startswith('-'):
            continue
        name = re.split(r'[\\/]', token.strip('\'"'))[-1].lower()
        if name in HEREDOC_PREFIXES:
            continue
        return name
    return ''


def _is_heredoc_interpreter(name):
    return name in HEREDOC_INTERPRETERS or (
        name.startswith('python') and re.fullmatch(r'[0-9.]*', name[len('python'):]) is not None)


def _head_masks(head, segment):
    return _is_heredoc_interpreter(head) or (head in HEREDOC_WRITERS and bool(HEREDOC_FILE.search(segment)))


def heredoc_delimiter(line):
    """Delimiter of the first `<<` heredoc on `line` whose owning command feeds a non-shell
    interpreter, or is a cat/tee writing a code or data file."""
    segments = [(s, e, _segment_head(line[s:e])) for s, e in heredoc_segments(line)]
    for op in HEREDOC_OP.finditer(line):
        if line[op.start() - 1:op.start()] == '<':
            continue
        for s, e, head in segments:
            if s <= op.start() < e and head and _head_masks(head, line[s:e]):
                return (op.group(1) or op.group(2) or op.group(3), op.group(3) is None)
    return None


def mask_heredocs(text):
    out = []
    lines = text.split('\n')
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        opened = heredoc_delimiter(line)
        if opened is None:
            continue
        delimiter, quoted = opened
        start = i
        while i < len(lines) and lines[i].strip(' \t\r') != delimiter:
            i += 1
        body = lines[start:i]
        # Unquoted bodies expand shell commands; preserve multiline substitutions too.
        if not quoted and any('$' in line or '`' in line for line in body):
            out.extend(body)
        else:
            out.append(HEREDOC_MASK)
        if i < len(lines):
            out.append(lines[i])
            i += 1
    return '\n'.join(out)


def features(text):
    text = mask_heredocs(text)
    raw = tokens(text)
    norm = [normalise(t) for t in raw]
    out = list(norm)
    out += [a + ' ' + b for a, b in zip(norm, norm[1:])]
    at_start = True; after = None
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
        at_start = False; after = None
    return out + relations(text)


# ---- Relation markers (issue #159): does a download flow into an interpreter? ----
# A small recursive parse over the same tokens plus newlines. Backticks become
# $( … ), newlines separate commands, '#' words start a comment up to the newline,
# '<NAME>' placeholders stay one word, quoted strings and substitutions are parsed
# as nested scripts (depth-limited). Each marker is emitted at most once per text,
# in a fixed order.
DOWNLOADERS = {'curl', 'curl.exe', 'wget', 'wget.exe', 'iwr', 'irm', 'invoke-webrequest',
               'invoke-restmethod'}
NET_METHODS = ('.downloadstring', '.downloaddata')
INTERPRETERS = {'sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'python', 'python2', 'python3',
                'perl', 'ruby', 'node', 'php', 'pwsh', 'pwsh.exe', 'powershell', 'powershell.exe',
                'cmd', 'cmd.exe', 'iex', 'invoke-expression', 'eval', 'source', '.'}
RUNNERS = INTERPRETERS | {'start', 'start-process', 'saps', 'msiexec', 'msiexec.exe'}
FILTERS = {'jq', 'head', 'tail', 'grep', 'egrep', 'fgrep', 'rg', 'wc', 'sort', 'uniq', 'less',
           'more', 'cat', 'cut', 'tr', 'column', 'tee', 'awk', 'sed', 'sha256sum', 'shasum',
           'md5sum', 'select-string', 'sls', 'convertfrom-json', 'select-object', 'select',
           'measure-object', 'measure', 'format-list', 'format-table', 'where-object',
           'out-string', 'out-null'}
PREFIXES = {'sudo', 'doas', 'env', 'exec', 'command', 'nohup', 'time'}
SCRIPT_FLAGS = {'-c', '-lc', '-ic', '-command', '/c', '/k'}
RELATIONS = ['DL->PIPE->INTERP', 'DL->SUBST->INTERP', 'DL->FILE->EXEC', 'DL->PIPE->FILTER',
             'DL->FILE']
MAX_DEPTH = 3
MAX_NESTING = 32  # deeper ( … ) / $( … ) nesting yields no relation markers at all
STRUCT_TOKEN = re.compile(r'<[A-Za-z_][A-Za-z0-9_-]*>|\n|' + TOKEN.pattern)


def relations(text):
    found = set()
    _script(_parse(_struct_tokens(text)), found, 0)
    return [m for m in RELATIONS if m in found]


def _struct_tokens(text):
    parts = text.split('`')
    joined = parts[0]
    for i, part in enumerate(parts[1:]):
        joined += (' $( ' if i % 2 == 0 else ' ) ') + part
    return STRUCT_TOKEN.findall(joined)


def _nesting(toks):
    """Deepest ( … ) / $( … ) nesting up to the first unmatched ')', where parsing stops."""
    depth = deepest = 0
    for t in toks:
        if t in ('$(', '('):
            depth += 1; deepest = max(deepest, depth)
        elif t == ')':
            depth -= 1
            if depth < 0:
                break
    return deepest


def _parse(toks):
    """Script = list of pipelines; pipeline = list of commands; command = list of words.
    A word is ('w', text), ('q', inner text), ('r', redirect), ('s', script) for $( … ) or
    ('g', script) for ( … ) and <( … ). Nesting beyond MAX_NESTING parses to an empty script,
    so the recursion stays bounded for any input."""
    if _nesting(toks) > MAX_NESTING:
        return []
    pos = 0

    def script():
        nonlocal pos
        pipes, pipe, cmd = [], [], []
        while pos < len(toks):
            t = toks[pos]; pos += 1
            if t == ')':
                break
            if t.startswith('#'):
                while pos < len(toks) and toks[pos] != '\n':
                    pos += 1
            elif t in ('$(', '('):
                cmd.append(('s' if t == '$(' else 'g', script()))
            elif t == '<' and pos < len(toks) and toks[pos] == '(':
                pos += 1; cmd.append(('g', script()))
            elif t == '|':
                pipe.append(cmd); cmd = []
            elif t in ('||', '&&', ';', '&', '\n'):
                pipe.append(cmd); pipes.append(pipe); pipe, cmd = [], []
            elif t in ('<', '>', '>>') or re.fullmatch(r'\d*>&\d*', t):
                cmd.append(('r', t))
            elif t[:1] in '\'"' and len(t) > 1:
                cmd.append(('q', t[1:-1] if t[-1:] == t[:1] else t[1:]))
            else:
                cmd.append(('w', t))
        pipe.append(cmd); pipes.append(pipe)
        return [[c for c in p if c] for p in pipes if any(p)]

    return script()


def _base(word):
    return re.split(r'[\\/]', word.strip('\'"'))[-1].lower()


def _head(cmd):
    """Index and lowercase name of the command head, skipping sudo/env prefixes."""
    i, prefixed = 0, False
    while i < len(cmd):
        kind, val = cmd[i]
        if kind != 'w':
            return i, None
        name = _base(val)
        if name in PREFIXES or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*=.*', val) or \
                (prefixed and val.startswith('-')):
            prefixed = prefixed or name in PREFIXES
            i += 1; continue
        return i, name
    return i, None


def _download(cmd, depth):
    """None, 'stdout' or ('file', basename) for one command."""
    i, name = _head(cmd)
    words = [v for k, v in cmd if k in ('w', 'q')]
    lower = [w.lower() for w in words]
    target = None
    for k, (kind, val) in enumerate(cmd):
        if kind == 'r' and val in ('>', '>>') and k + 1 < len(cmd):
            target = _base(cmd[k + 1][1]) if cmd[k + 1][0] in ('w', 'q') else None
    if name in DOWNLOADERS:
        args = [v for k, v in cmd[i + 1:] if k in ('w', 'q')]
        if name.startswith('wget') and any(a.startswith('--post-') for a in args):
            return None  # upload, not a download
        out = _output_file(name, args)
        if out is None and target is not None:
            out = target
        return 'stdout' if out is None else ('file', out)
    if any(w.startswith(NET_METHODS) for w in lower):
        return 'stdout' if target is None else ('file', target)
    if i < len(cmd) and cmd[i][0] in ('g', 's') and depth < MAX_DEPTH and \
            _emits(cmd[i][1], depth + 1):
        return 'stdout'
    return None


def _output_file(name, args):
    url = next((a for a in args if URL.match(a)), '')
    remote = _base(url.split('?')[0]) if url else 'remote'
    if name.startswith('curl'):
        for k, a in enumerate(args):
            if a in ('-o', '--output') and k + 1 < len(args):
                return _base(args[k + 1])
            if a in ('-O', '--remote-name', '--remote-name-all'):
                return remote
            if re.fullmatch(r'-[A-Za-z]+', a) and ('o' in a or 'O' in a):
                return _base(args[k + 1]) if a.endswith('o') and k + 1 < len(args) else remote
        return None
    if name.startswith('wget'):
        for k, a in enumerate(args):
            if a.startswith('--output-document='):
                return None if a.endswith('=-') else _base(a.split('=', 1)[1])
            if a == '--output-document' or re.fullmatch(r'-[A-Za-z]*O', a):
                nxt = args[k + 1] if k + 1 < len(args) else '-'
                return None if nxt in ('-', '/dev/stdout') else _base(nxt)
            if re.fullmatch(r'-[A-Za-z]*O-', a):
                return None
        return remote
    for k, a in enumerate(args):  # PowerShell cmdlets: object on stdout unless -OutFile
        if a.lower() == '-outfile' and k + 1 < len(args):
            return _base(args[k + 1])
    return None


def _emits(script, depth):
    """True when the script's output contains downloaded content."""
    return any(_download(c, depth) == 'stdout' for p in script for c in p)


def _nested(cmd, i):
    """Scripts an interpreter receives as text: every quoted argument, plus an unquoted
    tail after -c, -Command or /c (cmd /c curl … && x.bat)."""
    out = [_parse(_struct_tokens(val)) for kind, val in cmd[i + 1:] if kind == 'q']
    rest = cmd[i + 1:]
    for k, (kind, val) in enumerate(rest):
        if kind == 'w' and val.lower() in SCRIPT_FLAGS:
            if k + 1 < len(rest) and rest[k + 1][0] == 'w':
                out.append([[rest[k + 1:]]])
            break
    return out


def _script(script, found, depth):
    if depth > MAX_DEPTH:
        return
    files, executed = set(), set()
    for pipe in script:
        for n, cmd in enumerate(pipe):
            i, name = _head(cmd)
            dl = _download(cmd, depth)
            if dl == 'stdout':
                later = [_head(c)[1] for c in pipe[n + 1:]]
                if any(h in INTERPRETERS for h in later):
                    found.add('DL->PIPE->INTERP')
                elif later and all(h in FILTERS for h in later):
                    found.add('DL->PIPE->FILTER')
            elif dl is not None:
                files.add(dl[1])
            if i < len(cmd) and cmd[i][0] == 's' and _emits(cmd[i][1], depth + 1):
                found.add('DL->SUBST->INTERP')  # $(download) in command position runs it
            if name in INTERPRETERS:
                for kind, val in cmd[i + 1:]:
                    if kind in ('g', 's') and _emits(val, depth + 1):
                        found.add('DL->SUBST->INTERP')
                    elif kind == 'w' and val.lower().startswith(NET_METHODS):
                        found.add('DL->SUBST->INTERP')
            if files and name is not None and dl is None:
                args = {_base(v) for k, v in cmd[i + 1:] if k in ('w', 'q')}
                hit = ({name} & files) | (files & args if name in RUNNERS else set())
                if hit:
                    executed |= hit; found.add('DL->FILE->EXEC')
            for kind, val in cmd:
                if kind in ('g', 's'):
                    _script(val, found, depth + 1)
            if name in INTERPRETERS:
                for inner in _nested(cmd, i):
                    _script(inner, found, depth + 1)
    if files - executed:
        found.add('DL->FILE')  # only for downloaded files this script never runs
