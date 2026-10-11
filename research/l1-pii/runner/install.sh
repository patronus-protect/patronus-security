#!/usr/bin/env bash
# Install the runner from a reviewed checkout. Runs on the VPS as ubuntu.
# The runner is copied, not linked: agent branches cannot change the gate.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HOME/ark-l1"

mkdir -p "$ROOT"/{bin,state,logs,worktrees,target,cache,data/dev,holdout}
chmod 700 "$ROOT/holdout" "$ROOT/state"
[ -x "$ROOT/gate-venv/bin/python" ] || python3 -m venv "$ROOT/gate-venv"
"$ROOT/gate-venv/bin/python" -m pip install -q -r "$SRC/../../../requirements-test.txt"
install -m 755 "$SRC/ark-l1" "$SRC/run.sh" "$ROOT/bin/"
install -m 644 "$SRC/../AGENT_PROMPT.md" "$ROOT/bin/AGENT_PROMPT.md"
sudo install -m 644 "$SRC/ark-l1.service" "$SRC/ark-l1.timer" /etc/systemd/system/
sudo systemctl daemon-reload
gh label create ark-l1 --repo patronus-protect/patronus-security --color 5319e7 \
  --description "Scheduled L1-PII run" --force >/dev/null
[ -f "$ROOT/secrets.env" ] || echo "missing $ROOT/secrets.env (CLAUDE_CODE_OAUTH_TOKEN=...)"
echo "installed; enable with: sudo systemctl enable --now ark-l1.timer"
