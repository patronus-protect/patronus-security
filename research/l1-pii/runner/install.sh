#!/usr/bin/env bash
# Install the runner from a reviewed checkout. Runs on the VPS as ubuntu.
# The runner is copied, not linked: agent branches cannot change the gate.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HOME/ark-l1"
DLP_ROOT="$HOME/ark-dlp"

mkdir -p "$ROOT"/{bin,state,logs,worktrees,gate,transfer,target,target-gate,gate-home,cache,data/dev,holdout}
mkdir -p "$DLP_ROOT"/{state,logs,worktrees,gate,transfer,cache,data/dev,holdout}
chmod 700 "$ROOT/holdout" "$ROOT/state" "$DLP_ROOT/holdout" "$DLP_ROOT/state"
# Gate builds use their own cargo home; seed it once from the host registry to avoid a full download.
if [ ! -d "$ROOT/gate-home/cargo/registry" ] && [ -d "$HOME/.cargo/registry" ]; then
  mkdir -p "$ROOT/gate-home/cargo" && cp -a "$HOME/.cargo/registry" "$ROOT/gate-home/cargo/"
fi
[ -x "$ROOT/gate-venv/bin/python" ] || python3 -m venv "$ROOT/gate-venv"
"$ROOT/gate-venv/bin/python" -m pip install -q --no-cache-dir -r "$SRC/../../../requirements-test.txt"
# The runner itself gets a venv no sandbox can write to (the gate venv is rebuilt by agent code).
[ -x "$ROOT/runner-venv/bin/python" ] || python3 -m venv "$ROOT/runner-venv"
"$ROOT/runner-venv/bin/python" -m pip install -q --no-cache-dir "PyYAML==6.0.2"
install -m 755 "$SRC/run.sh" "$ROOT/bin/"
sed "1s|.*|#!$ROOT/runner-venv/bin/python|" "$SRC/ark-l1" > "$ROOT/bin/ark-l1"
chmod 755 "$ROOT/bin/ark-l1"
install -m 644 "$SRC/../AGENT_PROMPT.md" "$ROOT/bin/AGENT_PROMPT.md"
install -m 644 "$SRC/../../dlp/AGENT_PROMPT.md" "$ROOT/bin/AGENT_PROMPT.dlp.md"
sudo install -m 644 "$SRC/ark-l1.service" "$SRC/ark-l1.timer" "$SRC/ark-dlp.service" "$SRC/ark-dlp.timer" \
  /etc/systemd/system/
sudo systemctl daemon-reload
gh label create ark-l1 --repo patronus-protect/patronus-security --color 5319e7 \
  --description "Scheduled L1-PII run" --force >/dev/null || echo "label not created (token lacks Issues permission); create it once by hand"
gh label create ark-dlp --repo patronus-protect/patronus-security --color 0e8a16 \
  --description "Scheduled L1-DLP run" --force >/dev/null || echo "label ark-dlp not created; create it once by hand"
[ -f "$ROOT/secrets.env" ] || echo "missing $ROOT/secrets.env (CLAUDE_CODE_OAUTH_TOKEN=...)"
echo "installed; enable with: sudo systemctl enable --now ark-l1.timer ark-dlp.timer"
