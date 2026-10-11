#!/usr/bin/env bash
# One scheduled L1-PII run: pick a task, let a sandboxed Claude Code session work on it,
# gate the result independently, publish a stacked draft PR or block the task.
set -uo pipefail

ROOT="${ARK_L1_ROOT:-$HOME/ark-l1}"
BIN="$ROOT/bin"
MAX_ROUNDS=3
MODEL="${ARK_L1_MODEL:-claude-opus-5-5}"

mkdir -p "$ROOT/logs" "$ROOT/state"
LOG="$ROOT/logs/$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$LOG") 2>&1
exec 9>"$ROOT/state/run.lock"
flock -n 9 || { echo "another run is active"; exit 0; }
find "$ROOT/logs" -name '*.log' -mtime +30 -delete

echo "== ark-l1 run $(date -u +%FT%TZ)"
"$BIN/ark-l1" next || exit 0
eval "$("$BIN/ark-l1" env)"

feedback=""
for round in $(seq 1 "$MAX_ROUNDS"); do
  echo "== round $round/$MAX_ROUNDS: $TASK_ID on $BRANCH (base $BASE)"
  prompt="$(cat "$BIN/AGENT_PROMPT.md")

## Deine Aufgabe in diesem Lauf
Worktree: $WORKTREE
Branch: $BRANCH (Base: $BASE)

\`\`\`yaml
$TASK_YAML
\`\`\`
$feedback"

  sudo systemd-run --uid="$(id -u)" --gid="$(id -g)" --pipe --wait --collect --quiet \
    --working-directory="$WORKTREE" \
    -p EnvironmentFile="$ROOT/secrets.env" \
    -p NoNewPrivileges=yes \
    -p ProtectSystem=strict \
    -p ProtectHome=read-only \
    -p PrivateTmp=yes \
    -p "ReadWritePaths=-$WORKTREE -$ROOT/repo/.git -$ROOT/target -$ROOT/cache -$HOME/.cargo -$HOME/.rustup -$HOME/.cache -$HOME/.claude -$HOME/.claude.json -$HOME/.local/state" \
    -p "InaccessiblePaths=-$ROOT/holdout -$ROOT/secrets.env -$ROOT/state -$HOME/.config/gh -$HOME/.ssh -$HOME/.bash_history -$HOME/patronus-research-scanner -$HOME/web-census -$HOME/repos" \
    -p RuntimeMaxSec=5400 \
    -p CPUQuota=500% \
    -p MemoryMax=9G \
    -E HOME="$HOME" \
    -E PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
    -E CARGO_TARGET_DIR="$ROOT/target" \
    -E ARK_L1_DEV_DATA="$ROOT/data/dev" \
    -E DISABLE_AUTOUPDATER=1 \
    "$HOME/.local/bin/claude" -p "$prompt" --model "$MODEL" --dangerously-skip-permissions --max-turns 250
  agent_rc=$?
  echo "== agent exit $agent_rc"

  if [ "$agent_rc" -ne 0 ] && [ "$(git -C "$WORKTREE" rev-list --count "$BASE_SHA..HEAD")" = "0" ]; then
    echo "== agent failed without commits; aborting run, task stays selectable"
    "$BIN/ark-l1" abort
    exit 1
  fi

  if "$BIN/ark-l1" gate; then
    "$BIN/ark-l1" publish
    exit 0
  fi
  feedback="
## Gate-Ergebnis der vorherigen Runde (rot) — behebe genau das
$(tail -c 12000 "$ROOT/state/gate-report.md")"
done

"$BIN/ark-l1" block "$TASK_ID" "gate red after $MAX_ROUNDS rounds; log $LOG"
exit 1
