#!/usr/bin/env bash
# One scheduled L1 run (programme pii or dlp): pick a task, let a sandboxed Claude Code session
# work on it, gate the result independently, wait for green GitHub CI, publish a ready stacked PR
# or block the task.
# Usage: run.sh [--program pii|dlp]
set -uo pipefail

PROGRAM="${ARK_L1_PROGRAM:-pii}"
if [ "${1:-}" = "--program" ]; then PROGRAM="${2:?--program needs a value}"; fi
SHARED="${ARK_L1_ROOT:-$HOME/ark-l1}"
case "$PROGRAM" in
  pii) ROOT="$SHARED" ;;
  dlp) ROOT="$(dirname "$SHARED")/ark-dlp" ;;
  *) echo "unknown programme $PROGRAM"; exit 2 ;;
esac
DLP_ROOT="$(dirname "$SHARED")/ark-dlp"
BIN="$SHARED/bin"
L1=("$BIN/ark-l1" --program "$PROGRAM")
MAX_ROUNDS=3
MODEL="${ARK_L1_MODEL:-claude-opus-5-5}"

mkdir -p "$ROOT/logs" "$ROOT/state" "$SHARED/state"
# One lock for all programmes: two agents with MemoryMax=9G do not fit on the VPS.
# A busy lock queues the run instead of dropping the slot: a long run of one programme
# (three rounds plus CI waits) used to swallow several slots of the other. systemd starts
# no second instance while this one waits, so at most one run per programme queues, and the
# programmes alternate. Taken before the log exists, so a skipped run leaves no log.
LOCK_WAIT=7200
exec 9>"$SHARED/state/run.lock"
flock -w "$LOCK_WAIT" 9 || { echo "another run stayed active for $((LOCK_WAIT / 60)) min; skipping"; exit 0; }
LOG="$ROOT/logs/$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$LOG") 2>&1
find "$ROOT/logs" -name '*.log' -mtime +30 -delete
# A full disk kills the gate halfway and leaves a STALE_RUN; the debug caches rebuild on demand.
MIN_FREE_GB=15
free_gb() { df -P -BG "$SHARED" | awk 'NR==2 { sub("G", "", $4); print $4 }'; }
if [ "$(free_gb)" -lt "$MIN_FREE_GB" ]; then
  echo "== only $(free_gb) GB free; removing debug build caches"
  rm -rf "$SHARED"/target*/debug "$DLP_ROOT"/target*/debug
  echo "== $(free_gb) GB free"
fi

echo "== ark-l1 $PROGRAM run $(date -u +%FT%TZ)"
"${L1[@]}" next
rc=$?
if [ "$rc" -eq 11 ]; then
  # The previous run passed the gate but CI or publishing did not finish: retry only that.
  "${L1[@]}" ci
  ci_rc=$?
  if [ "$ci_rc" -eq 1 ]; then
    "${L1[@]}" block "$("${L1[@]}" env | sed -n 's/^TASK_ID=//p' | tr -d "'")" "GitHub CI red after a resumed run; log $LOG"
    exit 1
  fi
  [ "$ci_rc" -eq 0 ] && "${L1[@]}" publish && exit 0
  echo "== CI or publish not done; the run stays pending"
  exit 1
fi
[ "$rc" -eq 10 ] && exit 0
[ "$rc" -eq 0 ] || exit 1
eval "$("${L1[@]}" env)"

feedback=""
for round in $(seq 1 "$MAX_ROUNDS"); do
  echo "== round $round/$MAX_ROUNDS: $TASK_ID on $BRANCH (base $BASE)"
  prompt="$(cat "$BIN/$PROMPT_FILE")

## Deine Aufgabe in diesem Lauf
Worktree: $WORKTREE
Branch: $BRANCH (Base: $BASE)

\`\`\`yaml
$TASK_YAML
\`\`\`
$feedback"

  sudo systemd-run --uid="$(id -u)" --gid="$(id -g)" --pipe --wait --collect --quiet \
    --working-directory="$WORKTREE" \
    -p EnvironmentFile="$SHARED/secrets.env" \
    -p NoNewPrivileges=yes \
    -p ProtectSystem=strict \
    -p ProtectHome=read-only \
    -p PrivateTmp=yes \
    -p "ReadWritePaths=-$WORKTREE -$SHARED/target -$HOME/.cargo -$HOME/.rustup -$HOME/.cache -$HOME/.claude -$HOME/.claude.json -$HOME/.local/state" \
    -p "InaccessiblePaths=-$SHARED/holdout -$SHARED/secrets.env -$SHARED/state -$SHARED/cache -$SHARED/gate -$SHARED/transfer -$DLP_ROOT/holdout -$DLP_ROOT/state -$DLP_ROOT/cache -$DLP_ROOT/gate -$DLP_ROOT/transfer -$HOME/.config/gh -$HOME/.ssh -$HOME/.bash_history -$HOME/patronus-research-scanner -$HOME/web-census -$HOME/repos" \
    -p RuntimeMaxSec=5400 \
    -p CPUQuota=500% \
    -p MemoryMax=9G \
    -E HOME="$HOME" \
    -E PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
    -E CARGO_TARGET_DIR="$SHARED/target" \
    -E ARK_L1_DEV_DATA="$ROOT/data/dev" \
    -E DISABLE_AUTOUPDATER=1 \
    "$HOME/.local/bin/claude" -p "$prompt" --model "$MODEL" --dangerously-skip-permissions --max-turns 250
  agent_rc=$?
  echo "== agent exit $agent_rc"

  if [ "$agent_rc" -ne 0 ] && [ "$("${L1[@]}" ahead)" = "0" ]; then
    echo "== agent failed without commits; aborting run, task stays selectable"
    "${L1[@]}" abort
    exit 1
  fi

  if "${L1[@]}" gate; then
    # A PR only for green GitHub CI: red CI goes back to the agent like a red gate.
    "${L1[@]}" ci
    ci_rc=$?
    if [ "$ci_rc" -eq 0 ]; then
      "${L1[@]}" publish && exit 0
      echo "== publish failed; the next run retries it"
      exit 1
    fi
    if [ "$ci_rc" -ne 1 ]; then
      echo "== no CI verdict; the next run waits for it again"
      exit 1
    fi
  fi
  feedback="
## Gate-/CI-Ergebnis der vorherigen Runde (rot) — behebe genau das
$(tail -c 12000 "$ROOT/state/gate-report.md")"
done

"${L1[@]}" block "$TASK_ID" "gate or CI red after $MAX_ROUNDS rounds; log $LOG"
exit 1
