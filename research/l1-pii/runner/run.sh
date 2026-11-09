#!/usr/bin/env bash
# One scheduled L1 run (programme pii or dlp): pick a task, let a sandboxed Claude Code session
# work on it, gate the result independently, wait for green GitHub CI, publish a ready stacked PR
# or block the task.
# Usage: run.sh [--program pii|dlp]
# Host settings (units: EnvironmentFile ~/ark-l1/host.env, written by install.sh): ARK_L1_LANE, the
# lane of a programme shared by two hosts (see ark-l1); ARK_L1_WHEN_IDLE, the programme with priority
# on this host: the other programmes start new work only while it is idle.
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
# Hard limit of one agent round. The unit's TimeoutStartSec (24h) must cover the lock wait plus
# MAX_ROUNDS x (agent round + gate) and the CI wait: 3 x (1.5 h + a gate of about 1.5 h) + 1.25 h CI
# is about 10 h for the run itself, and the lock wait can be one such run of the other programme.
# At 4h a second red gate was killed mid-gate and the watchdog dropped the run with all its commits
# (A13, 2026-10-29); 14h still left no room for the lock wait.
AGENT_MAX_SEC=5400
MODEL="${ARK_L1_MODEL:-claude-opus-5-5}"

mkdir -p "$ROOT/logs" "$ROOT/state" "$SHARED/state"
# One lock for all programmes: two agents with MemoryMax=9G do not fit on the VPS.
# A busy lock queues the run instead of dropping the slot: a long run of one programme
# (three rounds of agent, gate and CI wait, up to about ten hours) used to swallow several
# slots of the other. The wait has no limit of its own; the unit's TimeoutStartSec bounds wait
# plus run. systemd starts no second instance while this one waits, so at most one run per
# programme queues, and the programmes alternate. Taken before the log exists.
exec 9>"$SHARED/state/run.lock"
flock -n 9 || { echo "== run lock busy; queued until the other run ends"; flock 9; }
# A second programme on this host (e.g. a DLP lane next to PII) starts a new task only while the
# priority programme's last run found nothing to do; a run in progress (resume) always finishes.
# Its green PRs still land meanwhile: a land-only run merges one or verifies it (one short agent
# round), never a restack, review or task. Otherwise they waited for hours (#265, 2026-11-05).
if [ -n "${ARK_L1_WHEN_IDLE:-}" ] && [ "$ARK_L1_WHEN_IDLE" != "$PROGRAM" ] \
    && [ ! -e "$ROOT/state/current.json" ] && ! "$BIN/ark-l1" --program "$ARK_L1_WHEN_IDLE" idle; then
  if ! "$BIN/ark-l1" --program "$PROGRAM" landable; then
    echo "== $ARK_L1_WHEN_IDLE has work; no $PROGRAM run"
    exit 0
  fi
  echo "== $ARK_L1_WHEN_IDLE has work; land-only $PROGRAM run"
  export ARK_L1_LAND_ONLY=1
fi
LOG="$ROOT/logs/$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$LOG") 2>&1
find "$ROOT/logs" -name '*.log' -mtime +30 -delete
# A full disk kills the gate halfway (the linker dies with a Bus error) and costs a round; the
# debug and release build caches rebuild on demand (release: latency runs, wheels). The check runs
# before every agent round and every gate, not only at the start of the run. Each step needs room
# for its own cache to grow to its peak (a cold agent round filled 33 GB of target/, a cold gate
# 29 GB of target-gate/), less what that cache already holds. A flat 20 GB minimum let a cold agent
# round fill the disk (DLP 20261108T021844Z, round 2). Both caches at their peak do not fit on the
# disk: the other step's cache goes first, the step's own cache only when that is not enough (a
# cold build is slow but cannot fail on space).
MIN_FREE_GB=10
AGENT_CACHE_GB=40
GATE_CACHE_GB=35
free_gb() { df -P -BG "$SHARED" | awk 'NR==2 { sub("G", "", $4); print $4 }'; }
cache_gb() { du -s -BG "$@" 2>/dev/null | awk '{ sub("G", "", $1); s += $1 } END { print s + 0 }'; }
ensure_free_space() {  # $1: what comes next, $2: agent | gate
  local own other peak need
  if [ "$2" = gate ]; then
    own=("$SHARED"/target-gate/{debug,release} "$DLP_ROOT"/target-gate/{debug,release})
    other=("$SHARED"/target/{debug,release,maturin} "$DLP_ROOT"/target/{debug,release,maturin})
    peak=$GATE_CACHE_GB
  else
    own=("$SHARED"/target/{debug,release,maturin} "$DLP_ROOT"/target/{debug,release,maturin})
    other=("$SHARED"/target-gate/{debug,release} "$DLP_ROOT"/target-gate/{debug,release})
    peak=$AGENT_CACHE_GB
  fi
  need=$((peak - $(cache_gb "${own[@]}")))
  [ "$need" -lt "$MIN_FREE_GB" ] && need=$MIN_FREE_GB
  [ "$(free_gb)" -ge "$need" ] && return 0
  echo "== only $(free_gb) GB free before $1 (needs $need GB); removing the other build caches"
  rm -rf "${other[@]}"
  if [ "$(free_gb)" -lt "$need" ]; then
    echo "== only $(free_gb) GB free; removing the build caches of $1 too"
    rm -rf "${own[@]}"
  fi
  echo "== $(free_gb) GB free"
}
ensure_free_space "the run" agent

echo "== ark-l1 $PROGRAM run $(date -u +%FT%TZ)"
"${L1[@]}" next
rc=$?
# CI waits and publishing need no agent memory: the other programme may run meanwhile.
unlock() { flock -u 9; }
relock() { flock -n 9 || { echo "== run lock busy; waiting for the other run before the next round"; flock 9; }; }
if [ "$rc" -eq 11 ]; then
  # The previous run passed the gate but CI or publishing did not finish: retry only that.
  unlock
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
if [ "$TASK_TYPE" = verify ]; then
  # Quiet latency A/B while this run holds the lock; the result reaches the agent through TASK_YAML.
  "${L1[@]}" latency
  eval "$("${L1[@]}" env)"
fi

feedback=""
for round in $(seq 1 "$MAX_ROUNDS"); do
  echo "== round $round/$MAX_ROUNDS: $TASK_ID on $BRANCH (base $BASE)"
  # A person may push to or merge the PR branch of a review/restack run meanwhile; stop at once
  # instead of spending the remaining rounds and gates on a stale head (dlp/114-d01, 2026-11-08).
  "${L1[@]}" stale && exit 1
  ensure_free_space "agent round $round" agent
  # The sandbox kills the agent at AGENT_MAX_SEC; work that is not committed by then is lost
  # and the run is aborted. Tell the agent the clock time so it commits in time.
  deadline="$(date -u -d "+$AGENT_MAX_SEC seconds" +%H:%M)"
  commit_by="$(date -u -d "+$((AGENT_MAX_SEC - 20 * 60)) seconds" +%H:%M)"
  prompt="$(cat "$BIN/$PROMPT_FILE")

## Deine Aufgabe in diesem Lauf
Worktree: $WORKTREE
Branch: $BRANCH (Base: $BASE)

\`\`\`yaml
$TASK_YAML
\`\`\`

## Zeitlimit dieser Runde
Die Sandbox wird um $deadline UTC hart beendet ($((AGENT_MAX_SEC / 60)) Minuten nach Start). Nicht committete
Arbeit geht dann verloren, und der Lauf wird ohne Ergebnis abgebrochen. Committe den Testbereich
(Schritt 2), sobald er steht, und danach jeden Zwischenstand, der baut. Spätestens um $commit_by UTC
committest du alles, auch Unfertiges, und prüfst danach nur noch. Ein rotes Gate kostet nichts: Du bekommst den
Bericht und eine weitere Runde. Die Uhrzeit liefert \`date -u\`; vermeide unnötige Voll-Builds.
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
    -p RuntimeMaxSec="$AGENT_MAX_SEC" \
    -p CPUQuota=500% \
    -p MemoryMax=9G \
    -E HOME="$HOME" \
    -E PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
    -E CARGO_TARGET_DIR="$SHARED/target" \
    -E CARGO_PROFILE_TEST_OPT_LEVEL=1 \
    -E CARGO_PROFILE_DEV_DEBUG=line-tables-only -E CARGO_PROFILE_TEST_DEBUG=line-tables-only \
    -E ARK_L1_DEV_DATA="$ROOT/data/dev" \
    -E DISABLE_AUTOUPDATER=1 \
    "$HOME/.local/bin/claude" -p "$prompt" --model "$MODEL" --dangerously-skip-permissions --max-turns 250
  agent_rc=$?
  echo "== agent exit $agent_rc"
  if [ "$TASK_TYPE" = verify ]; then
    # One round, never gated or published: the runner acts on the agent's verdict file.
    "${L1[@]}" verdict
    exit $?
  fi

  if [ "$agent_rc" -ne 0 ] && [ "$("${L1[@]}" ahead)" = "0" ]; then
    echo "== agent failed without commits; aborting run, task stays selectable"
    "${L1[@]}" abort
    exit 1
  fi

  "${L1[@]}" stale && exit 1
  ensure_free_space "the gate" gate
  if "${L1[@]}" gate; then
    # A PR only for green GitHub CI: red CI goes back to the agent like a red gate.
    unlock
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
    relock
  fi
  feedback="
## Gate-/CI-Ergebnis der vorherigen Runde (rot) — behebe genau das
$(tail -c 12000 "$ROOT/state/gate-report.md")"
done

"${L1[@]}" block "$TASK_ID" "gate or CI red after $MAX_ROUNDS rounds; log $LOG"
exit 1
