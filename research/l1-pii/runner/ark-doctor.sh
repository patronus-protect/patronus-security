#!/usr/bin/env bash
# Health check for the ARK runner programme on this VPS (ark-doctor.timer, every 20 min).
# When the check reports the programme stuck, a Claude "doctor" run diagnoses and repairs it.
set -uo pipefail
PROGRAM="${1:?pii|dlp|threat}"
BASE="$HOME/ark-l1"
OUT="$BASE/doctor"
mkdir -p "$OUT"
exec 9>"$OUT/doctor-$PROGRAM.lock"
flock -n 9 || { echo "doctor already running"; exit 0; }

ts="$(date -u +%Y%m%dT%H%M%SZ)"
diag="$("$BASE/runner-venv/bin/python" "$BASE/bin/ark-doctor-check.py" "$PROGRAM")" && { echo "$diag"; exit 0; }
echo "$diag"

# At most one doctor run per COOLDOWN, so a problem it cannot fix does not burn the quota.
COOLDOWN_MIN=90
last="$(ls -t "$OUT"/"$PROGRAM"-*.log 2>/dev/null | head -1)"
if [ -n "$last" ] && [ "$(( ($(date +%s) - $(stat -c %Y "$last")) / 60 ))" -lt "$COOLDOWN_MIN" ]; then
  echo "doctor ran $(basename "$last") less than $COOLDOWN_MIN min ago; waiting"
  exit 0
fi

set -a; . "$BASE/secrets.env"; set +a
prompt="$(cat "$BASE/bin/DOCTOR_PROMPT.md")

## Diagnosis ($ts, programme $PROGRAM)
$diag"
log="$OUT/$PROGRAM-$ts.log"
cd "$BASE" && timeout 90m "$HOME/.local/bin/claude" -p "$prompt" --model "${ARK_L1_MODEL:-claude-opus-5-5}" \
  --dangerously-skip-permissions --max-turns 200 >"$log" 2>&1
echo "doctor exit $? -> $log"
