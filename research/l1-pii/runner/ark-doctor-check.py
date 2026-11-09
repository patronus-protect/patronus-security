#!/usr/bin/env python3
"""Detect a stuck ARK runner programme. Prints a diagnosis and exits 1 when stuck, 0 otherwise.

Stuck means one of:
  - no progress (LANDED / AUTO_MERGED / new PR, or a finished review or verify run, which print the
    PR= line too) for STALL_HOURS while runs keep happening and the programme is not idle
    (NOTHING_TO_DO / PAUSED);
  - the same error line in REPEAT_LIMIT or more of the last runs;
  - an own open PR (of this host's lane) that has not changed for PR_STALE_HOURS, unless the run in
    progress works on it, or it waits behind a RESTACK/REVIEW/VERIFY run (PR_STALE_HOURS from that
    run's end).
"""
import datetime as dt
import json
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

PROGRAM = sys.argv[1]                      # pii | dlp
HOME = Path.home()
LOGS = HOME / ("ark-l1/logs" if PROGRAM == "pii" else "ark-dlp/logs")
PREFIX = "l1/" if PROGRAM == "pii" else "dlp/"
REPO = "patronus-protect/patronus-security"
STALL_HOURS = 8
PR_STALE_HOURS = 5
REPEAT_LIMIT = 3
RECENT = 8
RUN_MAX_HOURS = 24                         # TimeoutStartSec of ark-l1/ark-dlp.service
# The longest silent stretch of a healthy run: the gate prints its report only at the end, and its
# cargo test step alone may take up to 6 h (GATE_TEST_MAX_SEC); an agent round stops at 1.5 h.
ACTIVE_QUIET_HOURS = 6
CURRENT = HOME / ("ark-l1/state" if PROGRAM == "pii" else "ark-dlp/state") / "current.json"
UNIT = "ark-l1.service" if PROGRAM == "pii" else "ark-dlp.service"

PROGRESS = re.compile(r"LANDED=#\d+|AUTO_MERGED=#\d+|^PR=https", re.M)
IDLE = re.compile(r"RESULT=(NOTHING_TO_DO|PAUSED|NO_BACKLOG)")
ERRORS = re.compile(r"^(PUBLISH_ERROR=.*|WATCHDOG=.*|STALE_RUN=.*|RESTACK_PUSH_ERROR=.*|BLOCKED=.*|"
                    r"REBASE_CONFLICT.*|LAND_WAIT=.*merge failed.*|CI=red.*|CI=timeout.*|VERIFY_ERROR=.*|"
                    r"Traceback.*|.*Error:.*)$", re.M)

now = dt.datetime.now(dt.timezone.utc)
logs = sorted(LOGS.glob("*.log"))
findings = []


def started(p: Path) -> dt.datetime:
    # Log names start with the run timestamp; some carry a suffix (e.g. "-t06-fixup").
    return dt.datetime.strptime(p.stem[:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)


def last_write(p: Path) -> dt.datetime:
    return dt.datetime.fromtimestamp(p.stat().st_mtime, dt.timezone.utc)


def active_run() -> dict:
    """current.json of the run in progress: the unit is running and the run is younger than
    RUN_MAX_HOURS (the unit's start timeout). A RESTACK run with several gate rounds leaves its PR
    unchanged for longer than PR_STALE_HOURS while it works. Empty when no run is in progress."""
    try:
        cur = json.loads(CURRENT.read_text())
        begun = dt.datetime.fromisoformat(cur["started"])
    except (OSError, ValueError, KeyError):
        return {}
    state = subprocess.run(["systemctl", "is-active", UNIT], capture_output=True, text=True).stdout.strip()
    if state not in ("active", "activating") or now - begun > dt.timedelta(hours=RUN_MAX_HOURS):
        return {}
    return cur


# Runs that work on an open PR. They take the open PRs one per run (the run lock), so while one runs
# the other PRs of the lane wait in line: on 2026-11-05 #266 raised this alarm while the RESTACK of
# #265, which had to land first, was in its CI wait.
PR_RUN = re.compile(r"^(RESTACK|REVIEW|VERIFY):")


# A run can take longer than STALL_HOURS (several gate rounds), so a log counts when it was
# started or last written inside the window; otherwise its PR=/LANDED= line is missed.
window = [p for p in logs if max(started(p), last_write(p)) > now - dt.timedelta(hours=STALL_HOURS)]
# The run in progress has not had its chance to land yet: one healthy multi-round run alone raised
# this alarm three times on 2026-10-28. It counts again once its log has been quiet for
# ACTIVE_QUIET_HOURS, i.e. when it really hangs. Meanwhile one finished run without progress (a task
# blocked once) is no stall yet: it takes two.
state = subprocess.run(["systemctl", "is-active", UNIT], capture_output=True, text=True).stdout.strip()


def unit_started() -> dt.datetime | None:
    """Start of the unit's current activation. run.sh opens its log only once it holds the run
    lock, so the newest log belongs to this activation only if it began after the unit started."""
    out = subprocess.run(["systemctl", "show", UNIT, "-p", "ExecMainStartTimestamp", "--value"],
                         capture_output=True, text=True).stdout.strip()
    parts = out.split()  # "Fri 2026-11-06 06:25:02 UTC"
    if len(parts) != 4 or parts[3] != "UTC":
        return None
    try:
        return dt.datetime.strptime(" ".join(parts[1:3]), "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None


# A unit queued on the run lock is "activating" without a log of its own: on 2026-11-06 the finished
# P10 log (PR=#287) was taken for the run in progress and dropped, which raised a false STUCK.
unit_begun = unit_started()
if window and state in ("active", "activating") \
        and (unit_begun is None or started(window[-1]) >= unit_begun - dt.timedelta(minutes=1)) \
        and now - last_write(window[-1]) < dt.timedelta(hours=ACTIVE_QUIET_HOURS):
    window = window[:-1]
    min_runs = 2
else:
    min_runs = 1
texts = {p: p.read_text(errors="replace") for p in window}
if len(window) >= min_runs and not any(PROGRESS.search(t) for t in texts.values()) \
        and not any(IDLE.search(t) for t in texts.values()) and started(logs[0]) < now - dt.timedelta(hours=STALL_HOURS):
    findings.append(f"no LANDED/AUTO_MERGED/new PR in {len(window)} runs over the last {STALL_HOURS} h")

# Errors from before the last progress (a merge, a new PR) are history, not a loop: a long task run
# after a fixed loop would otherwise keep the old errors among the last RECENT logs for hours.
recent_logs = logs[-RECENT:]
last_progress = max((i for i, p in enumerate(recent_logs) if PROGRESS.search(p.read_text(errors="replace"))),
                    default=0)
recent = [p.read_text(errors="replace") for p in recent_logs[last_progress:]]
# A fresh task run (TASK_ID=, not a resume) after an abort or a block starts over: an error that the
# newest fresh run (and the resumes after it) does not repeat belongs to the dropped run, not a loop.
last_fresh = max((i for i, t in enumerate(recent) if re.search(r"^TASK_ID=", t, re.M)), default=0)
counts = Counter()
current = set()
for i, t in enumerate(recent):
    for line in set(m.group(1)[:160] for m in ERRORS.finditer(t)):
        key = re.sub(r"[0-9a-f]{12,40}", "<sha>", line)
        counts[key] += 1
        if i >= last_fresh:
            current.add(key)
for line, n in counts.items():
    if n >= REPEAT_LIMIT and line in current:
        findings.append(f"same error in {n} of the last {len(recent)} runs: {line}")

def gh_retry(cmd: list[str], attempts: int = 3) -> str:
    """Run a gh command, retrying transient API/network errors; raise on the last failure."""
    for i in range(attempts):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout
        if i < attempts - 1:
            time.sleep(10 * (i + 1))
    raise subprocess.CalledProcessError(r.returncode, cmd, r.stdout, f"{r.stderr.strip()[-200:]}")


try:
    prs = json.loads(gh_retry(
        ["gh", "pr", "list", "--repo", REPO, "--state", "open", "--limit", "100",
         "--json", "number,headRefName,updatedAt,author,mergeable"]))
    login = subprocess.run(["gh", "api", "user", "--jq", ".login"], capture_output=True, text=True).stdout.strip()
    # With lanes (ARK_L1_LANE) the other host's PRs are not this host's to repair.
    own = set(subprocess.run([str(HOME / "ark-l1/bin/ark-l1"), "--program", PROGRAM, "own",
                              *[pr["headRefName"] for pr in prs]],
                             capture_output=True, text=True, check=True).stdout.split())
    run = active_run()
    # A PR waiting behind open-PR runs counts as stale from the end of the last one, so the next run
    # has PR_STALE_HOURS to take it. Backlog task runs give no such grace: next() takes open PRs first.
    last_task = re.findall(r"^TASK_ID=(\S+)", logs[-1].read_text(errors="replace") if logs else "", re.M)
    queued_since = last_write(logs[-1]) if logs and last_task and PR_RUN.match(last_task[-1]) else None
    for pr in prs:
        if pr["headRefName"] not in own or (pr.get("author") or {}).get("login") != login:
            continue
        if pr["headRefName"] == run.get("branch"):
            continue  # the running task (e.g. a RESTACK) pushes the branch only after its gate
        if PR_RUN.match(run.get("task_id", "")):
            continue  # queued behind the open-PR run in progress
        changed = dt.datetime.fromisoformat(pr["updatedAt"].replace("Z", "+00:00"))
        age = now - max(changed, queued_since or changed)
        if age > dt.timedelta(hours=PR_STALE_HOURS):
            findings.append(f"PR #{pr['number']} {pr['headRefName']} unchanged for {age.total_seconds() / 3600:.1f} h")
except subprocess.CalledProcessError as err:
    findings.append(f"gh not usable: {err} {err.stderr or ''}".strip())
except ValueError as err:
    findings.append(f"gh not usable: {err}")

if findings:
    print(f"STUCK {PROGRAM}:")
    for f in findings:
        print(f"- {f}")
    print("Recent runs:")
    for p in logs[-RECENT:]:
        marks = re.findall(r"TASK_ID=\S+|RESULT=\S+|LANDED=#\d+|WATCHDOG=\S+|STALE_RUN=\S+|PUBLISH_ERROR=.{0,80}|CI=\w+",
                           p.read_text(errors="replace"))
        print(f"  {p.name}: {' '.join(marks)[:300]}")
    sys.exit(1)
print(f"OK {PROGRAM}")
