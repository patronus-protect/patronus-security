#!/usr/bin/env python3
"""Reject plaintext provider tokens added by any commit in base..head.

GitHub push protection scans every pushed commit and rejects the whole branch for one literal
token, even a synthetic one (T06, 2026-10-19). Goldens therefore keep secret values as generator
recipes and tests assemble them at test time (research/dlp/README.md, "Secret-sichere Goldens").
This check approximates push protection: gitleaks' provider rules (not its entropy-based
generic-api-key) plus patterns GitHub flags that gitleaks does not know. It prints rule, commit,
file and line, never the value.

Usage: secret_check.py --repo DIR --base SHA --head SHA [--gitleaks PATH]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# Entropy-based rules: they fire on ordinary identifiers and push protection does not block them.
IGNORED_GITLEAKS_RULES = {"generic-api-key"}

EXTRA_PATTERNS = {
    "xai-api-key": re.compile(r"\bxai-[A-Za-z0-9]{70,}"),
    "google-oauth-client-id": re.compile(r"\b[0-9]{6,}-[a-z0-9]{32}\.apps\.googleusercontent\.com\b"),
    "google-oauth-client-secret": re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{28}\b"),
    "huggingface-token": re.compile(r"\bhf_[A-Za-z0-9]{34}\b"),
    "openai-api-key": re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}"),
    "anthropic-api-key": re.compile(r"\bsk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{80,}"),
}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, text=True,
                          capture_output=True, errors="replace").stdout


def gitleaks_hits(gitleaks: Path, repo: Path, base: str, head: str) -> set[tuple[str, str, str, int]]:
    proc = subprocess.run(
        [str(gitleaks), "git", str(repo), f"--log-opts={base}..{head}", "--no-banner", "--redact=100",
         "--report-format", "json", "--report-path", "-", "--exit-code", "0", "--log-level", "error"],
        text=True, capture_output=True,
    )
    if proc.returncode != 0:
        sys.exit(f"gitleaks failed ({proc.returncode}): {proc.stderr.strip()[-2000:]}")
    return {(x["RuleID"], x["Commit"][:12], x["File"], int(x["StartLine"]))
            for x in json.loads(proc.stdout or "[]") if x["RuleID"] not in IGNORED_GITLEAKS_RULES}


def pattern_hits(repo: Path, base: str, head: str) -> set[tuple[str, str, str, int]]:
    hits = set()
    commit = path = ""
    line_no = 0
    log = git(repo, "log", "-p", "--no-ext-diff", "--no-color", "--unified=0", "--format=commit %H",
              f"{base}..{head}")
    for line in log.splitlines():
        if line.startswith("commit ") and len(line) == 47:
            commit = line[7:19]
        elif line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else line[4:]
        elif line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            line_no = int(match.group(1)) if match else 0
        elif line.startswith("+"):
            for rule, pattern in EXTRA_PATTERNS.items():
                if pattern.search(line):
                    hits.add((rule, commit, path, line_no))
            line_no += 1
    return hits


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--gitleaks", type=Path, default=None)
    args = parser.parse_args(argv)
    hits = pattern_hits(args.repo, args.base, args.head)
    if args.gitleaks is not None and args.gitleaks.exists():
        hits |= gitleaks_hits(args.gitleaks, args.repo, args.base, args.head)
    else:
        print("WARN: gitleaks not available; only the built-in patterns ran")
    for rule, commit, path, line in sorted(hits, key=lambda h: (h[2], h[3], h[0])):
        print(f"{rule}: {commit} {path}:{line}")
    if hits:
        print(f"{len(hits)} plaintext token(s) would make GitHub push protection reject the branch. "
              "Store golden values as generator recipes and assemble test values at test time from "
              "synthetic pieces (concat!/format!/join), in every commit of the branch.")
        return 1
    print("no plaintext provider tokens")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
