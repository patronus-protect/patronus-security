# Project rules

- **English only on GitHub:** pull request titles and descriptions, commit messages, review
  comments and issue text are always written in English. This applies to interactive sessions and to
  the scheduled VPS runner agents. Code comments and docs keep the language of the surrounding file.

# Code rules

These rules apply to every change, from interactive sessions and from the scheduled VPS runner
agents alike. A change that breaks one of them is not done.

- **Tests:** new behaviour ships with at least unit tests, in the module or in the matching
  `rust/tests/` file. A bug fix starts with a regression test that fails without the fix.
- **No dead code:** remove what your change leaves unused — functions, parameters, fields,
  variants, feature branches, unreachable paths, fixtures and docs that nothing references.
- **No obsolete or superfluous code:** remove wrappers that only forward, shims and API variants
  that a new one supersedes (search the whole workspace, the Python bindings and the docs for
  callers first), and comments or docs that no longer hold.
  - **Duplicated logic counts as superfluous.** Before adding a function, look for one that already
    does it. When two places do the same thing, keep one shared implementation instead of adding
    a second copy. A diff that only adds lines where existing code could be reused, merged or
    replaced is not done.
- **L1 must be very fast.** L1 and everything on the way to it (request parsing, text preparation
  and normalization, prefilters, rule matching) is the hot path:
  - compile regexes and automata once (`OnceLock`/`LazyLock`), never per call or per input;
  - give every new rule a literal or structural prefilter (keywords, Aho-Corasick, the `RuleMeta`
    gates) and keep its regex linear and bounded;
  - no avoidable allocation, cloning or re-scan of the whole text inside per-match loops; reuse the
    prepared views (`NativeText`, `MatchText`);
  - no I/O, network or remote model calls and no locks held across a scan on L1; the one
    model-backed L1 detector (`shell_command`, a TF-IDF logistic regression loaded once) stays a
    single in-memory pass, and no further L1 model is added without a measured reason;
  - measure: state the latency effect of an L1 change in the PR (`scripts/l1_dlp/latency.py`,
    `scripts/benchmark_injection_l1.py`, the CI `native-throughput` job). A measurable slowdown
    needs a reason, and the DLP budget (100 KiB p95 ≤ 10 ms) must hold.
