# DLP external content goldens: document-label and evidence-span contract 0.1.8

This contract defines how predictions attach to document labels and which part of a document is
scored. It applies to the external content goldens of the DLP scoreboard
(`scripts/l1_dlp/external_content.py`, `scripts/l1_dlp/scoreboard.py`). The same rules apply to
later document classes (HR, legal, M&A, export control) once they have external Gold. It extends
the evidence tier "External derived content label" of
[`pii-dlp-benchmark-contract-0.1.6.md`](pii-dlp-benchmark-contract-0.1.6.md) and replaces the
scoring of the former `scripts/measure_external_dlp_runtime.py`.

## Sources

Both sources are admitted in `python/patronus_ark/benchmark_data/external_dlp/manifest.json` and
pinned there (commit and license SHA-256, archive SHA-256 and published MD5). The normalized rows
are pinned again by SHA-256 in `external_content.py`. No raw text is in the repository.

| Corpus | Rows | Document labels | Evidence-span Gold |
|---|---|---|---|
| `gitleaks-go-source-v8` (MIT, `b58d3f1…`) | 214 `.go` + 13 `.md` files | `.go`: `content.source_code`; `.md`: none | none |
| `schemapile-perm-sql-v1` (permissive subset) | 10 `.sql` files | `content.sql` | 250 statements |

The component is **dev only**. gitleaks ships secret rules and test values, so it is neither
neutral code nor secret Gold, and it never enters the holdout. The scoreboard refuses an
`external/` directory in a holdout split.

## Row schema

Each row is one whole source file (`text` in code points):

| Field | Meaning |
|---|---|
| `document_labels` | Gold classes of the document (entity ids from `research/dlp/entity_map.yaml`) |
| `judged` | Classes whose document labels are exhaustive for this row. A judged class that is missing from `document_labels` is a negative. |
| `span_judged` | Classes whose evidence spans are exhaustive inside `scope` |
| `scope` | `[start, end)`: the part of the document the Gold covers |
| `entities` | Gold evidence spans `{start, end, entity, label}` |

| Rows | `judged` | `span_judged` | `scope` |
|---|---|---|---|
| gitleaks `.go` | `content.source_code`, `content.sql` | none | whole file |
| gitleaks `.md` | `content.source_code` | none | whole file |
| SchemaPile `.sql` | `content.sql` | `content.sql` | whole file, or up to the end of the last selected statement in the file where the 250-statement cap stops |

The Markdown files are not judged for SQL, and the SQL files are not judged for source code. The
manifest only states these pairs; a `.sql` file is arguably code, and Markdown may quote SQL.

## SQL evidence spans

A Gold statement is the text of a lexically terminated statement from its first non-whitespace
character up to and including the terminating `;`. Semicolons in quotes, identifiers and comments
do not end a statement. Leading comments belong to the statement, which matches the span of
`dlp_sql_statement`. MySQL conditional comments (`/*!40101 SET NAMES utf8 */;`) are executed by
MySQL and count as statements. Trailing text without `;` is not Gold, but it is in scope.
Statements are taken in archive member order, then in offset order, until 250 are selected.

## Attach

1. A predicted span has the classes of its `entities` (ARK: from the `ark` mapping of the entity
   map; baselines: from their mapped entities). A span without entities has the class of its engine
   `group` (`dlp.content.sql` → `content.sql`).
2. A span belongs to a row if it intersects that row's `scope`. An empty span belongs to the row
   if its offset lies inside `scope`. Spans after the scope are counted as `out_of_scope` and not
   scored. Before E12 they were the reason no SchemaPile precision could be reported.
3. A document has a predicted label C if at least one in-scope span of class C exists. This span is
   the evidence span. A `document_labels` field in a prediction row without such a span is counted
   in `labels_without_evidence` and is not credited.
4. A class that a row does not judge is not scored on that row. Its spans are counted as
   `unjudged`. The scoreboard counts only content classes there, not secret spans on the gitleaks
   test files.
5. Spans with identical offsets count once, even if several rules report them
   (`dlp_sql_statement` and `dlp_sql_multiline_statement`).

## Metrics

- **Document level** per class over all rows that judge it, and per corpus: gold, predicted, TP,
  P/R/F1.
- **Span level** per class over the rows that judge its spans: exact P/R/F1 (identical code-point
  offsets) and overlap P/R/F1 (intersection; precision counts predictions that touch a Gold span,
  recall counts Gold spans that a prediction touches), plus `out_of_scope`.
- Content classes are off by default, so the scoreboard predicts the component only in the
  `extended` profile, which enables every opt-in rule.

The gate compares head and base on dev. Like the synthetic content classes, the following checks
are regressions if they lose more than 0.5 pp: `f1.external.document:<class>`,
`f1.external.exact:content.sql` and `f1.external.overlap:content.sql`.

## Measured (ARK 0.1.8, extended profile, at the E12 commit)

| Task | Result |
|---|---|
| `content.source_code` documents (gitleaks) | P 213/216 = 98.6 %, R 213/214 = 99.5 %, F1 **99.1 %** |
| `content.sql` documents (SchemaPile positives, Go negatives) | P 10/12 = 83.3 %, R 10/10 = 100 %, F1 **90.9 %** |
| SchemaPile SQL spans, **exact** | P 198/198 = 100 %, R 198/250 = 79.2 %, F1 **88.4 %** |
| SchemaPile SQL spans, overlap | P 100 %, R 79.2 %, F1 88.4 % |
| SQL spans after the scope (ignored) | 17 |

Errors:

- 42 of the 52 missed statements are MySQL conditional comments (`/*!40101 … */;`). 9 are
  `LOCK`/`UNLOCK TABLES` and 1 is a `USE`. These are recall candidates for M20. A rule that matches
  the conditional comment as a statement must keep the comment-only hard negatives clean.
- Every predicted SQL span on SchemaPile is an exact statement: there is no boundary drift.
- Two Go files (`detect/detect.go`, `sources/git.go`) get a SQL span, which makes them false
  positive SQL documents. Three Markdown files with code-heavy documentation get a source-code span
  (`README.md`, `report_templates/README.md`, `testdata/repos/archives/README.md`).
  `sources/git_test.go` is the missed Go document.

Reproduce on dev data: in the gate, `scoreboard.py gate` scores the component when `DEV/external`
exists. To run it by hand, use `run_ark.py` with `--enable-rule` for every opt-in rule of the entity
map (the `extended` profile):

```bash
python3 scripts/l1_dlp/external_content.py prepare --out DEV/external --sources CACHE/external_sources
cat DEV/external/*.jsonl > ext.jsonl
.venv/bin/python scripts/l1_dlp/run_ark.py --input ext.jsonl --output ext-pred.jsonl --enable-rule RULE …
python3 scripts/l1_dlp/external_content.py score --corpus DEV/external --predictions ext-pred.jsonl
```

## Limits

- This Gold is derived content Gold, not human DLP annotation: file type stands in for the
  document label, and a lexer defines the statement boundary. It shows how document and content
  classes behave, but it is no evidence of secret recall.
- 250 statements from 10 files are a small and skewed sample: one MySQL dump contributes most
  conditional comments. External Gold for logs, dumps, business identifiers and document classes
  is still missing.
