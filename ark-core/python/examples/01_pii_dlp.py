# SPDX-License-Identifier: MIT OR Apache-2.0
"""PII and DLP with the native L1 rules: no model files, no downloads.

`scan` returns one result per category with its evidence spans (UTF-8 byte and
character offsets into the original text), so you can redact, block or log.
`rules` switches single rules off by their stable id (see the L1 rule catalog).

Run: python 01_pii_dlp.py
"""
from patronus_ark_core import Scanner

TEXT = (
    "Hi, I'm Jane Doe. Reach me at jane.doe@example.com or +49 30 901820.\n"
    "Refund to IBAN DE89 3704 0044 0532 0130 00.\n"
    "DATABASE_URL=postgres://app:Xk9#mP2vQ7rL@db.internal:5432/prod"
)

# Build once, reuse for every call. Every key is optional.
scanner = Scanner({"categories": ["pii", "dlp"]})
report = scanner.scan(TEXT)
for result in report["native"]:
    print(f"{result['category']:<4} class={result['class_name']:<18} "
          f"confidence={result['confidence']:.2f}")
    for span in result["evidence_spans"]:
        print(f"     {span['label']:<22} chars {span['start_char']:>3}..{span['end_char']:<3} "
              f"{span['text']!r}")

# Redact every PII span, back to front so earlier offsets stay valid.
redacted = TEXT
pii = [s for r in report["native"] if r["category"] == "pii" for s in r["evidence_spans"]]
for span in sorted(pii, key=lambda s: s["start_char"], reverse=True):
    redacted = redacted[:span["start_char"]] + f"<{span['label']}>" + redacted[span["end_char"]:]
print(f"\n{redacted}\n")

# Turn a single rule off by its id, for example e-mail addresses.
scanner = Scanner({"categories": ["pii", "dlp"], "rules": {"pii_email": False}})
spans = sum(len(r["evidence_spans"]) for r in scanner.scan(TEXT)["native"])
print(f"without pii_email: {spans} spans")

# A tool output: scan it for DLP only, with the same scanner.
report = scanner.scan("build ok, 12 tests passed", categories=["dlp"])
print(f"tool output: {sum(len(r['evidence_spans']) for r in report['native'])} spans")
