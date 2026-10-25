"""PII golden schema v2 (E10): rule ids, carriers, difficulty tags, known gaps, coverage."""

import json
import runpy
import unittest
from collections import Counter

from patronus_ark import benchmark


TAGS = ("no_context", "structured", "obfuscated", "ocr")
CARRIERS = {"line", "prose", "json", "yaml", "xml", "csv", "kv", "table"}
STRUCTURED_CARRIERS = {"json", "yaml", "xml", "csv", "kv", "table"}
LANGUAGES = ("de", "en")
MIN_PER_LANGUAGE = 5
# Opt-in PII modes a row may name (K03); rows without `pii_mode` run in `strict`.
SCORED_MODES = ("balanced", "recall")
V2_FIELDS = (
    "id", "suite", "schema_version", "language", "case_type", "target_label", "rule_id",
    "carrier", "tags", "known_gap",
)
# The rule fixture lists every registered rule; rust/tests/l1_bilingual_rules.rs ties it
# to PII_PATTERNS.
RULE_FIXTURE = benchmark.DATA_DIR.parents[2] / "ark-core" / "tests" / "fixtures" / "l1_bilingual_rules.json"


def load_rows():
    path = benchmark.DATA_DIR / "pii_l1.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()]


def all_rule_ids():
    """Every pii_* rule in PII_PATTERNS."""
    cases = json.loads(RULE_FIXTURE.read_text())
    return {case["rule_id"] for case in cases if case["category"] == "pii"}


class PiiGoldenSchemaV2Tests(unittest.TestCase):
    def test_generator_declares_the_schema_constants(self):
        namespace = runpy.run_path(str(benchmark.DATA_DIR / "generate_l1_goldens.py"))
        self.assertEqual(namespace["PII_SCHEMA_VERSION"], 2)
        self.assertEqual(namespace["PII_TAGS"], TAGS)
        self.assertEqual(set(namespace["PII_CARRIERS"]), CARRIERS)
        self.assertEqual(set(namespace["PII_STRUCTURED_CARRIERS"]), STRUCTURED_CARRIERS)
        self.assertEqual(namespace["PII_MIN_PER_LANGUAGE"], MIN_PER_LANGUAGE)
        self.assertEqual(namespace["PII_MODES"], ("strict", *SCORED_MODES))

    def test_every_row_carries_the_v2_fields_first(self):
        known_rules = all_rule_ids()
        self.assertGreaterEqual(len(known_rules), 37)
        for row in load_rows():
            self.assertEqual(tuple(row)[: len(V2_FIELDS)], V2_FIELDS, row["id"])
            self.assertEqual(row["schema_version"], 2, row["id"])
            self.assertIn(row["rule_id"], known_rules, row["id"])
            self.assertIn(row["carrier"], CARRIERS, row["id"])
            self.assertIs(type(row["known_gap"]), bool, row["id"])
            self.assertEqual(row["tags"], [tag for tag in TAGS if tag in row["tags"]], row["id"])
            self.assertEqual(len(set(row["tags"])), len(row["tags"]), row["id"])

    def test_pii_mode_follows_known_gap_and_names_a_scored_mode(self):
        rows = load_rows()
        for row in rows:
            if "pii_mode" in row:
                self.assertEqual(tuple(row).index("pii_mode"), len(V2_FIELDS), row["id"])
                self.assertIn(row["pii_mode"], SCORED_MODES, row["id"])
                self.assertFalse(row["known_gap"], row["id"])
        # K03: the context engine has gated positives and hard negatives per language in balanced.
        counts = Counter(
            (row["language"], row["case_type"]) for row in rows if row.get("pii_mode") == "balanced"
        )
        for language in LANGUAGES:
            for case_type in ("positive", "hard_negative"):
                self.assertGreaterEqual(counts[(language, case_type)], MIN_PER_LANGUAGE, (language, case_type))

    def test_only_positives_can_be_known_gaps(self):
        for row in load_rows():
            if row["known_gap"]:
                self.assertEqual(row["case_type"], "positive", row["id"])

    def test_structured_tag_follows_the_carrier(self):
        for row in load_rows():
            self.assertEqual("structured" in row["tags"], row["carrier"] in STRUCTURED_CARRIERS, row["id"])

    def test_every_tag_occurs_in_both_languages(self):
        rows = load_rows()
        positives = Counter(
            (tag, row["language"]) for row in rows if row["case_type"] == "positive" for tag in row["tags"]
        )
        gated = Counter(
            (tag, row["language"])
            for row in rows
            if row["case_type"] == "positive" and not row["known_gap"]
            for tag in row["tags"]
        )
        for language in LANGUAGES:
            for tag in TAGS:
                self.assertGreater(positives[(tag, language)], 0, (tag, language))
            # Since K06 the detector also passes obfuscated values.
            for tag in TAGS:
                self.assertGreater(gated[(tag, language)], 0, (tag, language))
        self.assertGreater(sum(row["known_gap"] for row in rows), 0)

    def test_each_label_has_n_gated_positives_and_hard_negatives_per_language(self):
        rows = load_rows()
        counts = Counter(
            (row["target_label"], row["language"], row["case_type"]) for row in rows if not row["known_gap"]
        )
        for label in {row["target_label"] for row in rows}:
            for language in LANGUAGES:
                for case_type in ("positive", "hard_negative"):
                    self.assertGreaterEqual(
                        counts[(label, language, case_type)], MIN_PER_LANGUAGE, (label, language, case_type)
                    )

    def test_every_rule_is_covered_per_language(self):
        rows = load_rows()
        positives = Counter(
            (row["rule_id"], row["language"])
            for row in rows
            if row["case_type"] == "positive" and not row["known_gap"]
        )
        negatives = Counter(row["rule_id"] for row in rows if row["case_type"] == "hard_negative")
        for rule_id in sorted(all_rule_ids()):
            for language in LANGUAGES:
                self.assertGreater(positives[(rule_id, language)], 0, (rule_id, language))
            self.assertGreater(negatives[rule_id], 0, rule_id)

    def test_spelled_out_email_addresses_stay_hard_negatives(self):
        # Gold convention T01: `[at]`/`[dot]` and spaced forms are not values of EMAIL in
        # strict and balanced. Only the opt-in `recall` mode reports them (K06).
        spelled_out = ("[at]", " @ ", " ät ", " punkt ", " dot ")
        modes = Counter()
        for row in load_rows():
            if row["target_label"] == "EMAIL" and any(token in row["text"] for token in spelled_out):
                mode = row.get("pii_mode", "strict")
                if mode != "recall":
                    self.assertEqual(row["case_type"], "hard_negative", row["id"])
                modes[(mode, row["case_type"])] += 1
        self.assertGreater(modes[("recall", "positive")], 0)
        self.assertGreater(modes[("strict", "hard_negative")] + modes[("balanced", "hard_negative")], 2)


if __name__ == "__main__":
    unittest.main()
