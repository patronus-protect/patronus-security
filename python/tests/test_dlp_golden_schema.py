"""DLP golden schema v2 (E13): rule ids, carriers, difficulty tags, known gaps, coverage."""

import json
import re
import runpy
import unittest
from collections import Counter

from patronus_ark import benchmark
from patronus_ark.dlp_synth import recipes, rules


TAGS = ("carrier", "no_context", "encoded", "split", "prose")
CARRIERS = {
    "line", "env", "yaml", "json", "toml", "ini", "xml", "code", "log", "cli", "http", "csv",
    "sql", "markdown", "prose",
}
LANGUAGES = ("de", "en")
MIN_PER_LANGUAGE = 5
V2_FIELDS = (
    "id", "suite", "schema_version", "language", "case_type", "target_label", "rule_id",
    "carrier", "tags", "known_gap",
)
# Opt-in DLP modes a row may name (K04); rows without `dlp_mode` run in `strict`.
SCORED_MODES = ("balanced", "recall")


def raw_lines():
    return (benchmark.DATA_DIR / "dlp_l1.jsonl").read_text().splitlines()


def load_rows():
    return [json.loads(line) for line in raw_lines()]


def is_glued(template):
    """T01: every placeholder continues a word, `+` or `/` run on its left."""
    return "<<secret:" in template and not re.search(r"(?<![A-Za-z0-9_+/])<<secret:", template)


def all_rule_ids():
    """Every dlp_* rule in DLP_PATTERNS (value rules plus content rules)."""
    return set(rules.load_rule_map()) | set(rules.content_rules())


class DlpGoldenSchemaV2Tests(unittest.TestCase):
    def test_generator_declares_the_schema_constants(self):
        namespace = runpy.run_path(str(benchmark.DATA_DIR / "generate_l1_goldens.py"))
        self.assertEqual(namespace["DLP_SCHEMA_VERSION"], 2)
        self.assertEqual(namespace["DLP_TAGS"], TAGS)
        self.assertEqual(set(namespace["DLP_CARRIERS"]), CARRIERS)
        self.assertEqual(namespace["DLP_MIN_PER_LANGUAGE"], MIN_PER_LANGUAGE)

    def test_every_row_carries_the_v2_fields_first(self):
        known_rules = all_rule_ids()
        for row in load_rows():
            self.assertEqual(tuple(row)[: len(V2_FIELDS)], V2_FIELDS, row["id"])
            self.assertEqual(row["schema_version"], 2, row["id"])
            self.assertIn(row["rule_id"], known_rules, row["id"])
            self.assertIn(row["carrier"], CARRIERS, row["id"])
            self.assertIs(type(row["known_gap"]), bool, row["id"])
            self.assertEqual(row["tags"], [tag for tag in TAGS if tag in row["tags"]], row["id"])
            self.assertEqual(len(set(row["tags"])), len(row["tags"]), row["id"])

    def test_dlp_mode_follows_known_gap_and_names_a_scored_mode(self):
        rows = load_rows()
        for row in rows:
            if "dlp_mode" in row:
                self.assertEqual(tuple(row).index("dlp_mode"), len(V2_FIELDS), row["id"])
                self.assertIn(row["dlp_mode"], SCORED_MODES, row["id"])
        # K04: >= 5 positives and 5 hard negatives per language run in balanced.
        balanced = Counter(
            (row["language"], row["case_type"]) for row in rows if row.get("dlp_mode") == "balanced"
        )
        for language in LANGUAGES:
            for case_type in ("positive", "hard_negative"):
                self.assertGreaterEqual(balanced[(language, case_type)], MIN_PER_LANGUAGE, (language, case_type))

    def test_generated_hard_negatives_run_in_a_scored_mode(self):
        # Strict hard negatives hold example/test values (fill recipes, T06); a plain
        # generator value is a hard negative only where context marks it as no secret (K04)
        # or where it is glued into an identifier, hex run or base64 blob (T01).
        glued = 0
        for row in load_rows():
            if row["case_type"] != "hard_negative" or "secrets" not in row:
                continue
            plain = any("fill" not in secret for secret in row["secrets"])
            if plain and is_glued(row["template"]) and "dlp_mode" not in row:
                glued += 1
                continue
            self.assertEqual(plain, row.get("dlp_mode") in SCORED_MODES, row["id"])
        # T01: >= 5 glued hard negatives per language.
        for language in LANGUAGES:
            self.assertGreaterEqual(
                sum(
                    row["case_type"] == "hard_negative"
                    and row["language"] == language
                    and "secrets" in row
                    and is_glued(row["template"])
                    for row in load_rows()
                ),
                MIN_PER_LANGUAGE,
                language,
            )
        self.assertGreater(glued, 0)

    def test_only_positives_can_be_known_gaps(self):
        for row in load_rows():
            if row["known_gap"]:
                self.assertEqual(row["case_type"], "positive", row["id"])

    def test_derived_tags_follow_carrier_and_placeholders(self):
        for row in load_rows():
            tags = set(row["tags"])
            self.assertEqual("carrier" in tags, row["carrier"] not in ("line", "prose"), row["id"])
            self.assertEqual("prose" in tags, row["carrier"] == "prose", row["id"])
            if row["case_type"] != "positive":
                continue
            entities = row["entities"]
            self.assertEqual("encoded" in tags, any("encoding" in entity for entity in entities), row["id"])
            self.assertEqual("split" in tags, any("part" in entity for entity in entities), row["id"])
            if "split" in tags:
                parts = [entity["part"] for entity in entities]
                self.assertEqual(parts, list(range(len(parts))), row["id"])
                self.assertGreaterEqual(len(parts), 2, row["id"])

    def test_encoded_entities_name_a_placeholder_transform(self):
        for row in load_rows():
            for entity in row["entities"]:
                if "encoding" in entity:
                    self.assertEqual(len(entity["encoding"]), 1, row["id"])
                    self.assertIn(entity["encoding"][0], recipes.TRANSFORMS, row["id"])

    def test_every_tag_occurs_in_both_languages(self):
        positives = Counter(
            (tag, row["language"]) for row in load_rows() if row["case_type"] == "positive" for tag in row["tags"]
        )
        gated = Counter(
            (tag, row["language"])
            for row in load_rows()
            if row["case_type"] == "positive" and not row["known_gap"]
            for tag in row["tags"]
        )
        for language in LANGUAGES:
            for tag in TAGS:
                self.assertGreater(positives[(tag, language)], 0, (tag, language))
            # Today's detector already passes these tags in realistic carriers.
            for tag in ("carrier", "no_context", "prose", "encoded"):
                self.assertGreater(gated[(tag, language)], 0, (tag, language))
        self.assertGreater(sum(row["known_gap"] for row in load_rows()), 0)

    def test_each_label_has_n_gated_positives_and_hard_negatives_per_language(self):
        counts = Counter(
            (row["target_label"], row["language"], row["case_type"])
            for row in load_rows()
            if not row["known_gap"]
        )
        for label in {row["target_label"] for row in load_rows()}:
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

    def test_raw_file_writes_placeholders_with_an_escaped_colon(self):
        # `<<secret:0>>` followed by more text reads as `secret: <value>` to generic scanners.
        raw = "\n".join(raw_lines())
        self.assertNotIn("<<secret:", raw)
        self.assertIn("<<secret\\u003a", raw)
        templates = [row["template"] for row in load_rows() if "template" in row]
        self.assertTrue(all("<<secret:" in template for template in templates))


if __name__ == "__main__":
    unittest.main()
