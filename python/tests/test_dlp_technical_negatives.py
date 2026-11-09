"""H01: 1,000 technical benign snippets for hard-negative mining.

The snippets are deterministic, unique, balanced over 20 families and DE/EN, and every one
is a hard negative in ``dlp_l1.jsonl`` (``13_l1_golden_eval`` checks that no DLP rule
reports it).
"""

import json
import unittest
from collections import Counter
from pathlib import Path

from patronus_ark.dlp_synth import technical_negatives


REPO = Path(__file__).resolve().parents[2]
GOLDENS = REPO / "python/patronus_ark/benchmark_data/dlp_l1.jsonl"
SOURCE = "Ark L1 hard-negative mining H01 (patronus_ark.dlp_synth.technical_negatives)"


class TechnicalNegativesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snippets = technical_negatives.snippets()

    def test_thousand_unique_snippets_balanced_per_family_and_language(self):
        self.assertEqual(len(self.snippets), 1000)
        self.assertEqual(len({snippet["text"] for snippet in self.snippets}), 1000)
        per_family = Counter((snippet["family"], snippet["language"]) for snippet in self.snippets)
        self.assertEqual(len(technical_negatives.FAMILIES), 20)
        self.assertEqual(set(per_family.values()), {technical_negatives.PER_LANGUAGE})

    def test_snippets_are_deterministic(self):
        self.assertEqual(technical_negatives.snippets(), self.snippets)

    def test_every_snippet_is_a_hard_negative_golden(self):
        rows = [json.loads(line) for line in GOLDENS.read_text(encoding="utf-8").splitlines()]
        mined = [row for row in rows if row["provenance"]["source"] == SOURCE]
        self.assertEqual(sorted(row["text"] for row in mined), sorted(snippet["text"] for snippet in self.snippets))
        self.assertTrue(all(row["case_type"] == "hard_negative" and not row["entities"] for row in mined))


if __name__ == "__main__":
    unittest.main()
