import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "tokenizer_parity_texts", Path(__file__).resolve().parents[1] / "tokenizer_parity_texts.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_literal_and_recipe_rows_are_both_materialized(tmp_path):
    golden = Path(__file__).resolve().parents[2] / "python/patronus_ark/benchmark_data/dlp_l1.jsonl"
    recipe = json.loads(golden.read_text().splitlines()[0])
    rows = [{"text": "literal fixture"}, recipe]
    (tmp_path / "cases.jsonl").write_text("\n".join(json.dumps(row) for row in rows))
    actual = module.texts(tmp_path)
    assert len(actual) == 2
    assert actual[0] == "literal fixture"
    assert hashlib.sha256(actual[1].encode()).hexdigest()[:24] == recipe["text_fingerprint"]



def test_malformed_rows_are_errors_instead_of_skipped(tmp_path):
    (tmp_path / "cases.jsonl").write_text('{}')
    with pytest.raises(KeyError):
        module.texts(tmp_path)


def test_missing_or_empty_dataset_directory_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        module.texts(tmp_path / "missing")
    with pytest.raises(ValueError, match="no JSONL fixtures"):
        module.texts(tmp_path)
