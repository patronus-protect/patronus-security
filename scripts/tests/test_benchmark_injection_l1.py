from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "benchmark_injection_l1.py"
SPEC = importlib.util.spec_from_file_location("benchmark_injection_l1", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_fixture_sizes_are_exact_and_attack_is_embedded_at_end():
    for size in MODULE.SIZES:
        benign = MODULE.text_of_size(size, False)
        attack = MODULE.text_of_size(size, True)
        assert len(benign.encode("utf-8")) == size
        assert len(attack.encode("utf-8")) == size
        assert attack.endswith(MODULE.ATTACK.decode("ascii"))


def test_percentile_uses_nearest_rank():
    assert MODULE.percentile([1.0, 2.0, 3.0, 4.0], 0.5) == 2.0
    assert MODULE.percentile([1.0, 2.0, 3.0, 4.0], 0.95) == 4.0
