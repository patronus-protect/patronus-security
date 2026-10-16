from __future__ import annotations

import hashlib
import importlib.util
import itertools
import json
import struct
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_presidio" / "latency.py"
SPEC = importlib.util.spec_from_file_location("latency", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

sys.path.insert(0, str(ROOT / "python"))

# Pinned per WORKLOAD_VERSION: changing a workload must bump the version, because
# compare refuses reports with different workloads.
WORKLOADS_SHA256 = "abf8673c9615ac71524a6f43c767d6c7d814d4b69652c290b708d449503d5230"


def workloads_digest():
    described = MODULE.describe_workloads(MODULE.workloads())
    return hashlib.sha256(json.dumps(described, sort_keys=True).encode()).hexdigest()


def elf(section_names):
    """A minimal 64-bit little-endian ELF file with the given section names."""
    names = ["", *section_names, ".shstrtab"]
    strtab = b""
    offsets = []
    for name in names:
        offsets.append(len(strtab))
        strtab += name.encode() + b"\0"
    header_size = 64
    strtab_offset = header_size
    shoff = strtab_offset + len(strtab)
    header = bytearray(header_size)
    header[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", header, 0x28, shoff)
    struct.pack_into("<HHH", header, 0x3A, 64, len(names), len(names) - 1)
    sections = b""
    for index, offset in enumerate(offsets):
        entry = bytearray(64)
        struct.pack_into("<I", entry, 0, offset)
        if index == len(names) - 1:
            struct.pack_into("<QQ", entry, 0x18, strtab_offset, len(strtab))
        sections += bytes(entry)
    return bytes(header) + strtab + sections


def fake_report(p95_by_size, *, machine=None, workloads=None, engine="ark"):
    sizes = {size: {"samples": 10, "p50_ms": p95 / 2, "p95_ms": p95, "p99_ms": p95 * 1.2,
                    "mean_ms": p95 / 2, "max_ms": p95 * 1.5} for size, p95 in p95_by_size.items()}
    return {
        "schema": MODULE.SCHEMA,
        "workload_version": MODULE.WORKLOAD_VERSION,
        "machine": machine or {"cpu": "test cpu", "cpus": 6, "cpus_usable": 6, "machine": "x86_64", "system": "Linux"},
        "workloads": workloads or MODULE.describe_workloads(MODULE.workloads()),
        "engines": {engine: {"init_ms": 1.0, "info": {}, "loadavg_1m": [0, 0], "sizes": sizes,
                             "results": {}}},
    }


def worker_result(engine, p95_by_size, spans=3):
    report = fake_report(p95_by_size, engine=engine)
    data = report["engines"][engine]
    data["results"] = {item["id"]: {**data["sizes"][item["size"]], "spans": spans}
                         for item in report["workloads"]}
    return {"engine": engine, "machine": report["machine"], "workloads": report["workloads"], **data}


class TestWorkloads:
    def test_one_workload_per_size_and_language(self):
        items = MODULE.workloads()
        assert [(item.size, item.language) for item in items] == list(
            itertools.product(MODULE.SIZES, MODULE.LANGUAGES))
        assert len({item.id for item in items}) == len(items)

    def test_long_workloads_have_the_exact_byte_size(self):
        for item in MODULE.workloads():
            size = MODULE.SIZES[item.size]
            if size is not None:
                assert len(item.text.encode("utf-8")) == size, item.id
        assert MODULE.SIZES["4kib"] == 4096 and MODULE.SIZES["100kib"] == 102400

    def test_short_workload_is_one_paragraph_with_pii(self):
        for item in MODULE.workloads():
            if item.size == "short":
                assert item.text == MODULE.PARAGRAPHS[item.language][0]
                assert "@" in item.text and len(item.text.encode("utf-8")) < 200

    def test_long_workloads_cycle_whole_paragraphs(self):
        text = MODULE.build_text("de", 4096)
        body = text.rstrip(" ")
        parts = body.split("\n\n")
        paragraphs = MODULE.PARAGRAPHS["de"]
        assert parts == [paragraphs[i % len(paragraphs)] for i in range(len(parts))]
        assert len(parts) > len(paragraphs)
        # Padding stays below one more paragraph.
        assert len(text) - len(body) < len(paragraphs[len(parts) % len(paragraphs)].encode()) + 2

    def test_german_workloads_are_not_ascii(self):
        text = MODULE.build_text("de", 102400)
        assert len(text) < len(text.encode("utf-8"))

    def test_workloads_are_pinned(self):
        assert workloads_digest() == WORKLOADS_SHA256, "workloads changed: bump WORKLOAD_VERSION and the pin"


class TestStatistics:
    def test_nearest_rank_percentile(self):
        values = list(range(1, 101))
        assert MODULE.percentile(values, 0.50) == 50
        assert MODULE.percentile(values, 0.95) == 95
        assert MODULE.percentile(values, 0.99) == 99
        assert MODULE.percentile([7.0], 0.95) == 7.0
        assert MODULE.percentile([3, 1, 2], 0.0) == 1

    def test_percentile_of_nothing_fails(self):
        with pytest.raises(ValueError):
            MODULE.percentile([], 0.5)

    def test_summary_in_milliseconds(self):
        summary = MODULE.summarize([1_000_000 * n for n in range(1, 21)])
        assert summary == {"samples": 20, "p50_ms": 10.0, "p95_ms": 19.0, "p99_ms": 20.0,
                           "mean_ms": 10.5, "max_ms": 20.0}

    def test_sample_counts_scale_but_stay_positive(self):
        assert MODULE.sample_counts(1.0) == MODULE.SAMPLES
        assert MODULE.sample_counts(0.0001) == {size: 1 for size in MODULE.SIZES}


class TestMeasure:
    def test_times_every_workload_after_warmup_and_pools_sizes(self):
        items = MODULE.workloads()
        calls = []

        def analyze(text, language):
            calls.append((len(text), language))
            return 2

        ticks = itertools.count(step=1_000_000)
        samples = {"short": 3, "4kib": 2, "100kib": 1}
        warmup = {"short": 1, "4kib": 0, "100kib": 2}
        result = MODULE.measure(analyze, items, samples, warmup, clock=lambda: next(ticks))
        per_item = {"short": 1 + 1 + 3, "4kib": 0 + 1 + 2, "100kib": 2 + 1 + 1}
        assert len(calls) == sum(per_item[item.size] for item in items)
        assert set(result["results"]) == {item.id for item in items}
        for item in items:
            row = result["results"][item.id]
            assert row["samples"] == samples[item.size] and row["spans"] == 2
            assert row["p95_ms"] == 1.0
        assert {size: data["samples"] for size, data in result["sizes"].items()} == {
            size: count * len(MODULE.LANGUAGES) for size, count in samples.items()}

    def test_budget_stops_after_min_samples(self):
        item = MODULE.workloads()[-1]
        ticks = itertools.count(step=2_000_000_000)  # every clock read advances 2 s
        spans, times = MODULE.time_workload(lambda text, language: 1, item, 50, 0,
                                            clock=lambda: next(ticks), min_samples=3, budget_s=1.0)
        assert spans == 1 and len(times) == 3

    def test_budget_does_not_cut_fast_workloads(self):
        item = MODULE.workloads()[0]
        spans, times = MODULE.time_workload(lambda text, language: 0, item, 40, 0, budget_s=60.0)
        assert len(times) == 40

    def test_passes_the_workload_language(self):
        seen = set()
        MODULE.measure(lambda text, language: seen.add(language) or 0, MODULE.workloads(),
                       {size: 1 for size in MODULE.SIZES}, {})
        assert seen == set(MODULE.LANGUAGES)


class TestElf:
    def test_reads_section_names(self, tmp_path):
        path = tmp_path / "lib.so"
        path.write_bytes(elf([".text", ".rodata"]))
        assert MODULE.elf_section_names(path) == ["", ".text", ".rodata", ".shstrtab"]

    def test_debug_sections_mark_a_debug_build(self, tmp_path):
        debug, release = tmp_path / "debug.so", tmp_path / "release.so"
        debug.write_bytes(elf([".text", ".debug_line", ".debug_abbrev"]))
        release.write_bytes(elf([".text", ".rodata", ".eh_frame"]))
        assert MODULE.is_debug_build(debug) is True
        assert MODULE.is_debug_build(release) is False

    def test_other_formats_are_unknown(self, tmp_path):
        path = tmp_path / "lib.dylib"
        path.write_bytes(b"\xcf\xfa\xed\xfe" + bytes(60))
        assert MODULE.is_debug_build(path) is None


class TestReport:
    def test_assemble_checks_m4(self):
        ok = MODULE.assemble([worker_result("ark", {"short": 0.05, "4kib": 0.3, "100kib": 6.0}),
                              worker_result("presidio-tuned", {"short": 5, "4kib": 40, "100kib": 900})])
        assert ok["m4"] == {"size": "100kib", "limit_ms": 10.0, "pass": True,
                            "engines": {"ark": {"p95_ms": 6.0, "pass": True}}}
        assert list(ok["engines"]) == ["ark", "presidio-tuned"]
        slow = MODULE.assemble([worker_result("ark", {"short": 0.05, "4kib": 0.3, "100kib": 10.5})])
        assert slow["m4"]["pass"] is False

    def test_m4_needs_every_ark_engine(self):
        report = MODULE.assemble([worker_result("ark", {"short": 0.05, "4kib": 0.3, "100kib": 12.0}),
                                  worker_result("ark-native", {"short": 0.02, "4kib": 0.2, "100kib": 5.0})])
        assert report["m4"]["engines"] == {"ark": {"p95_ms": 12.0, "pass": False},
                                           "ark-native": {"p95_ms": 5.0, "pass": True}}
        assert report["m4"]["pass"] is False

    def test_assemble_without_ark_has_no_m4(self):
        report = MODULE.assemble([worker_result("presidio-default", {"short": 5, "4kib": 40, "100kib": 900})])
        assert "m4" not in report

    def test_assemble_rejects_different_workloads(self):
        other = worker_result("presidio-default", {"short": 5, "4kib": 40, "100kib": 900})
        other["workloads"] = other["workloads"][:-1]
        with pytest.raises(MODULE.LatencyError):
            MODULE.assemble([worker_result("ark", {"short": 1, "4kib": 1, "100kib": 1}), other])

    def test_assemble_rejects_different_machines(self):
        other = worker_result("presidio-default", {"short": 5, "4kib": 40, "100kib": 900})
        other["machine"] = {"cpu": "elsewhere", "cpus": 2}
        with pytest.raises(MODULE.LatencyError):
            MODULE.assemble([worker_result("ark", {"short": 1, "4kib": 1, "100kib": 1}), other])

    def test_markdown_lists_engines_ratios_spans_and_m4(self):
        report = MODULE.assemble([worker_result("ark", {"short": 0.05, "4kib": 0.3, "100kib": 6.0}),
                                  worker_result("ark-native", {"short": 0.02, "4kib": 0.3, "100kib": 3.0}),
                                  worker_result("presidio-tuned", {"short": 5, "4kib": 40, "100kib": 900})])
        text = MODULE.markdown(report)
        assert "| ark |" in text and "| presidio-tuned |" in text
        assert "| presidio-tuned | 100× | 133× | 150× |" in text
        assert "| ark-native | 0.40× | 1.00× | 0.50× |" in text
        assert "| 100kib-de | 102400 |" in text
        assert "M4 (ark 100kib p95 ≤ 10 ms): 6.000 ms, pass." in text
        assert "M4 (ark-native 100kib p95 ≤ 10 ms): 3.000 ms, pass." in text


class TestCompare:
    def test_within_tolerance_passes(self):
        result = MODULE.compare(fake_report({"short": 0.05, "4kib": 0.3, "100kib": 6.0}),
                                fake_report({"short": 0.08, "4kib": 0.6, "100kib": 6.6}))
        assert not result["regression"]
        assert [row["gated"] for row in result["rows"]] == [False, False, True]
        assert result["rows"][2]["change_pct"] == 10.0

    def test_100kib_above_tolerance_regresses(self):
        result = MODULE.compare(fake_report({"short": 0.05, "4kib": 0.3, "100kib": 6.0}),
                                fake_report({"short": 0.05, "4kib": 0.3, "100kib": 6.7}))
        assert result["regression"] and result["rows"][2]["regression"]

    def test_gated_sizes_and_tolerance_are_configurable(self):
        base = fake_report({"short": 0.05, "4kib": 0.3, "100kib": 6.0})
        head = fake_report({"short": 0.1, "4kib": 0.3, "100kib": 6.0})
        assert MODULE.compare(base, head, sizes=["short", "100kib"])["regression"]
        assert not MODULE.compare(base, head, sizes=["short"], tolerance_pct=150)["regression"]

    def test_rejects_different_workloads_machines_or_missing_engine(self):
        base = fake_report({"short": 1, "4kib": 1, "100kib": 1})
        changed = fake_report({"short": 1, "4kib": 1, "100kib": 1}, workloads=base["workloads"][:1])
        elsewhere = fake_report({"short": 1, "4kib": 1, "100kib": 1}, machine={"cpu": "other", "cpus": 2})
        presidio = fake_report({"short": 1, "4kib": 1, "100kib": 1}, engine="presidio-tuned")
        for head in (changed, elsewhere, presidio):
            with pytest.raises(MODULE.LatencyError):
                MODULE.compare(base, head)

    def test_cli_exit_codes(self, tmp_path, capsys):
        base, fast, slow = tmp_path / "base.json", tmp_path / "fast.json", tmp_path / "slow.json"
        base.write_text(json.dumps(fake_report({"short": 0.05, "4kib": 0.3, "100kib": 6.0})))
        fast.write_text(json.dumps(fake_report({"short": 0.05, "4kib": 0.3, "100kib": 5.0})))
        slow.write_text(json.dumps(fake_report({"short": 0.05, "4kib": 0.3, "100kib": 9.0})))
        assert MODULE.main(["compare", "--base", str(base), "--head", str(fast)]) == 0
        assert capsys.readouterr().out.strip().endswith("RESULT: PASS")
        assert MODULE.main(["compare", "--base", str(base), "--head", str(slow)]) == 1
        assert "100kib" in capsys.readouterr().out
        other = tmp_path / "other.json"
        other.write_text(json.dumps(fake_report({"short": 1, "4kib": 1, "100kib": 1}, machine={"cpu": "x"})))
        assert MODULE.main(["compare", "--base", str(base), "--head", str(other)]) == 2


FAKE_NATIVE = """#!{python}
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    job = json.loads(line)
    assert job["min_samples"] == {min_samples} and job["budget_ms"] > 0
    print(json.dumps({{"id": job["id"], "spans": len(job["text"]) // 1000,
                      "samples_ns": [1000 * (n + 1) for n in range(job["samples"])], "init_ms": 1.5}}))
"""


class TestNativeWorker:
    def fake_binary(self, tmp_path, body=None):
        path = tmp_path / "l1_latency_workloads"
        path.write_text(body or FAKE_NATIVE.format(python=sys.executable, min_samples=MODULE.MIN_SAMPLES))
        path.chmod(0o755)
        return path

    def test_summarizes_like_the_python_engines(self, tmp_path):
        binary = self.fake_binary(tmp_path)
        result = MODULE.measure_native(binary, {"short": 4, "4kib": 2, "100kib": 1})
        assert result["engine"] == "ark-native" and result["init_ms"] == 1.5
        assert result["workloads"] == MODULE.describe_workloads(MODULE.workloads())
        assert result["results"]["short-en"]["samples"] == 4
        assert result["results"]["short-en"]["p95_ms"] == 0.004
        assert result["results"]["100kib-de"]["spans"] == 101
        assert result["sizes"]["4kib"]["samples"] == 4
        assert result["info"]["binary_sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest()
        assert MODULE.assemble([result])["m4"]["engines"]["ark-native"]["pass"]

    def test_rejects_missing_workloads_and_failures(self, tmp_path):
        partial = self.fake_binary(tmp_path, f"#!{sys.executable}\nprint('{{\"id\": \"short-de\", "
                                             f"\"spans\": 0, \"samples_ns\": [1], \"init_ms\": 1}}')\n")
        with pytest.raises(MODULE.LatencyError):
            MODULE.measure_native(partial, MODULE.SAMPLES)
        failing = self.fake_binary(tmp_path, f"#!{sys.executable}\nimport sys\nsys.exit(3)\n")
        with pytest.raises(MODULE.LatencyError):
            MODULE.measure_native(failing, MODULE.SAMPLES)


def native_module():
    try:
        from patronus_ark import _patronus_ark
    except ImportError:
        return None
    return Path(_patronus_ark.__file__)


@pytest.mark.skipif(native_module() is None, reason="patronus_ark is not installed")
class TestArkEngine:
    def test_ark_finds_pii_in_every_workload(self, tmp_path):
        output = tmp_path / "ark.json"
        assert MODULE.main(["measure", "--engine", "ark", "--allow-debug", "--samples-scale", "0.02",
                            "--output", str(output)]) == 0
        result = json.loads(output.read_text())
        assert result["engine"] == "ark"
        assert result["workloads"] == MODULE.describe_workloads(MODULE.workloads())
        assert set(result["sizes"]) == set(MODULE.SIZES)
        for item_id, row in result["results"].items():
            assert row["spans"] > 0, item_id
        assert result["info"]["native_sha256"] == hashlib.sha256(native_module().read_bytes()).hexdigest()

    def test_debug_build_is_refused(self, tmp_path):
        if not MODULE.is_debug_build(native_module()):
            pytest.skip("installed module is a release build")
        assert MODULE.main(["measure", "--engine", "ark", "--output", str(tmp_path / "ark.json")]) == 2


@pytest.mark.skipif(importlib.util.find_spec("presidio_analyzer") is None, reason="presidio_analyzer is not installed")
def test_presidio_default_finds_pii(tmp_path):
    output = tmp_path / "presidio.json"
    assert MODULE.main(["measure", "--engine", "presidio-default", "--samples-scale", "0.02",
                        "--output", str(output)]) == 0
    result = json.loads(output.read_text())
    assert all(row["spans"] > 0 for row in result["results"].values())
