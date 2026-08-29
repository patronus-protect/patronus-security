import json
import sys
import statistics
import threading
import time
import tempfile
import unittest
from unittest import mock
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import ark_api_profile as profile  # noqa: E402
import ark_api_http_benchmark as http_benchmark  # noqa: E402
import ark_api_throughput_benchmark as benchmark  # noqa: E402
import ark_api_capacity_benchmark as capacity  # noqa: E402
import ark_api_agent_benchmark as agent_benchmark  # noqa: E402


class ApiThroughputProfileTests(unittest.TestCase):
    def test_capacity_profile_has_mode_three_and_bounded_right_tail(self):
        batches = capacity.triangular_batches(10_000)
        counts = __import__("collections").Counter(batches)

        self.assertEqual(sum(batches), 10_000)
        self.assertTrue(all(1 <= value <= 10 for value in batches))
        self.assertEqual(counts.most_common(1)[0][0], 3)
        self.assertIn(10, counts)

    def test_agent_profile_has_mode_three_and_concurrency_one_to_six(self):
        batches = agent_benchmark.agent_batches(10_000, 20260828)
        counts = __import__("collections").Counter(batches)

        self.assertEqual(sum(batches), 10_000)
        self.assertEqual(set(counts), set(range(1, 7)))
        self.assertEqual(counts.most_common(1)[0][0], 3)

    def test_moby_packets_are_contiguous_and_exact_cover(self):
        text = "Möby Dick — Call me Ishmael.\n" * 101
        for count in (1, 2, 4, 8, 13, 20):
            packets = capacity.exact_packets(text, count)
            self.assertEqual(len(packets), count)
            self.assertEqual("".join(packet for _, packet in packets), text)

    def test_profile_is_full_gated_unified_api_profile(self):
        self.assertEqual(
            profile.CATEGORIES,
            ["injection", "dlp", "pii", "sensitive_document", "threat", "routing", "dynamic-pii"],
        )
        gates = profile.execution_gates()
        self.assertEqual(gates["levels"], {"l1": True, "l2": True, "l3": True})
        self.assertTrue(gates["models"]["gliner_small-v2.5-edge"])
        self.assertTrue(gates["models"]["unified-v3-routing"])
        self.assertTrue(gates["models"]["unified-v3-threat"])
        self.assertEqual(gates["conditional"][0]["pipeline"], "dynamic-pii")

    def test_dynamic_pii_accepts_the_api_upload_limit(self):
        config = profile.dynamic_pii_config()
        self.assertEqual(config["max_text_bytes"], 25 * 1024 * 1024)
        self.assertIn("person", config["labels"])
        self.assertGreaterEqual(len(config["conditional_labels"]), 8)

    def test_workload_mixes_long_and_one_to_five_chunk_requests(self):
        requests = benchmark.workload(2.0, 2, 1)
        self.assertEqual(len(requests), 7)
        self.assertEqual([name for name, _ in requests[:2]], ["long-0", "long-1"])
        self.assertEqual(len(requests[0][1].encode()), 2 * 1024 * 1024)
        self.assertEqual([name for name, _ in requests[2:]], [f"short-0-{n}" for n in range(1, 6)])

    def test_throughput_profile_matches_initial_api_surface(self):
        self.assertEqual(benchmark.THROUGHPUT_CATEGORIES, ["injection", "dlp", "threat"])
        gates = benchmark.throughput_gates()
        self.assertTrue(gates["models"]["unified-v3-threat"])
        self.assertEqual(gates["l3"]["clustering"], "representative")
        self.assertEqual(gates["l3"]["representatives_per_cluster"], 1)

    def test_sustained_traffic_profile_averages_100_kib_with_spikes(self):
        requests = benchmark.traffic_workload(1.0, 1, 96.0, 32, 1)
        sizes_kib = [len(content.encode()) / 1024 for _, content in requests]

        self.assertEqual(len(requests), 42)
        self.assertEqual(statistics.mean(sizes_kib), 100.0)
        self.assertEqual(statistics.median(sizes_kib), 96.0)
        self.assertEqual(min(sizes_kib), 2.0)
        self.assertEqual(max(sizes_kib), 1024.0)
        self.assertEqual(len({name for name, _ in requests}), 42)
        self.assertTrue(all("attack-" in name or "benign-" in name for name, _ in requests))

    def test_http_profile_makes_categories_and_operating_point_explicit(self):
        config = http_benchmark.request_config(
            ["injection", "dlp"], "best_promote",
        )

        self.assertEqual(config["categories"], ["injection", "dlp"])
        self.assertEqual(config["ntdb_operating_point"], "best_promote")

    def test_http_profile_extracts_l3_queue_worker_and_chunk_timing(self):
        timing = http_benchmark.l3_run_timing({"layers": [{
            "level": "L3",
            "details": {
                "l3_queue_wait_ms": 12.5,
                "l3_worker_wall_ms": 87.25,
                "chunk_count": 3,
            },
        }]})

        self.assertEqual(timing, (12.5, 87.25, 3))

    def test_http_workload_uses_unmodified_short_medium_and_long_rows(self):
        rows = []
        for bucket, size in (("short", 100), ("medium", 3_000), ("long", 10_000)):
            rows.extend((f"{bucket}-{index}", "x" * size) for index in range(15))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "val.csv"
            with path.open("w", newline="", encoding="utf-8") as handle:
                writer = __import__("csv").writer(handle)
                writer.writerow(["label", "text"])
                writer.writerows(rows)
            requests = http_benchmark.validation_workload(path)

        self.assertEqual(len(requests), 42)
        self.assertEqual(
            {text for _, text in requests},
            {text for _, text in rows},
        )
        self.assertEqual({name.split("-", 1)[0] for name, _ in requests}, {
            "short", "medium", "long",
        })

    def test_http_scheduler_keeps_one_active_request_per_container(self):
        active = {}
        max_active = {}
        lock = threading.Lock()

        def submit(base_url, _token, name, _content, _config, _timeout):
            with lock:
                active[base_url] = active.get(base_url, 0) + 1
                max_active[base_url] = max(max_active.get(base_url, 0), active[base_url])
            return {"name": name, "request_id": name, "base_url": base_url}

        def consume(job, _token, _timeout):
            time.sleep(0.001)
            with lock:
                active[job["base_url"]] -= 1
            return {
                **job,
                "models": {http_benchmark.UNIFIED_MODEL},
                "l3_models": {http_benchmark.UNIFIED_MODEL},
                "pipelines": {"injection", "dlp", "threat"},
                "levels": {"L1", "L2", "L3"},
                "failures": [],
                "l2_promoted_categories": {"injection"},
                "l3_categories": {"injection"},
                "l3_runs": {(0.0, 1.0, 1)},
                "l2_chunk_spans": {
                    "injection": {(0, 10), (10, 20)},
                    "threat": {(0, 10), (10, 20)},
                },
                "promoted_chunk_spans": {
                    "injection": {(10, 20)},
                    "threat": {(0, 10)},
                },
                "completion": "complete",
            }

        with mock.patch.object(http_benchmark, "submit", side_effect=submit), mock.patch.object(
            http_benchmark, "consume", side_effect=consume
        ):
            report = http_benchmark.run_batch(
                ["http://ark-1", "http://ark-2", "http://ark-3"],
                "token",
                [(f"case-{index}", str(index)) for index in range(42)],
                1.0,
                ["injection", "dlp", "threat"],
                "best_promote",
            )
            rotated = http_benchmark.run_batch(
                ["http://ark-1", "http://ark-2", "http://ark-3"],
                "token", [("rotated", "content")], 1.0,
                ["injection", "dlp", "threat"], "best_promote",
                concurrency=1, endpoint_offset=1,
            )

        self.assertEqual(max_active, {
            "http://ark-1": 1,
            "http://ark-2": 1,
            "http://ark-3": 1,
        })
        self.assertEqual(sum(report["requests_by_container"].values()), 42)
        self.assertEqual(report["requests_promoted_by_category"], {
            "injection": 42,
            "dlp": 0,
            "threat": 0,
        })
        self.assertNotIn("promotion_rate", report)
        self.assertEqual(report["chunk_promotion"], {
            "by_category": {
                "injection": {"total_chunks": 84, "promoted_chunks": 42, "rate": 0.5},
                "dlp": {"total_chunks": 0, "promoted_chunks": 0, "rate": None},
                "threat": {"total_chunks": 84, "promoted_chunks": 42, "rate": 0.5},
            },
            "union": {"total_chunks": 84, "promoted_chunks": 84, "rate": 1.0},
        })
        self.assertEqual(rotated["requests_by_container"], {
            "http://ark-1": 0,
            "http://ark-2": 1,
            "http://ark-3": 0,
        })

    def test_native_and_http_use_the_same_deterministic_payload(self):
        expected = (
            "benchmark-run:0123456789abcdef0123456789abcdef "
            "case:medium-0\npayload"
        )

        self.assertEqual(benchmark.benchmark_content("medium-0", "payload"), expected)

    def test_http_scheduler_gives_more_work_to_the_faster_container(self):
        def submit(base_url, _token, name, _content, _config, _timeout):
            return {"name": name, "request_id": name, "base_url": base_url}

        def consume(job, _token, _timeout):
            if job["base_url"].endswith("ark-slow"):
                time.sleep(0.03)
            else:
                time.sleep(0.001)
            return {
                **job,
                "models": {http_benchmark.UNIFIED_MODEL},
                "l3_models": {http_benchmark.UNIFIED_MODEL},
                "pipelines": {"injection"},
                "levels": {"L2", "L3"},
                "failures": [],
                "l2_promoted_categories": {"injection"},
                "l3_categories": {"injection"},
                "l3_runs": {(0.0, 1.0, 1)},
                "l2_chunk_spans": {"injection": {(0, 10)}},
                "promoted_chunk_spans": {"injection": {(0, 10)}},
                "completion": "complete",
            }

        with mock.patch.object(http_benchmark, "submit", side_effect=submit), mock.patch.object(
            http_benchmark, "consume", side_effect=consume,
        ):
            report = http_benchmark.run_batch(
                ["http://ark-fast", "http://ark-slow"], "token",
                [(f"case-{index}", str(index)) for index in range(20)],
                1.0, ["injection"], "best_promote", concurrency=10,
            )

        distribution = report["requests_by_container"]
        self.assertGreater(distribution["http://ark-fast"], distribution["http://ark-slow"])


if __name__ == "__main__":
    unittest.main()
