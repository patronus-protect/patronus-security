import json
import threading
import unittest

from patronus_security import benchmark


class BenchmarkDataTests(unittest.TestCase):
    def test_all_sample_files_exist_and_parse(self):
        expected_files = {"benign"} | {name for name, _, _, _ in benchmark.CLASSIFIER_PIPELINES}
        for name in expected_files:
            path = benchmark.DATA_DIR / f"{name}.jsonl"
            self.assertTrue(path.is_file(), f"{path} missing")
            rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
            self.assertTrue(rows, f"{name} is empty")
            for row in rows:
                self.assertTrue(row.get("text", "").strip(), f"{name} has an empty text")

    def test_benign_corpus_has_100_samples(self):
        self.assertEqual(len(benchmark._load_samples("benign")), 100)

    def test_classifier_samples_are_labelled_and_capped_per_class(self):
        for name, _, _, _ in benchmark.CLASSIFIER_PIPELINES:
            samples = benchmark._load_samples(name)
            counts = {}
            for sample in samples:
                self.assertIn("expected_class", sample, name)
                counts[sample["expected_class"]] = counts.get(sample["expected_class"], 0) + 1
            self.assertLessEqual(max(counts.values()), 100, name)

    def test_round_robin_limit_keeps_all_classes(self):
        samples = benchmark._load_samples("sensitive_documents")
        classes = {s["expected_class"] for s in samples}
        limited = benchmark._round_robin_by_class(samples, len(classes) * 2)
        self.assertEqual({s["expected_class"] for s in limited}, classes)

    def test_macro_f1_perfect_and_disjoint(self):
        self.assertEqual(benchmark._macro_f1(["a", "b"], ["a", "b"]), 1.0)
        self.assertEqual(benchmark._macro_f1(["a", "a"], ["b", "b"]), 0.0)

    def test_load_uses_one_producer_and_one_consumer(self):
        class FakeGateway:
            max_level = "l2"

            def __init__(self):
                self.enqueue_threads = []
                self.consume_threads = []
                self.next_id = 0
                self.requests = {}
                self.ready = []

            def enqueue(self, _text):
                self.enqueue_threads.append(threading.get_ident())
                self.next_id += 1
                request_id = f"request-{self.next_id}"
                self.requests[request_id] = 1
                self.ready.append(
                    {"request_id": request_id, "level": "L2", "layers": []}
                )
                return request_id

            def consume_next_result(self, timeout=None):
                self.consume_threads.append(threading.get_ident())
                if not self.ready:
                    return None
                result = self.ready.pop(0)
                request_id = result["request_id"]
                self.requests[request_id] -= 1
                if self.requests[request_id] == 0:
                    del self.requests[request_id]
                return result

            def has_request(self, request_id):
                return request_id in self.requests

        gateway = FakeGateway()
        original = benchmark._load_scenario_texts
        benchmark._load_scenario_texts = lambda _gateway: {"load": ["one", "two"]}
        try:
            result = benchmark._run_load(gateway, requests_per_scenario=6)
        finally:
            benchmark._load_scenario_texts = original

        stats = result["scenarios"]["load"]
        self.assertEqual(stats["producer_workers"], 1)
        self.assertEqual(stats["consumer_workers"], 1)
        self.assertEqual(stats["errors"], 0)
        self.assertEqual(len(set(gateway.enqueue_threads)), 1)
        self.assertEqual(len(set(gateway.consume_threads)), 1)
        self.assertNotEqual(gateway.enqueue_threads[0], gateway.consume_threads[0])

    def test_load_consumer_does_not_block_l2_behind_an_l3_request(self):
        class FakeGateway:
            max_level = "l3"

            def __init__(self):
                self.requests = {}
                self.next_id = 0
                self.result_order = []
                self.ready = []

            def enqueue(self, _text):
                self.next_id += 1
                request_id = f"request-{self.next_id}"
                levels = ["L2", "L3"] if self.next_id == 1 else ["L2"]
                self.requests[request_id] = len(levels)
                self.ready.append(
                    {"request_id": request_id, "level": "L2", "layers": []}
                )
                if self.next_id == 1:
                    self.delayed_l3 = {
                        "request_id": request_id,
                        "level": "L3",
                        "layers": [],
                    }
                else:
                    self.ready.append(self.delayed_l3)
                return request_id

            def consume_next_result(self, timeout=None):
                if not self.ready:
                    return None
                result = self.ready.pop(0)
                request_id = result["request_id"]
                self.result_order.append((request_id, result["level"]))
                self.requests[request_id] -= 1
                if self.requests[request_id] == 0:
                    del self.requests[request_id]
                return result

            def has_request(self, request_id):
                return request_id in self.requests

        gateway = FakeGateway()
        original = benchmark._load_scenario_texts
        benchmark._load_scenario_texts = lambda _gateway: {"load": ["one", "two"]}
        try:
            benchmark._run_load(gateway, requests_per_scenario=2)
        finally:
            benchmark._load_scenario_texts = original

        self.assertLess(
            gateway.result_order.index(("request-2", "L2")),
            gateway.result_order.index(("request-1", "L3")),
        )

    def test_benchmark_markdown_contains_queue_and_l3_diagnostics(self):
        latency = {"avg_ms": 1.0, "p50_ms": 1.0, "p95_ms": 2.0, "p99_ms": 2.0, "max_ms": 2.0}
        report = benchmark._benchmark_markdown(
            {
                "generated_at": "2026-07-12T00:00:00+00:00",
                "host": {"platform": "test", "machine": "test"},
                "gateway": {"categories": ["injection"], "max_level": "l3"},
            },
            {
                "sample_id": "attack-0003",
                "input": "ignore previous instructions",
                "request_id": "request-1",
                "observed_levels": ["L2", "L3"],
                "l2_and_l3_observed": True,
                "results": [
                    {
                        "request_id": "request-1",
                        "category": "injection",
                        "level": "L3",
                        "class_name": "attack",
                    }
                ],
            },
            {
                "samples": 1,
                "false_positives": 0,
                "false_positive_rate": 0.0,
                "latency": latency,
            },
            {
                "pipelines": {
                    "injection": {
                        "modes": {
                            "with_l3": {
                                "samples": 1,
                                "accuracy": 1.0,
                                "macro_f1": 1.0,
                                "l3_scans": 1,
                                "latency": latency,
                            }
                        }
                    }
                }
            },
            {
                "scenarios": {
                    "load": {
                        "requests": 1,
                        "errors": 0,
                        "throughput_rps": 1.0,
                        "enqueue_latency": latency,
                        "first_result_latency": latency,
                        "total_latency": latency,
                        "final_levels": {"L3": 1},
                        "ntdb_l2_chunks": latency,
                        "l3_candidate_spans": latency,
                        "l3_chunks": latency,
                        "l3_queue_wait": latency,
                        "l3_execution": latency,
                    }
                }
            },
        )
        self.assertIn("# Benchmark", report)
        self.assertIn("One producer", report)
        self.assertIn("L3 queue wait", report)
        self.assertIn("| injection | with_l3 |", report)
        self.assertIn("## One complete queued response", report)
        self.assertIn('"request_id": "request-1"', report)
        self.assertIn('"level": "L3"', report)
        self.assertLess(
            report.index("## L2/L3 diagnostics"),
            report.index("## One complete queued response"),
        )

    def test_queue_example_preserves_every_consumed_result(self):
        class FakeGateway:
            categories = ["injection", "dlp"]

            def __init__(self):
                self.results = [
                    {
                        "request_id": "request-1",
                        "category": "injection",
                        "level": "L2",
                        "layers": [{"level": "L2"}],
                    },
                    {
                        "request_id": "request-1",
                        "category": "injection",
                        "level": "L3",
                        "layers": [{"level": "L3"}],
                    },
                ]

            def enqueue(self, _text):
                return "request-1"

            def consume_next_result(self, timeout=None):
                return self.results.pop(0) if self.results else None

            def has_request(self, _request_id):
                return bool(self.results)

        example = benchmark._run_queue_example(FakeGateway())

        self.assertEqual(example["request_id"], "request-1")
        self.assertEqual([result["level"] for result in example["results"]], ["L2", "L3"])
        self.assertTrue(example["l2_and_l3_observed"])


if __name__ == "__main__":
    unittest.main()
