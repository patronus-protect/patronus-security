# SPDX-License-Identifier: GPL-3.0-only
from ._patronus_ark import SecurityGateway as RustSecurityGateway
from ._patronus_ark import normalize_text as _rust_normalize_text
from copy import deepcopy
import json
import math

from patronus_ark_core import ScanGates, ScannerConfig


def _decode_json_object(value):
    try:
        decoded = json.loads(value or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _to_dict(result):
    output = {
        "category": result.category,
        "class_name": result.class_name,
        "confidence": result.confidence,
        "level": result.level,
        "model": result.model,
        "duration_ms": result.duration_ms,
        "layers": [
            {
                "level": layer.level,
                "layer_type": layer.layer_type,
                "class_name": layer.class_name,
                "confidence": layer.confidence,
                "matched": layer.matched,
                "duration_ms": layer.duration_ms,
                "thresholds": layer.thresholds,
                "details": layer.details,
            }
            for layer in result.layers
        ],
        "evidence_spans": result.evidence_spans,
        "label_scores": [
            {
                "label": score.label,
                "confidence": score.confidence,
                "matched": score.matched,
            }
            for score in result.label_scores
        ],
    }
    request_id = getattr(result, "request_id", None)
    if request_id is not None:
        output["request_id"] = request_id
    decision = _decode_json_object(getattr(result, "decision_json", None))
    if decision:
        output["decision"] = decision
    decided_by = getattr(result, "decided_by", None)
    if decided_by is not None:
        output["decided_by"] = decided_by
    l1_outcome = getattr(result, "l1_outcome", None)
    if l1_outcome is not None:
        output["l1_outcome"] = l1_outcome
    return output


def _failure_to_dict(failure):
    return {
        "stage": failure.stage,
        "level": failure.level,
        "detector_id": failure.detector_id,
        "kind": failure.kind,
        "retryable": failure.retryable,
        "message": failure.message,
    }


def _event_to_dict(event):
    output = {
        "event_type": event.event_type,
        "request_id": event.request_id,
    }
    if event.event_type in ("result", "provisional"):
        output["result"] = _to_dict(event.result)
    elif event.event_type == "progress":
        output["progress"] = _decode_json_object(getattr(event, "progress_json", None))
    else:
        output["completion"] = event.completion
        output["failures"] = [_failure_to_dict(failure) for failure in event.failures]
    return output


def _request_state_to_dict(state):
    return {
        "state": state.state,
        "completion": state.completion,
        "failures": [_failure_to_dict(failure) for failure in state.failures],
    }


def _level_readiness_to_dict(readiness):
    return {
        "state": readiness.state,
        "failures": [_failure_to_dict(failure) for failure in readiness.failures],
    }


def _execution_gates_json(execution_gates):
    """Gates in the one gate schema; the native extension validates them."""
    if execution_gates is None:
        return None
    if not isinstance(execution_gates, dict):
        raise ValueError("execution_gates must be a dict")
    return json.dumps(execution_gates)


def _dynamic_pii_config_json(config):
    if config is None:
        return None
    if not isinstance(config, dict):
        raise ValueError("dynamic_pii_config must be a dict")
    return json.dumps(config)


def _normalization_configs_json(configs):
    if configs is None:
        return None
    if not isinstance(configs, dict):
        raise ValueError("configs must be a dict")
    return json.dumps(configs)


def _unix_ms_from_ts(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("until_ts must be a Unix timestamp")
    if not math.isfinite(value) or value < 0:
        raise ValueError("until_ts must be a non-negative finite Unix timestamp")
    if value >= 1_000_000_000_000:
        return int(value)
    return int(value * 1000)


def normalize_text(text: str, configs: dict | None = None) -> str:
    """Return canonical_security_text_v1-style normalized text.

    `configs` gates individual normalization steps. Supported keys are
    `html_entities`, `nfkc`, `confusables`, `format_characters`, `whitespace`,
    and `trim`; omitted steps default to enabled.
    """
    return _rust_normalize_text(text, _normalization_configs_json(configs))


class GatewayConfig(ScannerConfig, total=False):
    """`SecurityGateway(config)`: Ark Core's `Scanner` config (`categories`,
    `max_level`, the gate keys, `cascade`, `cache_root`, `wolf`, `shell`)
    with the same meaning, plus Ark's keys. Unknown keys raise `ValueError`."""

    download: str
    download_categories: list[str]
    l3_strategy: str
    ntdb_operating_point: str
    ntdb_decision_threshold_point: str
    execution_backend: str
    onnx_batch_mode: str
    onnx_runtime: dict[str, object]
    dynamic_pii: dict[str, object]
    cache: dict[str, object]


# Ark keys the isolated benchmark worker keeps from the gateway's config.
_BENCHMARK_WORKER_KEYS = (
    "cache_root",
    "onnx_batch_mode",
    "execution_backend",
    "ntdb_decision_threshold_point",
    "l3_strategy",
    "wolf",
)


class SecurityGateway:
    """Python gateway for Patronus Ark scanners.

    Args:
        config: The gateway config, a dict (see `GatewayConfig`): the keys of
            Ark Core's `Scanner` config with the same meaning, plus Ark's own.

            Core keys: `categories` (any Ark category), `max_level` (`l1`,
            `l2` or `l3`; default `l2` here), the gate keys at the top level
            (`l1`/`l2`/`l3`, `rules`, `models`, `pii_mode`, `dlp_mode`, one
            `<category>_mode` per attack class, `explain`, `conditional`, the
            L3 worker policy `l3_policy` and the opt-in `cascade`
            (`{"modules": {...}}`: L1 early exit with per-category
            `detect_threshold`/`clear_threshold`; results then carry
            `decided_by`)), `cache_root` (the model cache root; default the
            platform cache directory plus `patronus_ark`), `wolf` (the
            dedicated injection L3: `model` `base`, `small` (default) or
            `edge`; `precision` `auto` (default), `fp32`, `fp16`, `mixed`,
            `mixed_x86`, `int8_int4` or `int8_int4_x86`; `execution` with
            `window_tokens`, `overlap_tokens`, `batch_size`, unset values
            retaining 256/0/1) and `shell` (`policy_dirs` and `allowlist` of
            the `shell_command` verdict).

            Ark keys: `download` (`missing`, the default here, lets `warmup()`
            download missing model assets; `never`), `download_categories`,
            `l3_strategy` (`dedicated` or `multi`), `ntdb_operating_point`,
            `ntdb_decision_threshold_point` (`best_f1` (default),
            `best_promote`, `best_fpr_in_f1`, `best_fnr_in_f1`,
            `best_latency_in_f1`), `execution_backend` (`auto`, `cpu`, `gpu`,
            `coreml`, `cuda`, `directml`, `tensorrt`), `onnx_batch_mode`
            (`lazy_batches` or `tensor_batch`; unset follows the backend),
            `onnx_runtime`, `dynamic_pii` (labels, result gates, thresholds,
            chunking, text limit and timeout of the L3-only `dynamic-pii`
            category) and `cache` (`storage_location`, `encryption_key_hex`,
            `entry_ttl_seconds`, `memory_max_entries`, `memory_max_bytes`;
            without a storage location the cache stays in memory).
    """

    def __init__(self, config: GatewayConfig):
        if not isinstance(config, dict):
            raise ValueError("config must be a dict")
        self._config = deepcopy(config)
        self._execution_gates = None
        self.rust_gateway = RustSecurityGateway(json.dumps(config))

    @classmethod
    def _from_benchmark_config(cls, benchmark_config: dict):
        """A gateway from `_benchmark_config()`: the config and any later gates."""
        gateway = cls(benchmark_config["config"])
        if benchmark_config["execution_gates"] is not None:
            gateway.set_execution_gates(benchmark_config["execution_gates"])
        return gateway

    def _benchmark_config(self) -> dict:
        """This gateway's config and later gates, for isolated benchmark gateways."""
        return {
            "config": deepcopy(self._config),
            "execution_gates": deepcopy(self._execution_gates),
        }

    def _benchmark_worker_config(self) -> dict:
        """The Ark keys an isolated benchmark worker keeps."""
        return {
            key: deepcopy(self._config[key])
            for key in _BENCHMARK_WORKER_KEYS
            if key in self._config
        }

    @property
    def wolf_options(self) -> dict[str, int]:
        """Effective dedicated-Wolf windows; returned as an independent copy."""
        return dict(self.rust_gateway.wolf_options)

    @property
    def wolf_model(self) -> str:
        """Dedicated-Wolf model: `base`, `small` or `edge`."""
        return self.rust_gateway.wolf_model

    @property
    def wolf_precision(self) -> str:
        """Requested dedicated-Wolf ONNX export, `auto` unless set explicitly."""
        return self.rust_gateway.wolf_precision

    @property
    def categories(self) -> list[str]:
        """Categories configured for `scan_all`."""
        return list(self.rust_gateway.categories)

    @property
    def max_level(self) -> str:
        """Maximum scanner level configured for this gateway."""
        return self.rust_gateway.max_level

    @property
    def l3_strategy(self) -> str:
        """Active global L3 model strategy."""
        return self.rust_gateway.l3_strategy

    def warmup(self):
        """Initialize model-backed scanners and download allowed missing assets.

        Native scanners are available without calling `warmup()`. Model-backed
        L2/L3 scanners are initialized only when their required assets are
        already cached or can be downloaded according to the download settings.
        L3 ONNX sessions are lazy-loaded on first L3 inference, not during
        `warmup()`.

        Raises:
            ValueError: If an allowed required asset download or model
                initialization fails.
        """
        self.rust_gateway.warmup()

    def stop_l3_models(self):
        """Unload resident L3 model sessions while preserving gateway configuration."""
        self.rust_gateway.stop_l3_models()

    def flush_cache(self):
        """Wait until all queued persistent cache writes are durable."""
        self.rust_gateway.flush_cache()

    def reset_cache_connections(self):
        """Flush and close persistent cache handles.

        The cache database file is preserved. A configured persistent cache is
        reopened lazily on the next cache access.
        """
        self.rust_gateway.reset_cache_connections()

    def reset_cache(self, until_ts: int | float) -> int:
        """Delete cache records created before `until_ts`.

        `until_ts` accepts Unix seconds or Unix milliseconds. The cache database
        file is preserved.
        """
        return self.rust_gateway.reset_cache(_unix_ms_from_ts(until_ts))

    def scan_all(self, text: str) -> list[dict]:
        """Scan text with every category configured on this gateway."""
        self._require_loaded_dynamic_pii(self.categories)
        results = self.rust_gateway.scan_all(text)
        return [_to_dict(r) for r in results]

    def set_execution_gates(self, execution_gates: ScanGates | None):
        """Replace the gate matrix used by subsequent scan calls.

        Pass `None` to reset to shared defaults (credentials/secrets-only DLP). The matrix
        uses the shared gate schema (`l1`/`l2`/`l3`, `rules`, `models`, `pii_mode`,
        `dlp_mode`, the attack-class `<category>_mode` keys, `explain`, `conditional`,
        `l3_policy`); model keys match result
        `model` values such as `native:mcp_runtime_risk`.
        """
        self.rust_gateway.set_execution_gates(_execution_gates_json(execution_gates))
        self._execution_gates = deepcopy(execution_gates)

    def set_onnx_batch_mode(self, mode: str):
        """Replace the ONNX batch mode for subsequent batch calls.

        `lazy_batches` preserves the per-text ONNX execution path.
        `tensor_batch` executes L3 fallbacks as one ONNX tensor batch when
        pipelines can batch their fallback texts.
        """
        self.rust_gateway.set_onnx_batch_mode(mode)
        self._config["onnx_batch_mode"] = mode

    def set_execution_backend(self, backend: str):
        """Replace execution backend and apply its default L3 mode.

        `auto` and `cpu` default to lazy L3 execution. `gpu`, `coreml`,
        `cuda`, `directml`, and `tensorrt` default to tensor batches. Call
        `set_onnx_batch_mode` afterwards to override.
        """
        self.rust_gateway.set_execution_backend(backend)
        self._config["execution_backend"] = backend
        # The backend's default batch mode replaces an earlier one.
        self._config.pop("onnx_batch_mode", None)

    def set_ntdb_operating_point(self, point: str):
        """Select the calibrated NTDB final-decision threshold set for subsequent scans."""
        self.rust_gateway.set_ntdb_operating_point(point)
        self._config["ntdb_decision_threshold_point"] = point

    def set_l3_strategy(self, strategy: str):
        """Select `dedicated` per-pipeline L3 models or the shared `multi` model."""
        self.rust_gateway.set_l3_strategy(strategy)
        self._config["l3_strategy"] = strategy

    def set_dynamic_pii_config(self, config: dict):
        """Replace labels, result gates, thresholds, limits, and timeout for `dynamic-pii`."""
        self.rust_gateway.set_dynamic_pii_config(_dynamic_pii_config_json(config))
        self._config["dynamic_pii"] = deepcopy(config)

    def set_shell_command_policy_config(
        self,
        policy_dirs: list[str] | None = None,
        allowlist: dict[str, str] | None = None,
    ):
        """Replace the user policies and allowlist of the `shell_command` verdict.

        `policy_dirs` are directories of user `*.cedar` policies, read in file-name
        order; `allowlist` maps a bundle-default policy id to `"ask"`. Same keys as
        Ark Core's `shell` config and the Ark API's `pipeline.shell`. A loaded
        bundle applies the configuration at once, otherwise `warmup()` does. A refused
        configuration raises `ValueError` and changes nothing.
        """
        self.rust_gateway.set_shell_command_policy_config(
            None if policy_dirs is None else [str(path) for path in policy_dirs],
            None if allowlist is None else dict(allowlist),
        )

    def _new_benchmark_gateway(self, l3_strategy: str):
        """Create an isolated gateway for one benchmark strategy."""
        config = self._benchmark_config()
        config["config"]["l3_strategy"] = l3_strategy
        return type(self)._from_benchmark_config(config)

    def _require_loaded_dynamic_pii(self, categories: list[str]):
        """Raise instead of silently returning no `dynamic-pii` result when its model is not loaded."""
        if "dynamic-pii" not in categories:
            return
        l3 = self.runtime_readiness()["l3"]
        if l3["state"] == "not_ready":
            reasons = "; ".join(failure["message"] for failure in l3["failures"])
            raise RuntimeError(
                f"dynamic-pii needs its L3 model loaded; call warmup() before scanning ({reasons})"
            )

    def scan_category(self, category: str, text: str) -> list[dict]:
        """Scan text with a single category."""
        self._require_loaded_dynamic_pii([category])
        results = self.rust_gateway.scan_category(category, text)
        return [_to_dict(r) for r in results]

    def scan_categories(self, categories: list[str], text: str) -> list[dict]:
        """Scan text with a caller-provided category subset."""
        self._require_loaded_dynamic_pii(categories)
        results = self.rust_gateway.scan_categories(categories, text)
        return [_to_dict(r) for r in results]

    def enqueue(
        self,
        text: str,
        categories: list[str] | None = None,
        execution_gates: ScanGates | None = None,
        metadata: dict | None = None,
        ntdb_operating_point: str | None = None,
        chunk_overlap_tokens: int = 0,
    ) -> str:
        """Queue one scan request and return its request id.

        This method does not return scan results. A background gateway worker
        executes L1/L2 and a separate worker executes promoted L3 jobs.
        `consume_events()` yields result and terminal events from the shared
        queue. Every event includes its `request_id`. `execution_gates`, when
        provided, applies only to this request. `ntdb_operating_point`, when
        provided, overrides the gateway final-decision threshold profile for this
        request and does not change L3 promotion.
        `chunk_overlap_tokens` controls classifier chunk overlap for this request
        and must be between 0 and 64.
        """
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError("metadata must be a dict")
        return self.rust_gateway.enqueue(
            text,
            categories,
            _execution_gates_json(execution_gates),
            None if metadata is None else json.dumps(metadata),
            ntdb_operating_point,
            chunk_overlap_tokens,
        )

    def consume_events(self, timeout: float | None = None):
        """Yield result and terminal events from the shared queue until timeout."""
        while True:
            event = self.consume_next_event(timeout)
            if event is None:
                return
            yield event

    def consume_next_event(self, timeout: float | None = None) -> dict | None:
        """Return the next result or terminal event from the shared queue."""
        event = self.rust_gateway.consume_next_event(timeout)
        return None if event is None else _event_to_dict(event)

    def has_request(self, request_id: str) -> bool:
        """Return whether work or an unconsumed terminal event exists for a request."""
        return self.rust_gateway.has_request(request_id)

    def request_state(self, request_id: str) -> dict | None:
        """Return lifecycle state until the terminal event is consumed."""
        state = self.rust_gateway.request_state(request_id)
        return None if state is None else _request_state_to_dict(state)

    def is_finished(self, request_id: str) -> bool | None:
        """Return whether a known request is terminal."""
        return self.rust_gateway.is_finished(request_id)

    def runtime_readiness(self) -> dict:
        """Return L1/L2/L3 readiness using the request failure schema."""
        readiness = self.rust_gateway.runtime_readiness()
        return {
            "l1": _level_readiness_to_dict(readiness.l1),
            "l2": _level_readiness_to_dict(readiness.l2),
            "l3": _level_readiness_to_dict(readiness.l3),
        }

    def run_local_benchmark(
        self,
        output_dir: str = "benchmark",
        limit_per_pipeline: int | None = None,
        load_requests: int = 200,
        print_summary: bool = True,
        native_l1_iterations: int = 200,
    ) -> dict:
        """Benchmark this gateway against the sample data shipped with the package.

        Runs every benchmark phase once with `dedicated` L3 and once with
        `multi` L3. Each strategy gets its own subdirectory below
        `output_dir`, plus a combined root `BENCHMARK.md` and
        `benchmark_result.json`:
        one complete queued response (`example_result.json`), benign false
        positives (`benign_result.json`), labelled classifier
        validation (`classifier_result.json`), exact-span GLiNER NER quality
        by document/tool context and joint L2/L3/GLiNER latency plus process
        peak RSS (`dynamic_pii_result.json`), native L1
        scans on exact 10 KiB texts (`native_l1_result.json`), and queue load tests where one
        producer enqueues texts as a burst and at a paced 10 req/s while one consumer drains
        the shared result queue (`load_result.json`). Injection L2/L3 plus GLiNER latency and
        peak RSS run in a fresh process containing only those two categories. Only pipelines whose
        category is configured on this gateway are evaluated; the L3 load
        scenario runs only when `max_level` is `l3`. Call `warmup()` first.

        Note: the classifier and native L1 phases temporarily replace the
        execution gate matrix to isolate individual scanners and reset it to
        the shared default matrix afterwards.
        """
        from . import benchmark

        return benchmark.run_local_benchmark(
            self,
            output_dir=output_dir,
            limit_per_pipeline=limit_per_pipeline,
            load_requests=load_requests,
            native_l1_iterations=native_l1_iterations,
            print_summary=print_summary,
        )
