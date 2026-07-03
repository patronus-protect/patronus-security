from ._patronus_security import SecurityGateway as RustSecurityGateway
import json


def _decode_json_object(value):
    try:
        decoded = json.loads(value or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _to_dict(result):
    return {
        "category": result.category,
        "class": result.class_name,
        "class_name": result.class_name,
        "confidence": result.confidence,
        "level": result.level,
        "model": result.model,
        "duration_ms": result.duration_ms,
        "layers": [
            {
                "level": layer.level,
                "type": layer.layer_type,
                "layer_type": layer.layer_type,
                "class": layer.class_name,
                "class_name": layer.class_name,
                "confidence": layer.confidence,
                "matched": layer.matched,
                "duration_ms": layer.duration_ms,
                "thresholds": _decode_json_object(layer.thresholds_json),
                "details": _decode_json_object(layer.details_json),
            }
            for layer in result.layers
        ],
    }


def _execution_gates_json(execution_gates):
    if execution_gates is None:
        return None
    if not isinstance(execution_gates, dict):
        raise ValueError("execution_gates must be a dict")

    normalized = {"levels": {}, "models": {}}
    levels = execution_gates.get("levels", {})
    models = execution_gates.get("models", execution_gates.get("model_areas", {}))
    tool_classifier = execution_gates.get("tool_classifier", {})
    l3_policy = execution_gates.get("l3")

    if not isinstance(levels, dict):
        raise ValueError("execution_gates['levels'] must be a dict")
    if not isinstance(models, dict):
        raise ValueError("execution_gates['models'] must be a dict")
    if tool_classifier and not isinstance(tool_classifier, dict):
        raise ValueError("execution_gates['tool_classifier'] must be a dict")
    levels = dict(levels)
    models = dict(models)
    tool_classifier = dict(tool_classifier)

    for key, value in execution_gates.items():
        lowered = str(key).lower()
        if lowered in {"l1", "l2"} or (lowered == "l3" and isinstance(value, bool)):
            levels[key] = value

    for key, value in levels.items():
        if not isinstance(value, bool):
            raise ValueError(f"execution_gates level {key!r} must be a bool")
        normalized["levels"][str(key).lower()] = value
    for key, value in models.items():
        if not isinstance(value, bool):
            raise ValueError(f"execution_gates model {key!r} must be a bool")
        normalized["models"][str(key)] = value
    for key, value in tool_classifier.items():
        if not isinstance(value, bool):
            raise ValueError(f"execution_gates tool_classifier {key!r} must be a bool")
        lowered = str(key).lower()
        valid_areas = {
            "description",
            "descriptions",
            "execution",
            "executions",
            "prompt",
            "prompts",
        }
        if lowered not in valid_areas:
            raise ValueError(
                "execution_gates['tool_classifier'] keys must be description, execution, or prompt"
            )
        canonical = {
            "descriptions": "description",
            "executions": "execution",
            "prompts": "prompt",
        }.get(lowered, lowered)
        normalized["models"][f"tool_classifier.{canonical}"] = value
    if l3_policy is not None and not isinstance(l3_policy, bool):
        if not isinstance(l3_policy, dict):
            raise ValueError("execution_gates['l3'] must be a dict or bool")
        normalized["l3"] = l3_policy

    return json.dumps(normalized)


class PatronusSecurity:
    """Python gateway for Patronus Security scanners.

    Args:
        categories: Scanner categories to use for `scan_all`.
        max_level: Maximum scanner level: `l1`, `l2`, or `l3`.
        use_dir: Optional asset cache root. Defaults to the platform cache
            directory plus `patronus_security`. Prefer `model_dir` in new
            code.
        model_dir: Public alias for the asset cache root. Pass either
            `model_dir` or `use_dir`, not both.
        download_files: Whether `warmup()` may download missing model assets.
        download_categories: Optional category allowlist for asset downloads.
            When omitted, every configured category may download if
            `download_files` is true.
        execution_gates: Optional scan execution matrix. Use
            `{"levels": {"l1": True, "l2": False, "l3": False},
            "models": {"native:mcp_runtime_risk": False}}` to disable
            levels or model/native scanner areas for subsequent scan calls.
            For `tool_classifier`, use
            `{"tool_classifier": {"description": False, "execution": True,
            "prompt": False}}` to gate its subpipelines. Unspecified gates
            default to enabled.
        onnx_batch_mode: `lazy_batches` keeps per-text ONNX execution;
            `tensor_batch` executes L3 fallbacks as one ONNX tensor batch
            when using batch APIs.
        execution_backend: `auto`, `cpu`, `gpu`, `coreml`, `cuda`,
            `directml`, or `tensorrt`. Backend defaults choose lazy L3 on
            CPU/auto and tensor batches on accelerator backends unless
            `onnx_batch_mode` is explicitly set.
    """

    def __init__(
        self,
        categories: list[str],
        max_level: str = "l2",
        use_dir: str = None,
        model_dir: str = None,
        download_files: bool = True,
        download_categories: list[str] | None = None,
        execution_gates: dict | None = None,
        onnx_batch_mode: str = "backend_default",
        execution_backend: str = "auto",
    ):
        if use_dir is not None and model_dir is not None:
            raise ValueError("Pass only one of use_dir or model_dir")
        resolved_model_dir = model_dir if model_dir is not None else use_dir
        self.rust_gateway = RustSecurityGateway(
            categories,
            max_level,
            use_dir=resolved_model_dir,
            download_files=download_files,
            download_categories=download_categories,
            execution_gates_json=_execution_gates_json(execution_gates),
            onnx_batch_mode=onnx_batch_mode,
            execution_backend=execution_backend,
        )

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

    def scan_all(self, text: str) -> list[dict]:
        """Scan text with every category configured on this gateway."""
        results = self.rust_gateway.scan_all(text)
        return [_to_dict(r) for r in results]

    def set_execution_gates(self, execution_gates: dict | None):
        """Replace the gate matrix used by subsequent scan calls.

        Pass `None` to reset to the default all-enabled matrix. The matrix
        accepts `levels` and `models` dictionaries; model keys match result
        `model` values such as `native:mcp_runtime_risk`.
        """
        self.rust_gateway.set_execution_gates(_execution_gates_json(execution_gates))

    def set_onnx_batch_mode(self, mode: str):
        """Replace the ONNX batch mode for subsequent batch calls.

        `lazy_batches` preserves the per-text ONNX execution path.
        `tensor_batch` executes L3 fallbacks as one ONNX tensor batch when
        pipelines can batch their fallback texts.
        """
        self.rust_gateway.set_onnx_batch_mode(mode)

    def set_execution_backend(self, backend: str):
        """Replace execution backend and apply its default L3 mode.

        `auto` and `cpu` default to lazy L3 execution. `gpu`, `coreml`,
        `cuda`, `directml`, and `tensorrt` default to tensor batches. Call
        `set_onnx_batch_mode` afterwards to override.
        """
        self.rust_gateway.set_execution_backend(backend)

    def set_long_text_policy(
        self,
        enabled: bool = True,
        no_full_l2_byte_limit: int = 1024,
        chunk_size_bytes: int = 256,
        overlap_bytes: int = 96,
        verify_non_benign_l2: bool = True,
    ):
        """Replace long-text routing policy for model-backed pipelines.

        Full-text L1 always runs first. If L1 returns a non-benign result,
        the pipeline can stop there. If L1 is benign and the text is at or
        above `no_full_l2_byte_limit`, full-text L2 is skipped and the text
        is evaluated through overlapping L1/L2 chunks instead. Chunks with
        unresolved or non-benign L2 decisions are then verified by L3 when
        L3 is enabled.
        """
        self.rust_gateway.set_long_text_policy(
            enabled,
            no_full_l2_byte_limit,
            chunk_size_bytes,
            overlap_bytes,
            verify_non_benign_l2,
        )

    def scan_category(self, category: str, text: str) -> list[dict]:
        """Scan text with a single category."""
        results = self.rust_gateway.scan_category(category, text)
        return [_to_dict(r) for r in results]

    def scan_categories(self, categories: list[str], text: str) -> list[dict]:
        """Scan text with a caller-provided category subset."""
        results = self.rust_gateway.scan_categories(categories, text)
        return [_to_dict(r) for r in results]

    def enqueue(self, text: str, categories: list[str] | None = None) -> str:
        """Queue one scan request and return its request id.

        `consume_results(request_id)` yields complete Result-Schema dicts as
        soon as the configured category scan for that request finishes.
        """
        return self.rust_gateway.enqueue(text, categories)

    def consume_results(self, request_id: str, timeout: float | None = None):
        """Yield queued complete scan results for one request id.

        Raises:
            KeyError: If the request id is unknown or already consumed.
        """
        while True:
            result = self.rust_gateway.consume_next_result(request_id, timeout)
            if result is None:
                return
            yield _to_dict(result)

    def has_request(self, request_id: str) -> bool:
        """Return whether a queued request is still active in the Rust aggregator."""
        return self.rust_gateway.has_request(request_id)

SecurityGateway = PatronusSecurity
