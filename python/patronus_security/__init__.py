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
    """

    def __init__(
        self,
        categories: list[str],
        max_level: str = "l2",
        use_dir: str = None,
        model_dir: str = None,
        download_files: bool = True,
        download_categories: list[str] | None = None,
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

    def scan_category(self, category: str, text: str) -> list[dict]:
        """Scan text with a single category."""
        results = self.rust_gateway.scan_category(category, text)
        return [_to_dict(r) for r in results]

    def scan_categories(self, categories: list[str], text: str) -> list[dict]:
        """Scan text with a caller-provided category subset."""
        results = self.rust_gateway.scan_categories(categories, text)
        return [_to_dict(r) for r in results]

    def evaluate(self, pipeline: str, text: str) -> dict:
        """Evaluate one legacy-compatible pipeline for one input.

        Pipeline names are `injection`, `dlp`, `pii`,
        `tool_classifier_prompts`, `tool_classifier_executions`,
        `sensitive_documents_prompts`, `tool_description_prompts`, and
        `user_intent_prompts`.
        """
        return _to_dict(self.rust_gateway.evaluate(pipeline, text))

    def evaluate_batch(self, pipeline: str, texts: list[str]) -> list[dict]:
        """Evaluate one legacy-compatible pipeline for many inputs.

        This is the optimized path for bulk scanning. Native scanners and
        model-backed pipelines use their batch implementations internally
        instead of looping through the public single-input API.
        """
        results = self.rust_gateway.evaluate_batch(pipeline, texts)
        return [_to_dict(r) for r in results]

    def evaluate_injection(self, text: str) -> dict:
        """Evaluate the prompt-injection pipeline for one input."""
        return self.evaluate("injection", text)

    def evaluate_injection_batch(self, texts: list[str]) -> list[dict]:
        """Evaluate the prompt-injection pipeline for many inputs."""
        return self.evaluate_batch("injection", texts)

    def evaluate_dlp(self, text: str) -> dict:
        """Evaluate the DLP pipeline for one input."""
        return self.evaluate("dlp", text)

    def evaluate_dlp_batch(self, texts: list[str]) -> list[dict]:
        """Evaluate the DLP pipeline for many inputs."""
        return self.evaluate_batch("dlp", texts)

    def evaluate_pii(self, text: str) -> dict:
        """Evaluate the PII pipeline for one input."""
        return self.evaluate("pii", text)

    def evaluate_pii_batch(self, texts: list[str]) -> list[dict]:
        """Evaluate the PII pipeline for many inputs."""
        return self.evaluate_batch("pii", texts)


SecurityGateway = PatronusSecurity


def useLibrary(
    categories: list[str],
    maxLevel: str = "l2",
    useDir: str = None,
    modelDir: str = None,
    downloadFiles: bool = True,
    downloadCategories: list[str] | None = None,
) -> PatronusSecurity:
    """Compatibility alias for constructing `PatronusSecurity`.

    New code should use `SecurityGateway` or `PatronusSecurity` with snake_case
    keyword arguments. `modelDir` is the camelCase alias for `model_dir`.
    """
    return PatronusSecurity(
        categories=categories,
        max_level=maxLevel,
        use_dir=useDir,
        model_dir=modelDir,
        download_files=downloadFiles,
        download_categories=downloadCategories,
    )
