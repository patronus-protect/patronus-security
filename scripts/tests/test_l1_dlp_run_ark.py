from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = load("l1_dlp_run_ark", ROOT / "scripts" / "l1_dlp" / "run_ark.py")
BASELINES = load("l1_dlp_run_baselines", ROOT / "scripts" / "l1_dlp" / "run_baselines.py")
BENIGN_CODE = load("l1_dlp_benign_code", ROOT / "scripts" / "l1_dlp" / "benign_code.py")

sys.path.insert(0, str(ROOT / "python"))


# Values are assembled at test time from obviously synthetic pieces; none is a real token,
# and none carries a valid provider checksum.
PASSWORD = "Qw7" + "zX4" + "Lp9" + "Vb2"
TOKEN = "tok_" + "Zq7Xw2Vt" * 3


def matched(rule_id: str, text: str, start: int, end: int) -> dict:
    """A ``matched_rules`` entry as the native detectors put it into layer details."""
    return {
        "rule_id": rule_id,
        "start_byte": len(text[:start].encode("utf-8")),
        "end_byte": len(text[:end].encode("utf-8")),
        "components": [],
    }


def span(label: str, text: str, start: int, end: int, score: float = 1.0) -> dict:
    """An evidence span as ``SecurityGateway.scan_category`` returns it."""
    prefix = len(text[:start].encode("utf-8"))
    return {
        "label": label,
        "text": text[start:end],
        "score": score,
        "start_byte": prefix,
        "end_byte": prefix + len(text[start:end].encode("utf-8")),
        "start_char": start,
        "end_char": end,
    }


def result(model: str, spans: list[dict], rules: list[dict], class_name: str | None = None) -> dict:
    details = {"matched_rules": rules} if rules else {}
    name = class_name or (spans[0]["label"] if spans else "safe")
    return {
        "category": "dlp",
        "class_name": name,
        "model": model,
        "layers": [{"layer_type": "native", "class_name": name, "details": details}],
        "evidence_spans": spans,
    }


class FakeGateway:
    """Records calls and returns canned scan results per text."""

    def __init__(self, results_by_text: dict[str, list[dict]]):
        self.results_by_text = results_by_text
        self.calls = []

    def scan_category(self, category: str, text: str) -> list[dict]:
        self.calls.append((category, text))
        return self.results_by_text.get(text, [result("native:dlp", [], [])])


# "Grüße 😀" puts multi-byte and non-BMP code points before the values.
ENV_TEXT = f'# Grüße 😀\nDB_PASSWORD="{PASSWORD}"\n'
PW_START = ENV_TEXT.index(PASSWORD)
PW_END = PW_START + len(PASSWORD)
LOG_TEXT = f"2026-10-15 INFO auth token={TOKEN} accepted"
TOKEN_START = LOG_TEXT.index(TOKEN)
TOKEN_END = TOKEN_START + len(TOKEN)


def rows() -> list[dict]:
    return [
        {"id": "env", "format": "env", "text": ENV_TEXT},
        {"id": "log", "format": "log", "text": LOG_TEXT},
        {"id": "neg", "format": "env", "text": "DB_PASSWORD=${DB_PASSWORD}\n"},
    ]


def fake_results() -> dict[str, list[dict]]:
    return {
        ENV_TEXT: [
            result(
                "native:dlp",
                [span("CREDENTIAL", ENV_TEXT, PW_START, PW_END)],
                [
                    # A same-range match of another rule in another group that the engine
                    # dropped, and the rule that produced the CREDENTIAL span.
                    matched("dlp_bearer_token", ENV_TEXT, PW_START, PW_END),
                    matched("dlp_env_var_secret", ENV_TEXT, PW_START, PW_END),
                ],
            ),
            result("native:sensitive_material", [], []),
        ],
        LOG_TEXT: [
            result(
                "native:dlp",
                [
                    # Cross-label overlap: one range, two groups, two rules.
                    span("CREDENTIAL", LOG_TEXT, TOKEN_START, TOKEN_END, 0.8),
                    span("SECRET_TOKEN", LOG_TEXT, TOKEN_START, TOKEN_END, 0.9),
                    span("SECRET_TOKEN", LOG_TEXT, TOKEN_START, TOKEN_END, 0.5),  # duplicate
                ],
                [
                    matched("dlp_bearer_token", LOG_TEXT, TOKEN_START, TOKEN_END),
                    matched("dlp_credential_in_url", LOG_TEXT, TOKEN_START, TOKEN_END),
                ],
            ),
        ],
    }


def entity_index() -> dict:
    return MODULE.load_rule_index()


def write_jsonl(path: Path, data: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in data), encoding="utf-8")


# ── Rule index and engine profile ─────────────────────────────────────────


def test_rule_index_maps_every_ark_rule_to_entity_and_group():
    import yaml

    data = yaml.safe_load(BASELINES.ENTITY_MAP_PATH.read_text(encoding="utf-8"))
    index = entity_index()
    expected = {rule: entity for entity in data["entities"] for rule in entity.get("ark") or []}
    assert set(index) == set(expected)
    for rule, entity in expected.items():
        groups = [entity["group"]] if entity.get("group") else []
        assert index[rule] == ([entity["id"]], groups)
    assert index["dlp_env_var_secret"][1] == ["CREDENTIAL"]
    # The baseline index is unchanged by the shared loader.
    baseline = BASELINES.load_entity_index()
    assert set(baseline) == set(BASELINES.TOOLS)


def test_execution_gates_keep_defaults_unless_rules_are_enabled():
    index = entity_index()
    assert MODULE.execution_gates([], index) is None
    gates = MODULE.execution_gates(["dlp_sql_statement"], index)
    assert gates == {"rules": {"dlp_sql_statement": True}}
    everything = MODULE.execution_gates(sorted(index), index)
    assert set(everything["rules"]) == set(index)
    assert all(everything["rules"].values())
    with pytest.raises(ValueError, match="unknown ARK DLP rule"):
        MODULE.execution_gates(["dlp_does_not_exist"], index)


def test_execution_gates_add_a_scored_dlp_mode_only_when_asked():
    index = entity_index()
    assert MODULE.execution_gates([], index, "strict") is None
    assert MODULE.execution_gates([], index, "recall") == {"dlp_mode": "recall"}
    assert MODULE.execution_gates(["dlp_sql_statement"], index, "balanced") == {
        "rules": {"dlp_sql_statement": True}, "dlp_mode": "balanced"}
    with pytest.raises(ValueError, match="unknown dlp_mode"):
        MODULE.execution_gates([], index, "precision")


# ── Prediction rows ───────────────────────────────────────────────────────


def test_predict_rows_attribute_rule_group_entities_and_score():
    gateway = FakeGateway(fake_results())
    predictions, stats = MODULE.predict_rows(rows(), gateway, entity_index())
    assert [call for call in gateway.calls] == [("dlp", row["text"]) for row in rows()]
    assert [row["id"] for row in predictions] == ["env", "log", "neg"]
    assert predictions[0] == {
        "id": "env",
        "tool": "ark",
        "evidence_spans": [
            {
                "start_char": PW_START,
                "end_char": PW_END,
                "rule_id": "dlp_env_var_secret",
                "label": "ark.dlp_env_var_secret",
                "group": "CREDENTIAL",
                "entities": entity_index()["dlp_env_var_secret"][0],
                "groups": ["CREDENTIAL"],
                "score": 1.0,
                "normalization": [],
            }
        ],
    }
    # Offsets are code points: the comment line has more bytes than characters.
    assert ENV_TEXT[PW_START:PW_END] == PASSWORD
    log = predictions[1]["evidence_spans"]
    assert [(s["rule_id"], s["group"], s["score"]) for s in log] == [
        ("dlp_bearer_token", "SECRET_TOKEN", 0.9),
        ("dlp_credential_in_url", "CREDENTIAL", 0.8),
    ]
    assert all(isinstance(s["score"], float) for s in log)
    assert predictions[2]["evidence_spans"] == []
    # Predictions never carry source or secret text.
    encoded = json.dumps(predictions)
    assert PASSWORD not in encoded and TOKEN not in encoded
    assert stats["findings"] == {
        "dlp_bearer_token": 1,
        "dlp_credential_in_url": 1,
        "dlp_env_var_secret": 1,
    }
    assert stats["groups"] == {"CREDENTIAL": 2, "SECRET_TOKEN": 1}
    assert stats["unmapped"] == {} and stats["group_mismatch"] == {}


def test_same_range_same_group_takes_the_first_matched_rule():
    text = f"api_key={TOKEN}"
    start = text.index(TOKEN)
    gateway = FakeGateway(
        {
            text: [
                result(
                    "native:dlp",
                    [span("CREDENTIAL", text, start, len(text))],
                    [
                        matched("dlp_env_var_secret", text, start, len(text)),
                        matched("dlp_generic_credential_assignment", text, start, len(text)),
                    ],
                )
            ]
        }
    )
    predictions, _ = MODULE.predict_rows([{"id": "a", "text": text}], gateway, entity_index())
    assert [s["rule_id"] for s in predictions[0]["evidence_spans"]] == ["dlp_env_var_secret"]


def test_same_range_takes_the_rule_that_was_not_suppressed():
    # K08: the engine keeps the higher-tier match of a range and marks the other one
    # with suppressed_by; matched_rules stays in rule order.
    text = f"token: https://token:{TOKEN}@bitbucket.org/acme/repo.git"
    start = text.index(TOKEN)
    end = start + len(TOKEN)
    loser = matched("dlp_generic_credential_assignment", text, start, end)
    loser["suppressed_by"] = "dlp_url_userinfo_password"
    gateway = FakeGateway(
        {
            text: [
                result(
                    "native:dlp",
                    [span("CREDENTIAL", text, start, end)],
                    [loser, matched("dlp_url_userinfo_password", text, start, end)],
                )
            ]
        }
    )
    predictions, _ = MODULE.predict_rows([{"id": "a", "text": text}], gateway, entity_index())
    assert [s["rule_id"] for s in predictions[0]["evidence_spans"]] == ["dlp_url_userinfo_password"]


def test_rules_join_within_their_own_scanner_result():
    text = f"scp ~/.ssh/id_rsa backup:/tmp {PASSWORD}"
    path_end = text.index(" backup")
    gateway = FakeGateway(
        {
            text: [
                result("native:dlp", [], [matched("dlp_password_assignment", text, 4, path_end)]),
                result(
                    "native:secret_transfer",
                    [span("secret_transfer", text, 4, path_end)],
                    [matched("dlp_secret_transfer", text, 4, path_end)],
                ),
            ]
        }
    )
    predictions, stats = MODULE.predict_rows([{"id": "a", "text": text}], gateway, entity_index())
    (item,) = predictions[0]["evidence_spans"]
    assert item["rule_id"] == "dlp_secret_transfer"
    assert item["group"] == "secret_transfer"
    # Out-of-scope action rules have no benchmark group; that is not a mismatch.
    assert item["groups"] == []
    assert stats["group_mismatch"] == {}


def test_unmapped_rule_and_group_mismatch_are_counted_not_hidden():
    text = f"x={TOKEN}"
    start = text.index(TOKEN)
    gateway = FakeGateway(
        {
            text: [
                result(
                    "native:dlp",
                    [span("API_KEY", text, start, len(text)), span("PAYMENT_KEY", text, 0, 1)],
                    [
                        matched("dlp_future_rule", text, start, len(text)),
                        matched("dlp_env_var_secret", text, 0, 1),
                    ],
                )
            ]
        }
    )
    predictions, stats = MODULE.predict_rows([{"id": "a", "text": text}], gateway, entity_index())
    spans = {s["rule_id"]: s for s in predictions[0]["evidence_spans"]}
    assert spans["dlp_future_rule"]["entities"] == [] and spans["dlp_future_rule"]["groups"] == []
    assert spans["dlp_future_rule"]["group"] == "API_KEY"
    # The engine's group stays authoritative for the span; the map is flagged as stale.
    assert spans["dlp_env_var_secret"]["group"] == "PAYMENT_KEY"
    assert stats["unmapped"] == {"dlp_future_rule": 1}
    assert stats["group_mismatch"] == {"dlp_env_var_secret:PAYMENT_KEY": 1}


def test_predict_rows_reject_bad_input_spans_and_scanner_errors():
    index = entity_index()
    with pytest.raises(ValueError, match="unique non-empty id"):
        MODULE.predict_rows([{"text": "x"}], FakeGateway({}), index)
    with pytest.raises(ValueError, match="unique non-empty id"):
        MODULE.predict_rows([{"id": "a", "text": "x"}] * 2, FakeGateway({}), index)
    with pytest.raises(ValueError, match="requires text"):
        MODULE.predict_rows([{"id": "a"}], FakeGateway({}), index)

    def one(text: str, item: dict, rules: list[dict]) -> None:
        gateway = FakeGateway({text: [result("native:dlp", [item], rules)]})
        MODULE.predict_rows([{"id": "a", "text": text}], gateway, index)

    with pytest.raises(ValueError, match="outside text"):
        one("abc", {**span("CREDENTIAL", "abc", 1, 3), "end_char": 9}, [])
    with pytest.raises(ValueError, match="does not match"):
        one("abc", {**span("CREDENTIAL", "abc", 1, 3), "text": "zz"}, [])
    no_score = span("CREDENTIAL", "abc", 1, 3)
    del no_score["score"]
    with pytest.raises(ValueError, match="score"):
        one("abc", no_score, [matched("dlp_env_var_secret", "abc", 1, 3)])
    with pytest.raises(ValueError, match="no matched rule"):
        one("abc", span("CREDENTIAL", "abc", 1, 3), [matched("dlp_env_var_secret", "abc", 0, 3)])
    error = {
        "category": "dlp",
        "class_name": "error",
        "model": "native:dlp",
        "layers": [{"layer_type": "scanner_error", "class_name": "error", "details": {}}],
        "evidence_spans": [],
    }
    with pytest.raises(RuntimeError, match="native:dlp"):
        MODULE.predict_rows([{"id": "a", "text": "abc"}], FakeGateway({"abc": [error]}), index)


def test_prediction_rows_share_the_baseline_format():
    predictions, _ = MODULE.predict_rows(rows(), FakeGateway(fake_results()), entity_index())
    baseline_rows, _ = BASELINES.predict(
        "gitleaks",
        rows(),
        [BASELINES.Finding(doc=0, rule_id="generic-api-key", secret=PASSWORD, line=2)],
        BASELINES.load_entity_index(),
    )
    assert set(predictions[0]) == set(baseline_rows[0]) == {"id", "tool", "evidence_spans"}
    ark_span = predictions[0]["evidence_spans"][0]
    baseline_span = baseline_rows[0]["evidence_spans"][0]
    assert set(baseline_span) <= set(ark_span)
    assert set(ark_span) - set(baseline_span) == {"group", "score"}
    assert (ark_span["start_char"], ark_span["end_char"]) == (
        baseline_span["start_char"],
        baseline_span["end_char"],
    )
    assert ark_span["label"] == f"ark.{ark_span['rule_id']}"
    assert baseline_span["label"] == f"gitleaks.{baseline_span['rule_id']}"


def test_predictions_feed_the_fp_per_mb_metric():
    predictions, _ = MODULE.predict_rows(rows(), FakeGateway(fake_results()), entity_index())
    documents = {
        row["id"]: {"bytes": len(row["text"].encode("utf-8")), "kind": "code", "repo": "fixture"}
        for row in rows()
    }
    report = BENIGN_CODE.fp_per_mb(documents, predictions)
    assert report["fp"] == 2  # the log token counts once although two rules report it
    assert set(report["by_rule"]) == {
        "dlp_env_var_secret",
        "dlp_bearer_token",
        "dlp_credential_in_url",
    }


# ── run() and CLI ─────────────────────────────────────────────────────────


def test_run_writes_byte_identical_predictions_and_metadata(tmp_path):
    source = tmp_path / "rows.jsonl"
    write_jsonl(source, rows())
    outputs = []
    for attempt in ("a", "b"):
        out = tmp_path / f"{attempt}.jsonl"
        meta_path = tmp_path / f"{attempt}.meta.json"
        MODULE.run(
            source,
            out,
            meta_path,
            gateway=FakeGateway(fake_results()),
            build={"native_sha256": "0" * 64, "package_version": "0.0.0"},
            enabled_rules=["dlp_sql_statement"],
        )
        outputs.append((out.read_bytes(), meta_path.read_bytes()))
    assert outputs[0] == outputs[1]
    meta = json.loads(outputs[0][1])
    assert meta["schema"] == "ark-l1-dlp-predictions-v1"
    assert meta["tool"] == "ark"
    assert meta["engine"] == {
        "categories": ["dlp"],
        "max_level": "l1",
        "enabled_rules": ["dlp_sql_statement"],
    }
    assert meta["build"] == {"native_sha256": "0" * 64, "package_version": "0.0.0"}
    assert meta["rows"] == 3 and meta["spans"] == 3
    assert meta["span_unit"] == "unicode_code_point"
    assert meta["entity_map_sha256"] == BASELINES.sha256_bytes(BASELINES.ENTITY_MAP_PATH.read_bytes())
    assert meta["input_sha256"] == BASELINES.sha256_bytes(source.read_bytes())
    assert meta["output_sha256"] == BASELINES.sha256_bytes(outputs[0][0])
    assert meta["groups"] == {"CREDENTIAL": 2, "SECRET_TOKEN": 1}
    assert "time" not in json.dumps(meta)
    lines = outputs[0][0].decode("utf-8").splitlines()
    assert [json.loads(line)["id"] for line in lines] == ["env", "log", "neg"]


def test_run_records_a_scored_mode_and_the_cli_rejects_unknown_modes(tmp_path, capsys):
    source = tmp_path / "rows.jsonl"
    write_jsonl(source, rows())
    meta = MODULE.run(source, tmp_path / "out.jsonl", tmp_path / "out.meta.json", gateway=FakeGateway(fake_results()),
                      build={"native_sha256": "0" * 64, "package_version": "0.0.0"}, mode="recall")
    assert meta["engine"]["dlp_mode"] == "recall"
    with pytest.raises(SystemExit):
        MODULE.main(["--input", str(source), "--output", str(tmp_path / "x.jsonl"), "--dlp-mode", "fast"])
    assert "invalid choice" in capsys.readouterr().err


def native_available() -> bool:
    try:
        return importlib.util.find_spec("patronus_ark._patronus_ark") is not None
    except ImportError:
        return False


needs_native = pytest.mark.skipif(not native_available(), reason="patronus_ark native binding is not built")


@needs_native
def test_real_binding_attributes_generated_carrier_secrets(tmp_path):
    from patronus_ark.dlp_synth import carriers

    rules = ["dlp_github_pat", "dlp_aws_access_key", "dlp_stripe_key", "dlp_private_key_block", "dlp_jwt_token"]
    data = carriers.build("dev", 41, rules=rules, variants=["positive", "placeholder", "env_ref"])
    languages = {row["language"] for row in data}
    assert languages == {"de", "en"}
    source = tmp_path / "carriers.jsonl"
    write_jsonl(source, data)
    digests = []
    for attempt in ("a", "b"):
        out = tmp_path / f"{attempt}.jsonl"
        meta = MODULE.run(source, out, tmp_path / f"{attempt}.meta.json")
        digests.append(meta["output_sha256"])
    assert digests[0] == digests[1]
    assert len(meta["build"]["native_sha256"]) == 64
    assert meta["engine"]["enabled_rules"] == []
    index = entity_index()
    predicted = {row["id"]: row for row in map(json.loads, out.read_text(encoding="utf-8").splitlines())}
    attributed = 0
    for row in data:
        for item in predicted[row["id"]]["evidence_spans"]:
            assert 0 <= item["start_char"] < item["end_char"] <= len(row["text"])
            assert 0.0 < item["score"] <= 1.0
            assert item["rule_id"] in index
            assert item["groups"] in ([], [item["group"]])
        if row["variant"] != "positive":
            continue
        (gold,) = row["entities"]
        hits = {
            item["rule_id"]
            for item in predicted[row["id"]]["evidence_spans"]
            if (item["start_char"], item["end_char"]) == (gold["start"], gold["end"])
            and item["group"] == gold["label"]
        }
        attributed += row["rule_id"] in hits
    positives = sum(row["variant"] == "positive" for row in data)
    # Provider-prefixed values in carriers are found on the exact value span and
    # attributed to the rule they were generated for.
    assert attributed >= positives * 0.8, (attributed, positives)


@needs_native
def test_real_binding_respects_default_off_content_rules(tmp_path):
    text = "SELECT id, email FROM users WHERE id = 1;\nUPDATE users SET name = 'x' WHERE id = 2;\n"
    source = tmp_path / "rows.jsonl"
    write_jsonl(source, [{"id": "sql", "text": text}])
    out = tmp_path / "ark.jsonl"
    assert MODULE.main(["--input", str(source), "--output", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["evidence_spans"] == []
    assert json.loads((tmp_path / "ark.meta.json").read_text(encoding="utf-8"))["rows"] == 1
    sql_rules = [rule for rule, (_, groups) in entity_index().items() if "SQL" in " ".join(groups).upper()]
    assert sql_rules
    enabled = tmp_path / "enabled.jsonl"
    args = ["--input", str(source), "--output", str(enabled)]
    for rule in sql_rules:
        args += ["--enable-rule", rule]
    assert MODULE.main(args) == 0
    spans = json.loads(enabled.read_text(encoding="utf-8"))["evidence_spans"]
    assert spans and {item["rule_id"] for item in spans} <= set(sql_rules)
    meta = json.loads((tmp_path / "enabled.meta.json").read_text(encoding="utf-8"))
    assert meta["engine"]["enabled_rules"] == sorted(sql_rules)


@needs_native
def test_real_binding_scores_spans_in_the_recall_mode(tmp_path):
    from patronus_ark.dlp_synth import recipes

    # K04: a wallet key without a credential term (only the F01 key context "signer") scores
    # 0.40 (kept by recall, below balanced); next to a digest term it is dropped, since F01
    # also in strict; a field-bound password scores 0.60. Strict scores 1.0.
    hex_value = lambda seed: recipes.generate("eth_private_key_hex", seed)  # noqa: E731
    data = [
        {"id": "bare", "text": f"signer {hex_value(1)} ok"},
        {"id": "counter", "text": f"tx hash: {hex_value(2)}"},
        {"id": "field", "text": "password: Sommer2026!x"},
    ]
    source = tmp_path / "rows.jsonl"
    write_jsonl(source, data)
    scores = {}
    for mode in ("strict", "balanced", "recall"):
        out = tmp_path / f"{mode}.jsonl"
        meta = MODULE.run(source, out, tmp_path / f"{mode}.meta.json", mode=mode)
        assert meta["engine"].get("dlp_mode", "strict") == mode
        scores[mode] = {row["id"]: [span["score"] for span in row["evidence_spans"]]
                        for row in map(json.loads, out.read_text(encoding="utf-8").splitlines())}
    assert scores["strict"] == {"bare": [1.0], "counter": [], "field": [1.0]}
    assert scores["balanced"] == {"bare": [], "counter": [], "field": [0.6]}
    assert scores["recall"] == {"bare": [0.4], "counter": [], "field": [0.6]}
