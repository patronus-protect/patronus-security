from __future__ import annotations

import importlib.util
import json
import stat
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_dlp" / "run_baselines.py"
SPEC = importlib.util.spec_from_file_location("l1_dlp_run_baselines", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

BASELINES = Path.home() / "ark-dlp" / "baselines" / "bin"
BASELINES_PYTHON = Path.home() / "ark-dlp" / "baselines-venv" / "bin" / "python"


# Values are assembled at test time from obviously synthetic pieces; none is a real token,
# and none carries a valid provider checksum.
def token(prefix: str, body: str, length: int) -> str:
    return prefix + (body * length)[:length]


GH = token("ghp_", "Zq7Xw2Vt", 36)
PASSWORD = "Qw7" + "zX4" + "Lp9" + "Vb2"
PEM_LABEL = "RSA " + "PRIVATE KEY"
PEM = f"-----BEGIN {PEM_LABEL}-----\nMIIBOgIBAAJBAK\nq7Xw2Vt9Zq\n-----END {PEM_LABEL}-----"
JWT_HEAD = "eyJ" + "hbGciOiJub25lIn0" + "." + "eyJ" + "zdWIiOiJ4In0"
JWT = JWT_HEAD + "." + "c2lnbmF0dXJl" + "LXN5bnRo"


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def finding(**kwargs) -> object:
    return MODULE.Finding(**kwargs)


# ── Pins and inputs ────────────────────────────────────────────────────────


def test_pins_match_backlog_and_entity_map():
    import yaml

    assert MODULE.PINS["gitleaks"]["version"] == "8.30.1"
    assert MODULE.PINS["trufflehog"]["version"] == "3.97.9"
    assert MODULE.PINS["detect-secrets"]["version"] == "1.5.0"
    for tool in ("gitleaks", "trufflehog"):
        assert len(MODULE.PINS[tool]["sha256"]) == 64
    baselines = yaml.safe_load(MODULE.ENTITY_MAP_PATH.read_text(encoding="utf-8"))["baselines"]
    assert baselines["gitleaks"]["version"] == MODULE.PINS["gitleaks"]["version"]
    assert baselines["trufflehog"]["version"] == MODULE.PINS["trufflehog"]["version"]
    assert baselines["detect_secrets"]["version"] == MODULE.PINS["detect-secrets"]["version"]


def test_trufflehog_never_verifies_and_gitleaks_uses_no_user_config():
    assert "--no-verification" in MODULE.COMMANDS["trufflehog"]
    assert "--no-update" in MODULE.COMMANDS["trufflehog"]
    assert not any("config" in part for part in MODULE.COMMANDS["gitleaks"])
    env = MODULE.tool_env(Path("/tmp/x"))
    assert set(env) == {"PATH", "HOME", "LC_ALL"}


def test_check_pins_reports_version_and_binary_digest(tmp_path):
    (tmp_path / "gitleaks").write_bytes(b"not the pinned binary")
    installed, problems = MODULE.check_pins(
        ["gitleaks", "detect-secrets"], tmp_path, tmp_path / "python",
        version_of=lambda tool, *_: {"gitleaks": "8.30.1", "detect-secrets": "1.4.0"}[tool],
    )
    assert installed["gitleaks"]["version"] == "8.30.1"
    assert installed["detect-secrets"] == {"version": "1.4.0"}
    assert any("gitleaks: binary sha256" in problem for problem in problems)
    assert any("detect-secrets: pinned 1.5.0, installed 1.4.0" in problem for problem in problems)


def test_read_rows_requires_unique_ids_and_text(tmp_path):
    path = tmp_path / "in.jsonl"
    write_jsonl(path, [{"id": "a", "text": "x"}, {"id": "a", "text": "y"}])
    with pytest.raises(ValueError, match="unique"):
        MODULE.read_rows(path)
    write_jsonl(path, [{"id": "a"}])
    with pytest.raises(ValueError, match="requires text"):
        MODULE.read_rows(path)


@pytest.mark.parametrize(
    "row, expected",
    [
        ({"path": "app/package-lock.json"}, "app/package-lock.json"),
        ({"path": "../etc/passwd", "format": "env"}, ".env"),
        ({"path": "/abs/file.py"}, "document.txt"),
        ({"format": "yaml"}, "config.yaml"),
        ({"format": "code", "code_language": "go"}, "main.go"),
        ({"format": "chat"}, "chat.txt"),
        ({}, "document.txt"),
    ],
)
def test_document_filename_keeps_safe_paths_and_carrier_formats(row, expected):
    assert MODULE.document_filename(row) == expected


def test_materialize_writes_one_directory_per_row_and_maps_back(tmp_path):
    rows = [{"id": "a", "text": "Grüße\r\n", "format": "env"}, {"id": "b", "text": "x", "path": "src/a.py"}]
    MODULE.materialize(rows, tmp_path)
    assert (tmp_path / "000000" / ".env").read_bytes() == "Grüße\r\n".encode("utf-8")
    assert MODULE.document_index(str(tmp_path / "000001" / "src" / "a.py"), tmp_path) == (1, "src/a.py")


# ── Parsers (shapes of the pinned tools' output) ───────────────────────────


def test_parse_gitleaks_converts_byte_columns_and_keeps_match(tmp_path):
    texts = ["x\nGrüße: api_key = \"" + GH + "\"\n"]
    report = [{
        "RuleID": "github-pat", "File": str(tmp_path / "000000" / ".env"),
        "StartLine": 2, "EndLine": 2, "StartColumn": 22, "EndColumn": 61,
        "Match": GH, "Secret": GH,
    }]
    [item] = MODULE.parse_gitleaks(report, tmp_path, texts)
    assert (item.doc, item.rule_id, item.line, item.secret) == (0, "github-pat", 2, GH)
    # byte offset 20 (two umlauts) -> code point 18 = start of the token
    assert item.column == texts[0].split("\n")[1].index(GH)


def test_parse_trufflehog_skips_log_lines_and_keeps_raw_v2(tmp_path):
    lines = [
        json.dumps({"level": "info-0", "msg": "finished scanning"}),
        json.dumps({
            "SourceMetadata": {"Data": {"Filesystem": {"file": str(tmp_path / "000003" / "a.txt"), "line": 4}}},
            "DetectorName": "AWS", "DecoderName": "BASE64", "Raw": "AKIDX", "RawV2": "AKIDXsecret",
        }),
    ]
    [item] = MODULE.parse_trufflehog("\n".join(lines), tmp_path)
    assert (item.doc, item.rule_id, item.line, item.secret) == (3, "AWS", 4, "AKIDX")
    assert item.alternatives == ("AKIDXsecret",)
    assert item.extra == {"decoder": "BASE64"}


def test_parse_detect_secrets_worker_lines(tmp_path):
    lines = [
        json.dumps({"path": "000002/config.yaml", "line": 3, "plugin": "KeywordDetector",
                    "start": 10, "end": 22, "normalization": ["relocated"]}),
        json.dumps({"path": "000002/config.yaml", "line": 4, "plugin": "KeywordDetector",
                    "start": None, "end": None, "normalization": []}),
    ]
    found, missing = MODULE.parse_detect_secrets("\n".join(lines) + "\n", tmp_path)
    assert (found.doc, found.rule_id, found.line, found.secret) == (2, "KeywordDetector", 3, "")
    assert found.located == (10, 22, ("relocated",)) and missing.located is None


# ── Locating and value normalization ───────────────────────────────────────


def test_locate_prefers_reported_line_and_column_hint():
    text = f"a={PASSWORD}\nb={PASSWORD} c={PASSWORD}\n"
    second_line = text.index("\n") + 1
    start, end, steps = MODULE.locate(text, finding(doc=0, rule_id="r", secret=PASSWORD, line=2, column=12))
    assert start == text.rindex(PASSWORD) and steps == []
    start, _, _ = MODULE.locate(text, finding(doc=0, rule_id="r", secret=PASSWORD, line=2))
    assert start == second_line + 2


def test_locate_secret_inside_match_and_fallbacks():
    text = f"secret_key = \"{PASSWORD}\"  # {PASSWORD}\n"
    start, end, _ = MODULE.locate(
        text, finding(doc=0, rule_id="generic-api-key", secret=PASSWORD, line=1, column=0,
                      match=f"secret_key = \"{PASSWORD}\"")
    )
    assert (start, end) == (14, 14 + len(PASSWORD))
    # wrong line -> first occurrence anywhere, flagged
    assert MODULE.locate(text, finding(doc=0, rule_id="r", secret=PASSWORD, line=9))[2] == ["relocated"]
    # re-wrapped multi-line value -> whitespace-tolerant
    flat = PEM.replace("\n", " ")
    assert MODULE.locate(PEM, finding(doc=0, rule_id="PrivateKey", secret=flat, line=1))[:2] == (0, len(PEM))
    # JSON-escaped newlines (TruffleHog reports the unescaped key)
    escaped = "{\"key\": \"" + PEM.replace("\n", "\\n") + "\"}"
    start, end, steps = MODULE.locate(escaped, finding(doc=0, rule_id="PrivateKey", secret=PEM, line=1))
    assert escaped[start:end] == PEM.replace("\n", "\\n") and steps == ["whitespace"]
    # RawV2 when Raw is not in the text; decoded values stay unlocated
    assert MODULE.locate(text, finding(doc=0, rule_id="r", secret="zzz-none", alternatives=(PASSWORD,)))[2] == ["raw_v2"]
    assert MODULE.locate(text, finding(doc=0, rule_id="r", secret="zzz-none")) is None


@pytest.mark.parametrize(
    "text, located, tool, rule, value, steps",
    [
        (f"x = '{PASSWORD}'", f"'{PASSWORD}'", "detect-secrets", "KeywordDetector", PASSWORD, ["trim"]),
        (f"k: \"{PASSWORD}\" ", f": \"{PASSWORD}\" ", "detect-secrets", "ArtifactoryDetector", PASSWORD, ["trim"]),
        (f"DB=postgres://app:{PASSWORD}@db:5432/x", f"postgres://app:{PASSWORD}@db:5432", "trufflehog", "Postgres", PASSWORD, ["url_password"]),
        (f"curl -u admin:{PASSWORD} https://h", f"admin:{PASSWORD}", "gitleaks", "curl-auth-user", PASSWORD, ["user_password"]),
        (f"key:\n{PEM}\n", PEM_LABEL, "detect-secrets", "PrivateKeyDetector", PEM, ["pem_block"]),
        (f"-----BEGIN {PEM_LABEL}-----\n(cut)", PEM_LABEL, "detect-secrets", "PrivateKeyDetector", f"-----BEGIN {PEM_LABEL}-----", ["pem_header"]),
        (f"key:\n{PEM}\n", PEM, "gitleaks", "private-key", PEM, []),
        (f"t={GH}", GH, "gitleaks", "github-pat", GH, []),
        ("pw=YWJj==", "YWJj==", "detect-secrets", "Base64HighEntropyString", "YWJj==", []),
        (f"\"t = \\\"{PASSWORD}\\\"\\n\"", PASSWORD + "\\", "detect-secrets", "Base64HighEntropyString", PASSWORD, ["trim"]),
        (f"ID_TOKEN={JWT}\n", JWT_HEAD, "detect-secrets", "JwtTokenDetector", JWT, ["regex_tail"]),
        (f"ID_TOKEN={JWT}\n", JWT, "gitleaks", "jwt", JWT, []),
    ],
)
def test_refine_to_value_span(text, located, tool, rule, value, steps):
    start = text.index(located)
    new_start, new_end, got = MODULE.refine(text, start, start + len(located), tool, rule)
    assert text[new_start:new_end] == value
    assert got == steps


# ── Predictions ─────────────────────────────────────────────────────────────


def entity_index():
    return {
        "gitleaks": {"github-pat": (["vcs.github.token"], ["SECRET_TOKEN"])},
        "trufflehog": {"Github": (["vcs.github.fine_grained_pat", "vcs.github.token"], ["SECRET_TOKEN"])},
        "detect-secrets": {},
    }


def test_predict_emits_value_spans_in_input_order_without_secret_text():
    rows = [
        {"id": "r1", "text": f"GITHUB_TOKEN={GH}\nGITHUB_TOKEN={GH}\n"},
        {"id": "r2", "text": "nothing here"},
        {"id": "r3", "text": f"pw = \"{PASSWORD}\""},
    ]
    findings = [
        finding(doc=0, rule_id="github-pat", secret=GH, line=2),
        finding(doc=0, rule_id="github-pat", secret=GH, line=1),
        finding(doc=0, rule_id="github-pat", secret=GH, line=1),  # duplicate collapses
        finding(doc=2, rule_id="generic-password", secret=f"\"{PASSWORD}\"", line=1),
        finding(doc=2, rule_id="generic-password", secret="decoded-only", line=1, extra={"decoder": "BASE64"}),
    ]
    predictions, summary = MODULE.predict("gitleaks", rows, findings, entity_index())
    assert [row["id"] for row in predictions] == ["r1", "r2", "r3"]
    spans = predictions[0]["evidence_spans"]
    assert [(s["start_char"], s["end_char"]) for s in spans] == [(13, 13 + len(GH)), (27 + len(GH), 27 + 2 * len(GH))]
    assert spans[0]["label"] == "gitleaks.github-pat"
    assert spans[0]["entities"] == ["vcs.github.token"] and spans[0]["groups"] == ["SECRET_TOKEN"]
    assert predictions[1]["evidence_spans"] == []
    [pw] = predictions[2]["evidence_spans"]
    assert rows[2]["text"][pw["start_char"]:pw["end_char"]] == PASSWORD
    assert pw["entities"] == [] and pw["normalization"] == ["trim"]
    assert summary["unlocated"] == {"generic-password:BASE64": 1}
    assert summary["unmapped"] == {"generic-password": 1}
    assert summary["findings"] == {"generic-password": 2, "github-pat": 3}
    assert summary["spans"] == 3
    encoded = json.dumps(predictions)
    assert GH not in encoded and PASSWORD not in encoded


def test_run_is_byte_identical_and_meta_has_digests(tmp_path):
    rows = [{"id": "a", "text": f"token={GH}\n", "format": "env"}, {"id": "b", "text": "plain"}]
    write_jsonl(tmp_path / "in.jsonl", rows)

    def scan(tool, scan_rows):
        assert tool == "trufflehog" and [row["id"] for row in scan_rows] == ["a", "b"]
        return [
            finding(doc=0, rule_id="Github", secret=GH, line=1, extra={"decoder": decoder})
            for decoder in ("PLAIN", "HTML")
        ]

    outputs = []
    for name in ("one", "two"):
        meta = MODULE.run(
            "trufflehog", tmp_path / "in.jsonl", tmp_path / f"{name}.jsonl", tmp_path / f"{name}.meta.json",
            scan, {"version": "3.97.9", "sha256": "x"},
        )
        outputs.append(((tmp_path / f"{name}.jsonl").read_bytes(), (tmp_path / f"{name}.meta.json").read_bytes()))
    assert outputs[0] == outputs[1]
    assert meta["schema"] == MODULE.SCHEMA and meta["tool"] == "trufflehog" and meta["rows"] == 2
    assert meta["pinned"]["version"] == "3.97.9" and meta["span_unit"] == "unicode_code_point"
    assert "--no-verification" in meta["command"]
    assert len(meta["input_sha256"]) == len(meta["entity_map_sha256"]) == 64
    [first, second] = [json.loads(line) for line in outputs[0][0].decode().splitlines()]
    [span] = first["evidence_spans"]
    assert span["entities"] == ["vcs.github.fine_grained_pat", "vcs.github.token"]
    # TruffleHog keeps one decoder per value, chosen nondeterministically: not in the output
    assert "decoder" not in span and "decoders" not in span and second["evidence_spans"] == []


def test_entity_index_covers_all_tools_from_entity_map():
    index = MODULE.load_entity_index()
    assert set(index) == set(MODULE.TOOLS)
    assert index["gitleaks"]["github-pat"][0] == ["vcs.github.token"]
    assert "vcs.github.token" in index["trufflehog"]["Github"][0]
    assert index["detect-secrets"]["BasicAuthDetector"][1] == ["CREDENTIAL"]
    assert "credential.url_userinfo" in index["trufflehog"]["Postgres"][0]


def test_unknown_trufflehog_detectors_bisects_with_the_binary(tmp_path):
    fake = tmp_path / "trufflehog"
    fake.write_text(
        "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in --include-detectors=*Bogus*) "
        "echo 'unrecognized detector type: Bogus'; exit 1;; esac; done\nexit 0\n"
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    assert MODULE.unknown_trufflehog_detectors(["Github", "AWS"], tmp_path) == []
    assert MODULE.unknown_trufflehog_detectors(["Github", "Bogus", "AWS"], tmp_path) == ["Bogus"]


# ── Real pinned tools (VPS only; skipped where they are not installed) ──────


def _tools_installed() -> bool:
    _, problems = MODULE.check_pins(MODULE.TOOLS, BASELINES, BASELINES_PYTHON)
    return not problems


@pytest.mark.skipif(not _tools_installed(), reason="pinned baselines not installed")
@pytest.mark.parametrize("tool", MODULE.TOOLS)
def test_real_tool_finds_value_spans(tool, tmp_path):
    text = (
        "# Konfiguration für den Deploy\n"
        f"github_token = \"{GH}\"\n"
        f"DATABASE_URL=postgres://app:{PASSWORD}@db.internal:5432/app\n"
    )
    rows = [{"id": "doc", "text": text, "format": "env"}, {"id": "empty", "text": "hello world\n"}]
    write_jsonl(tmp_path / "in.jsonl", rows)
    installed, _ = MODULE.check_pins([tool], BASELINES, BASELINES_PYTHON)
    meta = MODULE.run(
        tool, tmp_path / "in.jsonl", tmp_path / "out.jsonl", tmp_path / "out.meta.json",
        lambda name, scan_rows: MODULE.scan_with_tool(name, scan_rows, BASELINES, BASELINES_PYTHON),
        installed[tool],
    )
    rows_out = [json.loads(line) for line in (tmp_path / "out.jsonl").read_text().splitlines()]
    values = {text[s["start_char"]:s["end_char"]] for s in rows_out[0]["evidence_spans"]}
    assert GH in values
    if tool != "gitleaks":  # gitleaks has no URL-userinfo rule in its default config
        assert PASSWORD in values
    assert rows_out[1]["evidence_spans"] == []
    assert meta["unlocated"] == {}


@pytest.mark.skipif(not _tools_installed(), reason="pinned baselines not installed")
def test_entity_map_names_exist_in_the_pinned_tools():
    assert MODULE.check_entity_map(BASELINES, BASELINES_PYTHON) == []


def test_cli_rejects_unpinned_tools(tmp_path, capsys):
    rows = tmp_path / "in.jsonl"
    write_jsonl(rows, [{"id": "a", "text": "x"}])
    code = MODULE.main([
        "--bin-dir", str(tmp_path), "--detect-secrets-python", str(tmp_path / "missing-python"),
        "run", "--tool", "gitleaks", "--input", str(rows), "--output", str(tmp_path / "o.jsonl"),
    ])
    assert code == 2
    assert "differ from the pins" in capsys.readouterr().err
    assert not (tmp_path / "o.jsonl").exists()


# ── Review fixes: multi-part, normalized URIs, JDBC, no secrets in logs ─────

# Shape-valid but obviously synthetic AWS pair (documentation-style EXAMPLE marker).
AWS_ID = token("AKIA", "EXAMPLEQ7", 16)
AWS_SECRET = token("", "fakeSecretKEY0+/", 40)


def trufflehog_line(tmp_path: Path, detector: str, line: int = 1, doc: int = 0, **fields) -> str:
    return json.dumps({
        "SourceMetadata": {"Data": {"Filesystem": {"file": str(tmp_path / f"{doc:06d}" / ".env"), "line": line}}},
        "DetectorName": detector, "DecoderName": "PLAIN", **fields,
    })


def aws_index():
    return {
        "gitleaks": {}, "detect-secrets": {},
        "trufflehog": {
            "AWS": (["cloud.aws.access_key_id", "cloud.aws.secret_access_key"], ["CLOUD_KEY"]),
            "Postgres": (["credential.url_userinfo"], ["CREDENTIAL"]),
            "JDBC": (["credential.url_userinfo"], ["CREDENTIAL"]),
        },
    }


@pytest.mark.parametrize("with_parts", [True, False])
def test_trufflehog_multipart_aws_emits_each_part_with_its_entity(tmp_path, with_parts):
    text = f"AWS_ACCESS_KEY_ID={AWS_ID}\nAWS_SECRET_ACCESS_KEY={AWS_SECRET}\n"
    fields = {"Raw": AWS_ID, "RawV2": AWS_ID + AWS_SECRET}
    if with_parts:
        fields["SecretParts"] = {"key": AWS_ID, "secret": AWS_SECRET, "account": "123456789012"}
    findings = MODULE.parse_trufflehog(trufflehog_line(tmp_path, "AWS", **fields), tmp_path)
    assert sorted((f.part, f.secret) for f in findings) == [
        ("access_key_id", AWS_ID), ("secret_access_key", AWS_SECRET),
    ]
    [row], summary = MODULE.predict("trufflehog", [{"id": "a", "text": text}], findings, aws_index())
    spans = {text[s["start_char"]:s["end_char"]]: s for s in row["evidence_spans"]}
    assert set(spans) == {AWS_ID, AWS_SECRET}
    assert spans[AWS_ID]["entities"] == ["cloud.aws.access_key_id"]
    assert spans[AWS_SECRET]["entities"] == ["cloud.aws.secret_access_key"]
    assert spans[AWS_SECRET]["label"] == "trufflehog.AWS.secret_access_key"
    assert spans[AWS_ID]["groups"] == ["CLOUD_KEY"] and summary["unlocated"] == {}


def test_trufflehog_single_value_results_are_not_split(tmp_path):
    [item] = MODULE.parse_trufflehog(trufflehog_line(tmp_path, "Github", Raw=GH, RawV2=GH + "x"), tmp_path)
    assert item.part is None and item.secret == GH and item.alternatives == (GH + "x",)


@pytest.mark.parametrize(
    "source, raw",
    [
        # probe shape from dlp_synth/rules.json: default port omitted in the source
        ("DATABASE_URL=postgres://app:{pw}@db\n", "postgres://app:{pw}@db:5432"),
        ("url = \"postgres://app:{pw}@db/reports\"\n", "postgresql://app:{pw}@db:5432/reports?sslmode=prefer"),
    ],
)
def test_trufflehog_normalized_postgres_uri_locates_the_password(tmp_path, source, raw):
    text = source.format(pw=PASSWORD)
    raw = raw.format(pw=PASSWORD)
    assert raw not in text
    findings = MODULE.parse_trufflehog(trufflehog_line(tmp_path, "Postgres", Raw=raw, RawV2=raw), tmp_path)
    [row], summary = MODULE.predict("trufflehog", [{"id": "a", "text": text}], findings, aws_index())
    [span] = row["evidence_spans"]
    assert text[span["start_char"]:span["end_char"]] == PASSWORD
    assert span["normalization"] == ["uri_password"] and summary["unlocated"] == {}


def test_trufflehog_password_secret_part_is_last_resort(tmp_path):
    text = f"host=db user=app password={PASSWORD}\n"
    findings = MODULE.parse_trufflehog(
        trufflehog_line(tmp_path, "Postgres", Raw=f"postgres://app:{PASSWORD}@db:5432",
                        SecretParts={"password": PASSWORD, "username": "app"}),
        tmp_path,
    )
    [row], _ = MODULE.predict("trufflehog", [{"id": "a", "text": text}], findings, aws_index())
    [span] = row["evidence_spans"]
    assert text[span["start_char"]:span["end_char"]] == PASSWORD and span["normalization"] == ["secret_part"]


@pytest.mark.parametrize(
    "conn",
    [
        "jdbc:postgresql://app:{pw}@db:5432/app",
        "jdbc:mysql://db:3306/app?user=app&password={pw}&useSSL=true",
        "jdbc:sqlserver://db:1433;databaseName=app;user=sa;password={pw};encrypt=true",
        "jdbc:oracle:thin:app/{pw}@db:1521/ORCL",
    ],
)
def test_jdbc_values_are_normalized_to_the_password(tmp_path, conn):
    conn = conn.format(pw=PASSWORD)
    text = f"spring.datasource.url={conn}\n"
    findings = MODULE.parse_trufflehog(trufflehog_line(tmp_path, "JDBC", Raw=conn), tmp_path)
    [row], _ = MODULE.predict("trufflehog", [{"id": "a", "text": text}], findings, aws_index())
    [span] = row["evidence_spans"]
    assert text[span["start_char"]:span["end_char"]] == PASSWORD
    assert "jdbc_password" in span["normalization"]


def test_jdbc_without_password_keeps_the_located_span():
    text = "url=jdbc:h2:mem:testdb\n"
    start = text.index("jdbc")
    new_start, new_end, steps = MODULE.refine(text, start, len(text) - 1, "trufflehog", "JDBC")
    assert (new_start, new_end, steps) == (start, len(text) - 1, [])


detect_secrets_available = importlib.util.find_spec("detect_secrets") is not None


@pytest.mark.skipif(not detect_secrets_available, reason="detect-secrets not installed")
def test_detect_secrets_worker_logs_spans_not_secrets(tmp_path, capsys):
    rows = [{"id": "a", "text": f"password = \"{PASSWORD}\"\r\ngithub_token = \"{GH}\"\n", "format": "env"}]
    MODULE.materialize(rows, tmp_path)
    assert MODULE.detect_secrets_worker(tmp_path) == 0
    captured = capsys.readouterr()
    for secret in (PASSWORD, GH):
        assert secret not in captured.out and secret not in captured.err
    findings = MODULE.parse_detect_secrets(captured.out, tmp_path)
    [row], summary = MODULE.predict("detect-secrets", rows, findings, entity_index())
    values = {rows[0]["text"][s["start_char"]:s["end_char"]] for s in row["evidence_spans"]}
    assert {PASSWORD, GH} <= values and summary["unlocated"] == {}


@pytest.mark.skipif(not detect_secrets_available, reason="detect-secrets not installed")
def test_detect_secrets_worker_version_message_has_no_pin_data(tmp_path, capsys, monkeypatch):
    monkeypatch.setitem(MODULE.PINS["detect-secrets"], "version", "0.0.0-pin")
    assert MODULE.detect_secrets_worker(tmp_path) == 2
    err = capsys.readouterr().err
    assert "is not the pinned release" in err and "0.0.0-pin" not in err


def test_worker_records_mark_unlocatable_values():
    text = f"a: {PASSWORD}\n"
    records = MODULE.worker_records(text, [(1, "KeywordDetector", PASSWORD), (1, "Other", "not-in-text")], {})
    assert records == [
        {"line": 1, "plugin": "KeywordDetector", "start": 3, "end": 3 + len(PASSWORD), "normalization": []},
        {"line": 1, "plugin": "Other", "start": None, "end": None, "normalization": []},
    ]
    assert PASSWORD not in json.dumps(records)


def test_cli_run_logs_no_secret(tmp_path, capsys, monkeypatch):
    rows = [{"id": "a", "text": f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}\nDB=postgres://app:{PASSWORD}@db\n"}]
    write_jsonl(tmp_path / "in.jsonl", rows)
    monkeypatch.setattr(MODULE, "check_pins", lambda tools, *_: ({t: {"version": "x"} for t in tools}, []))
    stdout = "\n".join([
        trufflehog_line(tmp_path, "AWS", Raw=AWS_ID, RawV2=AWS_ID + AWS_SECRET),
        trufflehog_line(tmp_path, "Postgres", line=2, Raw=f"postgres://app:{PASSWORD}@db:5432"),
    ])
    monkeypatch.setattr(MODULE, "scan_with_tool", lambda tool, rows, *_: MODULE.parse_trufflehog(stdout, tmp_path))
    code = MODULE.main(["run", "--tool", "trufflehog", "--input", str(tmp_path / "in.jsonl"),
                        "--output", str(tmp_path / "o.jsonl")])
    assert code == 0
    captured = capsys.readouterr()
    written = (tmp_path / "o.jsonl").read_text() + (tmp_path / "o.meta.json").read_text()
    for secret in (AWS_ID, AWS_SECRET, PASSWORD):
        assert secret not in captured.out + captured.err and secret not in written
    assert "1 unlocated" in captured.err  # the key id is not in this text
