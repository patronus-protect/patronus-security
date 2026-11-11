from __future__ import annotations

import copy
import importlib.util
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "l1_threat" / "oss_inventory.py"
SPEC = importlib.util.spec_from_file_location("l1_threat_oss_inventory", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

COMMIT = "0123456789abcdef0123456789abcdef01234567"
TAXONOMY = {
    "classes": {
        cls: {"families": [{"id": "fam_a"}, {"id": "fam_b"}]}
        for cls in MODULE.taxonomy.CLASSES
    }
}


def source(**overrides):
    entry = {
        "id": "src",
        "name": "Source",
        "repo": "https://example.org/src",
        "commit": COMMIT,
        "licence": "MIT",
        "licence_file": "LICENSE",
        "extractor": "yara",
        "clone": "owner_src",
        "paths": ["rules/*.yar"],
        "category_map": [
            {"match": "^secrets$", "out_of_scope": "secrets in text"},
            {"match": "^shell$", "handoff": "shell_command"},
            {"match": "^inj$", "classes": ["instruction_injection", "*"]},
            {"match": "^tool$", "classes": ["tool_poisoning"], "family": "fam_b"},
        ],
    }
    entry.update(overrides)
    return entry


def inventory(**overrides):
    entry = {
        "schema": MODULE.SCHEMA,
        "sources": [source()],
        "default_families": {cls: "fam_a" for cls in MODULE.taxonomy.CLASSES},
        "hints": [
            {"match": "reverse shell", "handoff": "shell_command"},
            {"match": "persona", "class": "jailbreak", "family": "fam_b"},
            {"match": "ignore", "class": "instruction_injection", "family": "fam_b"},
        ],
    }
    entry.update(overrides)
    return entry


def raw(rule_id="r1", title="title", category="inj", kind="regex", bodies=("ignore previous instructions",), active=True):
    return {
        "id": rule_id,
        "title": title,
        "category": category,
        "path": "rules/a.yar",
        "kind": kind,
        "bodies": list(bodies),
        "active": active,
        "language": None,
    }


def built(raws, inv=None):
    inv = inv or inventory()
    rules = MODULE.inventory_rules(inv["sources"][0], raws, inv)
    return {**inv, "counts": MODULE.counts(rules), "rules": rules}


# --- body analysis


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (r"(ignorier|vergiss)\w*\s+(die\s+)?vorherigen\s+Anweisungen", ["de"]),
        (r"ignore\s+(all\s+)?previous\s+instructions", ["en"]),
        (r"<\|im_start\|>|\[/?INST\]", ["en"]),
        (r"[​-‏]{3,}", ["any"]),
        (r"\d{3}-\d{2}-\d{4}", ["any"]),
        (r"(이전|모든)\s*지시", ["ko"]),
        (r"忽略之前的指令", ["zh"]),
        (r"oubliez\s+les\s+règles", ["fr"]),
    ],
)
def test_languages_from_body(body, expected):
    assert MODULE.languages(body) == expected


def test_declared_language_is_added():
    assert MODULE.languages(r"\bxyz\b", "de") == ["de"]
    assert MODULE.languages(r"ignore\s+previous", "de") == ["en", "de"]
    assert MODULE.languages(r"[​]+", "de") == ["de"]


@pytest.mark.parametrize(
    ("body", "kind", "expected"),
    [
        (r"ignore\s+previous", "regex", True),
        (r"(?i)(?P<verb>ignore)", "regex", True),
        (r"ignore(?!\s+this)", "regex", False),
        (r"(?<=system:)\s*", "regex", False),
        (r"(a)\s+\1", "regex", False),
        (r"(?>atomic)", "regex", False),
        (r"a++", "regex", False),
        ("(?!literal text)", "text", True),
    ],
)
def test_portable(body, kind, expected):
    assert MODULE.portable(body, kind) is expected


def test_body_sha_is_short_and_stable():
    assert MODULE.body_sha("abc") == MODULE.body_sha("abc")
    assert len(MODULE.body_sha("abc")) == 12


# --- extractors


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_extract_yara_one_rule_per_string(tmp_path):
    write(
        tmp_path / "rules" / "a.yar",
        """
rule tool_poisoning {
    meta:
        description = "Detects hidden behaviour"
    strings:
        $also = /\\balso\\s+(send|upload)/i
        // a comment
        $lit = "do not tell the user" nocase
        $hex = { 4D 5A }
    condition:
        any of them
}
rule other {
    strings:
        $a = "x"
    condition:
        $a
}
""",
    )
    rules = list(MODULE.extract_yara(tmp_path, ["rules/*.yar"]))
    assert [(r["id"], r["kind"]) for r in rules] == [
        ("tool_poisoning.$also", "regex"),
        ("tool_poisoning.$lit", "text"),
        ("tool_poisoning.$hex", "hex"),
        ("other.$a", "text"),
    ]
    assert rules[0]["bodies"] == [r"\balso\s+(send|upload)"]
    assert rules[1]["bodies"] == ["do not tell the user"]
    assert rules[0]["title"] == "Detects hidden behaviour"
    assert rules[0]["category"] == "tool_poisoning"


def test_extract_atr_kinds_and_status(tmp_path):
    write(
        tmp_path / "rules" / "prompt-injection" / "a.yaml",
        """
id: ATR-1
title: Direct override
status: experimental
detection_tier: pattern
tags: {subcategory: direct}
detection:
  conditions:
    - {field: content, operator: regex, value: 'ignore\\s+previous'}
  false_positives: ['ignore previous text in docs']
""",
    )
    write(
        tmp_path / "rules" / "agent-manipulation" / "b.yaml",
        """
id: ATR-2
title: Semantic judge
status: deprecated
detection_tier: semantic
tags: {subcategory: persona}
detection: {}
""",
    )
    rules = {r["id"]: r for r in MODULE.extract_atr(tmp_path, ["rules/*/*.yaml"])}
    assert rules["ATR-1"]["kind"] == "regex"
    assert rules["ATR-1"]["category"] == "prompt-injection/direct"
    assert rules["ATR-1"]["bodies"] == [r"ignore\s+previous"]
    assert rules["ATR-1"]["active"] is True
    assert rules["ATR-2"]["kind"] == "semantic"
    assert rules["ATR-2"]["active"] is False


def test_extract_python_re_names(tmp_path):
    write(
        tmp_path / "scan.py",
        """
import re
_PATTERNS = [
    ("instruction_override", re.compile(r"ignore\\s+" r"previous"), 1, "x"),
]
_TOXIC = re.compile(r"xyz")
DEFAULT_REGEX_PATTERNS = {"Prompt injection": r"ignore previous instructions"}
""",
    )
    rules = {r["id"]: r for r in MODULE.extract_python_re(tmp_path, ["scan.py"])}
    assert rules["scan.instruction_override"]["bodies"] == [r"ignore\s+previous"]
    assert "scan._TOXIC" in rules
    assert rules["scan.Prompt injection"]["bodies"] == ["ignore previous instructions"]


def test_extract_prompt_guard_lists_dicts_and_yaml(tmp_path):
    write(
        tmp_path / "prompt_guard" / "patterns.py",
        """
SCENARIO_JAILBREAK = [r"pretend\\s+you\\s+are"]
PATTERNS_DE = {"instruction_override": [r"vergiss\\s+alles"]}
SECRET_PATTERNS = {"ko": [r"비밀번호"]}
UNTRUSTED = frozenset({"web"})
""",
    )
    write(
        tmp_path / "patterns" / "critical.yaml",
        "patterns:\n  jailbreak:\n    - pattern: 'dan\\s+mode'\n      category: jailbreak\n",
    )
    rules = {
        r["id"]: r
        for r in MODULE.extract_prompt_guard(tmp_path, ["prompt_guard/patterns.py", "patterns/*.yaml"])
    }
    assert set(rules) == {
        "SCENARIO_JAILBREAK[0]",
        "PATTERNS_DE.instruction_override[0]",
        "SECRET_PATTERNS.ko[0]",
        "critical.jailbreak[0]",
    }
    assert rules["PATTERNS_DE.instruction_override[0]"]["language"] == "de"
    assert rules["SECRET_PATTERNS.ko[0]"]["language"] == "ko"
    assert rules["critical.jailbreak[0]"]["category"] == "jailbreak/jailbreak"


def test_extract_pipelock_go(tmp_path):
    write(
        tmp_path / "defaults.go",
        """
const NewInstructionsRegex = `(?i)new\\s+instructions`
var p = []ResponseScanPattern{
				{Name: "Prompt Injection", Regex: `(?i)ignore\\s+previous`},
				{Name: "New Instructions", Regex: NewInstructionsRegex},
}
var toolPoisonPatterns = []*compiledToolPattern{
	{
		name: "File Exfiltration Directive",
		re:   regexp.MustCompile(`(?i)read\\s+.{0,40}\\.ssh`),
	},
	{
		name: "File Exfiltration Directive",
		re:   regexp.MustCompile(`(?i)\\.ssh.{0,40}upload`),
	},
}
""",
    )
    rules = {r["id"]: r for r in MODULE.extract_pipelock_go(tmp_path, ["defaults.go"])}
    assert set(rules) == {
        "defaults.Prompt Injection",
        "defaults.New Instructions",
        "defaults.File Exfiltration Directive",
        "defaults.File Exfiltration Directive#2",
    }
    assert "new\\s+instructions" in rules["defaults.New Instructions"]["bodies"][0]
    assert "upload" in rules["defaults.File Exfiltration Directive#2"]["bodies"][0]


def test_extract_citadel_go(tmp_path):
    write(
        tmp_path / "categories.go",
        """
func (r *Registry) registerJailbreakPatterns() {
	cat := CategoryJailbreak
	r.register("dan_mode", `(?i)dan\\s+mode`, cat, 80, "DAN mode")
}
""",
    )
    write(
        tmp_path / "patterns.go",
        """
var P = []struct{}{
	{
		Pattern:  regexp.MustCompile(`(?i)writing\\s+a\\s+novel`),
		Category: "fiction_frame",
		Score:    0.7,
	},
}
var toolPoisonPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\[HIDDEN\]`),
	regexp.MustCompile(`(?i)keep\s+this\s+secret`),
}
""",
    )
    rules = {r["id"]: r for r in MODULE.extract_citadel_go(tmp_path, ["categories.go", "patterns.go"])}
    assert rules["dan_mode"]["category"] == "Jailbreak"
    assert rules["dan_mode"]["title"] == "DAN mode"
    assert rules["patterns.fiction_frame.1"]["category"] == "fiction_frame"
    # Literal regexes outside the registry are named after their enclosing variable.
    assert rules["patterns.toolPoisonPatterns.2"]["category"] == "toolPoisonPatterns"
    assert len(rules) == 4


# --- mapping and harvest


def test_map_rule_category_hint_and_default():
    inv = inventory()
    src = inv["sources"][0]
    assert MODULE.map_rule(raw(category="secrets"), src, inv)["mapping"] == "out_of_scope"
    assert MODULE.map_rule(raw(category="shell"), src, inv)["mapping"] == "handoff"
    assert MODULE.map_rule(raw(title="reverse shell in skill"), src, inv)["mapping"] == "handoff"
    assert MODULE.map_rule(raw(title="persona swap"), src, inv) == {
        "class": "jailbreak",
        "family": "fam_b",
        "mapping": "hint",
    }
    assert MODULE.map_rule(raw(title="other"), src, inv) == {
        "class": "instruction_injection",
        "family": "fam_a",
        "mapping": "default",
    }
    # Hints outside the allowed classes are skipped; the category family applies.
    assert MODULE.map_rule(raw(category="tool", title="persona"), src, inv) == {
        "class": "tool_poisoning",
        "family": "fam_b",
        "mapping": "category",
    }
    assert MODULE.map_rule(raw(category="unknown"), src, inv)["class"] is None


@pytest.mark.parametrize(
    ("licence", "overrides", "duplicate", "expected"),
    [
        ("MIT", {}, False, None),
        ("Apache-2.0", {}, False, None),
        ("AGPL-3.0", {}, False, "licence"),
        ("MIT", {"kind": "semantic"}, False, "semantic"),
        ("MIT", {"kind": "hex"}, False, "semantic"),
        ("MIT", {"active": False}, False, "inactive"),
        ("MIT", {"bodies": [r"ignore(?!\s+me)"]}, False, "not_portable"),
        ("MIT", {}, True, "duplicate"),
    ],
)
def test_harvest_reason(licence, overrides, duplicate, expected):
    rule = {"class": "instruction_injection", "family": "fam_a", "mapping": "hint"}
    data = {**raw(), **overrides}
    assert MODULE.harvest_reason(rule, data, licence, duplicate) == expected


def test_harvest_reason_mapping():
    data = raw()
    assert MODULE.harvest_reason({"class": None, "mapping": "handoff"}, data, "MIT", False) == "handoff"
    assert MODULE.harvest_reason({"class": None, "mapping": "out_of_scope"}, data, "MIT", False) == "out_of_scope"
    assert MODULE.harvest_reason({"class": None, "mapping": "default"}, data, "MIT", False) == "unmapped"


def test_inventory_rules_marks_duplicates_and_counts_languages():
    inv = built([raw("a"), raw("b"), raw("c", bodies=[r"vergiss\s+alles"]), raw("d", category="secrets")])
    by_id = {r["id"]: r for r in inv["rules"]}
    assert by_id["a"]["harvest"] is True and "reason" not in by_id["a"]
    assert by_id["b"]["reason"] == "duplicate"
    assert by_id["c"]["languages"] == ["de"]
    assert by_id["d"]["reason"] == "out_of_scope"
    assert inv["counts"]["by_class"]["instruction_injection"] == {
        "en": {"rules": 2, "harvest": 1},
        "de": {"rules": 1, "harvest": 1},
    }
    assert inv["counts"]["by_class"]["(out_of_scope)"]["en"] == {"rules": 1, "harvest": 0}
    assert inv["counts"]["by_source"]["src"] == {"rules": 4, "harvest": 2}
    assert [r["id"] for r in MODULE.harvest_list(inv, "instruction_injection")] == ["a", "c"]


# --- check


def test_check_accepts_a_valid_inventory():
    assert MODULE.check(built([raw("a"), raw("b", category="secrets")]), TAXONOMY) == []


def problems_after(mutate):
    inv = copy.deepcopy(built([raw("a"), raw("b", category="secrets")]))
    mutate(inv)
    return MODULE.check(inv, TAXONOMY)


def test_check_rejects_unpinned_commit():
    assert any("40-hex" in p for p in problems_after(lambda inv: inv["sources"][0].update(commit="main")))


def test_check_rejects_harvest_from_agpl_source():
    problems = problems_after(lambda inv: inv["sources"][0].update(licence="AGPL-3.0"))
    assert any("harvested from a AGPL-3.0 source" in p for p in problems)


def test_check_rejects_rule_bodies():
    problems = problems_after(lambda inv: inv["rules"][0].update(regex="ignore previous"))
    assert any("carries a rule body" in p for p in problems)


def test_check_rejects_unknown_family_and_class():
    problems = problems_after(lambda inv: inv["rules"][0].update(family="nope"))
    assert any("unknown family instruction_injection.nope" in p for p in problems)
    problems = problems_after(lambda inv: inv["hints"].append({"match": "x", "class": "nope", "family": "fam_a"}))
    assert any("unknown class 'nope'" in p for p in problems)


def test_check_rejects_harvest_without_class_and_reasonless_rejection():
    def no_class(inv):
        inv["rules"][0].update({"class": None, "family": None})

    assert any("harvested without class" in p for p in problems_after(no_class))
    assert any("reason None" in p for p in problems_after(lambda inv: inv["rules"][1].pop("reason")))


def test_check_rejects_duplicate_ids_and_unknown_source():
    assert any("duplicate rule id" in p for p in problems_after(lambda inv: inv["rules"].append(dict(inv["rules"][0]))))
    assert any("unknown source" in p for p in problems_after(lambda inv: inv["rules"][0].update(source="x")))


def test_check_rejects_stale_counts():
    def stale(inv):
        inv["counts"]["by_source"]["src"]["rules"] = 99

    assert any("counts do not match" in p for p in problems_after(stale))


def test_check_rejects_bad_category_map_and_licence():
    problems = problems_after(lambda inv: inv["sources"][0]["category_map"].append({"match": "x"}))
    assert any("category_map entry" in p for p in problems)
    assert any("unknown licence" in p for p in problems_after(lambda inv: inv["sources"][0].update(licence="BSD")))


# --- build from a pinned clone


def test_build_from_clone_and_rejects_moved_head(tmp_path):
    clone = tmp_path / "owner_src"
    write(clone / "rules" / "a.yar", 'rule r { strings: \n $a = /ignore\\s+previous/\n condition: $a }\n')
    git = ["git", "-C", str(clone), "-c", "user.name=t", "-c", "user.email=t@example.org"]
    subprocess.run(["git", "init", "-q", str(clone)], check=True)
    subprocess.run(git + ["add", "."], check=True)
    subprocess.run(git + ["commit", "-qm", "init"], check=True)
    head = MODULE.git_head(clone)

    inv = inventory(sources=[source(commit=head, category_map=[{"match": ".", "classes": ["instruction_injection"]}])])
    out = MODULE.build(inv, tmp_path)
    assert [(r["id"], r["class"], r["harvest"]) for r in out["rules"]] == [("r.$a", "instruction_injection", True)]
    assert MODULE.check(out, TAXONOMY) == []

    inv["sources"][0]["commit"] = COMMIT
    with pytest.raises(SystemExit, match="pins"):
        MODULE.build(inv, tmp_path)


def test_dump_round_trips(tmp_path):
    inv = built([raw("a")])
    path = tmp_path / "oss_rules.yaml"
    path.write_text(MODULE.dump(inv), encoding="utf-8")
    assert MODULE.load(path) == inv


# --- repository inventory


def test_repository_inventory_passes_check():
    inv = MODULE.load()
    assert MODULE.check(inv, MODULE.taxonomy.load()) == []


def test_repository_inventory_covers_the_backlog_sources():
    ids = {s["id"] for s in MODULE.load()["sources"]}
    assert ids == {
        "atr",
        "pipelock",
        "cisco_mcp_scanner",
        "prompt_guard",
        "vigil",
        "nemo_yara",
        "llamafirewall",
        "skillspector",
        "sentinel_ai",
        "citadel",
    }


def test_repository_inventory_harvests_only_permissive_sources():
    inv = MODULE.load()
    licences = {s["id"]: s["licence"] for s in inv["sources"]}
    harvested = [r for r in inv["rules"] if r["harvest"]]
    assert harvested
    assert {licences[r["source"]] for r in harvested} <= set(MODULE.HARVEST_LICENCES)
    assert all(not (MODULE.BODY_KEYS & set(r)) for r in inv["rules"])
