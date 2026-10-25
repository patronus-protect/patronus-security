"""E04: carrier templates for synthetic DLP secrets.

Carrier families embed generated values (``dlp_synth.recipes``) in realistic config,
code, CI, notebook, log, HTTP and DE/EN prose documents. Families belong to exactly one
of the dev and holdout splits. Every positive has a code-point span on the embedded
value; every family also yields hard negatives (placeholder, env/template reference,
documented example value, test key) without spans. Generated text exists only in memory.
"""

import html
import json
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

import yaml

from patronus_ark.dlp_synth import carriers, checks, recipes, rules


REPO = Path(__file__).resolve().parents[2]
ENTITY_MAP = REPO / "research/dlp/entity_map.yaml"
FORMATS = {
    "env", "yaml", "json", "toml", "hcl", "xml", "properties", "shell", "dockerfile",
    "ci_yaml", "jupyter", "log", "http", "code", "chat", "ticket", "mail",
}
CODE_LANGUAGES = {"python", "javascript", "typescript", "go", "java", "csharp", "rust", "ruby"}
HARD_NEGATIVES = {"placeholder", "env_ref", "doc_example", "test_key", "lookalike"}
SEED = 20261013
# Checksum or structure checks a doc-example or test-key value must never pass.
STRUCTURAL = {
    "github_ghp_token": lambda v: checks.has_valid_crc32_suffix(v, "ghp_"),
    "github_gho_token": lambda v: checks.has_valid_crc32_suffix(v, "gho_"),
    "npm_access_token": lambda v: checks.has_valid_crc32_suffix(v, "npm_"),
    "btc_wif_mainnet_compressed": checks.is_valid_btc_wif,
    "btc_wif_mainnet_uncompressed": checks.is_valid_btc_wif,
    "btc_wif_testnet_compressed": checks.is_valid_btc_wif,
    "btc_wif_testnet_uncompressed": checks.is_valid_btc_wif,
    "de_vat_id": checks.is_valid_de_vat_id,
    "jwt_signed_hs256": lambda v: checks.jwt_parts(v) is not None,
    "jwt_signed_rs256": lambda v: checks.jwt_parts(v) is not None,
    "http_basic_auth": lambda v: checks.basic_auth_pair(v) is not None,
    "pem_pkcs8_ed25519_private_key": lambda v: any(checks.is_valid_pkcs8_ed25519(b) for _, b in checks.pem_blocks(v)),
    "pem_pkcs1_rsa_private_key": lambda v: any(checks.is_valid_pkcs1_rsa(b) for _, b in checks.pem_blocks(v)),
    "pem_sec1_ec_private_key": lambda v: any(checks.is_valid_sec1_p256(b) for _, b in checks.pem_blocks(v)),
    "pem_dsa_private_key": lambda v: any(checks.is_valid_dsa(b) for _, b in checks.pem_blocks(v)),
    "pem_openssh_ed25519_private_key": lambda v: any(
        checks.is_valid_openssh_ed25519(b) for _, b in checks.pem_blocks(v)
    ),
}
# Value patterns of rules without a validator (mirrors ark-core/src/detectors/dlp/rules/): a
# doc-example or test-key value must still match them, so only structural validation
# can tell it from a real value.
SHAPE = {
    "btc_wif_mainnet_compressed": r"[KL][1-9A-HJ-NP-Za-km-z]{51}",
    "btc_wif_mainnet_uncompressed": r"5[1-9A-HJ-NP-Za-km-z]{50}",
    "btc_wif_testnet_compressed": r"c[1-9A-HJ-NP-Za-km-z]{51}",
    "btc_wif_testnet_uncompressed": r"9[1-9A-HJ-NP-Za-km-z]{50}",
    "jwt_signed_hs256": r"(ey[a-zA-Z0-9_\-=]{10,}\.){2}[a-zA-Z0-9_\-=]{10,}",
    "jwt_signed_rs256": r"(ey[a-zA-Z0-9_\-=]{10,}\.){2}[a-zA-Z0-9_\-=]{10,}",
    "discord_bot_token": r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27,}",
}


def key_of(row):
    """The carrier key of a row: its value rule, or its entity for a baseline entity (GOLD-D2)."""
    return row["rule_id"] or row["entity"]


def unescape(text, family):
    """Undo the family's value escapes, outermost first."""
    for escape in reversed(family.escape):
        if escape == "json":
            text = json.loads(f'"{text}"')
        elif escape == "xml":
            text = html.unescape(text)
        elif escape == "indent":
            text = text.replace("\n" + " " * family.indent, "\n")
        else:
            raise AssertionError(f"unknown escape {escape}")
    return text


def leaves(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from leaves(value)
    elif isinstance(node, list):
        for value in node:
            yield from leaves(value)
    elif isinstance(node, str):
        yield node


def parse_leaves(syntax, text):
    if syntax == "json":
        return list(leaves(json.loads(text)))
    if syntax == "jsonl":
        return [leaf for line in text.splitlines() for leaf in leaves(json.loads(line))]
    if syntax == "yaml":
        return list(leaves(yaml.safe_load(text)))
    if syntax == "toml":
        return list(leaves(tomllib.loads(text)))
    if syntax == "xml":
        root = ET.fromstring(text)
        return [t for e in root.iter() for t in [e.text or "", *e.attrib.values()]]
    raise AssertionError(f"unknown syntax {syntax}")


class FamilyTests(unittest.TestCase):
    def test_every_format_has_dev_and_holdout_families(self):
        families = carriers.families()
        self.assertEqual({f.format for f in families}, FORMATS)
        for split in carriers.SPLITS:
            self.assertEqual({f.format for f in carriers.families(split)}, FORMATS, split)
            self.assertEqual(
                {f.code_language for f in carriers.families(split) if f.format == "code"},
                CODE_LANGUAGES,
                split,
            )
            for format in FORMATS:
                languages = {f.language for f in carriers.families(split) if f.format == format}
                self.assertEqual(languages, {"de", "en"}, f"{split} {format}")

    def test_dev_and_holdout_families_are_disjoint(self):
        dev, holdout = (carriers.families(split) for split in carriers.SPLITS)
        self.assertEqual(len(dev) + len(holdout), len(carriers.families()))
        self.assertFalse({f.id for f in dev} & {f.id for f in holdout})
        self.assertFalse({f.template for f in dev} & {f.template for f in holdout})
        ids = [f.id for f in carriers.families()]
        self.assertEqual(len(ids), len(set(ids)))
        for family in carriers.families():
            self.assertIn(family.split, carriers.SPLITS)
            self.assertIn(family.language, ("de", "en"))

    def test_both_languages_appear_outside_prose(self):
        for split in carriers.SPLITS:
            languages = Counter(
                f.language for f in carriers.families(split) if f.format not in ("chat", "ticket", "mail")
            )
            self.assertGreaterEqual(languages["de"], 8, split)
            self.assertGreaterEqual(languages["en"], 8, split)

    def test_templates_use_only_known_markers_and_one_value_slot(self):
        marker = re.compile(r"<<([A-Za-z][A-Za-z-]*)>>")
        for family in carriers.families():
            self.assertEqual(family.template.count("<<value>>"), 1, family.id)
            names = set(marker.findall(family.template)) | set(marker.findall(family.env_ref[1]))
            self.assertLessEqual(names, carriers.MARKERS, family.id)
            old, new = family.env_ref
            self.assertIn("<<value>>", old, family.id)
            self.assertIn(old, family.template, family.id)
            self.assertNotIn("<<value>>", new, family.id)
            self.assertLessEqual(set(family.escape), {"json", "xml", "indent"}, family.id)
            self.assertEqual("indent" in family.escape, family.indent > 0, family.id)

    def test_invalid_family_is_rejected(self):
        family = carriers.families("dev")[0]
        for broken in (
            family._replace(template=family.template + "<<value>>"),
            family._replace(template=family.template.replace("<<value>>", "")),
            family._replace(template=family.template + "<<secret>>"),
            family._replace(env_ref=("not in template <<value>>", "x")),
            family._replace(escape=("base64",)),
            family._replace(split="test"),
        ):
            with self.assertRaises(carriers.CarrierError):
                carriers.validate_family(broken)


class ProfileTests(unittest.TestCase):
    def test_every_value_rule_has_a_profile_matching_the_entity_map(self):
        entity_map = yaml.safe_load(ENTITY_MAP.read_text(encoding="utf-8"))
        by_rule = {}
        for entity in entity_map["entities"]:
            for rule_id in entity.get("ark") or []:
                by_rule[rule_id] = entity
        by_rule.update({entity["id"]: entity for entity in entity_map["entities"] if entity["id"] in rules.baseline_entities()})
        profiles = carriers.profiles()
        self.assertEqual(set(profiles), set(rules.load_rule_map()) | set(rules.baseline_entities()))
        for rule_id, profile in profiles.items():
            self.assertEqual(profile.entity, by_rule[rule_id]["id"], rule_id)
            self.assertEqual(profile.group, by_rule[rule_id].get("group"), rule_id)
            self.assertIn(profile.kind, {"secret", "identifier", "fragment"}, rule_id)
            self.assertTrue(profile.label_de and profile.label_en, rule_id)
            self.assertRegex(profile.key, r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$", rule_id)
        content = {entity["id"] for entity in entity_map["entities"] if entity["id"].startswith("content.")}
        for family in carriers.families():
            self.assertLessEqual(set(family.content), content, family.id)

    def test_key_forms(self):
        self.assertEqual(
            carriers.key_forms("openai_api_key"),
            {
                "KEY": "OPENAI_API_KEY",
                "key": "openai_api_key",
                "keyCamel": "openaiApiKey",
                "KeyPascal": "OpenaiApiKey",
                "key-kebab": "openai-api-key",
                "Key-Header": "Openai-Api-Key",
            },
        )

    def test_wrapped_values_keep_the_span_on_the_value(self):
        row = carriers.render("http.request_headers", "dlp_bearer_token", "positive", 7)
        (entity,) = row["entities"]
        self.assertEqual(row["text"][entity["start"] - len("Bearer ") : entity["start"]], "Bearer ")
        row = carriers.render("env.app_dotenv", "dlp_url_userinfo_password", "positive", 7)
        (entity,) = row["entities"]
        self.assertEqual(row["text"][entity["end"] : entity["end"] + 3], "@db")


class BuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = {split: carriers.build(split, SEED) for split in carriers.SPLITS}
        cls.families = {family.id: family for family in carriers.families()}

    def test_build_is_deterministic_and_seeded(self):
        again = carriers.build("dev", SEED, rules=["dlp_github_token", "dlp_password_assignment"])
        subset = [
            row for row in self.rows["dev"] if row["rule_id"] in ("dlp_github_token", "dlp_password_assignment")
        ]
        self.assertEqual(again, subset)
        other = carriers.build("dev", SEED + 1, rules=["dlp_github_token"], variants=["positive"])
        same = [row for row in subset if row["rule_id"] == "dlp_github_token" and row["variant"] == "positive"]
        self.assertEqual([row["id"] for row in other], [row["id"] for row in same])
        self.assertFalse({row["text"] for row in other} & {row["text"] for row in same})

    def test_rows_only_use_families_of_their_split(self):
        for split, rows in self.rows.items():
            ids = [row["id"] for row in rows]
            self.assertEqual(len(ids), len(set(ids)), split)
            for row in rows:
                self.assertEqual(row["split"], split)
                self.assertEqual(self.families[row["family"]].split, split)
                self.assertEqual(row["span_unit"], "unicode_code_point")

    def test_positive_spans_are_code_points_on_the_value_only(self):
        non_bmp = 0
        for rows in self.rows.values():
            for row in rows:
                if row["variant"] != "positive":
                    continue
                family = self.families[row["family"]]
                profile = carriers.profiles()[key_of(row)]
                (entity,) = row["entities"]
                value = recipes.generate(row["generator"], row["seed"])
                surface = row["text"][entity["start"] : entity["end"]]
                self.assertEqual(surface, entity["text"], row["id"])
                self.assertEqual(unescape(surface, family), value, row["id"])
                self.assertEqual(entity["encoding"], list(family.escape), row["id"])
                self.assertEqual(
                    (entity["label"], entity["entity"], entity["rule_id"]),
                    (profile.group, profile.entity, row["rule_id"]),
                )
                self.assertIn(row["generator"], rules.generators_for(key_of(row)))
                self.assertEqual(row["case_type"], "positive")
                prefix = row["text"][: entity["start"]]
                if any(ord(char) > 0xFFFF for char in prefix):
                    non_bmp += 1
                    self.assertNotEqual(len(prefix.encode("utf-16-le")) // 2, entity["start"])
        self.assertGreater(non_bmp, 0, "no family puts a non-BMP character before the value")

    def test_structured_carriers_parse_and_carry_the_value(self):
        checked = Counter()
        for rows in self.rows.values():
            for row in rows:
                family = self.families[row["family"]]
                if family.syntax is None:
                    continue
                found = parse_leaves(family.syntax, row["text"])
                checked[family.syntax] += 1
                if row["variant"] == "positive":
                    value = recipes.generate(row["generator"], row["seed"])
                    inner = value
                    for escape in family.escape[:-1]:
                        inner = carriers.escape_value(inner, (escape,), family.indent)
                    self.assertTrue(any(inner in leaf for leaf in found), row["id"])
        self.assertEqual(set(checked), {"json", "jsonl", "yaml", "toml", "xml"})

    def test_hard_negatives_have_no_spans_and_no_generated_value(self):
        for rows in self.rows.values():
            positives = {
                (row["family"], key_of(row)): recipes.generate(row["generator"], row["seed"])
                for row in rows
                if row["variant"] == "positive"
            }
            for row in rows:
                if row["variant"] == "positive":
                    continue
                self.assertIn(row["variant"], HARD_NEGATIVES)
                self.assertEqual(row["case_type"], "hard_negative")
                self.assertEqual(row["entities"], [])
                self.assertNotIn(positives[(row["family"], key_of(row))], row["text"], row["id"])
                if row["variant"] == "env_ref":
                    forms = carriers.key_forms(carriers.profiles()[key_of(row)].key)
                    self.assertTrue(any(form in row["text"] for form in forms.values()), row["id"])

    def test_doc_examples_and_test_keys_keep_the_shape_but_fail_structure(self):
        for name, check in STRUCTURAL.items():
            for variant in ("doc_example", "test_key"):
                value = carriers.hard_negative_value(name, variant)
                self.assertEqual(len(value), recipes.generator_length(name), f"{name} {variant}")
                self.assertFalse(check(value), f"{name} {variant}")
        for name, pattern in SHAPE.items():
            for variant in ("doc_example", "test_key"):
                self.assertRegex(carriers.hard_negative_value(name, variant), f"^{pattern}$", f"{name} {variant}")

    def test_encoded_hard_negatives_only_break_checksum_or_structure(self):
        for variant in ("doc_example", "test_key"):
            # Base58Check: version byte and length intact, only the check value is wrong.
            for name, size, version in (
                ("btc_wif_mainnet_uncompressed", 37, b"\x80"),
                ("btc_wif_mainnet_compressed", 38, b"\x80"),
                ("btc_wif_testnet_uncompressed", 37, b"\xef"),
                ("btc_wif_testnet_compressed", 38, b"\xef"),
            ):
                value = carriers.hard_negative_value(name, variant)
                self.assertIsNone(checks.base58check_decode(value), name)
                number = 0
                for character in value:
                    number = number * 58 + checks.BASE58.index(character)
                raw = number.to_bytes(size, "big")
                self.assertEqual(raw[:2], version + b"\x7e", name)
                self.assertEqual(checks.base58check_decode(recipes.base58check(raw[:-4])), raw[:-4], name)
            # JWT: every segment is canonical base64url, the header still reads as JSON
            # up to its last byte, which is what breaks it.
            for name in ("jwt_signed_hs256", "jwt_signed_rs256"):
                segments = [checks.b64url_decode(part) for part in carriers.hard_negative_value(name, variant).split(".")]
                self.assertTrue(all(segment is not None for segment in segments), name)
                self.assertTrue(segments[0].startswith(b'{"alg":"'), name)
                self.assertEqual(json.loads(segments[0][:-1] + b"}")["typ"], "JWT", name)
            # PEM: label, line width and canonical base64 intact, DER/OpenSSH layout broken.
            for name in [name for name in STRUCTURAL if name.startswith("pem_")]:
                value = carriers.hard_negative_value(name, variant)
                self.assertEqual(len(checks.pem_blocks(value)), 1, name)
        self.assertIn("EXAMPLE", carriers.hard_negative_value("aws_access_key_id", "doc_example"))
        self.assertTrue(carriers.hard_negative_value("github_ghp_token", "test_key").startswith("ghp_"))
        self.assertNotEqual(
            carriers.hard_negative_value("password", "doc_example"),
            carriers.hard_negative_value("password", "test_key"),
        )

    def test_every_rule_and_variant_is_covered_per_split_and_language(self):
        for split, rows in self.rows.items():
            positives = Counter((key_of(row), row["language"]) for row in rows if row["variant"] == "positive")
            for rule_id in carriers.profiles():
                for language in ("de", "en"):
                    self.assertGreaterEqual(positives[(rule_id, language)], 3, f"{split} {rule_id} {language}")
            variants = Counter((row["variant"], row["language"]) for row in rows)
            for variant in carriers.VARIANTS:
                for language in ("de", "en"):
                    self.assertGreaterEqual(variants[(variant, language)], 50, f"{split} {variant} {language}")
            formats = Counter(row["format"] for row in rows if row["variant"] == "positive")
            self.assertEqual(set(formats), FORMATS, split)

    def test_baseline_entities_get_gold_and_hard_negatives_in_both_languages(self):
        # GOLD-D2: >= 10 positives and >= 5 hard negatives per entity, DE and EN, in every split.
        baseline = rules.baseline_entities()
        for split, rows in self.rows.items():
            counts = Counter((row["entity"], row["case_type"], row["language"]) for row in rows if row["entity"] in baseline)
            formats = Counter((row["entity"], row["format"]) for row in rows if row["variant"] == "positive")
            for entity in baseline:
                for language in ("de", "en"):
                    self.assertGreaterEqual(counts[(entity, "positive", language)], 5, f"{split} {entity} {language}")
                    self.assertGreaterEqual(counts[(entity, "hard_negative", language)], 5, f"{split} {entity} {language}")
                self.assertGreaterEqual(sum(counts[(entity, "positive", language)] for language in ("de", "en")), 10)
                self.assertLessEqual(
                    {"env", "yaml", "json", "code", "log", "chat", "mail"}, {f for e, f in formats if e == entity}, entity
                )
            for row in rows:
                if row["entity"] not in baseline:
                    self.assertNotEqual(row["variant"], "lookalike", row["id"])
                    continue
                self.assertIsNone(row["rule_id"], row["id"])
                if row["variant"] == "positive":
                    self.assertIsNone(row["entities"][0]["rule_id"], row["id"])
                    self.assertIn(row["generator"], baseline[row["entity"]]["generators"], row["id"])
                if row["variant"] == "lookalike":
                    # Neutral key: under the entity's own key the value would still be a credential.
                    self.assertIn(row["generator"], baseline[row["entity"]]["lookalike"], row["id"])
                    self.assertNotIn(carriers.profiles()[row["entity"]].key, row["text"].lower(), row["id"])
                    self.assertIn(recipes.generate(row["generator"], row["seed"]), row["text"], row["id"])

    def test_family_kinds_and_multiline_values_are_respected(self):
        for rows in self.rows.values():
            for row in rows:
                family = self.families[row["family"]]
                profile = carriers.profiles()[key_of(row)]
                self.assertIn(profile.kind, family.accepts, row["id"])
                if row["variant"] == "positive" and not family.multiline:
                    self.assertNotIn("\n", recipes.generate(row["generator"], row["seed"]), row["id"])

    def test_content_labels_follow_the_family(self):
        for rows in self.rows.values():
            for row in rows:
                self.assertEqual(row["content_labels"], list(self.families[row["family"]].content))
        code = [f for f in carriers.families() if f.format in ("code", "jupyter")]
        self.assertTrue(all("content.source_code" in f.content for f in code))
        logs = [f for f in carriers.families() if f.format == "log"]
        self.assertTrue(all("content.system_log" in f.content for f in logs))


class CliTests(unittest.TestCase):
    def test_cli_writes_jsonl_for_one_split(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "dev.jsonl"
            subprocess.run(
                [
                    sys.executable, "-m", "patronus_ark.dlp_synth.carriers",
                    "--split", "dev", "--seed", "5", "--rule", "dlp_jwt_token", "--out", str(out),
                ],
                check=True,
                cwd=REPO / "python",
            )
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(rows, carriers.build("dev", 5, rules=["dlp_jwt_token"]))

    def test_cli_rejects_unknown_split(self):
        result = subprocess.run(
            [sys.executable, "-m", "patronus_ark.dlp_synth.carriers", "--split", "test", "--seed", "1"],
            cwd=REPO / "python",
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)


class SelfScanTests(unittest.TestCase):
    def test_template_source_has_no_secret_finding(self):
        from patronus_ark import SecurityGateway

        gateway = SecurityGateway(categories=["dlp"], max_level="l1", download_files=False)
        value_rules = set(rules.load_rule_map())
        source = Path(carriers.__file__).with_name("carrier_templates.py").read_text(encoding="utf-8")
        findings = [
            (match["rule_id"], source.encode("utf-8")[match["start_byte"] : match["end_byte"]][:24])
            for result in gateway.scan_category("dlp", source)
            for layer in result["layers"]
            for match in (layer.get("details") or {}).get("matched_rules", [])
            if match["rule_id"] in value_rules
        ]
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
