import base64
import hashlib
import json
import re
import runpy
import unittest
import zlib

from patronus_ark import benchmark
from patronus_ark.dlp_synth import recipes, rules


# F01: rules whose strict hard negatives may also hold plain generator values (no key context).
CONTEXT_GATED_RULES = set(
    runpy.run_path(str(benchmark.DATA_DIR / "generate_l1_goldens.py"))["DLP_CONTEXT_GATED_RULES"]
)
LOOKALIKE_GENERATORS = {name for entry in rules.load_rule_map().values() for name in entry.get("lookalike", [])}
SECRET_GROUPS = {
    "API_KEY",
    "CLOUD_KEY",
    "CREDENTIAL",
    "CRYPTO_KEY",
    "PASSWORD_HASH",
    "PAYMENT_KEY",
    "PRIVATE_KEY",
    "SECRET_TOKEN",
}

BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def load_dlp_rows():
    path = benchmark.DATA_DIR / "dlp_l1.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def base62_crc32(value):
    checksum = zlib.crc32(value.encode("ascii"))
    digits = ""
    while checksum:
        checksum, remainder = divmod(checksum, 62)
        digits = BASE62[remainder] + digits
    return digits.rjust(6, "0")


def has_valid_crc32_suffix(token):
    """GitHub/npm token layout: prefix_ + 30 random chars + 6 base62 CRC32 chars."""
    body = token.split("_", 1)[1]
    return len(body) == 36 and base62_crc32(body[:30]) == body[30:]


def has_valid_base58check(value):
    number = 0
    for character in value:
        number = number * 58 + BASE58.index(character)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(value) - len(value.lstrip("1"))) + raw
    if len(raw) < 5:
        return False
    payload, checksum = raw[:-4], raw[-4:]
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum


class SplitMix64Tests(unittest.TestCase):
    def test_reference_vectors(self):
        # Published SplitMix64 outputs (Steele, Lea & Flood 2014 reference code).
        rng = recipes.SplitMix64(1234567)
        self.assertEqual(
            [rng.next_u64() for _ in range(5)],
            [
                6457827717110365317,
                3203168211198807973,
                9817491932198370423,
                4593380528125082431,
                16408922859458223821,
            ],
        )
        self.assertEqual(recipes.SplitMix64(0).next_u64(), 0xE220A8397B1DCDAF)

    def test_seed_must_be_an_unsigned_64_bit_integer(self):
        for seed in (-1, 2**64, 1.5, "7", True):
            with self.assertRaises(recipes.RecipeError, msg=repr(seed)):
                recipes.SplitMix64(seed)


class GeneratorTests(unittest.TestCase):
    def test_every_generator_is_deterministic_and_has_its_declared_length(self):
        generators = recipes.load_generators()
        self.assertTrue(generators)
        for name in generators:
            value = recipes.generate(name, 7)
            self.assertEqual(value, recipes.generate(name, 7), name)
            self.assertEqual(len(value), recipes.generator_length(name), name)
            self.assertTrue(value.isascii(), name)

    def test_random_generators_depend_on_the_seed(self):
        for name in recipes.load_generators():
            if recipes.is_random(name):
                self.assertNotEqual(recipes.generate(name, 7), recipes.generate(name, 8), name)

    def test_unknown_generator_is_rejected(self):
        with self.assertRaises(recipes.RecipeError):
            recipes.generate("no_such_generator", 1)

    def test_random_segments_draw_from_their_alphabet(self):
        generators = recipes.load_generators()
        alphabets = recipes.load_alphabets()
        for name, spec in generators.items():
            parts = recipes.generate_segments(name, 11)
            self.assertEqual(len(parts), len(spec["segments"]), name)
            for segment, part in zip(spec["segments"], parts):
                if "lit" in segment:
                    self.assertEqual(part, segment["lit"], name)
                elif "alphabet" in segment:
                    self.assertEqual(len(part), segment["len"], name)
                    self.assertTrue(set(part) <= set(alphabets[segment["alphabet"]]), name)


class MaterializeTests(unittest.TestCase):
    def test_placeholders_are_replaced_and_spans_are_code_points(self):
        secrets = [
            {"gen": "aws_access_key_id", "seed": 1},
            {"gen": "gitlab_pat", "seed": 2},
        ]
        text, spans = recipes.materialize("Schlüssel: <<secret:1>> / ä <<secret:0>>.", secrets)
        first = recipes.generate("aws_access_key_id", 1)
        second = recipes.generate("gitlab_pat", 2)
        self.assertEqual(text, f"Schlüssel: {second} / ä {first}.")
        self.assertEqual(text[spans[0][0] : spans[0][1]], first)
        self.assertEqual(text[spans[1][0] : spans[1][1]], second)
        self.assertEqual(spans[1][0], len("Schlüssel: "))

    def test_invalid_templates_are_rejected(self):
        recipe = [{"gen": "aws_access_key_id", "seed": 1}]
        for template, secrets in (
            ("no placeholder", recipe),
            ("<<secret:0>> <<secret:0>>", recipe),
            ("<<secret:1>>", recipe),
            ("<<secret:0>> <<secret:1>>", recipe),
            ("<<secret:00>>", recipe),
            ("<<secret:0>>", [{"gen": "aws_access_key_id"}]),
            ("<<secret:0>>", [{"gen": "aws_access_key_id", "seed": 1, "extra": True}]),
            ("<<secret:0>>", []),
        ):
            with self.assertRaises(recipes.RecipeError, msg=template):
                recipes.materialize(template, secrets)


# Fingerprints of fill recipes (T06), shared with rust/tests/dlp_golden_recipes.rs.
FILL_VECTORS = (
    ("discord_bot_token", 3, "BEISPIEL", "d11dbcce9d135339073d4b7b"),
    ("jwt_signed_hs256", 4, "TEST", "b4882c1e8ceb557640c94fe5"),
    ("slack_user_token", 5, "1234567890", "675ae1cdc899798059fe00cd"),
    ("pem_pkcs8_ed25519_private_key", 6, "EXAMPLEKEY", "bc01d602c9960964878238e1"),
    ("github_ghp_token", 7, "EXAMPLEKEY", "44968e27b5851e702074d3da"),
    ("bearer_opaque_token", 8, "DUMMY", "732f853eb396c222a69bfb5c"),
)


class FillRecipeTests(unittest.TestCase):
    """The example/test variant of a generator (``"fill"``, T06)."""

    def test_fill_keeps_literals_and_length_and_repeats_the_word(self):
        word = "EXAMPLEKEY"
        value = recipes.generate("github_ghp_token", 7, word)
        # Values are assembled here from the word; the checksum is zeroed.
        self.assertEqual(value, "ghp_" + (word * 3)[:30] + "0" * 6)
        self.assertEqual(recipes.generate("github_ghp_token", 8, word), value)
        value = recipes.generate("anthropic_api_key", 1, word)
        self.assertEqual(value, "sk-ant-api03-" + (word * 10)[:93] + "AA")
        for name in recipes.load_generators():
            for fill in ("EXAMPLEKEY", "deadbeef", "1234567890"):
                try:
                    value = recipes.generate(name, 3, fill)
                except recipes.RecipeError:
                    continue
                self.assertEqual(len(value), recipes.generator_length(name), (name, fill))
                self.assertEqual(value, recipes.generate(name, 3, fill), (name, fill))

    def test_segments_without_the_word_are_drawn_and_encoded_segments_repeat_it(self):
        # Slack: digit segments take the sequential fill, the one-digit leads 1-9 are drawn.
        value = recipes.generate("slack_user_token", 5, "1234567890")
        self.assertTrue(value.startswith("xoxp-"), value)
        self.assertTrue(value.endswith("-" + ("1234567890" * 4)[:32]), value)
        # Random-only base64url segments repeat the word over the encoded characters.
        signature = recipes.generate("jwt_signed_hs256", 4, "TEST").rsplit(".", 1)[1]
        self.assertEqual(signature, ("TEST" * 11)[:43])
        # Mixed segments encode the word bytes: the PEM body keeps its DER prefix and width.
        body = recipes.generate("pem_pkcs8_ed25519_private_key", 6, "EXAMPLEKEY").split("\n")[1]
        self.assertEqual(base64.b64decode(body)[16:], (b"EXAMPLEKEY" * 4)[:32])

    def test_zero_checksums_turn_to_ones_when_zeros_would_be_valid(self):
        for seed in range(4):
            value = recipes.generate("npm_access_token", seed, "test")
            self.assertEqual(value[-6:], "000000")
            self.assertNotEqual(recipes.crc32_base62(value[4:-6]), value[-6:])

    def test_fill_vectors_are_pinned(self):
        for name, seed, fill, fingerprint in FILL_VECTORS:
            self.assertEqual(recipes.fingerprint(recipes.generate(name, seed, fill)), fingerprint, name)

    def test_invalid_fills_are_rejected(self):
        for name, fill in (
            ("github_ghp_token", ""),
            ("github_ghp_token", "EXAMPLE KEY"),
            ("github_ghp_token", "BEISPIEL-1"),
            ("github_ghp_token", "Müster"),
            ("github_ghp_token", 5),
            ("md5_hex", "TESTKEY"),  # fits no segment: the value would stay random
            ("btc_wif_mainnet_compressed", "EXAMPLEKEY"),  # Base58Check stays valid
        ):
            with self.assertRaises(recipes.RecipeError, msg=(name, fill)):
                recipes.generate(name, 1, fill)
        with self.assertRaises(recipes.RecipeError):
            recipes.materialize("<<secret:0>>", [{"gen": "gitlab_pat", "seed": 1, "fill": "TEST", "x": 1}])
        text, spans = recipes.materialize("k=<<secret:0>>", [{"gen": "gitlab_pat", "seed": 1, "fill": "TEST"}])
        self.assertEqual(text[spans[0][0] : spans[0][1]], recipes.generate("gitlab_pat", 1, "TEST"))


class PlaceholderTransformTests(unittest.TestCase):
    def test_transform_vectors(self):
        # Fixed vectors, shared with rust/tests/dlp_golden_recipes.rs.
        value = 'a/b c+d:"e"\\\n\t\x01~'
        self.assertEqual(recipes.transform(value, "base64"), "YS9iIGMrZDoiZSJcCgkBfg==")
        self.assertEqual(recipes.transform(value, "hex"), "612f6220632b643a2265225c0a09017e")
        self.assertEqual(recipes.transform(value, "url"), "a%2Fb%20c%2Bd%3A%22e%22%5C%0A%09%01~")
        self.assertEqual(recipes.transform(value, "json"), 'a/b c+d:\\"e\\"\\\\\\n\\t\\u0001~')
        self.assertEqual(recipes.transform("\b\f\r", "json"), "\\b\\f\\r")
        self.assertEqual(json.loads(f'"{recipes.transform(value, "json")}"'), value)
        self.assertEqual(recipes.TRANSFORMS, ("base64", "hex", "url", "json"))
        with self.assertRaises(recipes.RecipeError):
            recipes.transform(value, "rot13")

    def test_encoded_placeholder_spans_cover_the_encoded_value(self):
        secrets = [{"gen": "github_ghp_token", "seed": 3}]
        value = recipes.generate("github_ghp_token", 3)
        text, fragments = recipes.materialize_fragments("tok: <<secret:0|base64>>!", secrets)
        encoded = base64.b64encode(value.encode()).decode()
        self.assertEqual(text, f"tok: {encoded}!")
        self.assertEqual(
            fragments, [{"secret": 0, "part": 0, "start": 5, "end": 5 + len(encoded), "encoding": "base64"}]
        )
        self.assertEqual(recipes.materialize("tok: <<secret:0|base64>>!", secrets), (text, [(5, 5 + len(encoded))]))

    def test_split_placeholders_yield_one_fragment_per_part(self):
        secrets = [{"gen": "aws_access_key_id", "seed": 4}, {"gen": "gitlab_pat", "seed": 5}]
        first = recipes.generate("aws_access_key_id", 4)
        second = recipes.generate("gitlab_pat", 5)
        template = 'k = "<<secret:0[0:4]>>" + "ä<<secret:1>>" + "<<secret:0[4:20]>>"'
        text, fragments = recipes.materialize_fragments(template, secrets)
        self.assertEqual(text, f'k = "{first[:4]}" + "ä{second}" + "{first[4:]}"')
        self.assertEqual([(f["secret"], f["part"]) for f in fragments], [(0, 0), (1, 0), (0, 1)])
        self.assertEqual("".join(text[f["start"] : f["end"]] for f in fragments if f["secret"] == 0), first)
        self.assertEqual(text[fragments[1]["start"] : fragments[1]["end"]], second)
        with self.assertRaises(recipes.RecipeError):
            recipes.materialize(template, secrets)

    def test_invalid_transforms_and_splits_are_rejected(self):
        one = [{"gen": "aws_access_key_id", "seed": 1}]
        for template in (
            "<<secret:0|rot13>>",
            "<<secret:0|>>",
            "<<secret:0|BASE64>>",
            "<<secret:0|json>>",  # JSON escaping leaves an AKIA key unchanged
            "<<secret:0[0:20]>>",  # a split needs at least two parts
            "<<secret:0[0:4]>><<secret:0[5:20]>>",  # gap
            "<<secret:0[0:4]>><<secret:0[3:20]>>",  # overlap
            "<<secret:0[4:20]>><<secret:0[0:4]>>",  # out of order
            "<<secret:0[0:4]>><<secret:0[4:19]>>",  # does not reach the end
            "<<secret:0[0:4]>><<secret:0[4:21]>>",  # past the end
            "<<secret:0[0:4]>><<secret:0>>",  # slice and whole value
            "<<secret:0[0:4]>><<secret:0[4:20]|hex>>",
            "<<secret:0[00:4]>><<secret:0[4:20]>>",
            "<<secret:0[0:0]>><<secret:0[0:20]>>",
            "<<secret:0|hex>> <<secret:0|hex>>",
        ):
            with self.assertRaises(recipes.RecipeError, msg=template):
                recipes.materialize_fragments(template, one)


class DlpGoldenRecipeTests(unittest.TestCase):
    def test_secret_values_are_stored_only_as_recipes(self):
        rows = load_dlp_rows()
        for row in rows:
            if row["target_label"] in SECRET_GROUPS and row["case_type"] == "positive":
                self.assertNotIn("text", row, row["id"])
                self.assertIn("template", row, row["id"])
                for entity in row["entities"]:
                    self.assertNotIn("text", entity, row["id"])
            if "template" in row:
                self.assertNotIn("text", row, row["id"])
                self.assertTrue(row["secrets"], row["id"])
                # Positives hold real-shaped recipes; hard negatives only fill variants, except
                # hard negatives of a scored DLP mode (K04), whose context marks the value as
                # no secret, values glued into a longer run (T01), which are no token, and
                # values of a context-gated rule without key context (F01), and lookalike values
                # with a wrong check value or length (F03), which are no secret.
                glued = not re.search(r"(?<![A-Za-z0-9_+/])<<secret:", row["template"])
                plain = (
                    row["case_type"] == "positive"
                    or row.get("dlp_mode") in ("balanced", "recall")
                    or glued
                    or all(secret["gen"] in LOOKALIKE_GENERATORS for secret in row["secrets"])
                )
                keys = {"gen", "seed"} if plain else {"gen", "seed", "fill"}
                for secret in row["secrets"]:
                    if row.get("rule_id") in CONTEXT_GATED_RULES and row["case_type"] != "positive":
                        self.assertIn(set(secret), ({"gen", "seed"}, {"gen", "seed", "fill"}), row["id"])
                        continue
                    self.assertEqual(set(secret), keys, row["id"])
            else:
                self.assertNotIn("secrets", row, row["id"])
        self.assertEqual(
            sum("template" in row and row["case_type"] == "positive" for row in rows),
            sum(
                row["target_label"] in SECRET_GROUPS and row["case_type"] == "positive"
                for row in rows
            ),
        )
        # T06: provider-format example/test values of hard negatives are fill recipes.
        self.assertGreaterEqual(sum("template" in row and row["case_type"] == "hard_negative" for row in rows), 50)

    def test_recipe_rows_materialize_to_the_recorded_text_and_spans(self):
        for row in load_dlp_rows():
            if "template" not in row:
                continue
            text, fragments = recipes.materialize_fragments(row["template"], row["secrets"])
            self.assertEqual(
                hashlib.sha256(text.encode("utf-8")).hexdigest()[:24],
                row["text_fingerprint"],
                row["id"],
            )
            self.assertEqual(recipes.fingerprint(text), row["text_fingerprint"], row["id"])
            self.assertEqual(recipes.materialize_row(row)["text"], text, row["id"])
            if row["case_type"] == "hard_negative":
                self.assertEqual(row["entities"], [], row["id"])
                continue
            # One entity per fragment: `part` only on split secrets, `encoding` only on
            # encoded ones, and the encoded span decodes back to the generator value.
            self.assertEqual(len(row["entities"]), len(fragments), row["id"])
            split = {fragment["secret"] for fragment in fragments if fragment["part"]}
            for entity, fragment in zip(row["entities"], fragments):
                self.assertEqual(
                    (entity["start"], entity["end"], entity["secret"]),
                    (fragment["start"], fragment["end"], fragment["secret"]),
                    row["id"],
                )
                self.assertEqual(entity.get("part"), fragment["part"] if fragment["secret"] in split else None, row["id"])
                encoding = [fragment["encoding"]] if fragment["encoding"] else None
                self.assertEqual(entity.get("encoding"), encoding, row["id"])
                if encoding:
                    secret = row["secrets"][fragment["secret"]]
                    self.assertEqual(
                        recipes.transform(recipes.generate(secret["gen"], secret["seed"]), encoding[0]),
                        text[entity["start"] : entity["end"]],
                        row["id"],
                    )

    def test_materialize_row_passes_literal_rows_through(self):
        row = next(row for row in load_dlp_rows() if "text" in row)
        self.assertEqual(recipes.materialize_row(row), row)

    def test_goldens_contain_no_checksum_valid_tokens(self):
        raw = (benchmark.DATA_DIR / "dlp_l1.jsonl").read_text()
        for token in re.findall(r"\b(?:gh[pousr]|npm)_[A-Za-z0-9]{36}\b", raw):
            self.assertFalse(has_valid_crc32_suffix(token))
        for candidate in re.findall(r"(?<![1-9A-Za-z])[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}(?![1-9A-Za-z])", raw):
            self.assertFalse(has_valid_base58check(candidate))
        # Private-key blocks and headers are generator output, never literal fixture text.
        self.assertNotIn("PRIVATE KEY-----", raw)

    def test_checksum_helpers_accept_constructed_valid_vectors(self):
        # Guard against a checker that can never fire; vectors are built at test time only.
        body = "".join(BASE62[(index * 7) % 62] for index in range(30))
        self.assertTrue(has_valid_crc32_suffix("ghp_" + body + base62_crc32(body)))
        self.assertFalse(has_valid_crc32_suffix("ghp_" + body + "000000"))
        payload = b"\x80" + bytes(range(32))
        raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        number = int.from_bytes(raw, "big")
        encoded = ""
        while number:
            number, remainder = divmod(number, 58)
            encoded = BASE58[remainder] + encoded
        self.assertTrue(has_valid_base58check(encoded))
        self.assertFalse(has_valid_base58check(encoded[:-1] + ("2" if encoded[-1] != "2" else "3")))


if __name__ == "__main__":
    unittest.main()
