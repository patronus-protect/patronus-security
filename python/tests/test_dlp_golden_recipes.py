import hashlib
import json
import re
import unittest
import zlib

from patronus_ark import benchmark
from patronus_ark.dlp_synth import recipes


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
            value = recipes.generate(name, 11)
            offset = 0
            for segment in spec["segments"]:
                if "lit" in segment:
                    self.assertEqual(value[offset : offset + len(segment["lit"])], segment["lit"], name)
                    offset += len(segment["lit"])
                else:
                    alphabet = alphabets[segment["alphabet"]]
                    chunk = value[offset : offset + segment["len"]]
                    self.assertTrue(set(chunk) <= set(alphabet), name)
                    offset += segment["len"]
            self.assertEqual(offset, len(value), name)


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
                for secret in row["secrets"]:
                    self.assertEqual(set(secret), {"gen", "seed"}, row["id"])
            else:
                self.assertNotIn("secrets", row, row["id"])
        self.assertEqual(
            sum("template" in row for row in rows),
            sum(
                row["target_label"] in SECRET_GROUPS and row["case_type"] == "positive"
                for row in rows
            ),
        )

    def test_recipe_rows_materialize_to_the_recorded_text_and_spans(self):
        for row in load_dlp_rows():
            if "template" not in row:
                continue
            text, spans = recipes.materialize(row["template"], row["secrets"])
            self.assertEqual(
                hashlib.sha256(text.encode("utf-8")).hexdigest(), row["text_sha256"], row["id"]
            )
            self.assertEqual(recipes.materialize_row(row)["text"], text, row["id"])
            for entity in row["entities"]:
                self.assertEqual(
                    (entity["start"], entity["end"]), spans[entity["secret"]], row["id"]
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
