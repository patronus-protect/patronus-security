"""E03: synthetic DLP secret generator.

Every generator listed for a rule in ``dlp_synth/rules.json`` must produce values that
(a) pass an independent offline format/structure/checksum check and (b) are reported
by exactly that rule with exactly the value span. Generated values exist only in memory.
"""

import json
import unittest
from pathlib import Path

from patronus_ark import SecurityGateway
from patronus_ark.dlp_synth import checks, recipes, rules


REPO = Path(__file__).resolve().parents[2]
VECTORS_PATH = REPO / "rust/tests/fixtures/dlp_synth_vectors.json"
SEEDS = range(64)


def prefixed(prefix, alphabet, length, suffix=""):
    def check(value):
        body = value[len(prefix) : len(value) - len(suffix)]
        return (
            value.startswith(prefix)
            and value.endswith(suffix)
            and len(body) == length
            and set(body) <= set(alphabet)
        )

    return check


def pem(label, der_check):
    def check(value):
        blocks = checks.pem_blocks(value)
        return len(blocks) == 1 and blocks[0][0] == label and der_check(blocks[0][1])

    return check


def jwt(alg, signature_bytes, claims):
    def check(value):
        parts = checks.jwt_parts(value)
        return (
            parts is not None
            and parts[0].get("alg") == alg
            and parts[0].get("typ") == "JWT"
            and set(parts[1]) == claims
            and len(parts[2]) == signature_bytes
        )

    return check


def discord(value):
    user, timestamp, hmac = value.split(".")
    user_id = checks.b64url_decode(user)
    return (
        user[0] in "MN"
        and user_id is not None
        and user_id.isdigit()
        and len(user_id) == 18
        and not user_id.startswith(b"0")
        and checks.b64url_decode(timestamp) is not None
        and len(checks.b64url_decode(timestamp)) == 4
        and checks.b64url_decode(hmac) is not None
        and len(checks.b64url_decode(hmac)) == 20
    )


def bcrypt(value):
    head, salt_and_hash = value[:7], value[7:]
    salt = checks.bcrypt64_decode(salt_and_hash[:22])
    digest = checks.bcrypt64_decode(salt_and_hash[22:])
    return head == "$2b$12$" and salt is not None and len(salt) == 16 and digest is not None and len(digest) == 23


def argon2id(value):
    prefix = "$argon2id$v=19$m=65536,t=3,p=4$"
    salt, _, digest = value[len(prefix) :].partition("$")
    salt_raw = checks.b64decode_unpadded(salt)
    digest_raw = checks.b64decode_unpadded(digest)
    return (
        value.startswith(prefix)
        and salt_raw is not None
        and len(salt_raw) == 16
        and digest_raw is not None
        and len(digest_raw) == 32
    )


def base64url_bytes(length):
    def check(value):
        raw = checks.b64url_decode(value)
        return raw is not None and len(raw) == length

    return check


def basic_auth(value):
    pair = checks.basic_auth_pair(value)
    return pair is not None and pair[0].islower() and len(pair[0]) == 8 and pair[1].isalnum()


def record_reference(value):
    letters, year, number = value.split("-")
    return letters.isupper() and len(letters) == 2 and year.startswith("20") and len(year) == 4 and len(number) == 6


ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
B64URL = ALNUM + "-_"
B64 = ALNUM + "+/"
HEX = "0123456789abcdef"
DIGITS = "0123456789"

# One independent check per format-valid generator (shape_only generators excluded).
CHECKS = {
    "anthropic_api_key": prefixed("sk-ant-api03-", B64URL, 93, "AA"),
    "anthropic_admin_key": prefixed("sk-ant-admin01-", B64URL, 93, "AA"),
    "openai_project_api_key": lambda v: prefixed("sk-proj-", B64URL, 156)(v) and v[82:90] == "T3BlbkFJ",
    "openai_service_account_key": lambda v: prefixed("sk-svcacct-", ALNUM + "-", 156)(v) and v[85:93] == "T3BlbkFJ",
    "openai_legacy_key": lambda v: prefixed("sk-", ALNUM, 48)(v) and v[23:31] == "T3BlbkFJ",
    "huggingface_token": prefixed("hf_", ALNUM[:52], 34),
    "groq_key": prefixed("gsk_", ALNUM, 52),
    "xai_api_key": prefixed("xai-", ALNUM, 80),
    "replicate_api_token": prefixed("r8_", ALNUM, 37),
    "aws_access_key_id": prefixed("AKIA", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16),
    "aws_session_access_key_id": prefixed("ASIA", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16),
    "aws_secret_access_key": prefixed("", B64, 40),
    "google_api_key": prefixed("AIza", B64URL, 35),
    "google_oauth_access_token": prefixed("ya29.", B64URL, 150),
    "gcp_oauth_client_secret": prefixed("GOCSPX-", B64URL, 28),
    "github_ghp_token": lambda v: checks.has_valid_crc32_suffix(v, "ghp_"),
    "github_gho_token": lambda v: checks.has_valid_crc32_suffix(v, "gho_"),
    "github_ghu_token": lambda v: checks.has_valid_crc32_suffix(v, "ghu_"),
    "github_ghs_token": lambda v: checks.has_valid_crc32_suffix(v, "ghs_"),
    "github_ghr_token": lambda v: checks.has_valid_crc32_suffix(v, "ghr_"),
    "github_fine_grained_pat": lambda v: prefixed("github_pat_", ALNUM + "_", 82)(v) and v[33] == "_",
    "gitlab_pat": prefixed("glpat-", B64URL, 20),
    "npm_access_token": lambda v: checks.has_valid_crc32_suffix(v, "npm_"),
    "stripe_secret_live": prefixed("sk_live_", ALNUM, 24),
    "stripe_restricted_test": prefixed("rk_test_", ALNUM, 24),
    "stripe_secret_test_long": prefixed("sk_test_", ALNUM, 99),
    "stripe_webhook_secret": prefixed("whsec_", ALNUM, 32),
    "slack_bot_token": lambda v: [len(p) for p in v.split("-")] == [4, 12, 13, 24] and v.startswith("xoxb-"),
    "slack_user_token": lambda v: [len(p) for p in v.split("-")] == [4, 12, 12, 13, 32] and v.startswith("xoxp-"),
    "discord_bot_token": discord,
    "eth_private_key_hex": checks.is_valid_eth_private_key,
    "btc_wif_mainnet_uncompressed": lambda v: v[0] == "5" and len(v) == 51 and checks.is_valid_btc_wif(v),
    "btc_wif_mainnet_compressed": lambda v: v[0] in "KL" and len(v) == 52 and checks.is_valid_btc_wif(v),
    "btc_wif_testnet_uncompressed": lambda v: v[0] == "9" and len(v) == 51 and checks.is_valid_btc_wif(v),
    "btc_wif_testnet_compressed": lambda v: v[0] == "c" and len(v) == 52 and checks.is_valid_btc_wif(v),
    "pem_pkcs8_ed25519_private_key": pem("PRIVATE KEY", checks.is_valid_pkcs8_ed25519),
    "pem_pkcs1_rsa_private_key": pem("RSA PRIVATE KEY", checks.is_valid_pkcs1_rsa),
    "pem_sec1_ec_private_key": pem("EC PRIVATE KEY", checks.is_valid_sec1_p256),
    "pem_dsa_private_key": pem("DSA PRIVATE KEY", checks.is_valid_dsa),
    "pem_openssh_ed25519_private_key": pem("OPENSSH PRIVATE KEY", checks.is_valid_openssh_ed25519),
    "pem_openssh_private_key_header": lambda v: v == "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
    "jwt_signed_hs256": jwt("HS256", 32, {"sub", "iat"}),
    "jwt_signed_rs256": jwt("RS256", 256, {"iss", "sub", "exp"}),
    "bearer_opaque_token": base64url_bytes(32),
    "csrf_token": base64url_bytes(32),
    "http_basic_auth": basic_auth,
    "password": lambda v: len(v) == 12 and v[0].isupper() and v[1:7].islower() and v[7:11].isdigit() and v[11] in "!%*?@",
    "url_userinfo_password": prefixed("", ALNUM + "-._~", 18),
    "url_token": prefixed("", ALNUM, 24),
    "generic_api_secret": prefixed("", HEX, 40),
    "aws_sigv4_signature": prefixed("", HEX, 64),
    "java_session_id": prefixed("", "0123456789ABCDEF", 32),
    "php_session_id": prefixed("", "0123456789abcdefghijklmnopqrstuv", 26),
    "bcrypt_2b_hash": bcrypt,
    "argon2id_phc_hash": argon2id,
    "md5_hex": prefixed("", HEX, 32),
    "sha256_hex": prefixed("", HEX, 64),
    "de_vat_id": checks.is_valid_de_vat_id,
    "de_commercial_register_number": lambda v: v.startswith("HRB ") and v[4:].isdigit() and v[4] != "0",
    "de_bsnr": lambda v: len(v) == 9 and v.isdigit() and v[0] != "0",
    "record_reference": record_reference,
}

# Pre-E03 shape generators that must not pass the structural check they lack.
SHAPE_ONLY_FAILURES = {
    "github_pat_classic": lambda v: checks.has_valid_crc32_suffix(v, "ghp_"),
    "btc_wif_uncompressed": checks.is_valid_btc_wif,
    "btc_wif_testnet_compressed_shape": checks.is_valid_btc_wif,
    "jwt_hs256": lambda v: checks.jwt_parts(v) is not None,
    "pem_pkcs8_private_key": pem("PRIVATE KEY", checks.is_valid_pkcs8_ed25519),
    "pem_rsa_private_key": pem("RSA PRIVATE KEY", checks.is_valid_pkcs1_rsa),
}

# F03 lookalikes: the rule's shape with a wrong check value or length.
LOOKALIKE_FAILURES = {
    **{
        f"github_{prefix}_bad_crc": (lambda prefix: lambda v: checks.has_valid_crc32_suffix(v, f"{prefix}_"))(prefix)
        for prefix in ("ghp", "gho", "ghu", "ghs", "ghr")
    },
    "github_ghp_short": lambda v: len(v) == 40,
    "github_gho_short": lambda v: len(v) == 40,
    "github_ghp_long": lambda v: len(v) == 40,
    "github_fine_grained_pat_short": lambda v: len(v) == 93,
    "github_fine_grained_pat_long": lambda v: len(v) == 93,
}


def valid_generators():
    names = set()
    for entry in rules.load_rule_map().values():
        names.update(entry["generators"])
    return names


def mutate(value, index):
    """Replace one character with a different one from the same character class."""
    character = value[index]
    pool = DIGITS if character.isdigit() else ALNUM
    return value[:index] + pool[(pool.index(character) + 1) % len(pool)] + value[index + 1 :]


class GeneratorSpecTests(unittest.TestCase):
    def test_every_generator_belongs_to_a_rule(self):
        referenced = set()
        for rule_id, entry in rules.load_rule_map().items():
            self.assertFalse(set(entry["generators"]) & set(entry.get("shape_only", [])), rule_id)
            self.assertGreaterEqual(len(entry["probes"]), 2, rule_id)
            self.assertFalse(set(entry["generators"]) & set(entry.get("weak", [])), rule_id)
            self.assertFalse(
                set(entry.get("lookalike", [])) & set(entry["generators"] + entry.get("weak", [])), rule_id
            )
            referenced.update(
                entry["generators"], entry.get("shape_only", []), entry.get("weak", []), entry.get("lookalike", [])
            )
        self.assertEqual(referenced, set(recipes.load_generators()))

    def test_every_valid_generator_has_an_independent_check(self):
        self.assertEqual(set(CHECKS), valid_generators())

    def test_shape_only_generators_are_never_listed_as_valid(self):
        shape_only = set()
        for entry in rules.load_rule_map().values():
            shape_only.update(entry.get("shape_only", []))
        self.assertFalse(shape_only & valid_generators())
        self.assertLessEqual(set(SHAPE_ONLY_FAILURES), shape_only)

    def test_generate_segments_join_to_generate(self):
        for name in recipes.load_generators():
            self.assertEqual("".join(recipes.generate_segments(name, 5)), recipes.generate(name, 5), name)

    def test_invalid_segments_are_rejected(self):
        alphabets = recipes.load_alphabets()
        for segment in (
            {"checksum": "luhn"},
            {"encode": "base32", "bytes": [{"random": 4}]},
            {"encode": "hex", "bytes": []},
            {"encode": "hex", "bytes": [{"hex": "zz"}]},
            {"encode": "hex", "bytes": [{"utf8": "ä"}]},
            {"encode": "hex", "bytes": [{"random": 0}]},
            {"encode": "base64url", "bytes": [{"random": 4}], "wrap": 64},
            {"encode": "base58check", "bytes": [{"random": 32}]},
            {"encode": "base58check", "bytes": [{"hex": "00"}, {"random": 32}]},
            {"alphabet": "no_such_alphabet", "len": 4},
            {"lit": ""},
        ):
            self.assertFalse(recipes._valid_segment(segment, alphabets), segment)


class StructureTests(unittest.TestCase):
    def test_generated_values_pass_their_format_structure_and_checksum_check(self):
        for name, check in CHECKS.items():
            for seed in SEEDS:
                value = recipes.generate(name, seed)
                self.assertTrue(check(value), f"{name} seed={seed}")
                self.assertEqual(len(value), recipes.generator_length(name), name)

    def test_shape_only_generators_fail_the_structural_check(self):
        for name, check in SHAPE_ONLY_FAILURES.items():
            for seed in range(8):
                self.assertFalse(check(recipes.generate(name, seed)), f"{name} seed={seed}")

    def test_lookalike_generators_fail_their_check(self):
        lookalike = set()
        for entry in rules.load_rule_map().values():
            lookalike.update(entry.get("lookalike", []))
        self.assertEqual(set(LOOKALIKE_FAILURES), lookalike)
        for name, check in LOOKALIKE_FAILURES.items():
            for seed in SEEDS:
                self.assertFalse(check(recipes.generate(name, seed)), f"{name} seed={seed}")

    def test_weak_github_token_keeps_its_repeated_chunk_and_a_valid_crc32(self):
        # F03: dlp_github_token checks the CRC32 over all 30 body characters.
        for seed in SEEDS:
            value = recipes.generate("weak_repeated_chunk_github_token", seed)
            self.assertTrue(checks.has_valid_crc32_suffix(value, "ghp_"), f"seed={seed}")
            self.assertEqual(value[14:26], "Zq7" * 4, f"seed={seed}")

    def test_checksum_checks_reject_a_single_changed_character(self):
        cases = {
            "github_ghp_token": lambda v: checks.has_valid_crc32_suffix(v, "ghp_"),
            "npm_access_token": lambda v: checks.has_valid_crc32_suffix(v, "npm_"),
            "btc_wif_mainnet_compressed": checks.is_valid_btc_wif,
            "btc_wif_mainnet_uncompressed": checks.is_valid_btc_wif,
            "btc_wif_testnet_compressed": checks.is_valid_btc_wif,
            "btc_wif_testnet_uncompressed": checks.is_valid_btc_wif,
            "de_vat_id": checks.is_valid_de_vat_id,
        }
        for name, check in cases.items():
            for seed in range(8):
                value = recipes.generate(name, seed)
                for index in (len(value) - 1, len(value) // 2):
                    self.assertFalse(check(mutate(value, index)), f"{name} seed={seed} index={index}")

    def test_wif_check_requires_a_wif_version_byte_and_flag(self):
        # F02: mainnet 0x80 and testnet 0xef, a scalar in 1..n-1, flag 0x01 when compressed.
        scalar = bytes([0x3C]) + bytes([0x5A]) * 31
        order = checks.SECP256K1_ORDER.to_bytes(32, "big")
        for payload, valid in (
            (b"\x80" + scalar, True),
            (b"\x80" + scalar + b"\x01", True),
            (b"\xef" + scalar, True),
            (b"\xef" + scalar + b"\x01", True),
            (b"\xef" + scalar + b"\x02", False),
            (b"\xef" + bytes(32), False),
            (b"\xef" + order + b"\x01", False),
            (b"\xee" + scalar, False),
            (b"\xf0" + scalar + b"\x01", False),
            (b"\x81" + scalar, False),
        ):
            self.assertEqual(checks.is_valid_btc_wif(recipes.base58check(payload)), valid, payload.hex())

    def test_checks_accept_published_reference_vectors(self):
        # RFC 8410, section 10.3: Ed25519 private key in PKCS#8.
        rfc8410 = (
            "-----BEGIN " + "PRIVATE KEY-----\n"
            "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n"
            "-----END " + "PRIVATE KEY-----"
        )
        self.assertTrue(pem("PRIVATE KEY", checks.is_valid_pkcs8_ed25519)(rfc8410))
        # ISO 7064 MOD 11,10 worked by hand for 1..8: products 2,8,2,1,1,3,9,3 -> 11 - 3 = 8.
        self.assertTrue(checks.iso7064_mod11_10_valid("123456788"))
        self.assertFalse(checks.iso7064_mod11_10_valid("123456787"))
        self.assertEqual(recipes.iso7064_mod11_10("12345678"), "8")
        # RFC 7617, section 2: "Aladdin:open sesame".
        self.assertEqual(checks.basic_auth_pair("QWxhZGRpbjpvcGVuIHNlc2FtZQ=="), ("Aladdin", "open sesame"))
        self.assertIsNone(checks.b64url_decode("QR"))  # non-canonical trailing bits
        self.assertEqual(recipes.crc32_base62(""), "000000")

    def test_python_and_rust_generators_match_pinned_vectors(self):
        vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(set(vectors["generators"]), set(recipes.load_generators()))
        for name, fingerprint in vectors["generators"].items():
            joined = "\n".join(recipes.generate(name, seed) for seed in vectors["seeds"])
            self.assertEqual(recipes.fingerprint(joined), fingerprint, name)


class RuleProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gateway = SecurityGateway(categories=["dlp"], max_level="l1", download_files=False)
        cls.all_rules = set(rules.load_rule_map()) | set(rules.content_rules())

    def test_each_rule_reports_exactly_its_generated_values(self):
        for rule_id in rules.load_rule_map():
            self.gateway.set_execution_gates(
                {"rules": {other: other == rule_id for other in self.all_rules}}
            )
            for sample in rules.samples(rule_id, range(8)):
                spans = {
                    (span["start_char"], span["end_char"])
                    for result in self.gateway.scan_category("dlp", sample.text)
                    if result["model"] == "native:dlp"
                    for span in result["evidence_spans"]
                }
                self.assertEqual(
                    spans,
                    {sample.span},
                    f"{rule_id} gen={sample.generator} probe={sample.probe} seed={sample.seed}",
                )
        self.gateway.set_execution_gates(None)

    def test_rules_do_not_report_their_lookalike_values(self):
        # F03: a token shape with a wrong check value or length is no match for its rule.
        checked = 0
        for rule_id in rules.load_rule_map():
            self.gateway.set_execution_gates(
                {"rules": {other: other == rule_id for other in self.all_rules}}
            )
            for sample in rules.samples(rule_id, range(8), lookalike=True):
                spans = [
                    span
                    for result in self.gateway.scan_category("dlp", sample.text)
                    if result["model"] == "native:dlp"
                    for span in result["evidence_spans"]
                ]
                self.assertEqual(spans, [], f"{rule_id} gen={sample.generator} probe={sample.probe} seed={sample.seed}")
                checked += 1
        self.gateway.set_execution_gates(None)
        self.assertGreater(checked, 0)

if __name__ == "__main__":
    unittest.main()
