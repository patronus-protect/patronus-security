"""E03: synthetic DLP secret generator.

Every generator listed for a rule in ``dlp_synth/rules.json`` must produce values that
(a) pass an independent offline format/structure/checksum check and (b) are reported
by exactly that rule with exactly the value span. Generated values exist only in memory.
"""

import base64
import binascii
import json
import math
import unittest
from collections import Counter
from pathlib import Path

import yaml

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


def express_session_id(value):
    # connect.sid: URL-encoded "s:" + 32-character uid-safe id + "." + 43-character signature.
    if not value.startswith("s%3A"):
        return False
    session_id, _, signature = value[4:].partition(".")
    return (
        len(session_id) == 32
        and set(session_id) <= set(ALNUM + "-_")
        and len(signature) == 43
        and signature.isalnum()
    )


def laravel_session(value):
    # Laravel encrypted cookie: base64 of {"iv", "value", "mac", "tag"} with a 64-hex MAC.
    try:
        payload = json.loads(base64.b64decode(value, validate=True))
    except (ValueError, binascii.Error):
        return False
    return (
        isinstance(payload, dict)
        and set(payload) == {"iv", "value", "mac", "tag"}
        and len(base64.b64decode(payload["iv"])) == 16
        and len(payload["mac"]) == 64
        and set(payload["mac"]) <= set(HEX)
    )


def record_reference(value):
    letters, year, number = value.split("-")
    return letters.isupper() and len(letters) == 2 and year.startswith("20") and len(year) == 4 and len(number) == 6


def onepassword_service_account(value):
    """1Password service account token: ops_ + base64 of the account JSON (gitleaks
    1password-service-account-token needs ops_eyJ and 250+ base64 characters)."""
    try:
        payload = json.loads(base64.b64decode(value.removeprefix("ops_"), validate=True))
    except (ValueError, binascii.Error):
        return False
    return (
        value.startswith("ops_eyJ")
        and len(value) >= 257
        and payload["signInAddress"] == "my.1password.com"
        and payload["email"].endswith("@1passwordserviceaccounts.com")
        and ONEPASSWORD_SECRET_KEY(payload["secretKey"])
        and len(payload["srpX"]) == 64
    )


def onepassword_secret_key(prefix):
    """1Password account Secret Key: version, six groups of upper-case alphanumerics."""

    def check(value):
        groups = value.split("-")
        return groups[0] == prefix and [len(group) for group in groups[1:]] == [6, 6, 5, 5, 5, 5] and all(
            set(group) <= set(UPPER_ALNUM) for group in groups[1:]
        )

    return check


def uuid_shaped(value):
    return [len(part) for part in value.split("-")] == [8, 4, 4, 4, 12] and set(value) <= set(HEX + "-")


def teams_webhook(value):
    head, _, rest = value.partition(".webhook.office.com/webhookb2/")
    ids, _, tail = rest.partition("/IncomingWebhook/")
    group, _, tenant = ids.partition("@")
    secret, _, owner = tail.partition("/")
    return (
        head.startswith("https://")
        and head[8:].isalpha()
        and uuid_shaped(group)
        and uuid_shaped(tenant)
        and prefixed("", HEX, 32)(secret)
        and uuid_shaped(owner)
    )


def slack_webhook(team, bot, secret):
    def check(value):
        path = value.removeprefix("https://hooks.slack.com/services/")
        parts = path.split("/")
        return (
            value.startswith("https://hooks.slack.com/services/")
            and len(parts) == 3
            and prefixed("T", UPPER_ALNUM, team)(parts[0])
            and prefixed("B", UPPER_ALNUM, bot)(parts[1])
            and prefixed("", ALNUM, secret)(parts[2])
        )

    return check


def authress(value, account="acc_"):
    """Authress service client access key: sc_<client>.<key>.acc_<account>.<base64 PKCS#8 Ed25519>."""
    parts = value.split(".")
    return (
        len(parts) == 4
        and prefixed("sc_", ALNUM, 10)(parts[0])
        and prefixed("", ALNUM, 5)(parts[1])
        and prefixed(account, BASE36, 16)(parts[2])
        and checks.is_valid_pkcs8_ed25519(base64.b64decode(parts[3]))
    )


def pypi_macaroon(value, location="pypi.org", signature=32):
    """PyPI API token: pypi- + unpadded base64url of a macaroon v2 (location pypi.org or
    test.pypi.org, UUID identifier, one caveat, 32-byte signature; gitleaks pypi-upload-token
    needs pypi-AgEIcHlwaS5vcmc and 50+ characters after it)."""
    body = value.removeprefix("pypi-")
    raw = checks.b64url_decode(body)
    header = bytes([2, 1, len(location)]) + location.encode("ascii")
    if not value.startswith("pypi-") or raw is None or not raw.startswith(header):
        return False
    # Version 2, then fields of type, length and data; None marks an end-of-section byte.
    fields, offset = [], 1
    while offset < len(raw) and raw[0] == 2:
        if raw[offset] == 0:
            fields.append(None)
            offset += 1
            continue
        length = raw[offset + 1] if offset + 1 < len(raw) else len(raw)
        fields.append((raw[offset], raw[offset + 2 : offset + 2 + length]))
        offset += 2 + length
    return (
        offset == len(raw)
        and len(fields) == 7
        and fields[0] == (1, location.encode("ascii"))
        and fields[1][0] == 2
        and uuid_shaped(fields[1][1].decode("ascii"))
        and fields[2] is None
        and fields[3][0] == 2
        and json.loads(fields[3][1])["version"] == 1
        and fields[4] is None
        and fields[5] is None
        and fields[6][0] == 6
        and len(fields[6][1]) == signature
    )


def terraform_cloud(body_length):
    def check(value):
        head, _, body = value.partition(".atlasv1.")
        return prefixed("", ALNUM, 14)(head) and prefixed("", ALNUM, body_length)(body)

    return check


def harness(secret_length):
    def check(value):
        parts = value.split(".")
        return (
            len(parts) == 4
            and parts[0] in ("pat", "sat")
            and prefixed("", B64URL, 22)(parts[1])
            and prefixed("", ALNUM, 24)(parts[2])
            and prefixed("", ALNUM, secret_length)(parts[3])
        )

    return check


def sourcegraph(value):
    instance, _, secret = value.removeprefix("sgp_").partition("_")
    return (
        value.startswith("sgp_")
        and (instance == "local" or prefixed("", HEX, 16)(instance))
        and prefixed("", HEX, 40)(secret)
    )


def bedrock(secret_length):
    """Long-term Amazon Bedrock API key: ABSK + base64 of BedrockAPIKey-<id>-at-<account>:<secret>."""

    def check(value):
        raw = checks.b64decode(value.removeprefix("ABSK"))
        if not value.startswith("ABSK") or raw is None or not raw.isascii():
            return False
        head, _, secret = raw.decode("ascii").partition(":")
        name, _, account = head.partition("-at-")
        return (
            prefixed("BedrockAPIKey-", BASE36, 4)(name)
            and prefixed("", DIGITS, 12)(account)
            and prefixed("", B64, secret_length)(secret)
        )

    return check


def azure_entra_client_secret(value):
    return (
        prefixed("", ALNUM, 3)(value[:3])
        and value[3:4].isdigit()
        and prefixed("Q~", ALNUM + "_~.-", 34)(value[4:])
    )


def base64_bytes(prefix, length):
    def check(value):
        raw = checks.b64decode(value.removeprefix(prefix))
        return value.startswith(prefix) and raw is not None and len(raw) == length

    return check


GCP_SERVICE_ACCOUNT_FIELDS = {
    "type", "project_id", "private_key_id", "private_key", "client_email", "client_id", "auth_uri", "token_uri",
    "auth_provider_x509_cert_url", "client_x509_cert_url", "universe_domain",
}


def pkcs8_rsa(der):
    """PKCS#8 PrivateKeyInfo with rsaEncryption and an RSAPrivateKey of a 2048-bit modulus."""
    outer = checks.der_parse(der)
    if not outer or len(outer) != 1 or outer[0][0] != 0x30:
        return False
    fields = checks.der_parse(outer[0][1])
    if not fields or [tag for tag, _ in fields] != [0x02, 0x30, 0x04] or fields[0][1] != b"\0":
        return False
    key = checks.der_parse(fields[2][1])
    return (
        checks.der_parse(fields[1][1]) == [(0x06, OID_RSA_ENCRYPTION), (0x05, b"")]
        and checks.is_valid_pkcs1_rsa(fields[2][1])
        and len(checks.der_parse(key[0][1])[1][1]) == 257
    )


def gcp_service_account_key(value):
    """Service account key file: JSON with the documented fields and a PKCS#8 RSA private key."""
    try:
        key = json.loads(value)
    except ValueError:
        return False
    if not isinstance(key, dict) or set(key) != GCP_SERVICE_ACCOUNT_FIELDS or key["type"] != "service_account":
        return False
    blocks = checks.pem_blocks(key["private_key"])
    return (
        prefixed("", HEX, 40)(key["private_key_id"])
        and key["client_email"].endswith(".iam.gserviceaccount.com")
        and prefixed("1", DIGITS, 20)(key["client_id"])
        and key["auth_provider_x509_cert_url"] == "https://www.googleapis.com/oauth2/v1/certs"
        and len(blocks) == 1
        and blocks[0][0] == "PRIVATE KEY"
        and pkcs8_rsa(blocks[0][1])
    )


def cloudflare_origin_ca_key(value):
    head, _, tail = value.removeprefix("v1.0-").partition("-")
    return value.startswith("v1.0-") and prefixed("", HEX, 24)(head) and prefixed("", HEX, 146)(tail)


def defined_networking(value):
    head, _, tail = value.removeprefix("dnkey-").partition("-")
    return value.startswith("dnkey-") and prefixed("", BASE32, 26)(head) and prefixed("", BASE32, 52)(tail)


def circleci(prefix):
    """CircleCI API token: prefix + base58 UUID (22) + _ + 40 hex digits."""
    def check(value):
        uuid, _, tail = value.removeprefix(prefix).partition("_")
        return value.startswith(prefix) and prefixed("", checks.BASE58, 22)(uuid) and prefixed("", HEX, 40)(tail)

    return check


def azure_devops_pat(value):
    """Azure DevOps PAT since 2024: 84 alphanumerics with AZDO at positions 76 to 80."""
    return len(value) == 84 and set(value) <= set(ALNUM) and value[76:80] == "AZDO"


def b64_json(body):
    """The JSON object that standard base64 ``body`` (padded or not) encodes, or ``None``."""
    try:
        payload = json.loads(base64.b64decode(body + "=" * (-len(body) % 4), validate=True))
    except (ValueError, binascii.Error):
        return None
    return payload if isinstance(payload, dict) else None


def sentry_org_token(value):
    """Sentry org auth token: sntrys_ + base64 JSON payload with a numeric iat + _ + 43 base64."""
    payload, _, secret = value.removeprefix("sntrys_").rpartition("_")
    claims = b64_json(payload) if value.startswith("sntrys_") else None
    return claims is not None and isinstance(claims.get("iat"), (int, float)) and prefixed("", B64, 43)(secret)


def grafana_api_key(value):
    """Legacy Grafana API key: base64 of {"k": str, "n": str, "id": int}."""
    key = b64_json(value)
    return (
        key is not None
        and isinstance(key.get("k"), str)
        and isinstance(key.get("n"), str)
        and isinstance(key.get("id"), int)
    )


def grafana_cloud_token(value):
    """Grafana Cloud access policy token: glc_ + base64 of a JSON object with the key in k."""
    token = b64_json(value.removeprefix("glc_")) if value.startswith("glc_") else None
    return token is not None and isinstance(token.get("k"), str)


def grafana_service_account_token(value):
    """glsa_ + 32 alphanumerics + _ + CRC32 of the part before it as little-endian hex."""
    head, _, checksum = value.rpartition("_")
    return (
        prefixed("glsa_", ALNUM, 32)(head)
        and checksum == binascii.crc32(head.encode()).to_bytes(4, "little").hex()
    )


def elastic_pair(value):
    """Elasticsearch API key id:api_key with 20 and 22 base64url characters."""
    key_id, _, key = value.partition(":")
    return prefixed("", B64URL, 20)(key_id) and prefixed("", B64URL, 22)(key)


def elastic_api_key(value):
    """Encoded Elasticsearch API key: standard base64 of id:api_key."""
    try:
        return elastic_pair(base64.b64decode(value, validate=True).decode("ascii"))
    except (ValueError, binascii.Error):
        return False


def dynatrace(prefix):
    """Dynatrace token: prefix + . + 24 + . + 64 upper-case alphanumerics."""
    return lambda v: prefixed(prefix + ".", UPPER_ALNUM + ".", 89)(v) and [
        len(part) for part in v.split(".")
    ] == [len(prefix), 24, 64]


def uuid_upper(value):
    return uuid_shaped(value.lower())


ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
UPPER_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
B64URL = ALNUM + "-_"
B64 = ALNUM + "+/"
HEX = "0123456789abcdef"
DIGITS = "0123456789"
BASE36 = DIGITS + "abcdefghijklmnopqrstuvwxyz"
LOWER = "abcdefghijklmnopqrstuvwxyz"
BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
OID_RSA_ENCRYPTION = bytes.fromhex("2a864886f70d010101")
OID_PKCS7_DATA = bytes.fromhex("2a864886f70d010701")
OID_PKCS7_ENCRYPTED_DATA = bytes.fromhex("2a864886f70d010706")
OID_SHROUDED_KEY_BAG = bytes.fromhex("2a864886f70d010c0a0102")
OID_PBE_SHA_RC2_40 = bytes.fromhex("2a864886f70d010c0106")
OID_PBE_SHA_3DES = bytes.fromhex("2a864886f70d010c0103")
OID_SHA1 = bytes.fromhex("2b0e03021a")
ONEPASSWORD_SECRET_KEY = onepassword_secret_key("A3")


def age_secret_key(value):
    """age X25519 identity: upper-case Bech32 under AGE-SECRET-KEY- carrying 32 bytes."""
    decoded = checks.bech32_decode(value)
    return value.isupper() and decoded is not None and decoded[0] == "age-secret-key-" and len(decoded[1]) == 32


def der_children(der, tag=0x30):
    """The children of one DER element with ``tag`` that spans all of ``der``."""
    outer = checks.der_parse(der)
    if not outer or len(outer) != 1 or outer[0][0] != tag:
        return None
    return checks.der_parse(outer[0][1])


def pbe_parameters(algorithm, oid):
    """AlgorithmIdentifier of a PKCS#12 PBE scheme with an 8-byte salt and 2048 iterations."""
    fields = checks.der_parse(algorithm)
    params = fields and len(fields) == 2 and fields[0] == (0x06, oid) and checks.der_parse(fields[1][1])
    return bool(params) and [tag for tag, _ in params] == [0x04, 0x02] and len(params[0][1]) == 8 and params[1][1] == b"\x08\x00"


def pkcs12_keystore(value):
    """RFC 7292 PFX v3 in the OpenSSL layout: encrypted certificate bag, shrouded key bag, SHA-1 MAC."""
    pfx = der_children(checks.b64decode(value) or b"")
    if not pfx or [tag for tag, _ in pfx] != [0x02, 0x30, 0x30] or pfx[0][1] != b"\x03":
        return False
    auth_safe = checks.der_parse(pfx[1][1])
    if not auth_safe or auth_safe[0] != (0x06, OID_PKCS7_DATA) or auth_safe[1][0] != 0xA0:
        return False
    octets = checks.der_parse(auth_safe[1][1])
    contents = octets and octets[0][0] == 0x04 and der_children(octets[0][1])
    if not contents or [checks.der_parse(info)[0] for _, info in contents] != [
        (0x06, OID_PKCS7_ENCRYPTED_DATA), (0x06, OID_PKCS7_DATA)
    ]:
        return False
    encrypted_data = der_children(checks.der_parse(contents[0][1])[1][1])
    if not encrypted_data or encrypted_data[0] != (0x02, b"\x00"):
        return False
    info = checks.der_parse(encrypted_data[1][1])
    if not info or info[0] != (0x06, OID_PKCS7_DATA) or not pbe_parameters(info[1][1], OID_PBE_SHA_RC2_40) or info[2][0] != 0x80:
        return False
    bags = checks.der_parse(checks.der_parse(contents[1][1])[1][1])
    bag = bags and bags[0][0] == 0x04 and der_children(bags[0][1])
    key_bag = bag and len(bag) == 1 and checks.der_parse(bag[0][1])
    if not key_bag or key_bag[0] != (0x06, OID_SHROUDED_KEY_BAG):
        return False
    shrouded = der_children(key_bag[1][1])
    if not shrouded or not pbe_parameters(shrouded[0][1], OID_PBE_SHA_3DES) or shrouded[1][0] != 0x04:
        return False
    mac = checks.der_parse(pfx[2][1])
    digest = mac and checks.der_parse(mac[0][1])
    return (
        bool(digest)
        and checks.der_parse(digest[0][1]) == [(0x06, OID_SHA1), (0x05, b"")]
        and len(digest[1][1]) == 20
        and len(mac[1][1]) == 8
        and mac[2][1] == b"\x08\x00"
    )


def shannon_entropy(value):
    """Shannon entropy in bits per character, as detect-secrets computes it."""
    return -sum(count / len(value) * math.log2(count / len(value)) for count in Counter(value).values())


def high_entropy(check, limit):
    return lambda value: check(value) and shannon_entropy(value) > limit


def gitlab_routable(value, prefix, length):
    """GitLab routable token (F04, gitleaks gitlab-pat-routable): `prefix`, a base64url
    payload of `length`, a dot, a two-character version and seven base36 characters."""
    head, _, tail = value.rpartition(".")
    return prefixed(prefix, B64URL, length)(head) and len(tail) == 9 and set(tail) <= set(BASE36)

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
    "aws_sts_bearer_key_id": prefixed("ABIA", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16),
    "aws_context_credential_key_id": prefixed("ACCA", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16),
    "aws_access_key_id_non_base32": prefixed("AKIA", "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 16),
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
    "gitlab_pat_routable": lambda v: gitlab_routable(v, "glpat-", 38),
    "gitlab_deploy_token": prefixed("gldt-", B64URL, 20),
    "gitlab_runner_token": prefixed("glrt-", B64URL, 20),
    "gitlab_runner_token_routable": lambda v: v[6] in DIGITS and v[7] == "_" and gitlab_routable(v[8:], "", 36)
    and v.startswith("glrt-t"),
    "gitlab_runner_registration_token": prefixed("GR1348941", B64URL, 20),
    "gitlab_trigger_token": prefixed("glptt-", HEX, 40),
    "gitlab_feed_token": prefixed("glft-", B64URL, 20),
    "gitlab_incoming_mail_token": prefixed("glimt-", B64URL, 25),
    "gitlab_agent_token": prefixed("glagent-", B64URL, 50),
    "gitlab_cicd_job_token": lambda v: v.startswith("glcbt-") and v[8] == "_" and prefixed("", ALNUM, 2)(v[6:8])
    and prefixed("", B64URL, 20)(v[9:]),
    "gitlab_scim_token": prefixed("glsoat-", B64URL, 20),
    "gitlab_feature_flag_token": prefixed("glffct-", B64URL, 20),
    "gitlab_oauth_app_secret": prefixed("gloas-", B64URL, 64),
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
    "express_session_id": express_session_id,
    "laravel_session": laravel_session,
    "bcrypt_2b_hash": bcrypt,
    "argon2id_phc_hash": argon2id,
    "md5_hex": prefixed("", HEX, 32),
    "sha256_hex": prefixed("", HEX, 64),
    "de_vat_id": checks.is_valid_de_vat_id,
    "de_commercial_register_number": lambda v: v.startswith("HRB ") and v[4:].isdigit() and v[4] != "0",
    "de_bsnr": lambda v: len(v) == 9 and v.isdigit() and v[0] != "0",
    "record_reference": record_reference,
    # GOLD-D2 baseline entities (formats of the gitleaks rules named in generators.json)
    "slack_app_token": lambda v: v.startswith("xapp-1-A")
    and [len(p) for p in v.split("-")] == [4, 1, 11, 13, 64]
    and set(v.split("-")[4]) <= set(HEX),
    "slack_config_access_token": prefixed("xoxe.xoxp-1-", ALNUM, 164),
    "slack_config_refresh_token": prefixed("xoxe-1-", ALNUM, 146),
    "slack_webhook_url": slack_webhook(10, 10, 24),
    "teams_webhook_url": teams_webhook,
    "discord_api_token": prefixed("", HEX, 64),
    "discord_client_secret": prefixed("", B64URL, 32),
    "telegram_bot_token": lambda v: v.split(":")[0].isdigit() and len(v.split(":")[0]) == 10 and v[0] != "0"
    and prefixed("AA", B64URL, 33)(v.split(":")[1]),
    "twilio_api_key": prefixed("SK", HEX, 32),
    "sendgrid_api_key": lambda v: v[25] == "." and prefixed("SG.", B64URL, 22)(v[:25]) and prefixed("", B64URL, 43)(v[26:]),
    "brevo_api_key": lambda v: prefixed("xkeysib-", HEX, 64)(v[:72]) and prefixed("-", ALNUM, 16)(v[72:]),
    "mailgun_private_api_key": prefixed("key-", HEX, 32),
    "mailgun_signing_key": lambda v: [len(p) for p in v.split("-")] == [32, 8, 8] and set(v) <= set(HEX + "-"),
    "mailchimp_api_key": lambda v: prefixed("", HEX, 32)(v[:32]) and v[32:35] == "-us" and v[35:].isdigit()
    and len(v) == 37 and v[35] != "0",
    "messagebird_api_key": prefixed("", ALNUM, 25),
    "mattermost_access_token": prefixed("", BASE36, 26),
    "sendbird_api_token": prefixed("", HEX, 40),
    "gitter_access_token": prefixed("", HEX, 40),
    "okta_api_token": prefixed("00", B64URL, 40),
    "authress_access_key": authress,
    "onepassword_secret_key": ONEPASSWORD_SECRET_KEY,
    "onepassword_service_account_token": onepassword_service_account,
    "duffel_live_token": prefixed("duffel_live_", B64URL, 43),
    "easypost_api_key": prefixed("EZAK", ALNUM, 54),
    "shippo_live_token": prefixed("shippo_live_", HEX, 40),
    # GOLD-D3 baseline entities (devops, ci, vcs, registry)
    "gitlab_session_cookie": prefixed("", HEX, 32),
    "bitbucket_client_secret": prefixed("", ALNUM, 64),
    "droneci_access_token": prefixed("", ALNUM, 32),
    "travisci_access_token": prefixed("", ALNUM, 22),
    "artifactory_api_key": prefixed("AKCp", ALNUM, 69),
    "artifactory_reference_token": prefixed("cmVmd", ALNUM, 59),
    "pypi_upload_token": pypi_macaroon,
    "rubygems_api_key": prefixed("rubygems_", HEX, 48),
    "clojars_deploy_token": prefixed("CLOJARS_", HEX, 60),
    "terraform_cloud_token": terraform_cloud(67),
    "pulumi_access_token": prefixed("pul-", HEX, 40),
    "vault_service_token": prefixed("hvs.", B64URL, 91),
    "vault_legacy_service_token": prefixed("s.", ALNUM, 24),
    "vault_batch_token": prefixed("hvb.", B64URL, 138),
    "doppler_personal_token": prefixed("dp.pt.", ALNUM, 43),
    # P05
    "doppler_service_token": prefixed("dp.st.prd.", ALNUM, 44),
    "doppler_cli_token": prefixed("dp.ct.", ALNUM, 40),
    "doppler_service_account_token": prefixed("dp.sa.", ALNUM, 42),
    "doppler_scim_token": prefixed("dp.scim.", ALNUM, 43),
    "doppler_audit_token": prefixed("dp.audit.", ALNUM, 44),
    "pypi_test_upload_token": lambda v: pypi_macaroon(v, "test.pypi.org"),
    "dockerhub_pat": prefixed("dckr_pat_", B64URL, 27),
    "dockerhub_org_token": prefixed("dckr_oat_", B64URL, 27),
    "cratesio_api_token": prefixed("cio", ALNUM, 32),
    "packagist_org_token": lambda v: checks.has_valid_crc32_hex_suffix(v, "packagist_out_"),
    "packagist_user_token": lambda v: checks.has_valid_crc32_hex_suffix(v, "packagist_uut_"),
    # P06
    "azure_devops_pat": azure_devops_pat,
    "azure_devops_legacy_pat": prefixed("", BASE36, 52),
    "circleci_personal_token": circleci("CCIPAT_"),
    "circleci_project_token": circleci("CCIPRJ_"),
    "circleci_legacy_token": prefixed("", HEX, 40),
    "vercel_personal_token": prefixed("vcp_", ALNUM, 56),
    "vercel_app_access_token": prefixed("vca_", ALNUM, 56),
    "vercel_legacy_token": prefixed("", ALNUM, 24),
    "netlify_personal_token": prefixed("nfp_", ALNUM, 36),
    "render_api_key": prefixed("rnd_", ALNUM, 32),
    "railway_token": uuid_shaped,
    # P07
    "datadog_api_key": prefixed("", HEX, 32),
    "datadog_app_key": prefixed("", HEX, 40),
    "newrelic_user_api_key": prefixed("NRAK-", UPPER_ALNUM, 27),
    "newrelic_insert_key": prefixed("NRII-", B64URL[:-1], 32),
    "newrelic_license_key": prefixed("", HEX, 32, "FFFFNRAL"),
    "newrelic_license_key_eu": prefixed("eu01xx", HEX, 26, "FFFFNRAL"),
    "newrelic_legacy_license_key": prefixed("", HEX, 40),
    "sentry_user_token": prefixed("sntryu_", HEX, 64),
    "sentry_org_token": sentry_org_token,
    "sentry_auth_token": prefixed("", HEX, 64),
    "sentry_dsn_secret_key": prefixed("", HEX, 32),
    "grafana_api_key": grafana_api_key,
    "grafana_cloud_token": grafana_cloud_token,
    "grafana_service_account_token": grafana_service_account_token,
    "dynatrace_api_token": dynatrace("dt0c01"),
    "dynatrace_platform_token": dynatrace("dt0s16"),
    "splunk_hec_token": uuid_upper,
    "elastic_api_key": elastic_api_key,
    "elastic_api_key_pair": elastic_pair,
    "honeycomb_api_key": prefixed("", ALNUM, 22),
    "honeycomb_classic_key": prefixed("", HEX, 32),
    "pagerduty_user_token": prefixed("u+", ALNUM + "_+-", 18),
    "pagerduty_api_key": prefixed("", ALNUM + "_+-", 20),
    "pagerduty_integration_key": prefixed("", HEX, 32),
    "prefect_api_key": prefixed("pnu_", ALNUM, 36),
    "infracost_api_key": prefixed("ico-", ALNUM, 32),
    "octopus_deploy_api_key": prefixed("API-", UPPER_ALNUM, 26),
    "harness_personal_access_token": harness(20),
    "harness_service_account_token": harness(20),
    "snyk_api_token": uuid_shaped,
    "sonar_user_token": prefixed("squ_", HEX, 40),
    "sonar_project_token": prefixed("sqp_", HEX, 40),
    "codecov_access_token": prefixed("", HEX, 32),
    "sourcegraph_access_token": sourcegraph,
    "sourcegraph_local_access_token": sourcegraph,
    # GOLD-D4 baseline entities (hosting, cloud, data)
    "bedrock_api_key": bedrock(60),
    "alibaba_access_key_id": prefixed("LTAI", ALNUM, 20),
    "alibaba_secret_key": prefixed("", ALNUM, 30),
    "azure_entra_client_secret": azure_entra_client_secret,
    "azure_storage_account_key": base64_bytes("", 64),
    "gcp_service_account_key": gcp_service_account_key,
    "ibm_cloud_iam_api_key": prefixed("", B64URL, 44),
    "yandex_api_key": prefixed("AQVN", B64URL, 36),
    "yandex_static_access_key_secret": prefixed("YC", B64URL, 38),
    "scalingo_api_token": prefixed("tk-us-", B64URL, 48),
    "flyio_oauth_token": prefixed("fo1_", B64URL, 43),
    "flyio_macaroon_token": base64_bytes("fm2_", 96),
    "netlify_access_token": prefixed("", B64URL, 43),
    "heroku_api_key": uuid_shaped,
    "heroku_api_key_v2": prefixed("HRKU-AA", B64URL, 58),
    "cloudflare_api_token": prefixed("", B64URL, 40),
    "cloudflare_global_api_key": prefixed("", HEX, 37),
    "cloudflare_origin_ca_key": cloudflare_origin_ca_key,
    "digitalocean_pat": prefixed("dop_v1_", HEX, 64),
    "digitalocean_oauth_token": prefixed("doo_v1_", HEX, 64),
    "digitalocean_refresh_token": prefixed("dor_v1_", HEX, 64),
    "openshift_user_token": lambda v: prefixed("sha256~", B64URL, 43)(v) and base64url_bytes(32)(v[7:]),
    "defined_networking_api_token": defined_networking,
    "fastly_api_token": prefixed("", B64URL, 32),
    "settlemint_personal_access_token": prefixed("sm_pat_", ALNUM, 16),
    "settlemint_application_access_token": prefixed("sm_aat_", ALNUM, 16),
    "settlemint_service_access_token": prefixed("sm_sat_", ALNUM, 16),
    "databricks_api_token": prefixed("dapi", HEX, 32),
    "planetscale_service_token": prefixed("pscale_tkn_", B64URL, 43),
    "planetscale_oauth_token": prefixed("pscale_oauth_", B64URL, 43),
    "planetscale_password": prefixed("pscale_pw_", B64URL, 43),
    "confluent_api_key": prefixed("", UPPER_ALNUM, 16),
    "confluent_api_secret": prefixed("", ALNUM, 64),
    "algolia_admin_api_key": prefixed("", HEX, 32),
    "clickhouse_cloud_api_secret": prefixed("4b1d", ALNUM, 38),
    "cloudant_password": prefixed("", HEX, 64),
    "cloudant_api_key": prefixed("", LOWER, 24),
    # GOLD-D6 baseline entities (credential, key)
    "curl_user_password": prefixed("", ALNUM + "._@-", 20),
    "nuget_cleartext_password": prefixed("", ALNUM, 24),
    "kubernetes_secret_data": lambda v: (raw := checks.b64decode(v)) is not None and len(raw) == 24 and raw.isalnum(),
    "base64_high_entropy_string": high_entropy(base64_bytes("", 33), 4.5),
    "hex_high_entropy_string": high_entropy(prefixed("", HEX, 48), 3.0),
    "age_secret_key": age_secret_key,
    "pkcs12_keystore": pkcs12_keystore,
    "laravel_app_key": base64_bytes("base64:", 32),
    "fernet_key": lambda v: v.endswith("=") and base64url_bytes(32)(v[:-1]),
    "aes256_hex_key": prefixed("", HEX, 64),
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
    # F04
    "npm_bad_crc": lambda v: checks.has_valid_crc32_suffix(v, "npm_"),
    "npm_short": lambda v: len(v) == 40,
    "npm_long": lambda v: len(v) == 40,
    "gitlab_pat_long": lambda v: len(v) == 26 or gitlab_routable(v, "glpat-", len(v) - 16),
    "gitlab_deploy_token_short": lambda v: len(v) == 25,
    "gitlab_trigger_token_upper_hex": prefixed("glptt-", HEX, 40),
    # F05
    "aws_access_key_id_long": lambda v: len(v) == 20,
    "aws_iam_user_unique_id": lambda v: v[:4] in ("AKIA", "ASIA", "ABIA", "ACCA"),
    "aws_secret_access_key_long": lambda v: len(v) == 40,
    "aws_secret_access_key_hex": lambda v: any(c.isupper() for c in v),
    # F-HTTP: random base64 that decodes to no user:password pair
    "http_basic_credentials": lambda v: checks.basic_auth_pair(v) is not None,
    # GOLD-D2: wrong prefix, length or character set of a baseline entity's format
    "slack_config_refresh_token_short": CHECKS["slack_config_refresh_token"],
    "slack_webhook_url_short": CHECKS["slack_webhook_url"],
    "discord_client_secret_short": CHECKS["discord_client_secret"],
    "telegram_bot_token_short": CHECKS["telegram_bot_token"],
    "twilio_account_sid": CHECKS["twilio_api_key"],
    "sendgrid_api_key_short": CHECKS["sendgrid_api_key"],
    "brevo_api_key_upper_hex": CHECKS["brevo_api_key"],
    "mailgun_public_key": lambda v: CHECKS["mailgun_private_api_key"](v) or CHECKS["mailgun_signing_key"](v),
    "mailchimp_api_key_no_dc": CHECKS["mailchimp_api_key"],
    "messagebird_api_key_short": CHECKS["messagebird_api_key"],
    "mattermost_access_token_short": CHECKS["mattermost_access_token"],
    "sendbird_api_token_short": CHECKS["sendbird_api_token"],
    "gitter_access_token_short": CHECKS["gitter_access_token"],
    "okta_api_token_wrong_prefix": CHECKS["okta_api_token"],
    "authress_access_key_wrong_account": lambda v: authress(v) or authress(v, "app_"),
    "onepassword_secret_key_wrong_version": ONEPASSWORD_SECRET_KEY,
    "shippo_live_token_short": CHECKS["shippo_live_token"],
    # GOLD-D3
    "gitlab_session_cookie_short": CHECKS["gitlab_session_cookie"],
    "bitbucket_client_secret_short": CHECKS["bitbucket_client_secret"],
    "droneci_access_token_short": CHECKS["droneci_access_token"],
    "travisci_access_token_short": CHECKS["travisci_access_token"],
    "artifactory_api_key_short": lambda v: CHECKS["artifactory_api_key"](v) or CHECKS["artifactory_reference_token"](v),
    "pypi_upload_token_truncated": pypi_macaroon,
    "rubygems_api_key_upper_hex": CHECKS["rubygems_api_key"],
    "clojars_deploy_token_short": CHECKS["clojars_deploy_token"],
    "terraform_cloud_token_short": CHECKS["terraform_cloud_token"],
    "pulumi_access_token_short": CHECKS["pulumi_access_token"],
    "vault_legacy_service_token_short": lambda v: any(
        CHECKS[name](v) for name in ("vault_service_token", "vault_legacy_service_token", "vault_batch_token")
    ),
    "doppler_personal_token_short": CHECKS["doppler_personal_token"],
    # P05
    "doppler_cli_token_long": lambda v: any(prefixed("dp.ct.", ALNUM, n)(v) for n in range(40, 45)),
    "pypi_upload_token_no_signature": pypi_macaroon,
    "dockerhub_pat_short": CHECKS["dockerhub_pat"],
    "cratesio_api_token_short": CHECKS["cratesio_api_token"],
    "packagist_token_bad_crc": lambda v: any(
        checks.has_valid_crc32_hex_suffix(v, f"packagist_{kind}_") for kind in ("ort", "out", "uut", "cut")
    ),
    # P06
    "azure_devops_pat_shifted": azure_devops_pat,
    "azure_devops_legacy_pat_short": CHECKS["azure_devops_legacy_pat"],
    "circleci_personal_token_short": CHECKS["circleci_personal_token"],
    "vercel_personal_token_short": CHECKS["vercel_personal_token"],
    "netlify_personal_token_short": CHECKS["netlify_personal_token"],
    "render_api_key_short": lambda v: any(prefixed("rnd_", ALNUM, n)(v) for n in range(24, 65)),
    "cloudflare_api_token_short": CHECKS["cloudflare_api_token"],
    # P07
    "datadog_api_key_short": CHECKS["datadog_api_key"],
    "datadog_client_token": lambda v: CHECKS["datadog_api_key"](v) or CHECKS["datadog_app_key"](v),
    "newrelic_user_api_key_short": CHECKS["newrelic_user_api_key"],
    "newrelic_insert_key_short": lambda v: any(prefixed("NRII-", B64URL, n)(v) for n in (25, 32)),
    "newrelic_license_key_short": CHECKS["newrelic_license_key"],
    "sentry_user_token_short": CHECKS["sentry_user_token"],
    "sentry_org_token_no_iat": sentry_org_token,
    "grafana_api_key_unterminated": grafana_api_key,
    "grafana_cloud_token_random": grafana_cloud_token,
    "grafana_service_account_token_bad_crc": grafana_service_account_token,
    "dynatrace_api_token_short": CHECKS["dynatrace_api_token"],
    "splunk_hec_token_short": uuid_upper,
    "elastic_api_key_short": elastic_api_key,
    "honeycomb_api_key_short": CHECKS["honeycomb_api_key"],
    "pagerduty_api_key_short": CHECKS["pagerduty_api_key"],
    "prefect_api_key_short": CHECKS["prefect_api_key"],
    "infracost_api_key_short": CHECKS["infracost_api_key"],
    "octopus_deploy_api_key_lower": CHECKS["octopus_deploy_api_key"],
    "harness_personal_access_token_short": harness(20),
    "snyk_api_token_short": CHECKS["snyk_api_token"],
    "sonar_user_token_short": lambda v: CHECKS["sonar_user_token"](v) or CHECKS["sonar_project_token"](v),
    "codecov_access_token_short": CHECKS["codecov_access_token"],
    "sourcegraph_access_token_short": sourcegraph,
    # GOLD-D4
    "bedrock_api_key_short": CHECKS["bedrock_api_key"],
    "alibaba_access_key_id_short": lambda v: CHECKS["alibaba_access_key_id"](v) or CHECKS["alibaba_secret_key"](v),
    "azure_entra_client_secret_short": CHECKS["azure_entra_client_secret"],
    "azure_storage_account_key_short": CHECKS["azure_storage_account_key"],
    "gcp_external_account_config": CHECKS["gcp_service_account_key"],
    "ibm_cloud_iam_api_key_short": CHECKS["ibm_cloud_iam_api_key"],
    "yandex_api_key_short": lambda v: CHECKS["yandex_api_key"](v) or CHECKS["yandex_static_access_key_secret"](v),
    "scalingo_api_token_short": CHECKS["scalingo_api_token"],
    "flyio_oauth_token_short": lambda v: CHECKS["flyio_oauth_token"](v) or CHECKS["flyio_macaroon_token"](v),
    "netlify_access_token_short": CHECKS["netlify_access_token"],
    "heroku_api_key_v2_short": lambda v: CHECKS["heroku_api_key"](v) or CHECKS["heroku_api_key_v2"](v),
    "cloudflare_origin_ca_key_short": lambda v: any(
        CHECKS[name](v) for name in ("cloudflare_api_token", "cloudflare_global_api_key", "cloudflare_origin_ca_key")
    ),
    "digitalocean_pat_short": lambda v: any(
        CHECKS[name](v) for name in ("digitalocean_pat", "digitalocean_oauth_token", "digitalocean_refresh_token")
    ),
    "openshift_user_token_short": CHECKS["openshift_user_token"],
    "defined_networking_api_token_short": CHECKS["defined_networking_api_token"],
    "fastly_api_token_short": CHECKS["fastly_api_token"],
    "settlemint_personal_access_token_short": lambda v: any(
        CHECKS[name](v)
        for name in (
            "settlemint_personal_access_token", "settlemint_application_access_token", "settlemint_service_access_token"
        )
    ),
    "databricks_api_token_short": CHECKS["databricks_api_token"],
    "planetscale_service_token_short": lambda v: any(
        CHECKS[name](v) for name in ("planetscale_service_token", "planetscale_oauth_token", "planetscale_password")
    ),
    "confluent_api_secret_short": lambda v: CHECKS["confluent_api_key"](v) or CHECKS["confluent_api_secret"](v),
    "algolia_admin_api_key_short": CHECKS["algolia_admin_api_key"],
    "clickhouse_cloud_api_secret_short": CHECKS["clickhouse_cloud_api_secret"],
    "cloudant_password_short": lambda v: CHECKS["cloudant_password"](v) or CHECKS["cloudant_api_key"](v),
    # GOLD-D6
    "curl_user_only": lambda v: ":" in v or CHECKS["curl_user_password"](v),
    "nuget_username": CHECKS["nuget_cleartext_password"],
    "kubernetes_configmap_binary": CHECKS["kubernetes_secret_data"],
    "uuid_v4": lambda v: CHECKS["base64_high_entropy_string"](v) or CHECKS["hex_high_entropy_string"](v)
    or shannon_entropy(v) > 4.5,
    "age_public_key": lambda v: CHECKS["age_secret_key"](v) or checks.bech32_decode(v)[0] != "age",
    "x509_certificate": CHECKS["pkcs12_keystore"],
    "sha1_hex_digest": lambda v: any(CHECKS[name](v) for name in ("laravel_app_key", "fernet_key", "aes256_hex_key")),
}


def value_entries():
    """Every value rule and baseline entity (GOLD-D2) of rules.json."""
    return {**rules.load_rule_map(), **rules.baseline_entities()}


def valid_generators():
    names = set()
    for entry in value_entries().values():
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
            self.assertFalse(set(entry["generators"] + entry.get("weak", [])) & set(entry.get("quoted", [])), rule_id)
            self.assertFalse(
                set(entry["generators"] + entry.get("weak", []) + entry.get("quoted", []))
                & set(entry.get("url_encoded", [])),
                rule_id,
            )
            self.assertFalse(
                set(entry.get("lookalike", []))
                & set(entry["generators"] + entry.get("weak", []) + entry.get("quoted", []) + entry.get("url_encoded", [])),
                rule_id,
            )
            referenced.update(
                entry["generators"],
                entry.get("shape_only", []),
                entry.get("weak", []),
                entry.get("quoted", []),
                entry.get("url_encoded", []),
                entry.get("lookalike", []),
            )
        for entity, entry in rules.baseline_entities().items():
            self.assertTrue(entry["generators"] and entry["lookalike"], entity)
            self.assertFalse(set(entry["generators"]) & set(entry["lookalike"]), entity)
            self.assertFalse(set(entry["generators"] + entry["lookalike"]) & referenced, entity)
            referenced.update(entry["generators"], entry["lookalike"])
        self.assertEqual(referenced, set(recipes.load_generators()))

    def test_baseline_entities_are_baseline_only_entities_with_a_format_source(self):
        # GOLD-D2/D3/D4/D6: gold for entities without an ARK rule follows a baseline rule of the
        # entity (gitleaks, or the TruffleHog detector or detect-secrets plugin of an entity
        # without a gitleaks rule) or, for an entity no baseline detects, vendor documentation
        # (docs:<url>); lookalikes name what they get wrong.
        entity_map = yaml.safe_load((REPO / "research/dlp/entity_map.yaml").read_text(encoding="utf-8"))
        by_id = {entity["id"]: entity for entity in entity_map["entities"]}
        fields = {"gitleaks": "gitleaks", "trufflehog": "trufflehog", "detect-secrets": "detect_secrets"}
        generators = recipes.load_generators()
        for entity, entry in rules.baseline_entities().items():
            self.assertEqual(by_id[entity]["scope"], "baseline_only", entity)
            self.assertNotIn("ark", by_id[entity], entity)
            for name in entry["generators"]:
                tool, _, rule = generators[name]["source"].partition(":")
                if tool == "docs":
                    self.assertFalse(set(fields.values()) & set(by_id[entity]), name)
                    self.assertRegex(rule, r"^[a-z0-9.-]+\.[a-z]+/\S*; ", name)
                    continue
                self.assertIn(tool, fields, name)
                self.assertIn(rule.split(";")[0], by_id[entity].get(fields[tool], []), name)
                if tool != "gitleaks":
                    self.assertNotIn("gitleaks", by_id[entity], name)
            for name in entry["lookalike"]:
                self.assertRegex(generators[name]["source"], r"^GOLD-D[2-6] lookalike: ", name)

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

    def test_invalid_entropy_limits_are_rejected(self):
        segments = [{"alphabet": "hex_lower", "len": 4}]
        for limit in (0, -1.0, 2.0, 2.5, "4.5", True, None):
            # 4 characters hold at most 2 bits each, so a limit of 2.0 or more is unreachable.
            self.assertFalse(recipes._valid_entropy_limit({"segments": segments, "entropy_above": limit}), limit)
        self.assertTrue(recipes._valid_entropy_limit({"segments": segments, "entropy_above": 1.5}))
        self.assertTrue(recipes._valid_entropy_limit({"segments": segments}))
        self.assertFalse(recipes._valid_entropy_limit({"segments": [{"lit": "abcd"}], "entropy_above": 1.0}))

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

    def test_high_entropy_generators_stay_above_the_detect_secrets_limit(self):
        # Review of #205: base64 of 33 random bytes fell to 4.49887 bits at seed 896 (305 of
        # the first 100k seeds); the generator redraws until the value clears the limit.
        for name, limit in (("base64_high_entropy_string", 4.5), ("hex_high_entropy_string", 3.0)):
            for seed in (*range(4096), 2**64 - 1):
                value = recipes.generate(name, seed)
                self.assertGreater(shannon_entropy(value), limit, f"{name} seed={seed}")
                self.assertEqual(len(value), recipes.generator_length(name), name)

    def test_shape_only_generators_fail_the_structural_check(self):
        for name, check in SHAPE_ONLY_FAILURES.items():
            for seed in range(8):
                self.assertFalse(check(recipes.generate(name, seed)), f"{name} seed={seed}")

    def test_lookalike_generators_fail_their_check(self):
        lookalike = set()
        for entry in value_entries().values():
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
            "age_secret_key": age_secret_key,
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
        # BIP 173 valid and invalid Bech32 strings.
        self.assertEqual(checks.bech32_decode("A12UEL5L"), ("a", b""))
        self.assertEqual(checks.bech32_decode("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw")[0], "abcdef")
        self.assertEqual(recipes.bech32_checksum("abcdef1", "qpzry9x8gf2tvdw0s3jn54khce6mua7l"), "mqqqxw")
        self.assertIsNone(checks.bech32_decode("A12UEl5L"))  # mixed case
        self.assertIsNone(checks.bech32_decode("a12uel5m"))  # wrong checksum
        self.assertEqual(recipes.crc32_base62(""), "000000")
        # CRC-32/ISO-HDLC check value of "123456789" is 0xCBF43926; P07 writes its little-endian bytes.
        self.assertEqual(recipes.checksum("crc32_hex_le", "", "_", "123456789"), "2639f4cb")

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
