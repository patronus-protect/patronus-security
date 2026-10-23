# SPDX-License-Identifier: GPL-3.0-only
"""Offline format, structure and checksum checks for synthetic DLP values.

The checks are written independently of the generator encoders in ``recipes`` so a
generator bug cannot hide behind the same bug in its verifier. They only parse and
recompute checksums; nothing here contacts a provider.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import zlib


BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BCRYPT64 = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
STD64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
OID_ED25519 = bytes.fromhex("2b6570")
OID_PRIME256V1 = bytes.fromhex("2a8648ce3d030107")
_PEM_RE = re.compile(
    r"-----BEGIN (?P<label>[A-Z0-9 ]+)-----\n(?P<body>[A-Za-z0-9+/=\n]+)\n-----END (?P=label)-----"
)


def crc32_base62(text: str) -> str:
    checksum = zlib.crc32(text.encode("ascii"))
    digits = []
    for _ in range(6):
        checksum, remainder = divmod(checksum, 62)
        digits.append(BASE62[remainder])
    return "".join(reversed(digits)) if checksum == 0 else ""


def has_valid_crc32_suffix(token: str, prefix: str) -> bool:
    """GitHub/npm layout: ``prefix`` + 30 base62 chars + 6 base62 CRC-32 chars."""
    if not token.startswith(prefix):
        return False
    body = token[len(prefix) :]
    return (
        len(body) == 36
        and all(character in BASE62 for character in body)
        and crc32_base62(body[:30]) == body[30:]
    )


def base58check_decode(value: str) -> bytes | None:
    """Return the payload of a Base58Check string, or ``None`` if it is invalid."""
    if not value or any(character not in BASE58 for character in value):
        return None
    number = 0
    for character in value:
        number = number * 58 + BASE58.index(character)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(value) - len(value.lstrip("1"))) + raw
    if len(raw) < 5:
        return None
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        return None
    return payload


def is_valid_btc_wif(value: str) -> bool:
    """WIF: version byte 0x80 (mainnet) or 0xef (testnet), a secp256k1 scalar, optional
    0x01 compression flag."""
    payload = base58check_decode(value)
    if payload is None or payload[0] not in (0x80, 0xEF) or len(payload) not in (33, 34):
        return False
    if len(payload) == 34 and payload[-1] != 0x01:
        return False
    return 0 < int.from_bytes(payload[1:33], "big") < SECP256K1_ORDER


def is_valid_eth_private_key(value: str) -> bool:
    if not re.fullmatch(r"0x[0-9a-f]{64}", value):
        return False
    return 0 < int(value[2:], 16) < SECP256K1_ORDER


def iso7064_mod11_10_valid(digits: str) -> bool:
    if not digits.isdigit():
        return False
    product = 10
    for digit in digits[:-1]:
        total = (int(digit) + product) % 10 or 10
        product = 2 * total % 11
    return (11 - product) % 10 == int(digits[-1])


def is_valid_de_vat_id(value: str) -> bool:
    return bool(re.fullmatch(r"DE[1-9][0-9]{8}", value)) and iso7064_mod11_10_valid(value[2:])


def _strict_b64decode(value: str, alphabet: str, padded: bool) -> bytes | None:
    """Decode canonical base64 (unused trailing bits zero), or return ``None``."""
    if padded:
        if len(value) % 4:
            return None
        value = value.rstrip("=")
    elif len(value) % 4 == 1:
        return None
    if any(character not in alphabet for character in value):
        return None
    standard = value.translate(str.maketrans(alphabet, STD64))
    try:
        raw = base64.b64decode(standard + "=" * (-len(standard) % 4), validate=True)
    except binascii.Error:
        return None
    reencoded = base64.b64encode(raw).decode("ascii").rstrip("=")
    return raw if reencoded == standard else None


def b64decode(value: str) -> bytes | None:
    return _strict_b64decode(value, STD64, padded=True)


def b64decode_unpadded(value: str) -> bytes | None:
    return _strict_b64decode(value, STD64, padded=False)


def b64url_decode(value: str) -> bytes | None:
    return _strict_b64decode(value, STD64[:62] + "-_", padded=False)


def bcrypt64_decode(value: str) -> bytes | None:
    return _strict_b64decode(value, BCRYPT64, padded=False)


def der_parse(raw: bytes) -> list[tuple[int, bytes]] | None:
    """Parse a DER TLV sequence completely; ``None`` on any length/encoding error."""
    elements = []
    offset = 0
    while offset < len(raw):
        if offset + 2 > len(raw):
            return None
        tag = raw[offset]
        length = raw[offset + 1]
        offset += 2
        if length & 0x80:
            count = length & 0x7F
            if count == 0 or count > 4 or offset + count > len(raw) or raw[offset] == 0:
                return None
            length = int.from_bytes(raw[offset : offset + count], "big")
            if length < 0x80:
                return None
            offset += count
        if offset + length > len(raw):
            return None
        elements.append((tag, raw[offset : offset + length]))
        offset += length
    return elements


def _der_integer_ok(content: bytes) -> bool:
    if not content or content[0] & 0x80:
        return False
    return len(content) == 1 or not (content[0] == 0 and content[1] < 0x80)


def _der_sequence(raw: bytes) -> list[tuple[int, bytes]] | None:
    outer = der_parse(raw)
    if not outer or len(outer) != 1 or outer[0][0] != 0x30:
        return None
    return der_parse(outer[0][1])


def pem_blocks(text: str) -> list[tuple[str, bytes]]:
    """Return ``(label, body)`` for each PEM block with canonical base64 lines."""
    blocks = []
    for match in _PEM_RE.finditer(text):
        lines = match.group("body").split("\n")
        width = 70 if match.group("label") == "OPENSSH PRIVATE KEY" else 64
        if any(len(line) != width for line in lines[:-1]) or not 0 < len(lines[-1]) <= width:
            continue
        body = b64decode("".join(lines))
        if body is not None:
            blocks.append((match.group("label"), body))
    return blocks


def is_valid_pkcs8_ed25519(der: bytes) -> bool:
    fields = _der_sequence(der)
    if not fields or [tag for tag, _ in fields] != [0x02, 0x30, 0x04]:
        return False
    algorithm = der_parse(fields[1][1])
    key = der_parse(fields[2][1])
    return (
        fields[0][1] == b"\0"
        and algorithm == [(0x06, OID_ED25519)]
        and key is not None
        and len(key) == 1
        and key[0][0] == 0x04
        and len(key[0][1]) == 32
    )


def is_valid_pkcs1_rsa(der: bytes) -> bool:
    fields = _der_sequence(der)
    return (
        fields is not None
        and len(fields) == 9
        and all(tag == 0x02 and _der_integer_ok(content) for tag, content in fields)
        and fields[0][1] == b"\0"
    )


def is_valid_sec1_p256(der: bytes) -> bool:
    fields = _der_sequence(der)
    if not fields or [tag for tag, _ in fields] != [0x02, 0x04, 0xA0, 0xA1]:
        return False
    curve = der_parse(fields[2][1])
    public = der_parse(fields[3][1])
    return (
        fields[0][1] == b"\x01"
        and len(fields[1][1]) == 32
        and 0 < int.from_bytes(fields[1][1], "big") < P256_ORDER
        and curve == [(0x06, OID_PRIME256V1)]
        and public is not None
        and len(public) == 1
        and public[0][0] == 0x03
        and len(public[0][1]) == 66
        and public[0][1][:2] == b"\0\x04"
    )


def is_valid_dsa(der: bytes) -> bool:
    fields = _der_sequence(der)
    return (
        fields is not None
        and len(fields) == 6
        and all(tag == 0x02 and _der_integer_ok(content) for tag, content in fields)
        and fields[0][1] == b"\0"
    )


def _ssh_strings(raw: bytes, count: int) -> tuple[list[bytes], bytes] | None:
    values = []
    for _ in range(count):
        if len(raw) < 4:
            return None
        length = int.from_bytes(raw[:4], "big")
        if len(raw) < 4 + length:
            return None
        values.append(raw[4 : 4 + length])
        raw = raw[4 + length :]
    return values, raw


def is_valid_openssh_ed25519(raw: bytes) -> bool:
    """openssh-key-v1, unencrypted, one ssh-ed25519 key (OpenSSH PROTOCOL.key)."""
    magic = b"openssh-key-v1\0"
    if not raw.startswith(magic):
        return False
    header = _ssh_strings(raw[len(magic) :], 3)
    if header is None or header[0] != [b"none", b"none", b""]:
        return False
    rest = header[1]
    if rest[:4] != (1).to_bytes(4, "big"):
        return False
    keys = _ssh_strings(rest[4:], 2)
    if keys is None or keys[1]:
        return False
    public, private = keys[0]
    public_fields = _ssh_strings(public, 2)
    if public_fields is None or public_fields[1] or public_fields[0][0] != b"ssh-ed25519":
        return False
    if len(public_fields[0][1]) != 32 or len(private) % 8 or private[:4] != private[4:8]:
        return False
    private_fields = _ssh_strings(private[8:], 4)
    if private_fields is None:
        return False
    (key_type, _, secret, _), padding = private_fields
    return (
        key_type == b"ssh-ed25519"
        and len(private_fields[0][1]) == 32
        and len(secret) == 64
        and padding == bytes(range(1, len(padding) + 1))
    )


def jwt_parts(token: str) -> tuple[dict, dict, bytes] | None:
    """Return ``(header, claims, signature)`` of a compact JWS, or ``None``."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    decoded = [b64url_decode(part) for part in parts]
    if any(part is None for part in decoded):
        return None
    try:
        header = json.loads(decoded[0])
        claims = json.loads(decoded[1])
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(header, dict) or not isinstance(claims, dict) or "alg" not in header:
        return None
    return header, claims, decoded[2]


def basic_auth_pair(value: str) -> tuple[str, str] | None:
    raw = b64decode(value)
    if raw is None:
        return None
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    user, separator, password = text.partition(":")
    if not separator or not user or not password or ":" in user:
        return None
    return user, password
