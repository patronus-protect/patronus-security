"""H01: technical benign snippets for hard-negative mining.

Every snippet carries a value a secret scanner tends to mistake for key material: content
hashes, UUIDs, image digests, lockfile integrity, commit SHAs, published test vectors and
documented example keys. None of them is a secret. Values come from a seeded PRNG, so the
same 1,000 snippets (20 families, 25 DE + 25 EN each) are produced on every run.
"""
from __future__ import annotations

import base64
import hashlib
import random
import uuid

PER_LANGUAGE = 25
LANGUAGES = ("de", "en")
SEED = 1_250_001

_PACKAGES = (
    "left-pad", "lodash", "react-dom", "serde", "tokio", "requests", "numpy", "express", "chalk",
    "zod", "anyhow", "regex", "clap", "pyyaml", "urllib3", "semver", "debug", "rand", "hyper",
)
_FILES = (
    "release-2.4.1.tar.gz", "ark-linux-x86_64.zip", "installer.msi", "model.onnx", "dump.sql.gz",
    "backup-2026-11-01.tar.zst", "firmware.bin", "app.apk", "wheel-0.42.0-py3-none-any.whl",
)
_IMAGES = ("nginx", "postgres", "redis", "python", "node", "alpine", "debian", "rust", "grafana/grafana")
_SERVICES = ("billing", "checkout", "search", "auth-proxy", "ingest", "reports", "gateway")


def _hex(rng: random.Random, length: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(length))


def _digest(rng: random.Random, algo: str) -> bytes:
    return hashlib.new(algo, rng.getrandbits(64).to_bytes(8, "big")).digest()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _uuid(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def _pick(rng: random.Random, items: tuple[str, ...]) -> str:
    return items[rng.randrange(len(items))]


def _version(rng: random.Random) -> str:
    return f"{rng.randint(0, 9)}.{rng.randint(0, 30)}.{rng.randint(0, 20)}"


def commit_sha(rng, lang):
    sha, short = _hex(rng, 40), _hex(rng, 7)
    if lang == "de":
        text = rng.choice((
            f"commit {sha}\nAuthor: Lena Weber <lena@example.org>\n\n    Fehlerbehebung im Export\n",
            f"Der Fix steckt in Commit {short}, gemergt als {sha}.\n",
            f"$ git cherry-pick {sha}\n[release/2.4 {short}] Prüfsumme im Export korrigieren\n",
        ))
    else:
        text = rng.choice((
            f"commit {sha}\nMerge: {short} {_hex(rng, 7)}\nAuthor: CI Bot <ci@example.org>\n",
            f"Reverted in {short}; the original change is {sha}.\n",
            f"$ git rev-parse HEAD\n{sha}\n",
        ))
    return "log" if text.startswith("commit") else "cli" if text.startswith("$") else "prose", text, "git commit SHA"


def sha256_sums(rng, lang):
    lines = "".join(f"{_digest(rng, 'sha256').hex()}  {_pick(rng, _FILES)}\n" for _ in range(rng.randint(1, 3)))
    head = "# SHA256SUMS der Release-Artefakte\n" if lang == "de" else "# SHA256SUMS for the release artifacts\n"
    return "cli", head + lines, "sha256sum output"


def md5_sha1(rng, lang):
    md5, sha1 = _digest(rng, "md5").hex(), _digest(rng, "sha1").hex()
    name = _pick(rng, _FILES)
    if lang == "de":
        text = f"Prüfsummen für {name}:\nMD5:  {md5}\nSHA1: {sha1}\n"
    else:
        text = f"$ md5sum {name}\n{md5}  {name}\n$ sha1sum {name}\n{sha1}  {name}\n"
    return "cli", text, "md5/sha1 checksums"


def sha512_hex(rng, lang):
    value = _digest(rng, "sha512").hex()
    key = rng.choice(("sha512", "checksum_sha512", "digest"))
    note = "Prüfsumme des Artefakts" if lang == "de" else "artifact checksum"
    return "yaml", f"artifact:\n  name: {_pick(rng, _FILES)}\n  # {note}\n  {key}: {value}\n", "sha512 hex digest"


def docker_digest(rng, lang):
    image, digest = _pick(rng, _IMAGES), _digest(rng, "sha256").hex()
    form = rng.randrange(3)
    if form == 0:
        return "code", f"FROM {image}:{_version(rng)}@sha256:{digest}\n", "pinned image digest in a Dockerfile"
    if form == 1:
        return "yaml", f"containers:\n  - name: {_pick(rng, _SERVICES)}\n    image: {image}@sha256:{digest}\n", "image digest in a pod spec"
    word = "Digest des Images" if lang == "de" else "Image digest"
    return "log", f"{word}: sha256:{digest}\nStatus: Downloaded newer image for {image}:latest\n", "docker pull digest"


def npm_integrity(rng, lang):
    pkg = _pick(rng, _PACKAGES)
    version = _version(rng)
    integrity = "sha512-" + _b64(_digest(rng, "sha512"))
    text = (
        f"    \"node_modules/{pkg}\": {{\n      \"version\": \"{version}\",\n"
        f"      \"resolved\": \"https://registry.npmjs.org/{pkg}/-/{pkg}-{version}.tgz\",\n"
        f"      \"integrity\": \"{integrity}\"\n    }},\n"
    )
    return "json", text, "package-lock integrity"


def yarn_integrity(rng, lang):
    pkg = _pick(rng, _PACKAGES)
    version = _version(rng)
    sha1 = _digest(rng, "sha1").hex()
    integrity = rng.choice(("sha1-" + _b64(_digest(rng, "sha1")), "sha512-" + _b64(_digest(rng, "sha512"))))
    text = (
        f"{pkg}@^{version}:\n  version \"{version}\"\n"
        f"  resolved \"https://registry.yarnpkg.com/{pkg}/-/{pkg}-{version}.tgz#{sha1}\"\n"
        f"  integrity {integrity}\n"
    )
    return "line", text, "yarn.lock integrity"


def cargo_lock(rng, lang):
    pkg = _pick(rng, _PACKAGES)
    text = (
        f"[[package]]\nname = \"{pkg}\"\nversion = \"{_version(rng)}\"\n"
        f"source = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
        f"checksum = \"{_digest(rng, 'sha256').hex()}\"\n"
    )
    return "toml", text, "Cargo.lock checksum"


def go_sum(rng, lang):
    module = rng.choice(("github.com/spf13/cobra", "golang.org/x/net", "github.com/google/uuid", "go.uber.org/zap"))
    version = f"v{_version(rng)}"
    text = (
        f"{module} {version} h1:{_b64(_digest(rng, 'sha256'))}\n"
        f"{module} {version}/go.mod h1:{_b64(_digest(rng, 'sha256'))}\n"
    )
    return "line", text, "go.sum hashes"


def pip_hashes(rng, lang):
    pkg = _pick(rng, _PACKAGES)
    text = (
        f"{pkg}=={_version(rng)} \\\n"
        f"    --hash=sha256:{_digest(rng, 'sha256').hex()} \\\n"
        f"    --hash=sha256:{_digest(rng, 'sha256').hex()}\n"
    )
    return "line", text, "pip --hash pins"


def uuids(rng, lang):
    form = rng.randrange(3)
    if form == 0:
        text = (
            f"{{\"request_id\": \"{_uuid(rng)}\", \"tenant_id\": \"{_uuid(rng)}\", "
            f"\"session_id\": \"{_uuid(rng)}\", \"status\": 200}}\n"
        )
        return "json", text, "request, tenant and session UUIDs"
    if form == 1:
        word = "Vorgang" if lang == "de" else "job"
        return "log", f"2026-11-09T10:{rng.randint(10, 59)}:03Z INFO {word} {_uuid(rng)} abgeschlossen\n" if lang == "de" else f"2026-11-09T10:{rng.randint(10, 59)}:03Z INFO {word} {_uuid(rng)} finished\n", "job UUID in a log line"
    text = f"CLIENT_ID={_uuid(rng)}\nSUBSCRIPTION_ID={_uuid(rng)}\nTENANT_ID={_uuid(rng)}\n"
    return "env", text, "client, subscription and tenant IDs (identifiers, not secrets)"


def trace_ids(rng, lang):
    trace, span = _hex(rng, 32), _hex(rng, 16)
    if rng.randrange(2):
        return "http", f"GET /api/v1/orders HTTP/1.1\ntraceparent: 00-{trace}-{span}-01\n", "W3C traceparent header"
    word = "Fehler bei der Abfrage" if lang == "de" else "query failed"
    return "log", f"level=error msg=\"{word}\" trace_id={trace} span_id={span}\n", "trace and span IDs in a log"


def sri_hashes(rng, lang):
    algo = rng.choice(("sha256", "sha384", "sha512"))
    value = _b64(_digest(rng, algo))
    lib = _pick(rng, _PACKAGES)
    text = (
        f"<script src=\"https://cdn.example.org/{lib}@{_version(rng)}/dist/{lib}.min.js\" "
        f"integrity=\"{algo}-{value}\" crossorigin=\"anonymous\"></script>\n"
    )
    return "xml", text, "subresource integrity hash"


def kubernetes_meta(rng, lang):
    text = (
        f"metadata:\n  name: {_pick(rng, _SERVICES)}-{_hex(rng, 10)}-{_hex(rng, 5)}\n"
        f"  uid: {_uuid(rng)}\n  resourceVersion: \"{rng.randint(100000, 9999999)}\"\n"
        f"  labels:\n    pod-template-hash: {_hex(rng, 10)}\n"
        f"  annotations:\n    checksum/config: {_digest(rng, 'sha256').hex()}\n"
    )
    return "yaml", text, "Kubernetes uid, pod-template-hash and config checksum"


def etags(rng, lang):
    etag = _digest(rng, "md5").hex()
    if rng.randrange(2):
        return "http", f"HTTP/1.1 200 OK\nETag: \"{etag}\"\nContent-Type: application/json\n", "HTTP ETag"
    key = rng.choice(("ETag", "etag", "VersionId"))
    value = etag if key != "VersionId" else _b64(_digest(rng, "sha1")).rstrip("=").replace("+", "x").replace("/", "y")
    return "json", f"{{\"Key\": \"exports/{_pick(rng, _FILES)}\", \"{key}\": \"\\\"{value}\\\"\", \"Size\": {rng.randint(1000, 999999)}}}\n", "S3 object ETag/version"


def tfstate(rng, lang):
    text = (
        f"{{\n  \"version\": 4,\n  \"serial\": {rng.randint(1, 900)},\n  \"lineage\": \"{_uuid(rng)}\",\n"
        f"  \"outputs\": {{}},\n  \"check_results\": null,\n"
        f"  \"source_code_hash\": \"{_b64(_digest(rng, 'sha256'))}\"\n}}\n"
    )
    return "json", text, "Terraform state lineage and source hash"


# Published test vectors (FIPS 180-2 / RFC 4231 / RFC 6238 / BIP 32 test data names only).
_HASH_VECTORS = (
    ("SHA-256", "abc", hashlib.sha256(b"abc").hexdigest()),
    ("SHA-1", "abc", hashlib.sha1(b"abc").hexdigest()),
    ("MD5", "", hashlib.md5(b"").hexdigest()),
    ("SHA-512", "abc", hashlib.sha512(b"abc").hexdigest()),
    ("SHA-256", "", hashlib.sha256(b"").hexdigest()),
)


def hash_test_vectors(rng, lang):
    algo, message, digest = _HASH_VECTORS[rng.randrange(len(_HASH_VECTORS))]
    name = algo.lower().replace("-", "")
    case = rng.randint(1, 999)
    form = rng.randrange(3)
    if form == 0:
        text = f"#[test]\nfn {name}_vector_{case}() {{\n    assert_eq!(hex(digest(b\"{message}\")), \"{digest}\");\n}}\n"
        return "code", text, "published hash test vector in a unit test"
    if form == 1:
        text = f"def test_{name}_{case}():\n    assert hashlib.{name}(b\"{message}\").hexdigest() == \"{digest}\"\n"
        return "code", text, "published hash test vector in a pytest"
    if lang == "de":
        text = f"Testfall {case}: erwarteter Hash laut Testvektor ({algo}, Nachricht \"{message}\"): {digest}\n"
    else:
        text = f"Case {case}: expected digest per test vector ({algo}, message \"{message}\"): {digest}\n"
    return "prose", text, "published hash test vector"


# Example values printed in vendor documentation; scanners allowlist them.
_DOC_EXAMPLES = (
    ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
    ("aws_secret_access_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    ("api_key", "YOUR_API_KEY"),
    ("client_secret", "<client-secret>"),
    ("token", "xxxxxxxxxxxxxxxxxxxxxxxx"),
)


def docs_example_keys(rng, lang):
    key, value = _DOC_EXAMPLES[rng.randrange(len(_DOC_EXAMPLES))]
    service, port = _pick(rng, _SERVICES), rng.randint(3000, 9999)
    if lang == "de":
        text = f"## {service} lokal starten\n\nBeispiel aus der Dokumentation (nicht verwenden):\n\n```\n{key}={value}\nPORT={port}\n```\n"
    else:
        text = f"## Running {service} locally\n\nThe documentation uses this example value:\n\n```\n{key}={value}\nPORT={port}\n```\n"
    return "markdown", text, "documented example value"


def content_ids(rng, lang):
    form = rng.randrange(3)
    if form == 0:
        cid = "bafybei" + "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(52))
        return "line", f"ipfs://{cid}/metadata.json\n", "IPFS CID"
    if form == 1:
        oid = _digest(rng, "sha256").hex()
        return "line", f"version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize {rng.randint(1000, 99999999)}\n", "git LFS pointer"
    blob = _hex(rng, 40)
    word = "Blob" if lang == "en" else "Objekt"
    return "cli", f"$ git cat-file -t {blob}\nblob\n# {word} {blob[:12]}\n", "git object id"


def public_keys(rng, lang):
    blob = _b64(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + _digest(rng, "sha256"))
    host = f"git{rng.randint(1, 9)}.example.org"
    if rng.randrange(2):
        comment = "Deploy-Schlüssel (öffentlich)" if lang == "de" else "deploy key (public)"
        return "line", f"ssh-ed25519 {blob} {comment}\n", "SSH public key in authorized_keys"
    fingerprint = "SHA256:" + _b64(_digest(rng, "sha256")).rstrip("=")
    return "cli", f"$ ssh-keyscan {host}\n{host} ssh-ed25519 {blob}\n$ ssh-keygen -lf known_hosts\n256 {fingerprint} {host} (ED25519)\n", "known_hosts entry and key fingerprint"


FAMILIES = (
    commit_sha, sha256_sums, md5_sha1, sha512_hex, docker_digest, npm_integrity, yarn_integrity,
    cargo_lock, go_sum, pip_hashes, uuids, trace_ids, sri_hashes, kubernetes_meta, etags, tfstate,
    hash_test_vectors, docs_example_keys, content_ids, public_keys,
)


def snippets() -> list[dict]:
    """All snippets in a fixed order: family, language, index."""
    rng = random.Random(SEED)
    rows = []
    for family in FAMILIES:
        for lang in LANGUAGES:
            for _ in range(PER_LANGUAGE):
                carrier, text, reason = family(rng, lang)
                rows.append({"family": family.__name__, "language": lang, "carrier": carrier, "text": text, "reason": reason})
    return rows
