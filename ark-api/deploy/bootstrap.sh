#!/usr/bin/env bash
# Download the release asset, verify its checksum, then run as root.
# The image workflow replaces these three markers in the published script.
set -euo pipefail
set +x
umask 077

RELEASE_COMMIT='__RELEASE_COMMIT__'
ARK_IMAGE='__ARK_IMAGE__'
REDIS_IMAGE='__REDIS_IMAGE__'
DEPLOY_DIR=/opt/patronus/ark-api
STATE_DIR=/var/lib/patronus-cube
CUBE_IP=10.20.0.11
NIC=ens6
GATEWAY=10.20.0.1

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
boot_id() { cat /proc/sys/kernel/random/boot_id; }
compose() { docker compose --project-directory "$DEPLOY_DIR" -f "$DEPLOY_DIR/compose.yaml" "$@"; }

host_check() {
    [[ $EUID == 0 ]] || die 'Run with sudo/root.'
    # shellcheck source=/dev/null
    . /etc/os-release
    [[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || die 'Requires Ubuntu 24.04.'
    [[ $(uname -m) == x86_64 ]] || die 'This release requires x86_64.'
    ip -4 -o address show dev "$NIC" | grep -Fq " $CUBE_IP/24 " || die 'Phase 1 is restricted to Cube 1 (10.20.0.11/24 on ens6).'
    install -d -m 0700 "$STATE_DIR" "$DEPLOY_DIR"
}

network_check() {
    ip -4 address show dev "$NIC"
    ip -4 route show
    ip -4 route get 1.1.1.1 | grep -Fq "via $GATEWAY dev $NIC" || die 'NAT default route is missing.'
    resolvectl status "$NIC"
    resolvectl query github.com >/dev/null
    curl --fail --silent --show-error --head --connect-timeout 10 --max-time 30 https://github.com >/dev/null
}

network_setup() {
    systemctl is-active --quiet systemd-networkd || die 'Inspect this network manager before changing persistent networking.'
    systemctl is-active --quiet systemd-resolved || die 'systemd-resolved must be active.'
    local network_file dropin boot_before
    network_file=$(LC_ALL=C networkctl status "$NIC" --no-pager --lines=0 | sed -n 's/^[[:space:]]*Network File: //p')
    [[ $network_file == /run/systemd/network/*netplan*.network ]] || die "Inspect DHCP configuration first; unexpected network file: $network_file"
    [[ -f $network_file ]] || die 'Active network file is missing.'
    grep -Eq '^DHCP=(yes|ipv4|true)$' "$network_file" || die 'Expected DHCP-generated private configuration.'
    if ip -4 route show default | grep -vE "^default via 10\.20\.0\.1 dev ens6( |$)" | grep -q .; then
        die 'Another default route exists; inspect it before continuing.'
    fi
    networkctl status "$NIC" --no-pager --lines=0
    # A drop-in augments the DHCP-generated file; it never overwrites Netplan.
    dropin="/etc/systemd/network/$(basename "$network_file").d/60-patronus-nat.conf"
    if [[ ! -f $STATE_DIR/network-boot-before ]]; then
        [[ ! -e $dropin ]] || die 'Unmanaged NAT drop-in already exists; inspect it first.'
        cp "$network_file" "$STATE_DIR/original-network.conf"
        ip -4 route show > "$STATE_DIR/original-routes.txt"
        resolvectl status "$NIC" > "$STATE_DIR/original-dns.txt"
        install -d -m 0755 "$(dirname "$dropin")"
        cat > "$dropin" <<'EOF'
[Network]
Gateway=10.20.0.1
DNS=1.1.1.1
DNS=8.8.8.8
Domains=~.

[DHCPv4]
UseDNS=no
UseDomains=no
EOF
        chmod 0644 "$dropin"
        printf '%s\n' "$dropin" > "$STATE_DIR/network-dropin"
        boot_id > "$STATE_DIR/network-boot-before"
    fi
    boot_before=$(cat "$STATE_DIR/network-boot-before")
    if [[ $boot_before == "$(boot_id)" ]]; then
        ip route replace default via "$GATEWAY" dev "$NIC"
        resolvectl dns "$NIC" 1.1.1.1 8.8.8.8
        resolvectl domain "$NIC" '~.'
        resolvectl flush-caches
        network_check
        printf 'Network configuration saved. Reboot Cube 1, then run this script with deploy.\n'
    else
        # No route or DNS repair here: this must prove reboot persistence.
        network_check
        printf 'Network persistence verified after reboot.\n'
    fi
}

install_docker() {
    if ! command -v docker >/dev/null; then
        local package
        for package in docker.io docker-compose docker-compose-v2 podman-docker containerd runc; do
            if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed'; then
                die "Conflicting package $package is installed; review migration first."
            fi
        done
        apt-get update
        apt-get install -y ca-certificates curl python3
        install -d -m 0755 /etc/apt/keyrings
        curl --fail --silent --show-error --proto '=https' --tlsv1.2 https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
        chmod 0644 /etc/apt/keyrings/docker.asc
        cat > /etc/apt/sources.list.d/docker.sources <<'EOF'
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: noble
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.asc
EOF
        chmod 0644 /etc/apt/sources.list.d/docker.sources
        apt-get update
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    fi
    command -v python3 >/dev/null || die 'Install python3 before continuing.'
    docker compose version
    install -d -m 0755 /etc/systemd/system/docker.service.d
    cat > /etc/systemd/system/docker.service.d/60-patronus-network.conf <<'EOF'
[Unit]
Wants=network-online.target
After=network-online.target
EOF
    chmod 0644 /etc/systemd/system/docker.service.d/60-patronus-network.conf
    systemctl daemon-reload
    systemctl enable --now docker
}

fetch_config() {
    [[ $RELEASE_COMMIT =~ ^[0-9a-f]{40}$ ]] || die 'Use the bootstrap asset produced by the image release workflow.'
    [[ $ARK_IMAGE =~ ^ghcr.io/patronus-protect/ark-api@sha256:[0-9a-f]{64}$ ]] || die 'ARK image must be pinned to a GHCR digest.'
    [[ $REDIS_IMAGE =~ ^redis@sha256:[0-9a-f]{64}$ ]] || die 'Redis must be pinned to a digest.'
    local file staging
    staging=$(mktemp -d "$DEPLOY_DIR/.download.XXXXXX")
    for file in compose.yaml worker.template.yaml entrypoint.template.yaml smoke.py; do
        curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --connect-timeout 10 --max-time 120 \
            "https://raw.githubusercontent.com/patronus-protect/patronus-security/$RELEASE_COMMIT/ark-api/deploy/$file" \
            -o "$staging/$file"
    done
    for file in compose.yaml worker.template.yaml entrypoint.template.yaml smoke.py; do
        install -m 0600 "$staging/$file" "$DEPLOY_DIR/$file"
    done
    rm -r "$staging"
}

configure_secrets() {
    # Values never pass through command arguments, stdout, or environment.
    python3 - "$DEPLOY_DIR" <<'PY'
import hashlib
import os
from pathlib import Path
import secrets
import sys

root = Path(sys.argv[1])
def token(name):
    path = root / name
    if not path.exists():
        with path.open('x') as handle:
            handle.write(secrets.token_hex(32) + '\n')
    path.chmod(0o600)
    value = path.read_text().strip()
    if len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise SystemExit(f'Invalid existing secret file: {name}')
    return value

public = token('public-api.key')
worker = token('worker.key')
replacements = {
    '__PUBLIC_HASH__': hashlib.sha256(public.encode()).hexdigest(),
    '__WORKER_HASH__': hashlib.sha256(worker.encode()).hexdigest(),
    '__WORKER_TOKEN__': worker,
}
for name in ('worker', 'entrypoint'):
    contents = (root / f'{name}.template.yaml').read_text()
    for key, value in replacements.items():
        contents = contents.replace(key, value)
    path = root / f'{name}.yaml'
    path.write_text(contents)
    os.chown(path, 10001, 10001)
    path.chmod(0o400)
PY
    printf 'ARK_IMAGE=%s\nREDIS_IMAGE=%s\nCUBE_IP=%s\n' "$ARK_IMAGE" "$REDIS_IMAGE" "$CUBE_IP" > "$DEPLOY_DIR/.env"
}

stack_check() {
    compose ps
    compose ps --format json | python3 -c '
import json, sys
text = sys.stdin.read().strip()
rows = json.loads(text) if text.startswith("[") else [json.loads(line) for line in text.splitlines()]
expected = {"entrypoint", "worker-1", "worker-2", "worker-3", "redis"}
assert {row["Service"] for row in rows} == expected, "Missing or unexpected services"
assert all(row["State"] == "running" and row.get("Health") == "healthy" for row in rows), "Unhealthy services"
'
    local service id
    for service in entrypoint worker-1 worker-2 worker-3 redis; do
        id=$(compose ps -q "$service")
        docker inspect "$id" | python3 -c '
import json, sys
service = sys.argv[1]
item = json.load(sys.stdin)[0]
host = item["HostConfig"]
ports = host.get("PortBindings") or {}
assert host["RestartPolicy"]["Name"] == "unless-stopped"
assert not item["State"]["OOMKilled"]
assert host["LogConfig"]["Config"].get("max-size") == "10m"
if service.startswith("worker-"):
    assert host["NanoCpus"] == 2500000000, "Worker CPU quota missing"
if service != "entrypoint":
    assert not ports, "Internal port exposed"
else:
    assert set(ports) == {"8080/tcp"}
    assert {(p["HostIp"], p["HostPort"]) for p in ports["8080/tcp"]} == {("127.0.0.1", "8080"), ("10.20.0.11", "8080")}
print(service, "healthy; CPU quota:", host["NanoCpus"], "memory limit:", host["Memory"])
' "$service"
    done
    local ids=()
    mapfile -t ids < <(compose ps -q)
    docker stats --no-stream "${ids[@]}"
    python3 "$DEPLOY_DIR/smoke.py" --url http://127.0.0.1:8080 --key-file "$DEPLOY_DIR/public-api.key"
}

deploy() {
    [[ -f $STATE_DIR/network-boot-before ]] || die 'Run network first.'
    [[ $(cat "$STATE_DIR/network-boot-before") != "$(boot_id)" ]] || die 'Reboot after network setup before deploying.'
    network_check
    install_docker
    fetch_config
    # Authenticate beforehand with sudo docker login ghcr.io --password-stdin
    # if this package is private; anonymous pulls are preferred for public images.
    docker pull "$ARK_IMAGE"
    docker pull "$REDIS_IMAGE"
    [[ $(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$ARK_IMAGE") == 0.1.6 ]] || die 'Expected ARK 0.1.6.'
    [[ $(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$ARK_IMAGE") == "$RELEASE_COMMIT" ]] || die 'Image/config revision mismatch.'
    configure_secrets
    compose config --quiet
    compose up -d --no-build --wait --wait-timeout 600
    stack_check
    printf '%s\n' "$RELEASE_COMMIT" > "$STATE_DIR/deployed-commit"
    boot_id > "$STATE_DIR/deployment-boot-before"
    printf 'Local checks passed. Reboot Cube 1, then run verify. API key: %s/public-api.key (root-only).\n' "$DEPLOY_DIR"
}

verify() {
    [[ -f $STATE_DIR/deployment-boot-before ]] || die 'Deploy and pass local tests first.'
    [[ $(cat "$STATE_DIR/deployment-boot-before") != "$(boot_id)" ]] || die 'A second reboot is required after deployment.'
    network_check
    systemctl is-active --quiet docker
    # Wait for automatic restart/warmup; never repair or start containers here.
    local attempt
    for ((attempt=0; attempt<120; attempt++)); do
        if compose ps --format json | python3 -c '
import json, sys
s = sys.stdin.read().strip()
rows = json.loads(s) if s.startswith("[") else [json.loads(line) for line in s.splitlines()]
sys.exit(0 if len(rows) == 5 and all(r.get("Health") == "healthy" for r in rows) else 1)
'; then break; fi
        sleep 5
    done
    stack_check
    boot_id > "$STATE_DIR/verified-boot"
    printf 'Cube 1 reboot acceptance passed. Next: external NLB test, then independent security review.\n'
}

case "${1:-help}" in
    network) host_check; network_setup ;;
    deploy) host_check; deploy ;;
    verify) host_check; verify ;;
    help|--help|-h) printf 'Usage: sudo bash bootstrap.sh {network|deploy|verify}\nTwo reboots are mandatory: after network and after deploy. Phase 1: Cube 1 only.\n' ;;
    *) die 'Expected network, deploy, or verify.' ;;
esac
