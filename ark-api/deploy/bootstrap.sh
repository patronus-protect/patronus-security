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
ENTRYPOINT_KEY_FILE=
REDIS_URL_FILE=

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
boot_id() { cat /proc/sys/kernel/random/boot_id; }
compose() {
    local profiles=
    [[ $(redis_mode) != local ]] || profiles=local-redis
    COMPOSE_PROFILES=$profiles docker compose --project-directory "$DEPLOY_DIR" -f "$DEPLOY_DIR/compose.yaml" "$@"
}
redis_mode() { if [[ -f $DEPLOY_DIR/redis-mode ]]; then cat "$DEPLOY_DIR/redis-mode"; else printf 'local\n'; fi; }

validate_cube_ip() {
    [[ $CUBE_IP =~ ^10\.20\.0\.([0-9]{1,3})$ ]] || die 'Cube IP must be an IPv4 host in 10.20.0.0/24.'
    local octet=${BASH_REMATCH[1]}
    [[ $octet == "$((10#$octet))" ]] && (( 10#$octet >= 2 && 10#$octet <= 254 )) || die 'Cube IP must be a host address from .2 to .254, excluding the NAT gateway.'
}

host_check() {
    [[ $EUID == 0 ]] || die 'Run with sudo/root.'
    # shellcheck source=/dev/null
    . /etc/os-release
    [[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || die 'Requires Ubuntu 24.04.'
    [[ $(uname -m) == x86_64 ]] || die 'This release requires x86_64.'
    ip -4 -o address show dev "$NIC" | grep -Fq " $CUBE_IP/24 " || die "Expected $CUBE_IP/24 on $NIC; check --cube-ip and the provisioned private NIC."
    install -d -m 0700 "$STATE_DIR" "$DEPLOY_DIR"
    if [[ -f $STATE_DIR/cube-ip ]]; then
        [[ $(cat "$STATE_DIR/cube-ip") == "$CUBE_IP" ]] || die 'Cube IP differs from the saved bootstrap state.'
    else
        printf '%s\n' "$CUBE_IP" > "$STATE_DIR/cube-ip"
    fi
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
        printf 'Network configuration saved. Reboot %s, then run this script with deploy --cube-ip %s.\n' "$CUBE_IP" "$CUBE_IP"
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
    local compose_version
    compose_version=$(docker compose version --short)
    [[ $compose_version =~ ^v?([0-9]+)\.([0-9]+)\.([0-9]+) ]] || die 'Cannot determine Docker Compose version.'
    (( BASH_REMATCH[1] > 2 || (BASH_REMATCH[1] == 2 && BASH_REMATCH[2] >= 20) )) || die 'Docker Compose 2.20 or newer is required for optional local Redis.'
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
    for file in compose.yaml worker.template.yaml entrypoint.template.yaml smoke.py bootstrap_config.py; do
        curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --connect-timeout 10 --max-time 120 \
            "https://raw.githubusercontent.com/patronus-protect/patronus-security/$RELEASE_COMMIT/ark-api/deploy/$file" \
            -o "$staging/$file"
    done
    for file in compose.yaml worker.template.yaml entrypoint.template.yaml smoke.py bootstrap_config.py; do
        install -m 0600 "$staging/$file" "$DEPLOY_DIR/$file"
    done
    rm -r "$staging"
}

configure_secrets() {
    # Only paths pass through arguments; credential values stay in private files.
    local args=()
    [[ -z $ENTRYPOINT_KEY_FILE ]] || args+=(--entrypoint-key-file "$ENTRYPOINT_KEY_FILE")
    [[ -z $REDIS_URL_FILE ]] || args+=(--redis-url-file "$REDIS_URL_FILE")
    python3 "$DEPLOY_DIR/bootstrap_config.py" "$DEPLOY_DIR" "${args[@]}"
    local profiles=
    [[ $(redis_mode) != local ]] || profiles=local-redis
    printf 'ARK_IMAGE=%s\nREDIS_IMAGE=%s\nCUBE_IP=%s\nCOMPOSE_PROFILES=%s\n' "$ARK_IMAGE" "$REDIS_IMAGE" "$CUBE_IP" "$profiles" > "$DEPLOY_DIR/.env"
}

stack_check() {
    compose ps
    compose ps --format json | python3 -c '
import json, sys
text = sys.stdin.read().strip()
rows = json.loads(text) if text.startswith("[") else [json.loads(line) for line in text.splitlines()]
expected = {"entrypoint", "worker-1", "worker-2", "worker-3"}
if sys.argv[1] == "local": expected.add("redis")
assert {row["Service"] for row in rows} == expected, "Missing or unexpected services"
assert all(row["State"] == "running" and row.get("Health") == "healthy" for row in rows), "Unhealthy services"
' "$(redis_mode)"
    local service id
    local services=(entrypoint worker-1 worker-2 worker-3)
    [[ $(redis_mode) != local ]] || services+=(redis)
    for service in "${services[@]}"; do
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
    assert {(p["HostIp"], p["HostPort"]) for p in ports["8080/tcp"]} == {("127.0.0.1", "8080"), (sys.argv[2], "8080")}
print(service, "healthy; CPU quota:", host["NanoCpus"], "memory limit:", host["Memory"])
' "$service" "$CUBE_IP"
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
    [[ $(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$ARK_IMAGE") == 0.1.6 ]] || die 'Expected ARK 0.1.6.'
    [[ $(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$ARK_IMAGE") == "$RELEASE_COMMIT" ]] || die 'Image/config revision mismatch.'
    configure_secrets
    if [[ $(redis_mode) == local ]]; then docker pull "$REDIS_IMAGE"; fi
    compose config --quiet
    # Configuration files are replaced atomically. Existing bind mounts still see
    # their old inodes, so even a same-image deployment must recreate containers.
    compose up -d --no-build --force-recreate --wait --wait-timeout 600
    # Keep the previous local store until the new external-store entrypoint is ready.
    if [[ $(redis_mode) == external ]]; then
        compose --profile local-redis rm --stop --force redis
    fi
    stack_check
    printf '%s\n' "$RELEASE_COMMIT" > "$STATE_DIR/deployed-commit"
    boot_id > "$STATE_DIR/deployment-boot-before"
    printf 'Local checks passed. Reboot %s, then run verify --cube-ip %s. API key: %s/public-api.key (root-only).\n' "$CUBE_IP" "$CUBE_IP" "$DEPLOY_DIR"
}

verify() {
    [[ -f $STATE_DIR/deployment-boot-before ]] || die 'Deploy and pass local tests first.'
    [[ $(cat "$STATE_DIR/deployed-commit") == "$RELEASE_COMMIT" ]] || die 'Use the bootstrap release that matches the deployed image/config revision.'
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
expected = 5 if sys.argv[1] == "local" else 4
sys.exit(0 if len(rows) == expected and all(r.get("Health") == "healthy" for r in rows) else 1)
' "$(redis_mode)"; then break; fi
        sleep 5
    done
    stack_check
    boot_id > "$STATE_DIR/verified-boot"
    printf 'Cube %s reboot acceptance passed. Next: external ALB test, then independent security review.\n' "$CUBE_IP"
}

phase=${1:-help}
[[ $# == 0 ]] || shift
while [[ $# -gt 0 ]]; do
    case "$1" in
        --cube-ip|--entrypoint-key-file|--redis-url-file)
            [[ $# -ge 2 && -n $2 ]] || die "Missing value for $1."
            case "$1" in
                --cube-ip) CUBE_IP=$2 ;;
                --entrypoint-key-file) ENTRYPOINT_KEY_FILE=$2 ;;
                --redis-url-file) REDIS_URL_FILE=$2 ;;
            esac
            shift 2 ;;
        *) die "Unknown option: $1" ;;
    esac
done
case "$phase" in
    network) validate_cube_ip; host_check; network_setup ;;
    deploy) validate_cube_ip; host_check; deploy ;;
    verify) validate_cube_ip; host_check; verify ;;
    help|--help|-h) printf '%s\n' \
        'Usage: sudo bash bootstrap.sh {network|deploy|verify} [--cube-ip 10.20.0.11]' \
        'Deploy options: --entrypoint-key-file /root/shared.key --redis-url-file /root/redis.url' \
        'Key file: 64 lowercase hex characters. Redis URL: redis[s]://user:password@private-host:port/0.' \
        'Input files must be root-owned and readable only by root. Omitted inputs reuse saved configuration.' \
        'Two reboots are mandatory: after network and after deploy. NIC ens6, /24, gateway 10.20.0.1.' ;;
    *) die 'Expected network, deploy, or verify.' ;;
esac
