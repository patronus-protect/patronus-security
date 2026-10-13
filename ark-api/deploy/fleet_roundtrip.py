"""Journaled one-Cube scale-up and scale-down through IONOS and the Coordinator."""
import argparse
import base64
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlsplit
sys.path.insert(0, str(Path(__file__).resolve().parent))

import ionos_access as cloud

os.umask(0o077)
DIRECTORY = Path(__file__).resolve().parents[2] / '.private' / 'fleet-roundtrip'
JOURNAL = DIRECTORY / 'journal.json'
BASE = None
API = cloud.fleet.API
IMAGE = TEMPLATE = API_DIGEST = COORDINATOR_DIGEST = None
PRIVATE_LAN = PUBLIC_LAN = NAT_GATEWAY = None
CUBE_TARGET_GROUP = COORDINATOR_TARGET_GROUP = ALB_ID = None

def load():
    return json.loads(JOURNAL.read_text())

def save(state):
    DIRECTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = JOURNAL.with_suffix('.tmp')
    with tmp.open('w') as handle:
        json.dump(state, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    tmp.chmod(0o600)
    tmp.replace(JOURNAL)

def resolve_path(value):
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[2] / path
    return path.resolve()

def unique_named(items, name, label):
    matches = [item for item in items
               if item.get('properties', {}).get('name', item.get('name')) == name]
    if len(matches) != 1:
        raise ValueError(f'Expected exactly one {label} named {name}')
    return matches[0]

def discover_profile(profile):
    token_file = resolve_path(profile.get('token_file', '.private/ionos-api-token.txt'))
    api = cloud.fleet.Ionos(cloud.fleet.read_token(token_file))
    if not profile.get('datacenter_id'):
        dcs = api.get('/datacenters?depth=1&limit=100')['items']
        profile['datacenter_id'] = unique_named(
            dcs, profile.get('datacenter_name', 'ARK CPU Flotte'), 'data center')['id']
    dc = cloud.fleet.resource_id(profile['datacenter_id'])
    dc_path = '/datacenters/' + dc
    servers = api.inventory(dc)['servers']
    if not profile.get('coordinator_server_id'):
        row = unique_named(servers, profile.get('coordinator_name', 'ark-coordinator-01'), 'Coordinator')
        profile['coordinator_server_id'] = row['id']
    if not profile.get('runtime_source_server_id'):
        row = unique_named(servers, profile.get('runtime_source_name', 'api-1'), 'runtime source Cube')
        profile['runtime_source_server_id'] = row['id']
    source = api.get(dc_path + '/servers/' + cloud.fleet.resource_id(profile['runtime_source_server_id']) + '?depth=3')
    if not profile.get('template_id'):
        profile['template_id'] = source['properties']['templateUuid']
    if not profile.get('image_id'):
        volumes = source.get('entities', {}).get('volumes', {}).get('items', [])
        images = [item['properties'].get('image') for item in volumes
                  if item.get('properties', {}).get('image')]
        if len(images) != 1:
            raise ValueError('Could not uniquely discover the worker boot image')
        profile['image_id'] = images[0]
    if not profile.get('expected_current_cubes'):
        profile['expected_current_cubes'] = sum(row['type'] == 'CUBE' for row in servers)
    tgs = api.get('/targetgroups?depth=1&limit=100')['items']
    if not profile.get('cube_target_group_id'):
        profile['cube_target_group_id'] = unique_named(
            tgs, profile.get('cube_target_group_name', 'ark-cubes'), 'Cube target group')['id']
    if not profile.get('coordinator_target_group_id'):
        profile['coordinator_target_group_id'] = unique_named(
            tgs, profile.get('coordinator_target_group_name', 'ark-coordinator'), 'Coordinator target group')['id']
    if not profile.get('alb_id'):
        albs = api.get(dc_path + '/applicationloadbalancers?depth=1&limit=100')['items']
        profile['alb_id'] = unique_named(albs, profile.get('alb_name', 'ark-alb'), 'ALB')['id']
    if not profile.get('nat_gateway_id'):
        nats = api.get(dc_path + '/natgateways?depth=1&limit=100')['items']
        profile['nat_gateway_id'] = unique_named(
            nats, profile.get('nat_gateway_name', 'ark-nat'), 'NAT gateway')['id']
    profile['token_file'] = str(token_file)
    profile['datacenter_id'] = dc
    return profile

def discover_image_digest(server_id, service):
    repository = ('ghcr.io/patronus-protect/ark-coordinator'
                  if service == 'coordinator' else 'ghcr.io/patronus-protect/ark-api')
    code = ("import json,subprocess\nservice=" + repr(service) + "\nrepository=" + repr(repository) + "\n"
            "ids=subprocess.check_output(['docker','ps','-q'],text=True).split()\n"
            "rows=json.loads(subprocess.check_output(['docker','inspect',*ids],text=True))\n"
            "found=[row for row in rows if row['Config'].get('Labels',{}).get('com.docker.compose.service')==service]\n"
            "assert len(found)==1\nimage=found[0]['Config']['Image']\n"
            "if '@sha256:' not in image:\n"
            " metadata=json.loads(subprocess.check_output(['docker','image','inspect',found[0]['Image']],text=True))[0]\n"
            " matches=sorted({item for item in metadata.get('RepoDigests',[]) if item.startswith(repository+'@sha256:')})\n"
            " assert len(matches)==1\n image=matches[0]\n"
            "print(image)\n")
    result = cloud.remote(code, server_id).strip() if server_id else cloud.remote(code).strip()
    if not re.fullmatch(r'[^\s@]+@sha256:[0-9a-f]{64}', result):
        raise RuntimeError('Could not discover a digest-pinned image for ' + service)
    return result

def validate_profile(profile):
    required = ('datacenter_id', 'coordinator_server_id', 'runtime_source_server_id',
                'expected_current_cubes', 'private_lan_id', 'nat_gateway_id',
                'template_id', 'image_id', 'ssh_public_key_file', 'api_image_digest',
                'coordinator_image_digest', 'cube_target_group_id',
                'coordinator_target_group_id', 'alb_id', 'origin_hostname',
                'origin_ca_file', 'l3')
    missing = [key for key in required if key not in profile]
    if missing:
        raise ValueError('Profile is missing required fields: ' + ', '.join(missing))
    for key in ('datacenter_id', 'coordinator_server_id', 'runtime_source_server_id',
                'nat_gateway_id', 'template_id', 'image_id', 'cube_target_group_id',
                'coordinator_target_group_id', 'alb_id'):
        cloud.fleet.resource_id(profile[key])
    if type(profile['expected_current_cubes']) is not int or profile['expected_current_cubes'] < 1:
        raise ValueError('expected_current_cubes must be a positive integer')
    for key in ('private_lan_id', 'public_lan_id'):
        if key in profile and (type(profile[key]) is not int or profile[key] < 1):
            raise ValueError(key + ' must be a positive integer')
    digest = re.compile(r'^[^\s@]+@sha256:[0-9a-f]{64}$')
    for key in ('api_image_digest', 'coordinator_image_digest'):
        if not digest.fullmatch(profile[key]):
            raise ValueError(key + ' must be pinned by sha256 digest')
    if not re.fullmatch(r'[A-Za-z0-9.-]+', profile['origin_hostname']):
        raise ValueError('origin_hostname is invalid')
    profile['token_file'] = str(resolve_path(profile.get('token_file', '.private/ionos-api-token.txt')))
    for key in ('ssh_public_key_file', 'origin_ca_file'):
        profile[key] = str(resolve_path(profile[key]))
    l3 = profile['l3']
    for key in ('identity_file', 'known_hosts', 'host_key_alias'):
        if key not in l3:
            raise ValueError('l3 profile is missing ' + key)
    for key in ('identity_file', 'known_hosts'):
        l3[key] = str(resolve_path(l3[key]))
    for key in ('token_file', 'ssh_public_key_file', 'origin_ca_file',
                'l3.identity_file', 'l3.known_hosts'):
        value = profile
        for part in key.split('.'):
            value = value[part]
        path = Path(value)
        if not path.is_file():
            raise ValueError(key + ' file does not exist')
        info = path.stat()
        if key in ('token_file', 'l3.identity_file') and (
                info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError(key + ' must be user-owned and inaccessible to group or others')
    cloud.fleet.read_token(profile['token_file'])

def mutate(state, method, path, body=None):
    # Persist intent before the request. An uncertain mutation is never retried.
    record = {'method': method, 'path': path, 'started_at': time.time(), 'status': 'submitted'}
    state.setdefault('operations', []).append(record)
    save(state)
    api = cloud.api()
    headers = {'Authorization': 'Bearer ' + api.token, 'Accept': 'application/json'}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers['Content-Type'] = 'application/json'
    request = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    try:
        with api.opener.open(request, timeout=45) as response:
            payload = response.read()
            location = response.headers.get('Location')
            record.update(status='accepted', http_status=response.status, location=location)
            if response.status in (200, 201, 204) and not location:
                record['status'] = 'done'
                record['completed_at'] = time.time()
            result = json.loads(payload) if payload else None
            if method == 'POST' and path == BASE + '/servers':
                state['server_id'] = cloud.fleet.resource_id(result['id'])
            save(state)
            return result
    except urllib.error.HTTPError as exc:
        record.update(status='rejected', http_status=exc.code)
        try:
            details = json.loads(exc.read())
            record['validation_messages'] = [
                {k: message[k] for k in ('errorCode', 'message') if k in message}
                for message in details.get('messages', [])]
        except (ValueError, UnicodeError):
            record['validation_messages'] = []
        save(state)
        raise RuntimeError(f'Provider rejected {method}: HTTP {exc.code}; '
                           + json.dumps(record['validation_messages'])) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        record['status'] = 'uncertain'
        save(state)
        raise RuntimeError('Provider outcome uncertain; reconcile the journal before continuing') from None

def wait_operations(state, limit=600):
    for record in state.get('operations', []):
        if record['status'] == 'done':
            continue
        if record['status'] == 'rejected' and record.get('http_status') == 422:
            continue
        if record['status'] != 'accepted' or not record.get('location'):
            raise RuntimeError('An operation requires manual reconciliation')
        parsed = urlsplit(record['location'])
        if parsed.netloc and parsed.netloc != 'api.ionos.com':
            raise RuntimeError('Unexpected provider operation origin')
        path = parsed.path
        prefix = '/cloudapi/v6'
        if path.startswith(prefix):
            path = path[len(prefix):]
        if not path.startswith('/requests/'):
            raise RuntimeError('Unexpected provider operation path')
        if not path.endswith('/status'):
            path += '/status'
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            result = cloud.api().get(path)
            status = result.get('metadata', {}).get('status')
            if status == 'DONE':
                record['status'] = 'done'
                record['completed_at'] = time.time()
                save(state)
                break
            if status == 'FAILED':
                record['status'] = 'failed'
                save(state)
                raise RuntimeError('Provider operation failed; inspect provider request')
            time.sleep(3)
        else:
            raise RuntimeError('Provider operation remains pending; resume status, do not repeat the mutation')

def verify_test_server(state):
    sid = cloud.fleet.resource_id(state['server_id'])
    if sid in state['baseline_server_ids'] or sid == cloud.COORDINATOR:
        raise RuntimeError('Protected baseline identity')
    resource = cloud.server(sid)
    p = resource['properties']
    if p['name'] != state['name'] or p['type'] != 'CUBE' or p['templateUuid'] != TEMPLATE:
        raise RuntimeError('Test server identity mismatch')
    if cloud.address(resource, PRIVATE_LAN) != state['private_ip']:
        raise RuntimeError('Test server NIC mismatch')
    if resource.get('metadata', {}).get('state') != 'AVAILABLE':
        raise RuntimeError('Test server has a pending operation')
    return resource

def test_ssh_args(state):
    verify_test_server(state)
    public = cloud.address(cloud.server(cloud.COORDINATOR), PUBLIC_LAN)
    return ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'UserKnownHostsFile=' + str(DIRECTORY / 'known_hosts'),
            '-o', 'HostKeyAlias=' + state['server_id'], '-o', 'ConnectTimeout=10',
            '-J', 'root@' + public, 'root@' + state['private_ip']]

def test_remote(state, code, timeout=60):
    result = subprocess.run(test_ssh_args(state) + ['python3 -'], input=code,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('new Cube command failed: ' + result.stderr[-1500:])
    return result.stdout

def create():
    prior = load() if JOURNAL.exists() else None
    if prior and (prior.get('server_id') or any(
        operation.get('status') != 'rejected' or operation.get('http_status') != 422
        for operation in prior.get('operations', []))):
        raise RuntimeError('Journal requires reconciliation; creation cannot be repeated')
    api = cloud.api()
    inventory = api.inventory(cloud.DC)
    current_count = len([s for s in inventory['servers'] if s['type'] == 'CUBE'])
    if current_count != cloud.PROFILE['expected_current_cubes']:
        raise RuntimeError('Live fleet size differs from expected_current_cubes in the profile')
    if prior and any(s['name'] == prior['name'] for s in inventory['servers']):
        raise RuntimeError('Prior test name exists; reconcile its identity')
    occupied = {ip for s in inventory['servers'] for n in s['nics'] if n['lan'] == PRIVATE_LAN for ip in n['ips']}
    for group in api.get(BASE + '/applicationloadbalancers?depth=1')['items']:
        occupied.update(ip.split('/')[0] for ip in group['properties'].get('lbPrivateIps', []))
    nats = api.get(BASE + '/natgateways?depth=1')['items']
    gateways = [ip.split('/')[0] for n in nats for lan in n['properties'].get('lans', [])
                if lan['id'] == PRIVATE_LAN for ip in lan.get('gatewayIps', [])]
    if len(gateways) != 1:
        raise RuntimeError('Expected one shared NAT gateway')
    gateway = gateways[0]
    occupied.add(gateway)
    subnet = ipaddress.ip_network(gateway + '/24', strict=False)
    address = next(str(subnet.network_address + n) for n in range(23, 255)
                   if str(subnet.network_address + n) not in occupied)
    name = prior['name'] if prior else cloud.PROFILE.get('new_cube_name', 'ark-cube-' + uuid.uuid4().hex[:8])
    state = {'name': name, 'private_ip': address, 'gateway_ip': gateway,
             'baseline_server_ids': [s['id'] for s in inventory['servers']],
             'created_at': time.time(), 'phase': 'creating'}
    if prior:
        state['operations'] = prior.get('operations', [])
    for gid in (CUBE_TARGET_GROUP, COORDINATOR_TARGET_GROUP):
        state.setdefault('baseline_target_groups', {})[gid] = api.get('/targetgroups/' + gid)['properties']
    save(state)
    script = '''#!/bin/bash
set -eu
umask 077
nic=ens6
file=$(LC_ALL=C networkctl status "$nic" --no-pager --lines=0 | sed -n 's/^[[:space:]]*Network File: //p')
case "$file" in /run/systemd/network/*netplan*.network) ;; *) exit 1 ;; esac
mkdir -p "/etc/systemd/network/$(basename "$file").d"
cat > "/etc/systemd/network/$(basename "$file").d/60-patronus-nat.conf" <<'EOF'
[Network]
Gateway=__GATEWAY__
DNS=1.1.1.1
DNS=9.9.9.9
Domains=~.
[DHCPv4]
UseDNS=no
UseDomains=no
EOF
ip route replace default via __GATEWAY__ dev ens6
resolvectl dns ens6 1.1.1.1 9.9.9.9
resolvectl domain ens6 '~.'
'''.replace('__GATEWAY__', gateway)
    key = Path(cloud.PROFILE['ssh_public_key_file']).read_text().strip()
    body = {'properties': {'name': name, 'type': 'CUBE', 'templateUuid': TEMPLATE,
                           'availabilityZone': cloud.PROFILE.get('availability_zone', 'AUTO')}, 'entities': {
        'volumes': {'items': [{'properties': {'name': name + '-storage', 'type': 'DAS',
            'image': IMAGE, 'sshKeys': [key],
            'userData': base64.b64encode(script.encode()).decode()}}]},
        'nics': {'items': [{'properties': {'name': 'ark-backend-roundtrip', 'lan': PRIVATE_LAN,
                                        'ips': [address], 'dhcp': True}}]}}}
    mutate(state, 'POST', BASE + '/servers', body)
    print(json.dumps({'name': state['name'], 'server_id': state['server_id'],
                      'phase': 'provider_creation_submitted', 'journal': str(JOURNAL)}), flush=True)
    wait_operations(state)
    verify_test_server(state)
    state['phase'] = 'created'
    save(state)
    print('New Cube created; baseline server identities protected.', flush=True)

def status():
    state = load()
    wait_operations(state)
    resource = verify_test_server(state)
    print(json.dumps({'name': state['name'], 'server_id': state['server_id'],
                      'phase': state['phase'], 'vm_state': resource['properties']['vmState']}))
    print(test_remote(state, 'import subprocess,json\nprint(json.dumps({"hostname":subprocess.check_output(["hostname"],text=True).strip(),"cloud_init":subprocess.run(["cloud-init","status"],capture_output=True,text=True).stdout.strip(),"nat_route_present":bool(subprocess.check_output(["ip","-4","route","show","default"],text=True).strip())}))'))

def probe():
    data = cloud.api().get('/datacenters?depth=1&limit=100')
    print(json.dumps({'api_access': 'ok', 'datacenters': [
        {'id': item['id'], 'name': item['properties'].get('name')} for item in data['items']]}))

def plan_readonly(profile):
    api = cloud.fleet.Ionos(cloud.fleet.read_token(profile['token_file']))
    if profile.get('datacenter_id'):
        dc = cloud.fleet.resource_id(profile['datacenter_id'])
    else:
        dcs = api.get('/datacenters?depth=1&limit=100')['items']
        dc = cloud.fleet.resource_id(unique_named(
            dcs, profile.get('datacenter_name', 'ARK CPU Flotte'), 'data center')['id'])
    inventory = api.inventory(dc)
    cubes = [row for row in inventory['servers'] if row['type'] == 'CUBE']
    expected = profile.get('expected_current_cubes', len(cubes))
    if type(expected) is not int or expected < 1:
        raise ValueError('expected_current_cubes must be a positive integer')
    if len(cubes) != expected:
        raise RuntimeError('Live Cube count differs from expected_current_cubes')
    state = load() if JOURNAL.exists() else None
    actions = (['resume ' + str(state.get('phase'))] if state and
               state.get('phase') not in ('deleted', 'deleted_unregistered') else
               ['create one Cube', 'install and verify three workers and private L3',
                'verify replacement Coordinator', 'handover ALB traffic'])
    print(json.dumps({'read_only': True, 'current_cubes': len(cubes),
                      'expected_current_cubes': expected,
                      'managed_cube': state.get('server_id') if state else None,
                      'phase': state.get('phase') if state else 'not_started',
                      'next_actions': actions,
                      'scale_down': 'drain, verify retained result after deletion, restore baseline'}, indent=2))

def preflight():
    api = cloud.api()
    inventory = api.inventory(cloud.DC)
    if len([row for row in inventory['servers'] if row['type'] == 'CUBE']) != cloud.PROFILE['expected_current_cubes']:
        raise RuntimeError('Live Cube count differs from expected_current_cubes')
    source = cloud.server(cloud.CUBE)
    coord = cloud.server(cloud.COORDINATOR)
    if source['properties'].get('vmState') != 'RUNNING' or source.get('metadata', {}).get('state') != 'AVAILABLE':
        raise RuntimeError('Runtime source Cube must be running and available')
    if coord['properties'].get('vmState') != 'RUNNING' or coord.get('metadata', {}).get('state') != 'AVAILABLE':
        raise RuntimeError('Coordinator must be running and available')
    worker_groups = [item for item in source.get('entities', {}).get('securitygroups', {}).get('items', [])
                     if item.get('properties', {}).get('name') == 'ark-workers']
    if len(worker_groups) != 1:
        raise RuntimeError('Runtime source must have exactly one ark-workers security group')
    for identifier in (CUBE_TARGET_GROUP, COORDINATOR_TARGET_GROUP):
        api.get('/targetgroups/' + identifier)
    api.get(BASE + '/applicationloadbalancers/' + ALB_ID)
    nat = api.get(BASE + '/natgateways/' + NAT_GATEWAY)
    if not any(item.get('id') == PRIVATE_LAN for item in nat['properties'].get('lans', [])):
        raise RuntimeError('Configured NAT gateway is not attached to the private worker LAN')
    coordinator_config = cloud.remote(
        'import yaml,pathlib; print(len(yaml.safe_load(pathlib.Path("/opt/patronus/ark-coordinator/config.yaml").read_text())["gateway"]["cubes"]))')
    if int(coordinator_config.strip()) != cloud.PROFILE['expected_current_cubes']:
        raise RuntimeError('Coordinator origins count differs from expected_current_cubes')
    endpoint = cloud.remote(
        'import subprocess; print(subprocess.check_output(["wg","show","wg-ark","endpoints"],text=True).split()[1])',
        cloud.CUBE).strip()
    if ':' not in endpoint:
        raise RuntimeError('Runtime source has no configured GPU WireGuard endpoint')
    cloud.gpu_remote('import subprocess; subprocess.check_output(["wg","show","wg-ark","peers"],text=True)')
    print('Preflight passed: IONOS, SSH-through-Coordinator, worker group, NAT, ALB, Coordinator and GPU peer are reachable.')

def attach_workers_group():
    state = load()
    verify_test_server(state)
    api = cloud.api()
    reference = cloud.server(cloud.CUBE)
    groups = reference['entities']['securitygroups']['items']
    workers = [group for group in groups if group['properties']['name'] == 'ark-workers']
    if len(workers) != 1:
        raise RuntimeError('Existing Cube must have one verified ark-workers group')
    gid = cloud.fleet.resource_id(workers[0]['id'])
    group = api.get(BASE + '/securitygroups/' + gid)
    if group['properties']['name'] != 'ark-workers' or group['metadata']['state'] != 'AVAILABLE':
        raise RuntimeError('Worker security group identity or operation mismatch')
    rules = api.get(BASE + '/securitygroups/' + gid + '/rules?depth=1')['items']
    print(json.dumps({'worker_security_group': gid, 'rules': [
        {k: item['properties'].get(k) for k in ('name', 'protocol', 'portRangeStart', 'portRangeEnd', 'type')}
        for item in rules]}), flush=True)
    current = cloud.server(state['server_id'])['entities']['securitygroups']['items']
    state['initial_security_group_ids'] = state.get('initial_security_group_ids', [item['id'] for item in current])
    save(state)
    if {item['id'] for item in current} != {gid}:
        mutate(state, 'PUT', BASE + '/servers/' + state['server_id'] + '/securitygroups', {'ids': [gid]})
        wait_operations(state)
    actual = cloud.server(state['server_id'])['entities']['securitygroups']['items']
    if {item['id'] for item in actual} != {gid}:
        raise RuntimeError('Worker security group attachment not confirmed')
    state['security_group_ids'] = [gid]
    save(state)
    print('new Cube now has the verified existing ark-workers security group.', flush=True)

def install():
    state = load()
    wait_operations(state)
    verify_test_server(state)
    state['phase'] = 'installing'
    save(state)
    script = '''set -euo pipefail
umask 077
exec > /root/ark-roundtrip-install.log 2>&1
. /etc/os-release
test "$ID" = ubuntu && test "$VERSION_ID" = 24.04
test "$(uname -m)" = x86_64
python3 - <<'PYCI'
import json, subprocess
result = subprocess.run(['cloud-init', 'status', '--wait', '--format', 'json'], capture_output=True, text=True)
status = json.loads(result.stdout)
assert status['status'] == 'done' and not status.get('errors'), 'Fatal cloud-init bootstrap error'
assert result.returncode in (0, 2), 'Unexpected cloud-init status'
assert not set(status.get('recoverable_errors', {})) - {'DEPRECATED'}, 'Inspect non-deprecation bootstrap warnings'
PYCI
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl python3-yaml wireguard-tools
if ! command -v docker >/dev/null; then
  install -d -m 0755 /etc/apt/keyrings
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod 0644 /etc/apt/keyrings/docker.asc
  printf '%s\\n' 'Types: deb' 'URIs: https://download.docker.com/linux/ubuntu' 'Suites: noble' 'Components: stable' 'Architectures: amd64' 'Signed-By: /etc/apt/keyrings/docker.asc' > /etc/apt/sources.list.d/docker.sources
  chmod 0644 /etc/apt/sources.list.d/docker.sources
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker
docker compose version
install -d -m 0700 /opt/patronus/ark-api /etc/wireguard /var/lib/patronus-cube
'''
    print('Installing Docker and WireGuard on the new Cube only.', flush=True)
    result = subprocess.run(test_ssh_args(state) + ['bash -s'], input=script,
                            capture_output=True, text=True, timeout=900)
    if result.returncode:
        raise RuntimeError('Installation failed; inspect /root/ark-roundtrip-install.log on the new Cube')
    state['phase'] = 'installed'
    save(state)
    print('new Cube Docker and WireGuard installation complete.', flush=True)

def copy_runtime(state):
    paths = ['opt/patronus/ark-api/' + filename for filename in (
        'compose.yaml', 'compose.override.yaml', '.env', 'entrypoint.yaml', 'worker.yaml',
        'public-api.key', 'public-api.keys', 'worker.key', 'redis.url', 'redis-mode', 'smoke.py')]
    paths += ['etc/systemd/system/ark-l3-network.service', 'usr/local/sbin/ark-l3-network']
    source = subprocess.Popen(cloud.ssh_args(cloud.CUBE) + ['tar -C / -cpf - ' + ' '.join(paths)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        target = subprocess.run(test_ssh_args(state) + ['tar -C / -xpf -'], stdin=source.stdout,
                                capture_output=True, timeout=90)
        source.stdout.close()
        source.wait(timeout=10)
        if source.returncode or target.returncode:
            raise RuntimeError('Private runtime transfer failed; no credential contents were emitted')
    finally:
        if source.poll() is None:
            source.terminate()

def network():
    state = load()
    verify_test_server(state)
    if state['phase'] not in ('installed', 'network_preparing'):
        raise RuntimeError('Install the new Cube first')
    state['phase'] = 'network_preparing'
    save(state)
    copy_runtime(state)
    # Transfer the peer configuration without the source host's private key.
    template = cloud.remote('import pathlib\nprint("\\n".join(line for line in pathlib.Path("/etc/wireguard/wg-ark.conf").read_text().splitlines() if not line.strip().startswith(("PrivateKey", "Address"))))', cloud.CUBE)
    config_data = json.loads(cloud.gpu_remote('''import pathlib,json
text=pathlib.Path("/etc/wireguard/wg-ark.conf").read_text()
print(json.dumps({"address":next(l.split("=",1)[1].strip() for l in text.splitlines() if l.strip().startswith("Address")),"used":[l.split("=",1)[1].strip() for l in text.splitlines() if l.strip().startswith("AllowedIPs")]}))
'''))
    subnet = ipaddress.ip_network(config_data['address'], strict=False)
    occupied = {ipaddress.ip_interface(config_data['address']).ip}
    for entry in config_data['used']:
        for part in entry.split(','):
            occupied.update(ipaddress.ip_network(part.strip(), strict=False))
    state['vpn_address'] = state.get('vpn_address') or next(
        str(subnet.network_address + n) for n in range(23, 255)
        if subnet.network_address + n not in occupied)
    save(state)
    params = {'template': template, 'vpn_address': state['vpn_address'],
              'private_ip': state['private_ip'], 'image': API_DIGEST}
    code = 'params=' + repr(params) + '\n' + '''import pathlib,subprocess,os,yaml,json
p=pathlib.Path("/opt/patronus/ark-api")
env=p/".env";lines=env.read_text().splitlines();env.write_text("\\n".join("CUBE_IP="+params["private_ip"] if line.startswith("CUBE_IP=") else line for line in lines)+"\\n");env.chmod(0o600)
config=yaml.safe_load(subprocess.check_output(["docker","compose","--project-directory",str(p),"config"],text=True))
assert set(config["services"])=={"entrypoint","worker-1","worker-2","worker-3"}
assert (p/"redis-mode").read_text().strip()=="external"
config["services"]["entrypoint"].get("depends_on",{}).pop("redis",None)
config["services"]["entrypoint"]["ports"]=[{"target":8080,"published":"8080","host_ip":ip,"protocol":"tcp"} for ip in (params["private_ip"],"127.0.0.1")]
for service in config["services"].values():service["image"]=params["image"]
(p/"compose.yaml").write_text(yaml.safe_dump(config,sort_keys=False));(p/"compose.yaml").chmod(0o600)
(p/"compose.override.yaml").rename(p/"compose.override.source.yaml")
key=pathlib.Path("/etc/wireguard/ark-private.key")
if not key.exists():key.write_text(subprocess.check_output(["wg","genkey"],text=True).strip()+"\\n");key.chmod(0o600)
public=subprocess.check_output(["wg","pubkey"],input=key.read_text(),text=True).strip()
template=params["template"];assert template.count("[Interface]")==1 and template.count("[Peer]")==1
config=template.replace("[Interface]","[Interface]\\nPrivateKey = "+key.read_text().strip()+"\\nAddress = "+params["vpn_address"]+"/32",1)
wg=pathlib.Path("/etc/wireguard/wg-ark.conf");wg.write_text(config);wg.chmod(0o600)
pathlib.Path("/etc/wireguard/ark-public.key").write_text(public+"\\n")
print(json.dumps({"public_key":public}))
'''
    state['peer_public_key'] = json.loads(test_remote(state, code))['public_key']
    state['peer_add_in_progress'] = True
    save(state)
    params = {'public_key': state['peer_public_key'], 'address': state['vpn_address'],
              'name': state['name'], 'expected_peers': cloud.PROFILE['expected_current_cubes']}
    code = 'params=' + repr(params) + '\n' + '''import pathlib,subprocess,os,json
p=pathlib.Path("/etc/wireguard/wg-ark.conf");text=p.read_text();blocks=text.split("[Peer]")
matching=[b for b in blocks[1:] if any(line.strip()=="PublicKey = "+params["public_key"] for line in b.splitlines())]
if matching:
 assert len(matching)==1 and any(line.strip()=="AllowedIPs = "+params["address"]+"/32" for line in matching[0].splitlines())
else:
 assert len(blocks)-1==params["expected_peers"]
 assert not any(params["address"]+"/32" in line for line in text.splitlines() if line.strip().startswith("AllowedIPs"))
 backup=p.with_name(p.name+".before-"+params["name"])
 if not backup.exists():backup.write_text(text);backup.chmod(0o600)
 text=text.rstrip()+"\\n\\n# "+params["name"]+"\\n[Peer]\\nPublicKey = "+params["public_key"]+"\\nAllowedIPs = "+params["address"]+"/32\\n"
 temp=p.with_name(".wg-ark-roundtrip.tmp");temp.write_text(text);temp.chmod(0o600);temp.replace(p)
subprocess.run(["wg","set","wg-ark","peer",params["public_key"],"allowed-ips",params["address"]+"/32"],check=True)
assert params["public_key"] in subprocess.check_output(["wg","show","wg-ark","peers"],text=True).splitlines()
print("One unique test peer added; existing peers retained.")
'''
    print(cloud.gpu_remote(code), flush=True)
    state['peer_added'] = True
    state['peer_add_in_progress'] = False
    save(state)
    print(test_remote(state, '''import subprocess
import sys
subprocess.run(["systemctl","daemon-reload"],check=True)
subprocess.run(["systemctl","enable","--now","wg-quick@wg-ark"],check=True)
subprocess.run(["systemctl","enable","--now","ark-l3-network.service"],check=True)
print("Private WireGuard and restricted worker egress enabled.")
'''), flush=True)
    state['phase'] = 'network_ready'
    save(state)

def start():
    state = load()
    if state['phase'] not in ('network_ready', 'starting'):
        raise RuntimeError('Prepare private L3 networking first')
    state['phase'] = 'starting'
    save(state)

    params = {'image': API_DIGEST, 'private_ip': state['private_ip']}
    code = 'params=' + repr(params) + '\n' + '''import subprocess,pathlib,json,yaml
p=pathlib.Path("/opt/patronus/ark-api")
config=yaml.safe_load((p/"compose.yaml").read_text())
assert (p/"redis-mode").read_text().strip()=="external"
config["services"]["entrypoint"].get("depends_on",{}).pop("redis",None)
config["services"]["entrypoint"]["ports"]=[{"target":8080,"published":"8080","host_ip":ip,"protocol":"tcp"} for ip in (params["private_ip"],"127.0.0.1")]
(p/"compose.yaml").write_text(yaml.safe_dump(config,sort_keys=False));(p/"compose.yaml").chmod(0o600)
log=pathlib.Path("/root/ark-roundtrip-start.log")
with log.open("w") as output:
 subprocess.run(["docker","pull",params["image"]],stdout=output,stderr=subprocess.STDOUT,check=True)
 subprocess.run(["docker","compose","--project-directory",str(p),"-f",str(p/"compose.yaml"),"up","-d","--wait","--wait-timeout","600"],stdout=output,stderr=subprocess.STDOUT,check=True)
print(subprocess.check_output(["docker","ps","--format","{{.Names}} {{.Status}}"],text=True))
'''
    print('Starting three workers and entrypoint with the verified live image digest.', flush=True)
    print(test_remote(state, code, timeout=900), flush=True)
    state['phase'] = 'running'
    save(state)

def setup():
    state = load()
    if state['phase'] in ('created', 'installing'):
        install()
    state = load()
    if state['phase'] in ('installed', 'network_preparing'):
        network()
    state = load()
    if state['phase'] in ('network_ready', 'starting'):
        start()
    if load()['phase'] != 'running':
        raise RuntimeError('Setup did not reach running state')

def canary():
    state = load()
    if state['phase'] not in ('running', 'verified', 'registered'):
        raise RuntimeError('Workers must be running before verification')
    code = '''import json, pathlib, subprocess, urllib.request, urllib.error, time, math, random
p=pathlib.Path("/opt/patronus/ark-api")
ids=subprocess.check_output(["docker","compose","--project-directory",str(p),"-f",str(p/"compose.yaml"),"ps","-q"],text=True).split()
containers=json.loads(subprocess.check_output(["docker","inspect",*ids],text=True))
assert len(containers)==4 and all(c["State"].get("Health",{}).get("Status")=="healthy" for c in containers)
worker=next(c for c in containers if c["Config"].get("Labels",{}).get("com.docker.compose.service")=="worker-1")
env=dict(item.split("=",1) for item in worker["Config"]["Env"] if "=" in item)
origin=env["PATRONUS_UNIFIED_TRITON_URL"].rstrip("/")
model="lion_warden_30ea449339d1075a31fcffa9199ebee4f2cfaf9a_fp16_256"
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def req(origin,path,data=None,token=None,content_type="application/json"):
 headers={"Content-Type":content_type}
 if token:headers["Authorization"]="Bearer "+token
 try:
  with opener.open(urllib.request.Request(origin+path,data=data,headers=headers),timeout=30) as r:return r.status,r.read()
 except urllib.error.HTTPError as e:return e.code,e.read()
status,raw=req(origin,"/v2/models/"+model);assert status==200
meta=json.loads(raw);assert len(meta["outputs"])==7 and len(meta["inputs"])==2
inputs=[{"name":item["name"],"datatype":"INT64","shape":[1,256],"data":[1]*256 if "mask" in item["name"] else [random.randint(100,10000) for _ in range(256)]} for item in meta["inputs"]]
status,raw=req(origin,"/v2/models/"+model+"/versions/1/infer",json.dumps({"inputs":inputs,"outputs":[{"name":o["name"]} for o in meta["outputs"]]}).encode());assert status==200
outputs=json.loads(raw)["outputs"];assert len(outputs)==7
assert {x["name"] for x in outputs}=={x["name"] for x in meta["outputs"]}
assert all(len(x["data"])==math.prod(x["shape"]) and all(math.isfinite(v) for v in x["data"]) for x in outputs)
blocked=subprocess.run(["docker","exec",worker["Id"],"wget","-q","-T","3","-O","/dev/null","http://1.1.1.1"],capture_output=True)
assert blocked.returncode!=0,"Worker egress is not restricted"
token=(p/"public-api.key").read_text().strip()
base="http://127.0.0.1:8080"
report={"containers":4,"workers":3,"triton_heads":7,"fresh_inference":"finite","restricted_egress":True,"scans":[]}
for mode,overlap in (("sync",0),("async",64)):
 boundary="ark-roundtrip-"+mode
 config={"categories":["injection"],"max_level":"L3","gates":{"l1":False,"l2":False,"l3":True},"chunk_overlap_tokens":overlap}
 body=("--"+boundary+'\\r\\nContent-Disposition: form-data; name="config"\\r\\n\\r\\n'+json.dumps(config)+"\\r\\n--"+boundary+'\\r\\nContent-Disposition: form-data; name="text"\\r\\n\\r\\n'+("This is an ordinary integration test document. "*40)+"\\r\\n--"+boundary+"--\\r\\n").encode()
 path="/v1/scan/sync" if mode=="sync" else "/v1/scan"
 content="multipart/form-data; boundary="+boundary
 unauth,_=req(base,path,body,content_type=content);assert unauth==401
 status,raw=req(base,path,body,token,content);assert status==(200 if mode=="sync" else 202),(mode,status)
 payload=json.loads(raw)
 if mode=="async":
  jobs=payload["jobs"];assert len(jobs)==1;job_path=jobs[0]["status_url"]
  deadline=time.monotonic()+90
  while time.monotonic()<deadline:
   status,raw=req(base,job_path,token=token);assert status==200;result=json.loads(raw)
   if result.get("status") in ("completed","failed"):break
   time.sleep(.1)
  else:raise AssertionError("Scan timed out")
 else:
  results=payload.get("jobs",payload.get("results")) if isinstance(payload,dict) else payload
  if results is None:results=[payload]
  assert len(results)==1;result=results[0]
 assert result.get("completion",{}).get("state")=="complete",(mode,result.get("completion"))
 if mode=="async":assert result.get("status")=="completed",result.get("status")
 report["scans"].append({"mode":mode,"overlap_tokens":overlap,"status":"completed","completion":"complete"})
print(json.dumps(report))
'''
    report = json.loads(test_remote(state, code, timeout=180))
    state['canary'] = report
    if state['phase'] == 'running':
        state['phase'] = 'verified'
    save(state)
    print(json.dumps(report), flush=True)

def coordinator_probe(state, port=8091, text_size=180000):
    params = {'port': port, 'size': text_size}
    code = 'params=' + repr(params) + '\n' + '''import urllib.request,json,time,pathlib
token=pathlib.Path("/root/ark-coordinator-secrets/origin.key").read_text().strip()
base="http://127.0.0.1:"+str(params["port"])
boundary="ark-fleet-roundtrip"
config={"categories":["injection"],"max_level":"L3","gates":{"l1":False,"l2":False,"l3":True}}
text=("An ordinary fleet integration document. "*((params["size"]//39)+1))[:params["size"]]
body=("--"+boundary+'\\r\\nContent-Disposition: form-data; name="config"\\r\\n\\r\\n'+json.dumps(config)+"\\r\\n--"+boundary+'\\r\\nContent-Disposition: form-data; name="text"\\r\\n\\r\\n'+text+"\\r\\n--"+boundary+"--\\r\\n").encode()
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
headers={"Authorization":"Bearer "+token,"Content-Type":"multipart/form-data; boundary="+boundary}
with opener.open(urllib.request.Request(base+"/v1/scan",data=body,headers=headers),timeout=30) as r:
 assert r.status==202;job=json.load(r)["jobs"][0]
deadline=time.monotonic()+120
while time.monotonic()<deadline:
 with opener.open(urllib.request.Request(base+job["status_url"],headers={"Authorization":"Bearer "+token}),timeout=10) as r:result=json.load(r)
 if result.get("status") in ("completed","failed"):break
 time.sleep(.1)
else:raise AssertionError("Coordinator scan timed out")
assert result["status"]=="completed" and result["completion"]["state"]=="complete"
print(json.dumps({"status_url":job["status_url"],"status":"completed","completion":"complete","port":params["port"]}))
'''
    return json.loads(cloud.remote(code, timeout=150))

def retained_result(state, port=8090):
    status_url = state['post_registration_canary']['status_url']
    params = {'port': port, 'status_url': status_url}
    code = 'params=' + repr(params) + '\n' + '''import json,pathlib,urllib.request
token=pathlib.Path("/root/ark-coordinator-secrets/origin.key").read_text().strip()
url="http://127.0.0.1:"+str(params["port"])+params["status_url"]
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(urllib.request.Request(url,headers={"Authorization":"Bearer "+token}),timeout=15) as r:result=json.load(r)
assert result.get("status")=="completed" and result.get("completion",{}).get("state")=="complete",result
print(json.dumps({"status":"completed","completion":"complete"}))
'''
    return json.loads(cloud.remote(code, timeout=30))

def https_alb_probe():
    profile = cloud.PROFILE
    hostname = profile['origin_hostname']
    ca = Path(profile['origin_ca_file']).read_bytes()
    alb = cloud.api().get(BASE + '/applicationloadbalancers/' + ALB_ID)
    # IONOS ALB inventory exposes assigned public addresses as `ips`; older
    # resource shapes used `lbPublicIps`.
    public_ips = alb['properties'].get('lbPublicIps') or alb['properties'].get('ips', [])
    ips = [str(ipaddress.IPv4Address(value.split('/')[0])) for value in public_ips]
    if not ips:
        raise RuntimeError('ALB has no public listener address to probe')
    # Origin CA is public certificate material; it is streamed over SSH and
    # removed immediately after curl verifies TLS and the live ALB route.
    params = {'hostname': hostname, 'ip': ips[0],
              'ca': base64.b64encode(ca).decode()}
    code = 'params=' + repr(params) + '\n' + '''import base64,os,pathlib,subprocess,tempfile
fd,path=tempfile.mkstemp(prefix='ark-origin-ca-')
try:
 os.write(fd,base64.b64decode(params['ca']));os.close(fd)
 result=subprocess.run(['curl','--fail','--silent','--show-error','--max-time','15',
  '--cacert',path,'--resolve',params['hostname']+':443:'+params['ip'],
  '-H','x-ark-backend: coordinator','-H','x-patronus-ark-backend: coordinator',
  'https://'+params['hostname']+'/readyz'],capture_output=True,text=True)
 if result.returncode: raise SystemExit('Verified HTTPS ALB probe failed')
 print(result.stdout)
finally:
 try:os.unlink(path)
 except FileNotFoundError:pass
'''
    return cloud.remote(code, timeout=30).strip()

def drain_cube(state, timeout=600):
    params = {'timeout': timeout}
    code = 'params=' + repr(params) + '\n' + '''import json,pathlib,subprocess,time,urllib.request,yaml
p=pathlib.Path('/opt/patronus/ark-api');c=yaml.safe_load((p/'entrypoint.yaml').read_text())
token=c['gateway']['worker_token'];deadline=time.monotonic()+params['timeout'];zero_since=None
while time.monotonic()<deadline:
 ids=subprocess.check_output(['docker','ps','-q'],text=True).split()
 rows=json.loads(subprocess.check_output(['docker','inspect',*ids],text=True))
 workers=[row for row in rows if row['Config'].get('Labels',{}).get('com.docker.compose.service','').startswith('worker-')]
 assert len(workers)==3
 counts=[]
 for row in workers:
  addrs=[v['IPAddress'] for v in row['NetworkSettings']['Networks'].values() if v.get('IPAddress')]
  data=None
  for address in addrs:
   try:
    req=urllib.request.Request('http://'+address+':8080/internal/status',headers={'Authorization':'Bearer '+token})
    with urllib.request.urlopen(req,timeout=4) as r:data=json.load(r)
    break
   except OSError:pass
  assert data is not None,'could not inspect worker activity'
  counts.append(data)
 if all(item.get('active_jobs')==0 and item.get('active_submissions')==0 for item in counts):
  zero_since=zero_since or time.monotonic()
  if time.monotonic()-zero_since>=5:
   print(json.dumps({'workers':len(counts),'active_jobs':0,'active_submissions':0}));break
 else:zero_since=None
 time.sleep(1)
else:raise SystemExit('Cube did not drain before timeout')
'''
    result = json.loads(cloud.remote(code, state['server_id'], timeout + 30))
    state['drain'] = result
    save(state)
    return result

def scale_down():
    state = load()
    phases = {'registered', 'direct_dispatch_stopped', 'coordinator_dispatch_stopped',
              'coordinator_drained', 'cube_target_removed', 'routing_restored',
              'peer_removed', 'coordinator_cleaned', 'deleting'}
    if state.get('phase') not in phases or not state.get('registered'):
        raise RuntimeError('No registered Cube is ready for scale-down or journal recovery')
    wait_operations(state)
    api = cloud.api()
    cube_group, coordinator_group = CUBE_TARGET_GROUP, COORDINATOR_TARGET_GROUP

    def patch_targets(group_id, expected, desired):
        current = api.get('/targetgroups/' + group_id)['properties']['targets']
        if current == desired:
            return
        if current != expected:
            raise RuntimeError('Target group changed concurrently; refusing to overwrite it')
        mutate(state, 'PATCH', '/targetgroups/' + group_id, {'targets': desired})
        wait_operations(state)

    if state['phase'] == 'registered':
        current = state['registered_cube_targets']
        matches = [item for item in current if item.get('ip') == state['private_ip']]
        if len(matches) != 1:
            raise RuntimeError('Registered Cube target is missing or ambiguous')
        desired = [dict(item, maintenanceEnabled=True) if item.get('ip') == state['private_ip'] else item
                   for item in current]
        patch_targets(cube_group, current, desired)
        state['direct_dispatch_targets'] = desired
        state['phase'] = 'direct_dispatch_stopped'
        save(state)

    if state['phase'] == 'direct_dispatch_stopped':
        current = state['registered_coordinator_targets']
        original = [item for item in current if item.get('port') == 8090]
        sidecar = [item for item in current if item.get('port') == 8091]
        if len(original) != 1 or len(sidecar) != 1:
            raise RuntimeError('Expected one original and one replacement Coordinator target')
        desired = [dict(original[0], maintenanceEnabled=False)] + [
            dict(item, maintenanceEnabled=True) for item in sidecar]
        patch_targets(coordinator_group, current, desired)
        state['coordinator_dispatch_targets'] = desired
        state['phase'] = 'coordinator_dispatch_stopped'
        save(state)

    if state['phase'] == 'coordinator_dispatch_stopped':
        stop = 'import subprocess; name=' + repr(state['sidecar_name']) + '; found=subprocess.run(["docker","inspect",name],capture_output=True,text=True); running=found.returncode==0 and __import__("json").loads(found.stdout)[0]["State"]["Running"]; subprocess.run(["docker","stop","--time","310",name],check=True,stdout=subprocess.DEVNULL) if running else None'
        cloud.remote(stop, timeout=330)
        state['sidecar_stopped'] = True
        state['phase'] = 'coordinator_drained'
        save(state)

    if state['phase'] == 'coordinator_drained':
        if 'retained_result_before_delete' not in state:
            state['retained_result_before_delete'] = retained_result(state)
            save(state)
        if 'drain' not in state:
            state['drain'] = drain_cube(state)
        baseline = state['baseline_target_groups'][cube_group]['targets']
        patch_targets(cube_group, state['direct_dispatch_targets'], baseline)
        state['phase'] = 'cube_target_removed'
        save(state)

    if state['phase'] == 'cube_target_removed':
        baseline = state['baseline_target_groups'][coordinator_group]['targets']
        patch_targets(coordinator_group, state['coordinator_dispatch_targets'], baseline)
        state['alb_route_restored'] = https_alb_probe()
        state['phase'] = 'routing_restored'
        save(state)

    if state['phase'] == 'routing_restored':
        peer, address = state['peer_public_key'], state['vpn_address']
        code = f'''import pathlib,subprocess
p=pathlib.Path('/etc/wireguard/wg-ark.conf');text=p.read_text();blocks=text.split('[Peer]')
matches=[b for b in blocks[1:] if any(x.strip()=='PublicKey = {peer}' for x in b.splitlines())]
if matches:
 assert len(matches)==1 and any(x.strip()=='AllowedIPs = {address}/32' for x in matches[0].splitlines())
 new=blocks[0]+'[Peer]'.join(b for b in blocks[1:] if b not in matches)
 tmp=p.with_name('.wg-ark-fleet-remove.tmp');tmp.write_text(new.rstrip()+'\\n');tmp.chmod(0o600);tmp.replace(p)
peers=subprocess.check_output(['wg','show','wg-ark','peers'],text=True).splitlines()
if '{peer}' in peers: subprocess.run(['wg','set','wg-ark','peer','{peer}','remove'],check=True)
assert '{peer}' not in subprocess.check_output(['wg','show','wg-ark','peers'],text=True).splitlines()
assert '{address}/32' not in p.read_text()
'''
        cloud.gpu_remote(code)
        state['peer_removed'] = True
        state['phase'] = 'peer_removed'
        save(state)

    if state['phase'] == 'peer_removed':
        coord = cloud.server(cloud.COORDINATOR)
        current_groups = {item['id'] for item in coord['entities']['securitygroups']['items']}
        original = set(state['coordinator_original_groups'])
        extra = state['extra_group_id']
        if current_groups == original | {extra}:
            mutate(state, 'PUT', BASE + '/servers/' + cloud.COORDINATOR + '/securitygroups',
                   {'ids': state['coordinator_original_groups']})
            wait_operations(state)
        elif current_groups != original:
            raise RuntimeError('Coordinator security groups changed; refusing to overwrite them')
        try:
            api.get(BASE + '/securitygroups/' + extra)
        except RuntimeError as error:
            if 'HTTP 404' not in str(error):
                raise
        else:
            mutate(state, 'DELETE', BASE + '/securitygroups/' + extra)
            wait_operations(state)
        cleanup = 'import pathlib,subprocess; name=' + repr(state['sidecar_name']) + '; found=subprocess.run(["docker","inspect",name],capture_output=True); subprocess.run(["docker","rm",name],check=True) if found.returncode==0 else None; pathlib.Path("/opt/patronus/ark-coordinator/roundtrip-config.json").unlink(missing_ok=True)'
        cloud.remote(cleanup)
        state['phase'] = 'coordinator_cleaned'
        save(state)

    if state['phase'] == 'coordinator_cleaned':
        state['phase'] = 'deleting'
        save(state)

    if state['phase'] == 'deleting':
        sid = state['server_id']
        try:
            resource = api.get(BASE + '/servers/' + sid + '?depth=2')
        except RuntimeError as error:
            if 'HTTP 404' not in str(error):
                raise
        else:
            props = resource.get('properties', {})
            if props.get('type') != 'CUBE' or props.get('name') != state['name']:
                raise RuntimeError('Server identity changed; refusing to delete it')
            mutate(state, 'DELETE', BASE + '/servers/' + sid)
            wait_operations(state)
        ids = {item['id'] for item in api.inventory(cloud.DC)['servers']}
        if sid in ids or not set(state['baseline_server_ids']) <= ids:
            raise RuntimeError('Post-delete inventory differs from the protected baseline')
        state['retained_result_after_delete'] = retained_result(state)
        state['phase'] = 'deleted'
        save(state)
        print(json.dumps({'phase': state['phase'], 'deleted_server_id': sid,
                          'retained_result': state['retained_result_after_delete']}), flush=True)

def register():
    state = load()
    if state['phase'] != 'verified':
        raise RuntimeError('Complete the worker canary first')
    api = cloud.api()
    coord = cloud.server(cloud.COORDINATOR)
    coord_ip = cloud.address(coord, PRIVATE_LAN)
    original_groups = [g['id'] for g in coord['entities']['securitygroups']['items']]
    alb = api.get(BASE + '/applicationloadbalancers/' + ALB_ID)
    source_ips = [ip.split('/')[0] for ip in alb['properties']['lbPrivateIps']]
    state['coordinator_original_groups'] = original_groups
    state['coordinator_ip'] = coord_ip
    state['sidecar_name'] = 'ark-coordinator-fleet-' + state['server_id'][:8]
    save(state)
    if not state.get('extra_group_id'):
        result = mutate(state, 'POST', BASE + '/securitygroups', {'properties': {
            'name': state['name'] + '-coordinator', 'description': 'Temporary private ALB access for journaled Cube roundtrip'}})
        state['extra_group_id'] = result['id']
        save(state)
        wait_operations(state)
        for ip in source_ips:
            mutate(state, 'POST', BASE + '/securitygroups/' + state['extra_group_id'] + '/rules', {'properties': {
                'name': 'trial-alb-to-coordinator', 'protocol': 'TCP', 'sourceIp': ip,
                'portRangeStart': 8091, 'portRangeEnd': 8091, 'type': 'INGRESS'}})
            wait_operations(state)
    mutate(state, 'PUT', BASE + '/servers/' + cloud.COORDINATOR + '/securitygroups',
           {'ids': original_groups + [state['extra_group_id']]})
    wait_operations(state)
    state['coordinator_group_added'] = True
    save(state)
    params = {'ip': coord_ip, 'cube_ip': state['private_ip'], 'name': state['sidecar_name'], 'image': COORDINATOR_DIGEST, 'expected_origins': cloud.PROFILE['expected_current_cubes'], 'cube_name': state['name']}
    code = 'params=' + repr(params) + '\n' + '''import pathlib,json,yaml,subprocess,urllib.request,time,os
p=pathlib.Path("/opt/patronus/ark-coordinator")
c=yaml.safe_load((p/"config.yaml").read_text());assert len(c["gateway"]["cubes"])==params["expected_origins"]
c["gateway"]["cubes"].append({"name":params["cube_name"],"url":"http://"+params["cube_ip"]+":8080","max_in_flight":3})
f=p/"roundtrip-config.json";f.write_text(json.dumps(c));os.chown(f,10001,10001);f.chmod(0o400)
old=json.loads(subprocess.check_output(["docker","inspect","patronus-ark-coordinator-coordinator-1"],text=True))[0]
network=next(iter(old["NetworkSettings"]["Networks"]))
args=["docker","run","-d","--name",params["name"],"--init","--restart","unless-stopped","--stop-timeout","310","--user","10001:10001","--read-only","--security-opt","no-new-privileges","--cap-drop","ALL","--cpus","2","--memory","1g","--memory-swap","1g","--pids-limit","128","--tmpfs","/tmp:size=32m,mode=1777","--network",network,"-e","RUST_LOG=info","-e","TOKIO_WORKER_THREADS=2","-p",params["ip"]+":8091:8090","-p","127.0.0.1:8091:8090","-v",str(f)+":/etc/ark-coordinator/config.yaml:ro","-v",str(p/"cube.token")+":/run/ark-coordinator/cube.token:ro","-v",str(p/"redis.url")+":/run/ark-coordinator/redis.url:ro",params["image"]]
subprocess.run(args,check=True,stdout=subprocess.DEVNULL)
for _ in range(60):
 try:
  with urllib.request.urlopen("http://127.0.0.1:8091/readyz",timeout=3) as r:
   if r.status==200:break
 except OSError:pass
 time.sleep(1)
else:raise AssertionError("Replacement Coordinator is not ready")
print("Ready replacement Coordinator with", len(c["gateway"]["cubes"]), "Cubes; original remains running.")
'''
    print(cloud.remote(code, timeout=90), flush=True)
    state['sidecar_created'] = True
    save(state)
    state['coordinator_canary'] = coordinator_probe(state)
    save(state)
    cubes_id = CUBE_TARGET_GROUP
    coor_id = COORDINATOR_TARGET_GROUP
    current = api.get('/targetgroups/' + cubes_id)['properties']['targets']
    if current != state['baseline_target_groups'][cubes_id]['targets']:
        raise RuntimeError('Cube targets changed concurrently')
    target = {'ip': state['private_ip'], 'port': 8080, 'weight': 1,
              'healthCheckEnabled': True, 'maintenanceEnabled': False, 'proxyProtocol': 'none'}
    mutate(state, 'PATCH', '/targetgroups/' + cubes_id, {'targets': current + [target]})
    wait_operations(state)
    state['cube_target_added'] = True
    save(state)
    current = api.get('/targetgroups/' + coor_id)['properties']['targets']
    if current != state['baseline_target_groups'][coor_id]['targets']:
        raise RuntimeError('Coordinator targets changed concurrently')
    new = dict(current[0]);new.update(port=8091, healthCheckEnabled=False, maintenanceEnabled=False)
    mutate(state, 'PATCH', '/targetgroups/' + coor_id, {'targets': current + [new]})
    wait_operations(state)
    state['coordinator_target_added'] = True
    save(state)
    # Both ready processes stay available during handover. Preserve accepted jobs.
    old = [dict(target, maintenanceEnabled=True) for target in current]
    mutate(state, 'PATCH', '/targetgroups/' + coor_id, {'targets': old + [new]})
    wait_operations(state)
    state['registered'] = True
    state['phase'] = 'registered'
    state['post_registration_canary'] = coordinator_probe(state)
    state['https_alb_probe'] = https_alb_probe()
    save(state)
    state['registered_cube_targets'] = api.get('/targetgroups/' + cubes_id)['properties']['targets']
    state['registered_coordinator_targets'] = api.get('/targetgroups/' + coor_id)['properties']['targets']
    save(state)
    print(json.dumps({'cube_targets':len(state['registered_cube_targets']),'coordinator_targets':len(state['registered_coordinator_targets']),'coordinator_scan':state['post_registration_canary']}),flush=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['probe', 'plan', 'check', 'up', 'down'])
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    try:
        profile = json.loads(args.config.read_text())
        profile['token_file'] = str(resolve_path(profile.get('token_file', '.private/ionos-api-token.txt')))
        if args.phase == 'plan':
            plan_readonly(profile)
            raise SystemExit(0)
        if args.phase == 'probe':
            api = cloud.fleet.Ionos(cloud.fleet.read_token(profile['token_file']))
            data = api.get('/datacenters?depth=1&limit=100')
            print(json.dumps({'api_access': 'ok', 'datacenters': [
                {'id': item['id'], 'name': item.get('properties', {}).get('name')}
                for item in data['items']]}))
            raise SystemExit(0)
        profile = discover_profile(profile)
        cloud.configure(profile)
        BASE = '/datacenters/' + cloud.DC
        PRIVATE_LAN = profile['private_lan_id']; PUBLIC_LAN = profile.get('public_lan_id', 7)
        NAT_GATEWAY = profile['nat_gateway_id']; CUBE_TARGET_GROUP = profile['cube_target_group_id']
        COORDINATOR_TARGET_GROUP = profile['coordinator_target_group_id']; ALB_ID = profile['alb_id']
        if args.phase == 'check':
            preflight()
            raise SystemExit(0)
        if not profile.get('api_image_digest'):
            profile['api_image_digest'] = discover_image_digest(cloud.CUBE, 'worker-1')
        if not profile.get('coordinator_image_digest'):
            profile['coordinator_image_digest'] = discover_image_digest(None, 'coordinator')
        validate_profile(profile)
        IMAGE = profile['image_id']; TEMPLATE = profile['template_id']
        API_DIGEST = profile['api_image_digest']; COORDINATOR_DIGEST = profile['coordinator_image_digest']
        if args.phase == 'up':
            if JOURNAL.exists() and load().get('phase') in ('deleted', 'deleted_unregistered'):
                archived = JOURNAL.with_name('journal-' + str(int(time.time())) + '.json')
                JOURNAL.replace(archived)
            if not JOURNAL.exists():
                preflight()
                create()
            else: status()
            phase = load()['phase']
            if phase == 'created': attach_workers_group()
            if phase in ('created', 'installing', 'installed', 'network_preparing', 'network_ready', 'starting'):
                setup()
            if load()['phase'] == 'running': canary()
            if load()['phase'] == 'verified': register()
            if load()['phase'] == 'registered': print('Fleet already expanded and registered.')
        elif args.phase == 'down':
            scale_down()
        else:
            raise RuntimeError('Unsupported command')
    except (RuntimeError, OSError, ValueError, KeyError, TypeError,
            subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error))
