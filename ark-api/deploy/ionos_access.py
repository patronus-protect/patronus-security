import json
import subprocess
from pathlib import Path

import importlib.util
import os

ROOT = Path(__file__).resolve().parents[2]
TOKEN = ROOT / '.private/ionos-api-token.txt'
DC = None
COORDINATOR = None
CUBE = None
PROFILE = {}
spec = importlib.util.spec_from_file_location('fleet', Path(__file__).with_name('fleet.py'))
fleet = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fleet)

def configure(profile):
    global TOKEN, DC, COORDINATOR, CUBE, PROFILE
    PROFILE = profile
    TOKEN = Path(profile.get('token_file', ROOT / '.private/ionos-api-token.txt'))
    DC = fleet.resource_id(profile['datacenter_id'])
    COORDINATOR = fleet.resource_id(profile['coordinator_server_id'])
    CUBE = fleet.resource_id(profile['runtime_source_server_id'])

def api():
    return fleet.Ionos(fleet.read_token(TOKEN))

def server(sid):
    return api().get(f'/datacenters/{DC}/servers/{sid}?depth=2')

def address(resource, lan):
    ips = [ip for n in resource['entities']['nics']['items']
           if n['properties']['lan'] == lan for ip in n['properties'].get('ips', [])]
    if len(ips) != 1:
        raise RuntimeError('Unexpected NIC address count')
    return ips[0]

def ssh_args(sid=None):
    sid = COORDINATOR if sid is None else fleet.resource_id(sid)
    public = address(server(COORDINATOR), PROFILE.get('public_lan_id', 7))
    args = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ConnectTimeout=10']
    if sid == COORDINATOR:
        host = public
    else:
        host = address(server(sid), PROFILE.get('private_lan_id', 3))
        args += ['-J', 'root@' + public]
    return args + ['root@' + host]

def remote(code, sid=None, timeout=60):
    result = subprocess.run(ssh_args(sid) + ['python3 -'], input=code,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('SSH command failed: ' + result.stderr[-2000:])
    return result.stdout

def gpu_args():
    endpoint = remote('import subprocess\nprint(subprocess.check_output(["wg","show","wg-ark","endpoints"],text=True).split()[1])', CUBE).strip().rsplit(':', 1)[0]
    public = address(server(COORDINATOR), PROFILE.get('public_lan_id', 7))
    profile = PROFILE['l3']
    return ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ConnectTimeout=10', '-o', 'IdentitiesOnly=yes',
            '-o', 'HostKeyAlias=' + profile['host_key_alias'],
            '-o', 'UserKnownHostsFile=' + profile['known_hosts'],
            '-i', profile['identity_file'], '-J', 'root@' + public,
            'ubuntu@' + endpoint]

def gpu_remote(code, timeout=60):
    result = subprocess.run(gpu_args() + ['sudo -n python3 -'], input=code,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('GPU SSH command failed: ' + result.stderr[-2000:])
    return result.stdout
