#!/usr/bin/env python3
"""Drain and reduce an IONOS Cube fleet through its Coordinator and ALB."""

import argparse
import concurrent.futures
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import fleet
import ionos_access as cloud
import fleet_roundtrip as roundtrip

STATE_DIR = ROOT / ".private" / "fleet-scale"
STATE_FILE = STATE_DIR / "journal.json"
OPS_FILE = STATE_DIR / "provider-operations.json"
SIDE_CAR_PORT = 8091


def save(state):
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = STATE_FILE.with_suffix(".tmp")
    with temp.open("w") as stream:
        json.dump(state, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    temp.chmod(0o600)
    temp.replace(STATE_FILE)


def api_mutation(api, method, path, payload=None):
    result = api.request(method, path, payload)
    if result.get("location"):
        api.wait_operation(result["location"])
    return result


def private_ip(row, lan):
    matches = [ip for nic in row["nics"] if nic["lan"] == lan for ip in nic["ips"]]
    if len(matches) != 1:
        raise RuntimeError("Cube does not have exactly one address on the configured private LAN")
    return str(ipaddress.IPv4Address(matches[0]))


def configure(profile):
    profile = roundtrip.discover_profile(profile)
    cloud.configure(profile)
    if not re.fullmatch(r"[A-Za-z0-9.-]+", profile.get("origin_hostname", "")):
        raise ValueError("origin_hostname is required for verified ALB routing checks")
    profile["origin_ca_file"] = str(roundtrip.resolve_path(profile["origin_ca_file"]))
    profile["l3"] = dict(profile["l3"])
    for key in ("identity_file", "known_hosts"):
        profile["l3"][key] = str(roundtrip.resolve_path(profile["l3"][key]))
        if not Path(profile["l3"][key]).is_file():
            raise ValueError("Missing GPU SSH trust input: " + key)
    if not Path(profile["origin_ca_file"]).is_file():
        raise ValueError("Missing Origin CA root certificate")
    fleet.read_token(profile["token_file"])
    roundtrip.BASE = "/datacenters/" + cloud.DC
    roundtrip.PRIVATE_LAN = profile["private_lan_id"]
    roundtrip.PUBLIC_LAN = profile.get("public_lan_id", 7)
    roundtrip.NAT_GATEWAY = profile["nat_gateway_id"]
    roundtrip.CUBE_TARGET_GROUP = profile["cube_target_group_id"]
    roundtrip.COORDINATOR_TARGET_GROUP = profile["coordinator_target_group_id"]
    roundtrip.ALB_ID = profile["alb_id"]
    return profile


def worker_status(server_id):
    code = '''import json,pathlib,subprocess,urllib.request
p=pathlib.Path('/opt/patronus/ark-api');token=__import__('yaml').safe_load((p/'entrypoint.yaml').read_text())['gateway']['worker_token']
ids=subprocess.check_output(['docker','ps','-q'],text=True).split();rows=json.loads(subprocess.check_output(['docker','inspect',*ids],text=True))
workers=[x for x in rows if x['Config'].get('Labels',{}).get('com.docker.compose.service','').startswith('worker-')]
assert len(workers)==3
counts=[]
for w in workers:
 addrs=[n['IPAddress'] for n in w['NetworkSettings']['Networks'].values() if n.get('IPAddress')];data=None
 for ip in addrs:
  try:
   req=urllib.request.Request('http://'+ip+':8080/internal/status',headers={'Authorization':'Bearer '+token})
   with urllib.request.urlopen(req,timeout=4) as r:data=json.load(r)
   break
  except OSError:pass
 assert data is not None,'worker status unreachable'
 counts.append({'service':w['Config']['Labels']['com.docker.compose.service'],'active_jobs':data.get('active_jobs'),'active_submissions':data.get('active_submissions')})
print(json.dumps(counts))
'''
    return json.loads(cloud.remote(code, server_id, timeout=60))


def drain(server_id, timeout=600):
    deadline = time.monotonic() + timeout
    zero_since = None
    while time.monotonic() < deadline:
        counts = worker_status(server_id)
        if all(row["active_jobs"] == 0 and row["active_submissions"] == 0 for row in counts):
            zero_since = zero_since or time.monotonic()
            if time.monotonic() - zero_since >= 5:
                return counts
        else:
            zero_since = None
        time.sleep(1)
    raise RuntimeError("Cube did not drain before timeout")


def build_plan(profile, api, target):
    inventory = api.inventory(cloud.DC)
    cubes = [row for row in inventory["servers"] if row["type"] == "CUBE"]
    if target >= len(cubes):
        raise ValueError("fleet_scale.py only reduces a fleet; use fleet_roundtrip.py for one-Cube scale-up")
    if target < 1:
        raise ValueError("target must retain at least one Cube")
    coordinator = cloud.server(cloud.COORDINATOR)
    coordinator_ip = cloud.address(coordinator, profile["private_lan_id"])
    statuses = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(worker_status, row["id"]): row for row in cubes}
        for future, row in [(future, row) for future, row in futures.items()]:
            statuses[row["id"]] = future.result()
    protected = {cloud.CUBE}
    def activity(row):
        return sum((item.get("active_jobs") or 0) + (item.get("active_submissions") or 0)
                   for item in statuses[row["id"]])
    # Keep the runtime source and the least-active Cubes. Break ties by name so
    # repeated plans select the same retirement set.
    ordered = sorted(cubes, key=lambda row: (
        row["id"] not in protected, activity(row), row["name"]))
    retained = sorted(ordered[:target], key=lambda row: row["name"])
    retired = sorted(ordered[target:], key=lambda row: row["name"])
    groups = set(retained[0]["security_group_ids"])
    for row in retained[1:]:
        groups &= set(row["security_group_ids"])
    if not groups:
        raise RuntimeError("Retained Cubes do not share a worker security group")
    slots = []
    for row in sorted(retained + retired, key=lambda item: (item in retired, item["name"])):
        slots.append({"name": row["name"], "server_id": row["id"],
                      "private_ip": private_ip(row, profile["private_lan_id"])})
    min_cores = min(row["cores"] for row in cubes)
    min_ram = min(row["ram_mb"] for row in cubes)
    config = {"datacenter_id": cloud.DC, "private_lan_id": profile["private_lan_id"],
              "minimum_cubes": target, "minimum_cores": min_cores,
              "minimum_ram_mb": min_ram, "worker_security_group_ids": sorted(groups),
              "protected_server_ids": [cloud.COORDINATOR], "slots": slots}
    plan = fleet.plan(config, inventory, target)
    ids = {row["id"] for row in retained}
    return {"config": config, "plan": plan, "inventory": inventory,
            "retained": retained, "retired": retired, "statuses": statuses,
            "retained_ids": sorted(ids), "coordinator_ip": coordinator_ip}


def wait_sidecar(state):
    name = state["sidecar_name"]
    params = {"name": name, "image": state["coordinator_image"],
              "ip": state["coordinator_ip"], "keep_ips": state["keep_ips"],
              "target": state["target"], "port": SIDE_CAR_PORT,
              "config_file": state["sidecar_config_file"]}
    code = "params=" + repr(params) + "\n" + '''import json,os,pathlib,subprocess,time,urllib.request,yaml
p=pathlib.Path('/opt/patronus/ark-coordinator');config=yaml.safe_load((p/'config.yaml').read_text())
keep=set(params['keep_ips']);cubes=[x for x in config['gateway']['cubes'] if x['url'].split('//',1)[1].split(':',1)[0] in keep]
assert len(cubes)==params['target']
config['gateway']['cubes']=cubes;f=p/params['config_file'];data=json.dumps(config)
if f.exists():assert f.read_text()==data
else:
 tmp=f.with_suffix('.tmp');tmp.write_text(data);os.chown(tmp,10001,10001);tmp.chmod(0o400);tmp.replace(f)
ids=subprocess.check_output(['docker','ps','-q'],text=True).split();running=json.loads(subprocess.check_output(['docker','inspect',*ids],text=True))
old=next((x for x in running if x['Config'].get('Labels',{}).get('com.docker.compose.service')=='coordinator'),None)
network=next(iter(old['NetworkSettings']['Networks']))
found=subprocess.run(['docker','inspect',params['name']],capture_output=True,text=True)
if found.returncode:
 args=['docker','run','-d','--name',params['name'],'--init','--restart','unless-stopped','--stop-timeout','310','--user','10001:10001','--read-only','--security-opt','no-new-privileges','--cap-drop','ALL','--cpus','2','--memory','1g','--memory-swap','1g','--pids-limit','128','--tmpfs','/tmp:size=32m,mode=1777','--network',network,'-e','RUST_LOG=info','-e','TOKIO_WORKER_THREADS=2','-p',params['ip']+':'+str(params['port'])+':8090','-p','127.0.0.1:'+str(params['port'])+':8090','-v',str(f)+':/etc/ark-coordinator/config.yaml:ro','-v',str(p/'cube.token')+':/run/ark-coordinator/cube.token:ro','-v',str(p/'redis.url')+':/run/ark-coordinator/redis.url:ro',params['image']]
 subprocess.run(args,check=True,stdout=subprocess.DEVNULL)
else:
 row=json.loads(found.stdout)[0];assert row['Config']['Image']==params['image'] and row['State']['Running']
for _ in range(60):
 try:
  with urllib.request.urlopen('http://127.0.0.1:'+str(params['port'])+'/readyz',timeout=3) as r:
   if r.status==200:print('ready');break
 except OSError:pass
 time.sleep(1)
else:raise SystemExit('sidecar readiness timeout')
'''
    cloud.remote(code, cloud.COORDINATOR, timeout=100)


def update_original_config(state):
    params = {"keep_ips": state["keep_ips"], "target": state["target"],
              "backup": state["config_backup"]}
    code = "params=" + repr(params) + "\n" + '''import hashlib,json,os,pathlib,subprocess,time,urllib.request,yaml
p=pathlib.Path('/opt/patronus/ark-coordinator');f=p/'config.yaml';backup=p/params['backup']
current=yaml.safe_load(f.read_text());keep=set(params['keep_ips'])
desired=[x for x in current['gateway']['cubes'] if x['url'].split('//',1)[1].split(':',1)[0] in keep]
if len(desired)==params['target']:
 current['gateway']['cubes']=desired;body=yaml.safe_dump(current,sort_keys=False)
 if backup.exists():
  # Backup is immutable across retries and contains the pre-scale config.
  assert backup.stat().st_mode & 0o077 == 0
 else:
  backup.write_bytes(f.read_bytes());backup.chmod(0o600)
 tmp=f.with_suffix('.fleet-scale.tmp');tmp.write_text(body);os.chown(tmp,10001,10001);tmp.chmod(0o400);tmp.replace(f)
 subprocess.run(['docker','compose','--project-directory',str(p),'-f',str(p/'compose.yaml'),'up','-d','--force-recreate','coordinator'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=600)
else:raise SystemExit('origin config does not match retained fleet')
deadline=time.monotonic()+180
while time.monotonic()<deadline:
 try:
  with urllib.request.urlopen('http://127.0.0.1:8090/readyz',timeout=3) as r:
   if r.status==200:break
 except OSError:pass
 time.sleep(2)
else:raise SystemExit('official Coordinator did not become ready')
print(json.dumps({'origin_count':len(desired),'config_sha256':hashlib.sha256(f.read_bytes()).hexdigest()}))
'''
    result = json.loads(cloud.remote(code, cloud.COORDINATOR, timeout=650))
    state["official_coordinator"] = result
    save(state)


def remove_peers(state):
    peers = state["retired_peers"]
    params = {"peers": peers, "expected_count": state["target"]}
    code = "params=" + repr(params) + "\n" + '''import hashlib,json,pathlib,subprocess
p=pathlib.Path('/etc/wireguard/wg-ark.conf');text=p.read_text();blocks=text.split('[Peer]')
for peer in params['peers']:
 matches=[b for b in blocks[1:] if any(x.strip()=='PublicKey = '+peer['public_key'] for x in b.splitlines())]
 if matches:
  assert len(matches)==1 and any(x.strip()=='AllowedIPs = '+peer['vpn_address']+'/32' for x in matches[0].splitlines())
  blocks[1:]=[b for b in blocks[1:] if b not in matches]
new=blocks[0]+'[Peer]'.join(blocks[1:]);tmp=p.with_name('.wg-ark-fleet-scale.tmp');tmp.write_text(new.rstrip()+'\\n');tmp.chmod(0o600);tmp.replace(p)
for peer in params['peers']:
 live=subprocess.check_output(['wg','show','wg-ark','peers'],text=True).splitlines()
 if peer['public_key'] in live:subprocess.run(['wg','set','wg-ark','peer',peer['public_key'],'remove'],check=True)
live=subprocess.check_output(['wg','show','wg-ark','peers'],text=True).splitlines()
assert all(peer['public_key'] not in live for peer in params['peers'])
assert len(live)==params['expected_count']
print(json.dumps({'peer_count':len(live)}))
'''
    cloud.gpu_remote(code, timeout=120)


def initialize(profile, target):
    api = cloud.fleet.Ionos(cloud.fleet.read_token(profile["token_file"]))
    plan = build_plan(profile, api, target)
    inv = plan["inventory"]
    dc = cloud.DC
    servers = {row["id"]: row for row in inv["servers"]}
    cubes = [row for row in inv["servers"] if row["type"] == "CUBE"]
    tg_cubes = api.get("/targetgroups/" + roundtrip.CUBE_TARGET_GROUP)["properties"]["targets"]
    tg_coord = api.get("/targetgroups/" + roundtrip.COORDINATOR_TARGET_GROUP)["properties"]["targets"]
    expected_cube_ips = {private_ip(row, profile["private_lan_id"]) for row in cubes}
    if {row["ip"] for row in tg_cubes} != expected_cube_ips or len(tg_cubes) != len(cubes):
        raise RuntimeError("Cube ALB target group does not exactly match the live fleet")
    if len(tg_coord) != 1 or tg_coord[0].get("port") != 8090 or tg_coord[0].get("maintenanceEnabled"):
        raise RuntimeError("Coordinator target group is not the expected single active target")
    current_groups = api.get("/datacenters/" + dc + "/servers/" + cloud.COORDINATOR + "?depth=2")["entities"]["securitygroups"]["items"]
    alb = api.get("/datacenters/" + dc + "/applicationloadbalancers/" + roundtrip.ALB_ID)
    source_ips = sorted({ip.split("/")[0] for ip in alb["properties"]["lbPrivateIps"]})
    if not source_ips:
        raise RuntimeError("ALB does not expose private source addresses")
    peers = cloud.gpu_remote('import subprocess; print(subprocess.check_output(["wg","show","wg-ark","allowed-ips"],text=True))').splitlines()
    peer_map = {line.split()[0]: line.split()[1:] for line in peers if len(line.split()) >= 2}
    retired_peers = []
    for row in plan["retired"]:
        code = '''import json,subprocess
public=subprocess.check_output(['wg','show','wg-ark','public-key'],text=True).strip()
address=subprocess.check_output(['ip','-4','-o','addr','show','dev','wg-ark'],text=True).split()[3].split('/')[0]
print(json.dumps({'public_key':public,'vpn_address':address}))'''
        wg = json.loads(cloud.remote(code, row["id"]))
        matches = [key for key, allowed in peer_map.items()
                   if any(wg["vpn_address"] in entry for entry in allowed)]
        if len(matches) != 1:
            raise RuntimeError("Retired Cube does not map to exactly one GPU WireGuard peer")
        retired_peers.append({"name": row["name"], "public_key": matches[0],
                              "vpn_address": wg["vpn_address"]})
    cinfo = json.loads(cloud.remote('''import json,pathlib,subprocess,yaml
p=pathlib.Path('/opt/patronus/ark-coordinator');c=yaml.safe_load((p/'config.yaml').read_text())
ids=subprocess.check_output(['docker','ps','-q'],text=True).split();rows=json.loads(subprocess.check_output(['docker','inspect',*ids],text=True))
coordinator=next(x for x in rows if x['Config'].get('Labels',{}).get('com.docker.compose.service')=='coordinator')
print(json.dumps({'cubes':c['gateway']['cubes'],'image':coordinator['Config']['Image'],'container':coordinator['Name'],'network':next(iter(coordinator['NetworkSettings']['Networks']))}))''', cloud.COORDINATOR))
    if len(cinfo["cubes"]) != len(cubes):
        raise RuntimeError("Coordinator configuration does not match IONOS fleet")
    origin_ips = [urlsplit(row["url"]).hostname for row in cinfo["cubes"]]
    if set(origin_ips) != expected_cube_ips:
        raise RuntimeError("Coordinator origins do not map exactly to current Cube IPs")
    keep_ips = [private_ip(row, profile["private_lan_id"]) for row in plan["retained"]]
    state = {"version": 1, "run_id": uuid.uuid4().hex,
             "phase": "planned", "target": target,
             "baseline_count": len(cubes), "baseline_server_ids": [row["id"] for row in inv["servers"]],
             "coordinator_id": cloud.COORDINATOR, "coordinator_ip": plan["coordinator_ip"],
             "coordinator_image": cinfo["image"], "coordinator_network": cinfo["network"],
             "coordinator_original_groups": [row["id"] for row in current_groups],
             "cube_group_id": roundtrip.CUBE_TARGET_GROUP,
             "coordinator_group_id": roundtrip.COORDINATOR_TARGET_GROUP,
             "baseline_cube_targets": tg_cubes, "baseline_coordinator_targets": tg_coord,
             "retained": plan["retained"], "retired": plan["retired"],
             "retained_ids": plan["retained_ids"], "keep_ips": keep_ips,
             "retired_peers": retired_peers, "alb_source_ips": source_ips,
             "image": cinfo["image"], "phase": "planned",
             "sidecar_name": "ark-coordinator-scale-" + str(target) + "-" + uuid.uuid4().hex[:8],
             "sidecar_config_file": "fleet-scale-" + str(target) + "-" + uuid.uuid4().hex[:8] + ".json",
             "config_backup": "config.yaml.before-fleet-scale-" + uuid.uuid4().hex[:8]}
    return state


def apply(profile, target):
    token = fleet.read_token(profile["token_file"])
    ops = fleet.OperationJournal(OPS_FILE)
    api = fleet.Ionos(token, ops)
    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else initialize(profile, target)
    if state["target"] != target:
        raise RuntimeError("Journal target differs; reconcile or archive it before another scale")
    if state["phase"] == "complete":
        print(json.dumps({"phase": "complete", "cubes": target}))
        return
    dc = cloud.DC
    if state["phase"] == "planned":
        if not state.get("extra_group_id"):
            result = api_mutation(api, "POST", "/datacenters/" + dc + "/securitygroups", {"properties": {
                "name": "ark-coordinator-fleet-scale-" + str(target),
                "description": "Temporary ALB access for journaled fleet scale"}})
            state["extra_group_id"] = result.get("resource_id")
            if not state["extra_group_id"]:
                raise RuntimeError("Temporary Coordinator security group has no API identity")
            save(state)
        existing_rules = api.get("/datacenters/" + dc + "/securitygroups/" + state["extra_group_id"] + "/rules?depth=1")["items"]
        existing_sources = {row.get("properties", {}).get("sourceIp") for row in existing_rules
                            if row.get("properties", {}).get("portRangeStart") == SIDE_CAR_PORT
                            and row.get("properties", {}).get("portRangeEnd") == SIDE_CAR_PORT}
        for source in state["alb_source_ips"]:
            if source in existing_sources:
                continue
            rule = {"properties": {"name": "fleet-scale-coordinator", "protocol": "TCP",
                                   "sourceIp": source, "portRangeStart": SIDE_CAR_PORT,
                                   "portRangeEnd": SIDE_CAR_PORT, "type": "INGRESS"}}
            api_mutation(api, "POST", "/datacenters/" + dc + "/securitygroups/" + state["extra_group_id"] + "/rules", rule)
        api.set_server_security_groups(dc, state["coordinator_id"],
                                       state["coordinator_original_groups"] + [state["extra_group_id"]])
        state["phase"] = "security_group_ready"; save(state)
    if state["phase"] == "security_group_ready":
        wait_sidecar(state)
        state["phase"] = "sidecar_ready"; save(state)
    if state["phase"] == "sidecar_ready":
        cube_group = state["cube_group_id"]
        current = api.get("/targetgroups/" + cube_group)["properties"]["targets"]
        retired_ips = {item["private_ip"] for item in state["retired"]}
        desired = [dict(row, maintenanceEnabled=True) if row["ip"] in retired_ips else row for row in state["baseline_cube_targets"]]
        if current == state["baseline_cube_targets"]:
            api.patch_target_group(cube_group, current, desired)
        elif current != desired:
            raise RuntimeError("Cube target group changed concurrently")
        current_coord = api.get("/targetgroups/" + state["coordinator_group_id"])["properties"]["targets"]
        side_target = dict(state["baseline_coordinator_targets"][0], port=SIDE_CAR_PORT,
                           maintenanceEnabled=False, healthCheckEnabled=False)
        desired_coord = [dict(state["baseline_coordinator_targets"][0], maintenanceEnabled=True), side_target]
        if current_coord == state["baseline_coordinator_targets"]:
            api.patch_target_group(state["coordinator_group_id"], current_coord, desired_coord)
        elif current_coord != desired_coord:
            raise RuntimeError("Coordinator target group changed concurrently")
        state["sidecar_target"] = side_target
        state["maintenance_cube_targets"] = desired
        state["routed_coordinator_targets"] = desired_coord
        state["phase"] = "targets_routed"; save(state)
    if state["phase"] == "targets_routed":
        canary = roundtrip.coordinator_probe({}, port=SIDE_CAR_PORT)
        state["post_registration_canary"] = canary
        state["sidecar_https_probe"] = roundtrip.https_alb_probe()
        state["phase"] = "canary_complete"; save(state)
    if state["phase"] == "canary_complete":
        before = roundtrip.retained_result(state, port=SIDE_CAR_PORT)
        drained = {}
        for row in state["retired"]:
            drained[row["id"]] = drain(row["id"])
        state["drain"] = drained
        state["retained_result_before_delete"] = before
        state["phase"] = "drained"; save(state)
    if state["phase"] == "drained":
        update_original_config(state)
        state["phase"] = "coordinator_updated"; save(state)
    if state["phase"] == "coordinator_updated":
        original = state["baseline_coordinator_targets"][0]
        active = dict(original, maintenanceEnabled=False)
        sidecar = dict(state["sidecar_target"], maintenanceEnabled=True)
        desired = [active, sidecar]
        current = api.get("/targetgroups/" + state["coordinator_group_id"])["properties"]["targets"]
        if current == state["routed_coordinator_targets"]:
            api.patch_target_group(state["coordinator_group_id"], current, desired)
        elif current != desired:
            raise RuntimeError("Coordinator target group changed during handover")
        state["official_route_targets"] = desired
        state["official_https_probe"] = roundtrip.https_alb_probe()
        state["retained_result_after_handover"] = roundtrip.retained_result(state, port=8090)
        state["phase"] = "coordinator_routed"; save(state)
    if state["phase"] == "coordinator_routed":
        remove_peers(state)
        state["phase"] = "peers_removed"; save(state)
    if state["phase"] == "peers_removed":
        current = api.get("/targetgroups/" + state["cube_group_id"])["properties"]["targets"]
        keep_targets = [row for row in current if row["ip"] not in {x["private_ip"] for x in state["retired"]}]
        if current != keep_targets:
            if current != state["maintenance_cube_targets"]:
                raise RuntimeError("Cube target group changed before target removal")
            api.patch_target_group(state["cube_group_id"], current, keep_targets)
        state["final_cube_targets"] = keep_targets
        state["phase"] = "cube_targets_removed"; save(state)
    if state["phase"] == "cube_targets_removed":
        protected = state["retained_ids"] + [state["coordinator_id"]]
        for row in state["retired"]:
            current_ids = {item["id"] for item in api.inventory(dc)["servers"]}
            if row["id"] in current_ids:
                api.delete_cube(dc, row["id"], row["name"], protected)
        state["phase"] = "cubes_deleted"; save(state)
    if state["phase"] == "cubes_deleted":
        result = roundtrip.retained_result(state, port=8090)
        inv = api.inventory(dc)
        actual = {row["id"] for row in inv["servers"] if row["type"] == "CUBE"}
        if actual != set(state["retained_ids"]):
            raise RuntimeError("Post-delete Cube inventory does not match the target")
        state["retained_result_after_delete"] = result
        current = api.get("/targetgroups/" + state["coordinator_group_id"])["properties"]["targets"]
        original = dict(state["baseline_coordinator_targets"][0], maintenanceEnabled=False)
        if current == state["official_route_targets"]:
            api.patch_target_group(state["coordinator_group_id"], current, [original])
        elif current != [original]:
            raise RuntimeError("Coordinator targets changed before sidecar cleanup")
        name = state["sidecar_name"]
        config_file = state["sidecar_config_file"]
        cleanup = "import pathlib,subprocess; n=" + repr(name) + "; c=" + repr(config_file) + "; r=subprocess.run(['docker','inspect',n],capture_output=True); subprocess.run(['docker','stop','--time','310',n],check=True,stdout=subprocess.DEVNULL) if r.returncode==0 else None; subprocess.run(['docker','rm',n],check=True,stdout=subprocess.DEVNULL) if r.returncode==0 else None; (pathlib.Path('/opt/patronus/ark-coordinator')/c).unlink(missing_ok=True)"
        cloud.remote(cleanup, cloud.COORDINATOR, timeout=340)
        coord = api.get("/datacenters/" + dc + "/servers/" + state["coordinator_id"] + "?depth=2")
        groups = {item["id"] for item in coord["entities"]["securitygroups"]["items"]}
        baseline_groups = set(state["coordinator_original_groups"])
        extra = state["extra_group_id"]
        if groups == baseline_groups | {extra}:
            api.set_server_security_groups(dc, state["coordinator_id"], state["coordinator_original_groups"])
        elif groups != baseline_groups:
            raise RuntimeError("Coordinator security groups changed before cleanup")
        try:
            api.get("/datacenters/" + dc + "/securitygroups/" + extra)
        except RuntimeError as error:
            if "HTTP 404" not in str(error): raise
        else:
            api_mutation(api, "DELETE", "/datacenters/" + dc + "/securitygroups/" + extra)
        state["final_https_probe"] = roundtrip.https_alb_probe()
        state["phase"] = "complete"; state["completed_at"] = time.time(); save(state)
        print(json.dumps({"phase": state["phase"], "cubes": target,
                          "removed": [row["name"] for row in state["retired"]],
                          "retained_result": result, "https": state["final_https_probe"]}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "apply"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--target-cubes", type=int, required=True)
    args = parser.parse_args()
    try:
        raw = json.loads(args.config.read_text())
        raw["token_file"] = str(roundtrip.resolve_path(raw.get("token_file", ".private/ionos-api-token.txt")))
        profile = configure(raw)
        if args.command == "plan":
            api = fleet.Ionos(fleet.read_token(profile["token_file"]))
            plan = build_plan(profile, api, args.target_cubes)
            print(json.dumps({"read_only": True, "current": sum(row["type"] == "CUBE" for row in plan["inventory"]["servers"]),
                              "target": args.target_cubes,
                              "retire": [{"name": row["name"], "workers": plan["statuses"][row["id"]]} for row in plan["retired"]],
                              "coordinator_origins_checked": True, "target_groups_checked": True}, indent=2))
        else:
            apply(profile, args.target_cubes)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError,
            subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error))


if __name__ == "__main__":
    main()
