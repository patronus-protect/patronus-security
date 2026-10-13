#!/usr/bin/env python3
"""IONOS Cube inventory, planning, and verified API lifecycle primitives."""

import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

API = "https://api.ionos.com/cloudapi/v6"


def resource_id(value):
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Resource IDs must be UUIDs") from exc


def read_token(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("Token must be a regular file owned by the current user")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("Token file must not be accessible to group or others")
        token = stream.read(16385).strip()
    if not token or len(token) > 16384 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ValueError("Invalid token file")
    return token


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class OperationJournal:
    """Durable, secret-free mutation journal; uncertain requests require reconcile."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.exists():
            info = self.path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise ValueError("Journal must be a regular file owned by the current user")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError("Journal must not be accessible to group or others")
            self.data = json.loads(self.path.read_text())
        else:
            self.data = {"version": 1, "operations": []}
            self.save()

    def save(self):
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        with temporary.open("w") as stream:
            json.dump(self.data, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        temporary.replace(self.path)

    def begin(self, method, path):
        if any(item["state"] in {"submitted", "uncertain", "accepted"}
               for item in self.data["operations"]):
            raise RuntimeError("Journal has an unresolved operation; reconcile before continuing")
        item = {"method": method, "path": path, "state": "submitted",
                "started_at": datetime.now(timezone.utc).isoformat()}
        self.data["operations"].append(item)
        self.save()
        return item


class CoordinatorSSH:
    """Reach the Coordinator and private Cubes through the configured SSH route."""

    def __init__(self, coordinator_ip, known_hosts, identity_file=None):
        self.coordinator_ip = str(ipaddress.IPv4Address(coordinator_ip))
        self.known_hosts = Path(known_hosts)
        self.identity_file = Path(identity_file) if identity_file else None

    def host_command(self, address, remote_command, code=None, timeout=120):
        address = str(ipaddress.IPv4Address(address))
        args = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "ConnectTimeout=10", "-o", "UserKnownHostsFile=" + str(self.known_hosts)]
        if self.identity_file:
            args += ["-i", str(self.identity_file), "-o", "IdentitiesOnly=yes"]
        args += ["root@" + address, remote_command]
        result = subprocess.run(args, input=code, capture_output=True, text=True,
                                timeout=timeout)
        if result.returncode:
            raise RuntimeError("Coordinator SSH command failed; inspect the host")
        return result.stdout

    def coordinator_python(self, source, timeout=120):
        return self.host_command(self.coordinator_ip, "python3 -", source, timeout)

    def command(self, private_ip, remote_command, code=None, timeout=120,
                host_alias=None, allow_new_host=False):
        address = str(ipaddress.IPv4Address(private_ip))
        strict = "accept-new" if allow_new_host else "yes"
        args = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=" + strict,
                "-o", "ConnectTimeout=10", "-o", "UserKnownHostsFile=" + str(self.known_hosts)]
        if host_alias:
            args += ["-o", "HostKeyAlias=" + host_alias]
        if self.identity_file:
            args += ["-i", str(self.identity_file), "-o", "IdentitiesOnly=yes"]
        args += ["-J", "root@" + self.coordinator_ip, "root@" + address, remote_command]
        result = subprocess.run(args, input=code, capture_output=True, text=True,
                                timeout=timeout)
        if result.returncode:
            raise RuntimeError("Private Cube SSH command failed; inspect the target host")
        return result.stdout

    def python(self, private_ip, source, timeout=120):
        return self.command(private_ip, "python3 -", source, timeout)

    def wait_ready(self, private_ip, port, host_alias, timeout=600):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Health-check port is invalid")
        source = (
            "import time,urllib.request\n"
            f"url='http://{ipaddress.IPv4Address(private_ip)}:{port}/readyz'\n"
            f"deadline=time.monotonic()+{int(timeout)}\n"
            "while time.monotonic()<deadline:\n"
            " try:\n"
            "  with urllib.request.urlopen(url,timeout=3) as r:\n"
            "   if r.status==200: print('ready'); raise SystemExit(0)\n"
            " except OSError: pass\n"
            " time.sleep(2)\n"
            "raise SystemExit('readiness timeout')\n"
        )
        return self.command(private_ip, "python3 -", source, timeout + 30,
                            host_alias=host_alias, allow_new_host=True)

    def copy_root_paths(self, source_ip, destination_ip, paths, timeout=180,
                        destination_alias=None):
        """Stream selected runtime files between private Cubes without local copies."""
        source = str(ipaddress.IPv4Address(source_ip))
        destination = str(ipaddress.IPv4Address(destination_ip))
        if destination_alias:
            destination_alias = resource_id(destination_alias)
        if not paths or any(not isinstance(path, str) or
                            not re.fullmatch(r"[A-Za-z0-9_./+-]+", path) or
                            path.startswith("/") or ".." in Path(path).parts for path in paths):
            raise ValueError("Runtime transfer paths must be safe root-relative paths")

        def ssh_args(address, alias=None, allow_new=False):
            args = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                    "-o", "ConnectTimeout=10", "-o", "UserKnownHostsFile=" + str(self.known_hosts)]
            if allow_new:
                args[args.index("StrictHostKeyChecking=yes")] = "StrictHostKeyChecking=accept-new"
            if alias:
                args += ["-o", "HostKeyAlias=" + alias]
            if self.identity_file:
                args += ["-i", str(self.identity_file), "-o", "IdentitiesOnly=yes"]
            return args + ["-J", "root@" + self.coordinator_ip, "root@" + address]

        source_args = ssh_args(source) + ["tar -C / -cpf - " + " ".join(paths)]
        destination_args = ssh_args(destination, destination_alias, True) + ["tar -C / -xpf -"]
        sender = subprocess.Popen(source_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            receiver = subprocess.run(destination_args, stdin=sender.stdout,
                                      capture_output=True, timeout=timeout)
            sender.stdout.close()
            source_error = sender.stderr.read()
            code = sender.wait(timeout=10)
            if code or receiver.returncode:
                raise RuntimeError("Private runtime transfer failed; credentials were not printed")
            if source_error:
                raise RuntimeError("Private runtime transfer source reported an error")
        finally:
            if sender.poll() is None:
                sender.terminate()


class Ionos:
    def __init__(self, token, journal=None):
        self.token = token
        self.journal = journal
        self.opener = urllib.request.build_opener(NoRedirect())

    def get(self, path):
        request = urllib.request.Request(
            API + path,
            headers={"Authorization": "Bearer " + self.token, "Accept": "application/json"},
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            # Provider bodies and request headers may contain account information.
            raise RuntimeError(f"IONOS inventory request failed: HTTP {exc.code}") from None
        except urllib.error.URLError:
            raise RuntimeError("IONOS inventory request failed: connection error") from None

    def request(self, method, path, payload=None):
        """Issue one API mutation, returning only safe operation metadata."""
        record = self.journal.begin(method, path) if self.journal else None
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            API + path, data=body, method=method,
            headers={"Authorization": "Bearer " + self.token,
                     "Accept": "application/json",
                     "Content-Type": "application/json"},
        )
        try:
            with self.opener.open(request, timeout=30) as response:
                location = response.headers.get("Location")
                payload = response.read()
                result = json.loads(payload) if payload else {}
                metadata = {"status": response.status, "location": location,
                            "request_id": result.get("id"),
                            "resource_id": result.get("id") if method == "POST" else None}
                if record:
                    record.update(state="accepted" if location else "done",
                                  http_status=response.status, location=location,
                                  resource_id=metadata["resource_id"])
                    self.journal.save()
                return metadata
        except urllib.error.HTTPError as exc:
            if record:
                record.update(state="rejected", http_status=exc.code)
                self.journal.save()
            raise RuntimeError(f"IONOS mutation failed: HTTP {exc.code}") from None
        except urllib.error.URLError:
            if record:
                record["state"] = "uncertain"
                self.journal.save()
            raise RuntimeError("IONOS mutation failed: connection error") from None

    def wait_operation(self, location, timeout=900):
        """Poll a provider request until DONE/FAILED; never retry its mutation."""
        if not location:
            return "DONE"
        from urllib.parse import urlsplit
        parsed = urlsplit(location)
        if parsed.netloc and parsed.netloc != "api.ionos.com":
            raise RuntimeError("Unexpected IONOS operation origin")
        path = parsed.path.removeprefix("/cloudapi/v6")
        if not path.startswith("/requests/"):
            raise RuntimeError("Unexpected IONOS operation path")
        if not path.endswith("/status"):
            path += "/status"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.get(path)
            state = result.get("metadata", {}).get("status")
            if state in ("DONE", "FAILED"):
                if self.journal:
                    pending = next((item for item in reversed(self.journal.data["operations"])
                                    if item["state"] == "accepted" and
                                    item.get("location") == location), None)
                    if pending:
                        pending["state"] = "done" if state == "DONE" else "failed"
                        self.journal.save()
                if state == "FAILED":
                    raise RuntimeError("IONOS provider operation failed")
                return state
            time.sleep(3)
        raise RuntimeError("IONOS operation timed out; reconcile before retrying")

    def set_server_security_groups(self, datacenter, server_id, group_ids):
        """Attach exact worker groups and confirm them through fresh inventory."""
        dc, sid = resource_id(datacenter), resource_id(server_id)
        ids = [resource_id(value) for value in group_ids]
        if not ids or len(ids) != len(set(ids)):
            raise ValueError("Security group IDs must be nonempty and unique")
        current = self.get(f"/datacenters/{dc}/servers/{sid}?depth=2")
        existing = {resource_id(row["id"]) for row in
                    current.get("entities", {}).get("securitygroups", {}).get("items", [])}
        if existing != set(ids):
            result = self.request("PUT", f"/datacenters/{dc}/servers/{sid}/securitygroups",
                                 {"ids": ids})
            self.wait_operation(result["location"])
        confirmed = self.get(f"/datacenters/{dc}/servers/{sid}?depth=2")
        actual = {resource_id(row["id"]) for row in
                  confirmed.get("entities", {}).get("securitygroups", {}).get("items", [])}
        if actual != set(ids):
            raise RuntimeError("IONOS did not confirm the requested security groups")

    def create_cube(self, datacenter, properties, volume, nic):
        """Create one Cube from caller-supplied, validated deployment inputs."""
        dc = resource_id(datacenter)
        name = properties.get("name")
        if (not isinstance(name, str) or not name or properties.get("type") != "CUBE" or
                not properties.get("templateUuid")):
            raise ValueError("Cube name, type and template are required")
        if not isinstance(volume, dict) or not isinstance(nic, dict):
            raise ValueError("A boot volume and private NIC are required")
        lan = nic.get("properties", {}).get("lan")
        if type(lan) is not int or lan < 1:
            raise ValueError("Private NIC must name a positive LAN ID")
        response = self.request("POST", f"/datacenters/{dc}/servers", {
            "properties": properties,
            "entities": {"volumes": {"items": [volume]}, "nics": {"items": [nic]}},
        })
        sid = response.get("resource_id")
        if not sid:
            raise RuntimeError("Cube creation returned no identity; reconcile provider state")
        sid = resource_id(sid)
        self.wait_operation(response["location"])
        current = self.get(f"/datacenters/{dc}/servers/{sid}?depth=2")
        actual = current.get("properties", {})
        if actual.get("type") != "CUBE" or actual.get("name") != name:
            raise RuntimeError("Created server identity does not match the request")
        return sid

    def patch_target_group(self, target_group_id, expected, targets):
        """Compare-and-swap a target list; IONOS expects a flat PATCH body."""
        gid = resource_id(target_group_id)
        path = "/targetgroups/" + gid
        current = self.get(path)["properties"].get("targets", [])
        if current != expected:
            raise RuntimeError("Target group changed concurrently; refusing to overwrite it")
        result = self.request("PATCH", path, {"targets": targets})
        self.wait_operation(result["location"])
        actual = self.get(path)["properties"].get("targets", [])
        if actual != targets:
            raise RuntimeError("IONOS target group update did not converge")

    def delete_cube(self, datacenter, server_id, expected_name, protected_ids):
        """Delete only an exact, available Cube identity after caller drains it."""
        dc, sid = resource_id(datacenter), resource_id(server_id)
        if sid in {resource_id(value) for value in protected_ids}:
            raise ValueError("Refusing to delete a protected server")
        path = f"/datacenters/{dc}/servers/{sid}?depth=2"
        current = self.get(path)
        props = current.get("properties", {})
        if (props.get("type") != "CUBE" or props.get("name") != expected_name or
                current.get("metadata", {}).get("state") != "AVAILABLE"):
            raise RuntimeError("Server identity or provider state is not safe to delete")
        result = self.request("DELETE", f"/datacenters/{dc}/servers/{sid}")
        self.wait_operation(result["location"])
        try:
            self.get(path)
        except RuntimeError as exc:
            if "HTTP 404" in str(exc):
                return
            raise
        raise RuntimeError("IONOS still reports the deleted server")

    def inventory(self, datacenter):
        dc = resource_id(datacenter)
        rows = []
        offset = 0
        while True:
            data = self.get(f"/datacenters/{dc}/servers?depth=3&limit=100&offset={offset}")
            page = data["items"]
            rows.extend(page)
            if len(page) < 100:
                break
            offset += len(page)
        return {"datacenter_id": dc, "servers": [summarize(row) for row in rows]}


def summarize(server):
    properties = server["properties"]
    nics = server.get("entities", {}).get("nics", {}).get("items", [])
    return {
        "id": resource_id(server["id"]),
        "name": properties.get("name"),
        "type": properties.get("type"),
        "state": properties.get("vmState"),
        "resource_state": server.get("metadata", {}).get("state"),
        "template_id": properties.get("templateUuid"),
        "cores": properties.get("cores"),
        "ram_mb": properties.get("ram"),
        "security_group_ids": [resource_id(group["id"]) for group in
            server.get("entities", {}).get("securitygroups", {}).get("items", [])],
        "nics": [{"lan": nic["properties"].get("lan"),
                  "ips": nic["properties"].get("ips", [])} for nic in nics],
    }


def plan(config, inventory, target):
    dc = resource_id(config["datacenter_id"])
    if dc != resource_id(inventory["datacenter_id"]):
        raise ValueError("Inventory belongs to a different data center")
    minimum = config["minimum_cubes"]
    lan = config["private_lan_id"]
    minimum_cores = config["minimum_cores"]
    minimum_ram = config["minimum_ram_mb"]
    if any(type(value) is not int or value < 1
           for value in (lan, minimum_cores, minimum_ram)):
        raise ValueError("LAN and minimum resource constraints must be positive integers")
    slots = config["slots"]
    if type(minimum) is not int or minimum < 1:
        raise ValueError("minimum_cubes must be a positive integer")
    if type(target) is not int or not minimum <= target <= len(slots):
        raise ValueError("Target is outside the configured fleet capacity range")
    protected = {resource_id(x) for x in config.get("protected_server_ids", [])}
    group_ids = config.get("worker_security_group_ids", [])
    if not isinstance(group_ids, list) or (
            "worker_security_group_ids" in config and not group_ids):
        raise ValueError("Worker security group IDs must be a nonempty list")
    required_groups = {resource_id(value) for value in group_ids}
    if len(required_groups) != len(group_ids):
        raise ValueError("Worker security group IDs must be unique")
    seen_ids, seen_ips, seen_names = set(), set(), set()
    servers = {}
    for row in inventory["servers"]:
        sid = resource_id(row["id"])
        if sid in servers:
            raise ValueError("Duplicate server ID in inventory")
        servers[sid] = row
    actions = []
    for index, slot in enumerate(slots):
        address = str(ipaddress.IPv4Address(slot["private_ip"]))
        name = slot["name"]
        if not isinstance(name, str) or not name or name in seen_names or address in seen_ips:
            raise ValueError("Fleet slot names and addresses must be unique")
        seen_names.add(name)
        seen_ips.add(address)
        sid = resource_id(slot["server_id"]) if slot.get("server_id") else None
        if sid and (sid in seen_ids or sid in protected):
            raise ValueError("Duplicate or protected server in fleet slots")
        if sid:
            seen_ids.add(sid)
        row = servers.get(sid)
        if sid and row is None:
            raise ValueError("Managed server missing; reconcile inventory before planning")
        owners = [s for s in servers.values()
                  if any(n.get("lan") == lan and address in n["ips"] for n in s["nics"])]
        if any(s["id"] != sid for s in owners):
            raise ValueError("Fleet address belongs to another server")
        if row:
            if row["type"] != "CUBE" or row["name"] != name or not owners:
                raise ValueError("Managed Cube identity differs from the configured slot")
            if (type(row.get("cores")) is not int or row["cores"] < minimum_cores or
                    type(row.get("ram_mb")) is not int or row["ram_mb"] < minimum_ram):
                raise ValueError("Managed Cube does not meet minimum resource constraints")
            if row["resource_state"] != "AVAILABLE":
                raise ValueError("Managed Cube has a pending resource operation")
            if not required_groups <= {
                    resource_id(value) for value in row.get("security_group_ids", [])}:
                raise ValueError("Managed Cube is missing a required worker security group")
        if index < target:
            if row and row["state"] != "RUNNING":
                raise ValueError("Retained Cube is not running; restore it before scaling")
            action = "retain" if row else "create_and_verify"
        else:
            action = "drain_then_remove" if row else "absent"
        actions.append({"slot": name, "server_id": sid, "private_ip": address, "action": action})
    return {
        "datacenter_id": dc,
        "target_cubes": target,
        "target_workers": target * 3,
        "read_only": True,
        "actions": actions,
        "required_before_apply": [
            "Validate rebuild with pinned images, credentials and AWS L3 networking",
            "Check ALB and coordinator routing and remaining capacity",
            "Drain active scans and preserve asynchronous result access before removal",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inv = commands.add_parser("inventory")
    inv.add_argument("--datacenter", required=True)
    inv.add_argument("--token-file", type=Path, required=True)
    proposal = commands.add_parser("plan")
    proposal.add_argument("--config", type=Path, required=True)
    proposal.add_argument("--inventory", type=Path, required=True)
    proposal.add_argument("--target", type=int, required=True)
    args = parser.parse_args()
    try:
        if args.command == "inventory":
            result = Ionos(read_token(args.token_file)).inventory(args.datacenter)
        else:
            result = plan(json.loads(args.config.read_text()),
                          json.loads(args.inventory.read_text()), args.target)
        print(json.dumps(result, indent=2))
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        print(f"Fleet planning failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
