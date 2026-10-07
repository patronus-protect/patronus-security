#!/usr/bin/env python3
"""Read-only IONOS Cube inventory and explicit fleet capacity planning.

This command deliberately does not provision or delete resources. A plan is
input to deployment validation, not proof that a Cube is safe to remove.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import stat
import sys
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


class Ionos:
    def __init__(self, token):
        self.token = token
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
