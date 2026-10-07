# IONOS Cube fleet planning

`ark-api/deploy/fleet.py` provides **read-only inventory and planning**. It does
not yet create, drain, register, or delete Cubes. A `drain_then_remove` plan entry
does not establish that deletion is safe.

Keep credentials and deployment configuration outside the repository. The API
token must be in a regular file owned by the invoking user, with mode `0600`.
The client uses the official IONOS Cloud API and rejects redirects.

```sh
umask 077
python3 ark-api/deploy/fleet.py inventory \
  --datacenter "$IONOS_DATACENTER_ID" \
  --token-file "$IONOS_TOKEN_FILE" > "$FLEET_INVENTORY_FILE"
python3 ark-api/deploy/fleet.py plan \
  --config "$FLEET_CONFIG_FILE" \
  --inventory "$FLEET_INVENTORY_FILE" --target 2
```

The private JSON configuration contains:

- `datacenter_id`: data center UUID.
- `private_lan_id`: positive integer LAN ID used for private address ownership.
  Addresses on unrelated isolated LANs do not claim a fleet slot.
- `minimum_cores` and `minimum_ram_mb`: positive integer resource requirements
  for each Cube, sized for all three workers plus host and entrypoint overhead.
  Inventory must meet both constraints before capacity is reported.
- `minimum_cubes`: minimum retained count, at least one, chosen from availability
  requirements and measured workload.
- `protected_server_ids`: UUIDs of shared infrastructure such as coordinator,
  Redis, and VPN hosts; these must never be fleet members.
- `slots`: ordered objects with `name`, `private_ip`, and `server_id`. Use `null`
  for a genuinely empty slot. Lower-index slots are retained first. Adopt
  existing Cubes by verified UUID; names alone do not establish ownership.

Planning rejects identity mismatches, duplicate identities, occupied addresses,
missing managed resources, non-Cube servers, and pending provider operations.
Retained Cubes must be running. Running does not prove application readiness.
Refresh inventory before every plan; a local plan is not a mutation transaction.

## Pending apply integration

Before enabling mutations, inventory the deployment's ALB forwarding rules,
coordinator configuration, private network, NAT and AWS L3 routes, shared Redis,
pinned images, and credential sources. Do not infer these from example values.

First provision one additional Cube. Verify bootstrap, reboot persistence,
restricted AWS L3 connectivity, authentication, sync/async scans, and chunk
overlap. Register it with routing only after these checks pass.

Before removal, stop new dispatches in both ALB and coordinator, finish accepted
work, preserve asynchronous result access for the retention period, and recheck
resource identity. The coordinator health loop alone is not a drain protocol.
Journal provider operations and reconcile timeouts before retrying mutations.

Apply/recovery integration and a live rebuild test are not implemented yet.
Existing production resources are not modified by this tool.

References: [Cube API](https://docs.ionos.com/cloud/compute-services/cubes/api-how-tos),
[Cloud-init](https://docs.ionos.com/cloud/compute-services/compute-engine/how-tos/boot-cloud-init).
