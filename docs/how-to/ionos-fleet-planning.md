# IONOS Cube fleet planning

`ark-api/deploy/fleet.py` inventories and plans the fleet and contains reusable
IONOS API primitives. `ark-api/deploy/fleet_roundtrip.py` packages the proven
single-Cube expansion and reduction sequence: create and bootstrap from a healthy
Cube, add its L3 peer, verify workers, stage a replacement Coordinator, hand over
ALB traffic, drain accepted work, verify a retained async result, then remove the
peer and Cube. It defaults to no cloud action unless `up` or `down` is explicitly
selected.

Keep credentials and deployment configuration outside tracked files. The local
`/.private/` directory is ignored by Git and can hold `ionos-api-token.txt`.
The API
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
- `worker_security_group_ids`: optional nonempty list of required server-level
  security group UUIDs. Inventory includes these identities; a declared group
  must be attached before a managed Cube passes planning. Creation can initially
  assign the provider's default group, which does not establish worker access.
- `slots`: ordered objects with `name`, `private_ip`, and `server_id`. Use `null`
  for a genuinely empty slot. Lower-index slots are retained first. Adopt
  existing Cubes by verified UUID; names alone do not establish ownership.

Planning rejects identity mismatches, duplicate identities, occupied addresses,
missing managed resources, non-Cube servers, and pending provider operations.
Retained Cubes must be running. Running does not prove application readiness.
Refresh inventory before every plan; a local plan is not a mutation transaction.

## Fleet scaling

The profile shape is shown in
[`ionos-fleet-profile.example.json`](ionos-fleet-profile.example.json). Copy it to
the ignored `.private/` directory and fill in the Ark origin hostname and local
SSH paths. The script discovers the data center, servers, image/template, NAT,
ALB, and target groups by their configured names through the IONOS API. The
token remains in `.private/ionos-api-token.txt`; SSH private keys stay at their
existing local paths.

```sh
python3 ark-api/deploy/fleet_roundtrip.py plan --config .private/ionos-fleet-profile.json
python3 ark-api/deploy/fleet_roundtrip.py check --config .private/ionos-fleet-profile.json
python3 ark-api/deploy/fleet_scale.py plan --config .private/ionos-fleet-profile.json --target-cubes 8
python3 ark-api/deploy/fleet_scale.py apply --config .private/ionos-fleet-profile.json --target-cubes 8
python3 ark-api/deploy/fleet_roundtrip.py up --config .private/ionos-fleet-profile.json
python3 ark-api/deploy/fleet_roundtrip.py down --config .private/ionos-fleet-profile.json
```

`plan` reads the IONOS inventory and is read-only. `check` also verifies SSH
through the Coordinator, the worker security group, NAT, ALB, Coordinator
origins, and the GPU WireGuard peer without changing resources. `up` repeats
the preflight before mutating cloud resources and writes its journal to
`.private/fleet-roundtrip/journal.json`. It adds one Cube to the configured
baseline. `down` stops dispatch to that Cube,
returns Coordinator traffic to the baseline, waits for active worker submissions
and jobs to reach zero, restores the baseline ALB target lists, removes the exact
WireGuard peer, and deletes the journaled Cube. It then confirms that the accepted
async result still resolves after deletion. `fleet_scale.py plan` chooses the
least-active Cubes while retaining the configured runtime source; `apply` moves
the Coordinator to a ready reduced-origin configuration, drains selected workers,
checks an accepted result through the replacement and official Coordinator,
removes matching WireGuard peers, then deletes only the planned Cube IDs. Its
journal is stored under `.private/fleet-scale/`.

## Coordinator configuration for a different fleet size

The Coordinator runtime accepts a nonempty list of Cube origins, subject to its
admission and upload-memory limits. Its deployment renderer and bootstrap accept
`--cube-count N` alongside the origins file. The default remains twelve, so an
unexpectedly incomplete legacy origins file still fails validation. For a
thirteenth-Cube trial, explicitly request `--cube-count 13`; for a six-Cube fleet,
request `--cube-count 6`. Origins must remain unique HTTP(S) origins and each Cube
retains three Coordinator slots.

Rendering a file does not update a running Coordinator. Membership is loaded at
startup. A live transition therefore requires a ready replacement process,
routing handover, completion of accepted work on the previous process, and shared
result-store access. Do not restart the only routed Coordinator and call that a
seamless fleet transition.

References: [Cube API](https://docs.ionos.com/cloud/compute-services/cubes/api-how-tos),
[Cloud-init](https://docs.ionos.com/cloud/compute-services/compute-engine/how-tos/boot-cloud-init).
