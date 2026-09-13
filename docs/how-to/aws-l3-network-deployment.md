# AWS L3 network deployment

Ark workers can reach a remote Unified L3 Triton service through a private
WireGuard network. The normal synchronous gateway path remains unchanged: L1/L2
capacity stays held while a worker waits for L3.

## Trust boundary

Triton's HTTP endpoint has no application authentication. Treat the GPU host and
every WireGuard peer that can route to the service as trusted. Bind Triton only
to the GPU host's WireGuard address, do not expose its HTTP port through the
cloud security group, and restrict WireGuard peers and host firewall rules to
the sources that run Ark workers.

Worker containers should use a dedicated egress network whose forwarding rules
allow only TCP traffic to the Triton WireGuard address and port. Keep the normal
application network attached as well. Route only the GPU host's WireGuard
address through the tunnel; no provider-private LAN route is required.

## Worker configuration

Set the remote origin on worker processes only:

```sh
PATRONUS_UNIFIED_TRITON_URL=http://<triton-wireguard-address>:8090
PATRONUS_UNIFIED_TRITON_TIMEOUT_MS=1000
```

The URL must be an HTTP(S) origin without credentials, a path, query, or
fragment. Unsetting it and restarting a worker restores local Unified inference.
Keep local model assets available for validation and rollback.

## Validation

Before a fleet rollout, verify the WireGuard handshake, confirm that the Triton
port is unreachable through public interfaces, and confirm that worker-container
egress to destinations other than the Triton endpoint is rejected. Run the
service verification described in the Triton deployment README, then exercise
the normal L1/L2/L3 application path on one worker before rolling out workers
incrementally.

Include all three independent tool-tag properties in the canary and verify that
each promoted property receives its own L3 result and L2 arbitration context.

## Rollback

Remove the worker image and remote-URL overrides, then recreate workers
incrementally and wait for readiness. Remove the dedicated egress network and
WireGuard configuration only after no worker depends on the remote service.
Preserve unrelated deployment changes made after the rollout.
