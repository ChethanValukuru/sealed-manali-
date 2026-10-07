# isolation/ — the isolation layer (Phase 2 / M2)

Five mechanisms, layered. The compose file wires the first four; nftables is an
optional host-level fifth layer.

### 1. Network segmentation (primary, proven by tests)
Each tenant shares a network **only with the broker**:

| network | members |
|---|---|
| `red-net` | red, broker |
| `blue-net` | blue, broker |
| `model-net` | model, broker |
| `audit-net` | audit, broker |

A tenant has **no route and no DNS** to any other tenant — the broker is the only
reachable peer (invariant 1). Audit is reachable only by the broker, so tenants
can't read the audit store (invariant 5). `tests/test_isolation.py` connects from
inside the red container to prove blue/model/audit are unreachable and broker is.

### 2. seccomp (`seccomp/tenant.json`)
Applied to red/blue/model via `security_opt`. ERRNO-blocks escalation/breakout
syscalls (`mount`, `ptrace`, `unshare`, `setns`, `bpf`, `keyctl`, …) plus a
`chmod` **canary** the test uses to confirm the profile is actually in force.

### 3. Capabilities & privileges
Every service runs with `cap_drop: [ALL]` and `no-new-privileges`. Tenants and the
broker run as a **non-root** user (uid 10001). The test asserts `CapEff == 0`.

### 4. Read-only rootfs + cgroups v2
Tenants and broker use `read_only: true` with a `/tmp` tmpfs (so a breakout can't
persist to the image). `PYTHONDONTWRITEBYTECODE=1` keeps Python happy on a
read-only fs. Per-service `cpus` / `mem_limit` / `pids_limit` partition resources
(cgroups v2) — bounding resource-contention side channels (mitigated, not
eliminated; see THREAT_MODEL.md).

### 5. nftables default-deny (`nftables/`, optional defense-in-depth)
Host firewall that drops inter-container forwarding by default, allowing only
tenant↔broker. The compose topology already prevents tenant-to-tenant traffic;
this is a second layer and a source of drop events for the Phase 4 monitor. Apply
with `nftables/apply.sh` after `make up`.

## Proving it
```bash
make up
make test            # runs tests/test_isolation.py (+ audit tests)
```
