# cgroups v2 — resource governance

Per-tenant CPU / memory / PID limits (the "resource governance" vertical) are
applied directly in `compose.yaml` via `cpus`, `mem_limit`, and `pids_limit` on
each service, rather than as separate cgroup fragments. Current limits:

| service | cpus | mem_limit | pids_limit |
|---|---|---|---|
| broker  | 1.0  | 512m | 256 |
| model   | 2.0  | 2g   | 256 |
| red     | 0.5  | 256m | 128 |
| blue    | 0.5  | 256m | 128 |
| audit   | 0.5  | 256m | 128 |
| monitor | 0.25 | 128m | 64  |

These partition CPU/memory/pids between tenants, bounding resource-contention
side channels (mitigated, not eliminated — see `../../THREAT_MODEL.md`). On
rootless Podman, cgroups v2 must be delegated to the user (the default on modern
systemd distros); verify with `cat /sys/fs/cgroup/cgroup.controllers`.
