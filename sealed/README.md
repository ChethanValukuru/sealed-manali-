# sealed — Secure Adversarial AI Testing Infrastructure

[![CI](https://github.com/ChethanValukuru/sealed-manali-/actions/workflows/ci.yml/badge.svg)](https://github.com/ChethanValukuru/sealed-manali-/actions/workflows/ci.yml)

Runs a **red team**, a **blue team**, and the **model under test** on one standard
Linux VM while keeping all three sealed off from each other, with a tamper-evident
audit log. Progress tracker: `CLAUDE.md`.

> **Build status:** all phases complete (scaffold, eval loop, isolation,
> tamper-evident audit, LLM-native fresh-context isolation, before/after demo,
> capability tokens + disclosure gating + timing + one-way monitor, threat model,
> latency report, minimal dashboard). Runtime confirmation needs one `make up` on
> a Linux Docker/Podman host.

## What's running (Phases 0–2)

Five hardened services. Each tenant shares a network **only with the broker**:

| Service | Role | Port | Network(s) |
|---|---|---|---|
| `broker` | mediates ALL traffic; runs the eval loop | 8000 | red/blue/model/audit nets |
| `audit` | tamper-evident hash-chained + signed log | 8001 | audit-net |
| `model` | model under test (Ollama, or mock) | 8002 | model-net |
| `blue` | trivial defensive filter | 8003 | blue-net |
| `red` | replays attacks through the broker | 8004 | red-net |

Eval loop: **red → broker → model (fresh context) → blue (verdict) → audit**.

Isolation (Phase 2): per-tenant networks, seccomp, `cap_drop ALL`, non-root,
read-only rootfs, cgroup limits — details in [`isolation/README.md`](isolation/README.md).

## Prerequisites (fresh Ubuntu 22.04/24.04 VM)

```bash
sudo apt-get update
sudo apt-get install -y make curl python3
# Container engine — either Docker or rootless Podman:
sudo apt-get install -y docker.io docker-compose-plugin     # Docker, OR
sudo apt-get install -y podman podman-compose               # rootless Podman
```

No GPU or special hardware required (Objective 04).

## Quick start (mock model — always works)

```bash
cp .env.example .env            # MOCK_MODEL=1 by default
make up                         # build + start all five services
make ps                         # confirm all healthy
make demo-secure                # run one full eval cycle + print the audit log
make down                       # tear everything down
```

With Podman instead of Docker:

```bash
make up COMPOSE="podman compose"      # or COMPOSE="podman-compose"
```

## Using a real model (Ollama)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:1b
# point the stack at the host's Ollama and turn off mock mode:
#   in .env:  MOCK_MODEL=0
#   OLLAMA_HOST should resolve from containers (host.containers.internal on
#   Podman; on Docker use the host gateway, e.g. http://172.17.0.1:11434)
make up
make demo-secure
```

## Real attack datasets

```bash
make fetch-datasets     # writes datasets/advbench.json (+ jailbreakbench stub)
```

The red tenant reads `/data/sample_attacks.json` by default (mounted from
`./datasets`). Point `ATTACKS_PATH` at `advbench.json` to replay the real set.

## Proving the objectives (Phase 2)

```bash
make up                 # all five healthy
pip install -r tests/requirements.txt    # one-time: pytest on the host
make test               # Obj 02 (isolation) + Obj 03 (audit) proofs — on a Linux host
make verify-audit       # re-walk the signed hash chain -> intact
make demo-tamper        # edit a copy of the log -> verifier flags the exact entry
```

`make test` runs `pytest` on the host and execs into the containers, so it needs a
Linux Docker/Podman host (the VM) with the stack up. Override the engine with
`make test COMPOSE="podman compose"`.

### Container-free smoke test (no Docker needed)

For quick logic validation on any machine with Python (e.g. Windows dev):

```bash
pip install fastapi "uvicorn[standard]" httpx cryptography
python tools/local_e2e.py
```

This launches every service as a local process over 127.0.0.1 and checks the
real eval loop, fresh-context vs naive contamination, capability tokens, disclosure
gating, the one-way monitor, and the tamper-evident audit chain — **13/13 passing**,
with a measured mediated-eval overhead of ~30 ms. It does **not** cover the
container-isolation asserts (network/seccomp/rootfs/caps/namespaces) or
deployability — those need the Linux container run via `make test`.

## The before/after demo (Phase 3 / M6)

```bash
make demo-naive     # BEFORE: brings up the naive sandbox, shows BOTH leaks
make up             # (if not already up) the secure stack
make demo-secure    # AFTER: same attacks contained + audited
make naive-down     # tear down the naive sandbox
```

`demo-naive` shows (1) **contamination** — Test B recovers Test A's planted secret
(`leaked:true`), and (2) **disclosure** — blue reads red's raw payload off the shared
volume. `demo-secure` shows both contained (`leaked:false`, no shared store) plus the
tamper-evident audit log. The two stacks use different ports/networks so they can run
side by side.

## Acceptance (what Phases 0–3 prove)

- **M0:** `make up` starts all five services healthy; `make down` stops them.
- **M1:** `make demo-secure` runs one full attack→model→defense→verdict cycle; every
  event appears in the audit log (`curl http://localhost:8001/log`).
- **M2 (Obj 02):** `tests/test_isolation.py` — from inside red: broker reachable;
  blue/model/audit unreachable; chmod blocked by seccomp; rootfs read-only;
  `CapEff == 0`; other tenants' processes invisible; other tenants' files unreachable.
- **M3 (Obj 03):** `make verify-audit` intact on a clean log; `make demo-tamper`
  reports the exact broken sequence number.
- **M4 (Obj 05):** `tests/test_contamination.py` — plant in Test A, probe in Test B,
  no trace of the secret (fresh context per test); the naive stack leaks for contrast.
- **M5 (Obj 02):** `tests/test_access.py` — red denied on the blue-only `/disclosure`
  route; blue can't read red's payload mid-test (403) but can after conclude; the
  denial is audited + a monitor alert recorded; tenants can't reach the monitor.
- **M7 (Obj 01, 06):** `make latency` prints isolation overhead per eval and writes
  `tests/latency_report.txt`; `THREAT_MODEL.md` states scope, limits, and failure modes.

## Minimal dashboard (optional)

```bash
make up
make dashboard        # serves http://localhost:8080
```
Isolation Health (live), audit log tail with a **Verify integrity** button, and
buttons to run an eval and a contamination probe. Reads the broker/audit/red APIs
(CORS-enabled); the secure stack must be up.

## Six objectives → where proven

| # | Objective | Proven by |
|---|---|---|
| 01 | Isolate without breaking function | `make latency` / `tests/test_latency.py` |
| 02 | Prevent information leakage | `tests/test_isolation.py`, `tests/test_access.py` |
| 03 | Audit integrity | `tests/test_audit.py`, `make verify-audit`, `make demo-tamper` |
| 04 | Deployable on standard cloud | `make up` on a stock Ubuntu VM |
| 05 | LLM-native threats | `tests/test_contamination.py` |
| 06 | Quantify residual risk | `THREAT_MODEL.md` |
