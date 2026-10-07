# Build Spec — Secure Adversarial AI Testing Infrastructure
### Hack in Hills '26 · Track 04 (Bayora) · Claude Code build instructions

> **How to use this file:** Give this whole file to Claude Code as the project spec. Build **milestone by milestone, in order (M0 → M7)**. Each milestone has an **acceptance test** — do not move on until it passes. The acceptance tests double as the live demo. Working project name placeholder: **`sealed`** (rename freely).

---

## 1. What we are building (one paragraph)

A proof-of-concept platform that runs a **red team** (attacks an LLM), a **blue team** (defends it), and the **model under test** **simultaneously on one standard Linux cloud VM**, while keeping all three cryptographically and operationally **sealed off from each other**. Every action is written to a **tamper-evident audit log** so any safety finding can be independently reconstructed. The system ships with a **before/after demo** that shows a naive shared sandbox leaking, then the hardened architecture containing the same attack, plus an **honest threat model** stating exactly what is and isn't protected.

This is a **systems / security / infrastructure** project. Deep ML is not required and not the point.

---

## 2. Scope guardrails (read before writing any code)

**DO build (this is what's graded):**
- Strong isolation between red / blue / model (containers, namespaces, seccomp, cgroups, network segmentation).
- A broker that mediates ALL traffic — no direct tenant-to-tenant path.
- A tamper-evident, cryptographically verifiable audit log + a verifier.
- LLM-native isolation: fresh model context per test, no cross-session contamination.
- Automated tests that PROVE each isolation property (these are the demo).
- A before/after demo (naive vs secure).
- An honest threat model documenting residual risk.

**DO NOT build (time sinks that score nothing):**
- A sophisticated jailbreak/attack engine — red just **replays AdvBench/JailbreakBench prompts**.
- A clever ML defense — blue is a **trivial keyword/regex/classifier filter**. Its quality is irrelevant.
- A polished frontend before the demo works — the dashboard is Phase 6, optional, minimal.
- Confidential-computing hardware (SEV-SNP/TDX), multi-node orchestration, user accounts, auth UIs. These go in "future work," not the build.
- Any claim of eliminating hardware side channels. We **mitigate + document**, never claim elimination.

**Honesty rule for the whole build:** if a property is mitigated but not guaranteed (timing channels, microarchitectural leaks), say so in code comments and in `THREAT_MODEL.md`. Do not let the demo or slides claim more than the tests prove.

---

## 3. Mapping to the grading (traceability)

The challenge lists **6 evaluation objectives**. Every one must be demonstrably addressed:

| Objective | Where it's satisfied | Proven by |
|---|---|---|
| **01 Isolate without breaking function** | Isolation layer + broker eval loop still completes in real time | `tests/test_latency.py` — overhead measured & reported |
| **02 Prevent information leakage** | Network segmentation, container isolation, disclosure gating, timing normalization | `tests/test_isolation.py` — leakage attempts all FAIL to leak |
| **03 Guarantee audit integrity** | Hash-chained, Ed25519-signed append-only log + verifier | `tests/test_audit.py` — tamper is detected |
| **04 Build for deployability** | Runs on a stock Ubuntu cloud VM via `make up`, standard runtimes, no special hardware | `README.md` + clean deploy on a fresh VM |
| **05 Address LLM-native threats** | Fresh context per test, output isolation, no KV-cache reuse | `tests/test_contamination.py` — plant-then-probe stays clean |
| **06 Quantify residual risk** | Honest threat model | `THREAT_MODEL.md` complete |

The **7 technical verticals** from the brief map to components: (1) Container isolation → `isolation/`; (2) Network segmentation → `isolation/nftables/` + broker; (3) Access control → broker capability tokens; (4) Audit/provenance → `audit/`; (5) Resource governance → `isolation/cgroups/` + timing; (6) LLM threat surface → `tenants/model/` fresh-context; (7) Observability → `monitor/`.

---

## 4. Architecture

```
   ┌─────────────┐        ┌────────────────────┐        ┌─────────────┐
   │  RED TEAM   │──attack─▶│                    │◀defense─│  BLUE TEAM  │
   │ container   │        │   BROKER / GATEWAY  │        │ container   │
   │ replays     │        │  - mediates ALL     │        │ trivial     │
   │ AdvBench    │        │    traffic          │        │ filter      │
   └─────────────┘        │  - capability tokens│        └─────────────┘
         │                │  - disclosure gating│              │
         │                │  - timing normalize │              │
   ┌─────────────┐        │                     │              │
   │ MODEL UNDER │◀─eval──▶│                    │              │
   │ TEST (Ollama)│        └─────────┬──────────┘              │
   │ fresh ctx   │                   │ every event             │
   └─────────────┘                   ▼ (append-only)           │
                          ┌────────────────────┐               │
                          │ TAMPER-EVIDENT     │               │
                          │ AUDIT LOG          │◀──alerts───────┘
                          │ (hash-chain + sign)│   (one-way)
                          └────────────────────┘
                                   ▲
                          ┌────────────────────┐
                          │ MONITOR (one-way)  │ watches boundary
                          │ writes, never read │ violations
                          └────────────────────┘
```

**Non-negotiable invariants** (the whole project rests on these):
1. No tenant has a network route to another tenant. The broker is the ONLY reachable peer.
2. Red's raw payload is NOT disclosed to blue until the broker marks the test `concluded`.
3. The model receives a **fresh context per test** — no conversation/KV carryover across tests or tenants.
4. The audit log is **append-only**; any edit/insert/delete is detectable by the verifier.
5. Tenants can write (indirectly, via broker) but can never **read** the monitor or the raw audit store.

---

## 5. Tech stack (concrete; swap only with reason)

- **Host:** Ubuntu 22.04 or 24.04 cloud VM (2+ vCPU, 8 GB RAM is plenty for a small model).
- **Containers:** **rootless Podman 4.x** (preferred) or Docker with `userns-remap`. Compose via `podman-compose` / `docker compose`.
- **Runtime hardening:** user namespaces, `--cap-drop=ALL`, read-only rootfs where possible, per-tenant **seccomp** JSON profiles, **cgroups v2** limits. **gVisor (`runsc`)** as an optional stronger boundary for tenants (measure its latency for Obj 01).
- **Network:** separate Podman networks per tenant; a `broker-net` only the broker joins; **nftables** default-deny with explicit tenant↔broker allows only.
- **Broker:** **Python 3.12 + FastAPI + uvicorn** (fastest to build). *Go net/http is an acceptable swap if the team wants lower latency — note it in the README.*
- **Model under test:** **Ollama** running a small model (`llama3.2:1b` or `3b`, or `mistral`) — CPU-friendly, no GPU needed.
- **Audit:** Python + `cryptography` (Ed25519 signatures), SHA-256 hash chain.
- **Attacks:** **AdvBench** (github.com/llm-attacks/llm-attacks) and **JailbreakBench** (jailbreakbench.github.io) — fetch scripts in `datasets/`.
- **Tests:** `pytest`.
- **Dashboard (optional, Phase 6):** FastAPI + a single HTMX/plain-JS page polling broker + audit. Keep it minimal.

---

## 6. Repository layout

```
sealed/
├── README.md                 # what it is, how to deploy on a fresh VM (Obj 04)
├── CLAUDE.md                 # short pointer to this spec + current milestone
├── Makefile                  # up, down, demo-naive, demo-secure, test, verify-audit
├── compose.yaml              # the whole stack (secure mode)
├── compose.naive.yaml        # deliberately-insecure shared sandbox (for the demo)
├── broker/
│   ├── main.py               # FastAPI app; the eval loop
│   ├── policy.py             # capability tokens + disclosure gating
│   ├── timing.py             # response timing normalization
│   └── audit_client.py       # sends events to the audit service
├── audit/
│   ├── log.py                # append-only hash-chained, signed log service (FastAPI)
│   ├── verify.py             # re-walk chain, check hashes + signatures
│   └── keys/                 # ed25519 keypair (gitignored)
├── tenants/
│   ├── red/                  # attack harness (replays AdvBench), Dockerfile, seccomp.json
│   ├── blue/                 # trivial defense filter, Dockerfile, seccomp.json
│   └── model/                # Ollama service wrapper, Dockerfile
├── monitor/
│   └── monitor.py            # one-way observability → writes alerts to audit
├── isolation/
│   ├── seccomp/              # per-tenant seccomp profiles (json)
│   ├── nftables/             # default-deny ruleset
│   └── cgroups/              # resource limit definitions / compose fragments
├── tests/
│   ├── test_isolation.py     # Obj 02
│   ├── test_audit.py         # Obj 03
│   ├── test_contamination.py # Obj 05
│   └── test_latency.py       # Obj 01
├── datasets/
│   ├── fetch_advbench.py
│   └── fetch_jailbreakbench.py
├── dashboard/                # optional, Phase 6
├── THREAT_MODEL.md           # Obj 06
└── docs/
```

---

## 7. Milestones (build in this order)

### M0 — Scaffold & stack skeleton
**Build:** repo layout above; `Makefile` with stub targets; `compose.yaml` bringing up five services (red, blue, model, broker, audit) as minimal healthy containers; `README.md` with fresh-VM deploy steps.
**Acceptance:** `make up` starts all five containers; `make down` stops them; `docker ps`/`podman ps` shows all healthy.

### M1 — Broker eval loop (happy path, no isolation yet)
**Build:** broker endpoints: `POST /test/start` → returns `test_id`; `POST /attack` (from red) → broker sends prompt to model with a **fresh context**, gets response → sends response to blue → blue returns verdict → broker records all events to audit → `POST /test/conclude`. Red harness replays a few AdvBench prompts. Blue is a trivial filter (e.g., flags refusals/keywords).
**Acceptance:** `make demo-secure` runs one full attack→model→defense→verdict cycle end to end; events appear in the audit log.

### M2 — Isolation layer (Obj 02 core)
**Build:** put each tenant on its own Podman network; only broker on `broker-net`; nftables default-deny + explicit tenant↔broker allows. Rootless, `--cap-drop=ALL`, read-only rootfs, per-tenant seccomp profiles, cgroups v2 CPU/mem/pids limits.
**Acceptance:** `pytest tests/test_isolation.py` passes, asserting from inside the red container:
- cannot open a TCP connection to blue or model (only broker reachable);
- cannot see blue/model processes (PID namespace isolated);
- cannot read any blue/model filesystem path;
- a disallowed syscall is blocked by seccomp.

### M3 — Tamper-evident audit (Obj 03)
**Build:** audit service appends entries `{seq, ts, test_id, actor, event, payload_hash, prev_hash, hash, sig}`; `hash = SHA256(seq|ts|...|prev_hash)`; `sig = Ed25519(hash)`. `audit/verify.py` re-walks the chain, verifies every hash link and signature.
**Acceptance:** `make verify-audit` passes on a clean run; then a scripted tamper (edit one entry's payload) makes `verify.py` report the exact broken entry. Show both.

### M4 — LLM-native isolation (Obj 05)
**Build:** guarantee fresh model context per test — new Ollama context/session per `test_id`, no `keep_alive` carryover, system prompt reset, no conversation history reuse. Broker enforces output isolation (model output goes only where policy allows).
**Acceptance:** `pytest tests/test_contamination.py` passes: Test A plants an instruction/secret in the model context; Test B probes for it; B's response shows **no trace** of A. Run the same against naive mode to show contamination there.

### M5 — Access control, disclosure gating, timing, monitor
**Build:**
- **Capability tokens:** each tenant gets a signed token scoping which broker endpoints it may call (red can't call blue-only routes, etc.).
- **Disclosure gating:** broker withholds red's raw payload from blue until `test/conclude`; before that, blue sees only what it needs (the model output to classify).
- **Timing normalization:** broker pads responses to a fixed quantum to blunt timing inference (document that this mitigates, not eliminates).
- **One-way monitor:** watches nftables denials + broker policy violations, writes alerts to audit; tenants have no read path to it.
**Acceptance:** tests assert blue cannot fetch red's raw payload mid-test (403/empty); a red attempt to hit a blue-only route is denied and logged; monitor alerts appear in the audit log; no tenant can read the monitor or raw audit store.

### M6 — Before/after demo + minimal dashboard
**Build:** `compose.naive.yaml` = deliberately broken shared sandbox (one network, shared volume, blue can read red's payload file, model context reused). `make demo-naive` shows the **leak + contamination**. `make demo-secure` shows the **same attack contained + logged**. Optional minimal dashboard: live eval loop, audit log tail, and a PASS/FAIL panel for the isolation tests.
**Acceptance:** running both targets back to back visibly shows leak → contained. A non-technical viewer can see the difference.

### M7 — Threat model + latency report + polish (Obj 06, 01)
**Build:** `THREAT_MODEL.md` (template in §9). `tests/test_latency.py` measures broker/isolation overhead vs a bare baseline and prints numbers. Tidy `README.md` deploy instructions for a fresh VM.
**Acceptance:** threat model complete and honest; latency overhead reported with a one-line conclusion ("isolation adds ~X ms/eval; does not invalidate real-time use").

---

## 8. The demo script (what you actually show judges)

1. **Frame it (10s):** "Red attacks, blue defends, model under test — all in one sandbox. If they leak into each other, the safety result is worthless."
2. **`make demo-naive` (30s):** show red's attack payload appearing on the blue side *before the test concludes*, and Test B picking up Test A's planted context. "This result can't be trusted."
3. **`make demo-secure` (40s):** same attack. Show the isolation test panel going green, blue getting only what policy allows, the model context clean, and every event landing in the audit log.
4. **Tamper proof (20s):** edit one audit entry live; run `make verify-audit`; it flags the exact entry. "Findings are independently verifiable."
5. **Honesty (20s):** open `THREAT_MODEL.md`: "Here's what we protect against, here's what we don't — CPU-level side channels need confidential computing, that's our roadmap. A safety tool you can't trust about its limits is worthless."

---

## 9. `THREAT_MODEL.md` template (Obj 06 — fill this honestly)

```
# Threat Model & Residual Risk

## In scope (what we protect against)
- Cross-tenant network observation: tenants cannot reach each other (default-deny + per-tenant networks).
- Cross-tenant filesystem/process observation: separate rootless containers, PID/mount namespaces.
- Premature disclosure: red payloads withheld from blue until test conclusion (broker gating).
- Cross-session model contamination: fresh context per test; no KV/conversation reuse.
- Audit tampering: hash-chained + Ed25519-signed append-only log; any edit detected.
- Privilege escalation via breakout: rootless + cap-drop + seccomp reduce host impact.

## Partially mitigated (reduced, NOT eliminated)
- Timing side channels: broker response timing normalized to a quantum; coarse channels remain possible.
- Resource-contention channels: cgroups partition CPU/mem; fine-grained contention signals may persist.

## Out of scope (known gaps)
- CPU microarchitectural side channels (cache timing, MDS/L1TF-class) on shared physical cores.
- A compromised host kernel or hypervisor.
- Malicious broker (broker is trusted in this model).

## Conditions under which guarantees fail
- Hyperthreading enabled on shared cores (microarchitectural leakage).
- Running tenants as root / with added capabilities (defeats isolation).
- Reusing model sessions across tests (defeats Obj 05).

## Future work
- Confidential computing (AMD SEV-SNP / Intel TDX) for hardware-backed tenant isolation.
- Per-tenant GPU partitioning (MIG) for isolated inference hardware.
- Formal verification of broker policy; broker attestation to remove it from the trusted base.
```

---

## 10. First commands for Claude Code

```
# 1. Confirm environment
podman --version   # or docker --version
# 2. Start at M0: scaffold repo, Makefile, compose.yaml, README
# 3. Work milestone by milestone; after each, run its acceptance test before continuing
make up
pytest tests/ -v
make verify-audit
make demo-naive
make demo-secure
```

**Definition of done for the whole project:** all six objective tests green, both demo modes work, `THREAT_MODEL.md` complete, and the project deploys clean on a fresh Ubuntu VM with `make up`.
