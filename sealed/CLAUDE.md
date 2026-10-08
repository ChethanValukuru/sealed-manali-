# CLAUDE.md — project pointer & progress

**Project:** `sealed` — Secure Adversarial AI Testing Infrastructure

Built **phase by phase, in order**. Each phase has a hard exit criterion — do not advance until it passes.

## Phase map (milestones grouped)

- [x] **Phase 0 — Foundation** (M0): repo scaffold, Makefile, compose (5 healthy services), README.
      Exit: `make up` → all five healthy; `make down` stops them.
- [x] **Phase 1 — Working eval loop** (M1): broker `/test/start`, `/attack`, `/test/conclude`;
      red replays sample attacks; model answers fresh-context; blue returns a verdict; audit records events.
      Exit: `make demo-secure` runs one full cycle; events appear in the audit log.
- [x] **Phase 2 — Core security proofs** (M2 isolation + M3 tamper-evident audit).
      Exit: `make test` green (isolation + audit); `make verify-audit` intact; `make demo-tamper` flags the entry.
- [x] **Phase 3 — LLM-native isolation + before/after demo** (M4 + M6-core).
      Exit: `tests/test_contamination.py` passes (fresh context, no leak); `make demo-naive` shows
      both leaks (contamination + disclosure), `make demo-secure` shows them contained.
- [x] **Phase 4 — Harden, honesty & polish** (M5 + M7 + dashboard).
      Exit: `tests/test_access.py` green (tokens, gating, monitor); `THREAT_MODEL.md` complete;
      `make latency` reports overhead; `make dashboard` serves the console.

**Definition of done:** all six objective tests green, both demo modes work, `THREAT_MODEL.md`
complete, clean deploy on a fresh VM via `make up`. (Runtime run pending on a Linux host.)

## Current state (all phases complete)

- 5 services: `broker`, `audit`, `model`, `tenants/red`, `tenants/blue`.
- Eval loop flows: **red → broker → model (fresh ctx) → blue → verdict → audit**.
- **Isolation (Phase 2 / M2):** per-tenant networks (each tenant shares a net ONLY with the broker;
  audit reachable only by broker), seccomp (`isolation/seccomp/tenant.json`), `cap_drop: ALL` +
  `no-new-privileges`, non-root uid 10001, read-only rootfs + `/tmp` tmpfs, cgroup cpus/mem/pids limits.
  nftables default-deny shipped as host defense-in-depth (`isolation/nftables/`). Proven by
  `tests/test_isolation.py`.
- **Tamper-evident audit (M3):** SHA-256 hash chain + Ed25519 signatures (`audit/chain.py`),
  `verify.py` CLI + `/verify` endpoint, `tamper_demo.py`. Proven by `tests/test_audit.py`.
- **LLM-native isolation (Phase 3 / M4):** model `CONTEXT_MODE=fresh` (secure) vs `persistent` (naive);
  fresh = stateless per call, no KV/history carryover. Proven by `tests/test_contamination.py`
  (plant in Test A, probe in Test B, no trace).
- **Before/after demo (Phase 3 / M6-core):** `compose.naive.yaml` (one net, shared `/shared` volume,
  persistent model) exposes both a disclosure leak (blue reads red's payload via `/peek_shared`) and
  contamination; `make demo-naive` shows the leaks, `make demo-secure` shows them contained.
- Model runs against **Ollama** when available, else a **deterministic mock** (`MOCK_MODEL=1`) so the
  loop + contamination demo are always reproducible.
- **Access control (Phase 4 / M5):** capability tokens (`broker/policy.py`; each tenant holds only its
  own via `CAP_TOKEN`), token-enforced disclosure gating (`/disclosure` route: red denied by cap, blue
  withheld until conclude), timing normalization (`timing.py`, `TIMING_QUANTUM_MS`), one-way `monitor`
  service (audit-net only; writes alerts, tenants can't reach it). Proven by `tests/test_access.py`.
- **Honesty + perf (Phase 4 / M7):** `THREAT_MODEL.md` (Obj 06); `tests/test_latency.py` +
  `make latency` report isolation overhead (Obj 01). Minimal `dashboard/index.html` (`make dashboard`).

## Verification status (2026-10-07)

- **Logic proven by real execution** via `tools/local_e2e.py` (runs all services as
  local processes, no Docker): **13/13 checks pass** — M1 eval loop, M3 audit
  verify+tamper (broke at exact seq), M4 fresh-context (secure clean / naive leaks
  `ZEBRA-4417`), M5 tokens+gating+monitor, Obj01 latency.
- **Efficiency fix applied:** broker + `audit_client` now reuse a pooled `httpx.Client`
  instead of one-per-call. Mediated eval overhead dropped ~6108 ms → ~32 ms/eval.
- **pytest suite**: 18 tests collect cleanly; they SKIP without a container engine and
  will run on the Linux VM via `make test`.
- **Not yet run anywhere:** M2 isolation (network/seccomp/rootfs/caps/namespaces) and
  Obj04 deployability — these require a Linux Docker/Podman host; statically verified.

## Known soft spots (honest, not failures)

- nftables ruleset needs subnets filled in (`isolation/nftables/apply.sh`); the compose network
  topology is the enforced guarantee, nft is defense-in-depth and not asserted by tests.
- seccomp uses default-allow + denylist for PoC robustness (production = default-deny allowlist).
- Audit holds its own signing key; broker is trusted. Both documented in `THREAT_MODEL.md`.
- Runtime confirmation needs one `make up` on a Linux Docker/Podman host (not possible on Windows).

## Scope discipline (do not drift)

- Red just **replays** prompts (no jailbreak engine). Blue is a **trivial keyword filter** (quality irrelevant).
- This is a **systems/security** project, not ML. Grading rewards isolation + audit integrity + honesty.
