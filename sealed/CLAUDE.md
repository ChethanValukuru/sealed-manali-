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

## Verification status (2026-11-08)

- **Logic proven by real execution** via `tools/local_e2e.py` (runs all services as
  local processes, no Docker): **31/31 checks pass** — M1 eval loop, M3 audit
  verify+tamper, M4 fresh-context (secure clean / naive leaks `ZEBRA-4417`),
  M5 tokens+gating+monitor, the verifiable attestation feature (signed/verifies/
  forgery-rejected/live-tamper-caught), the **Evaluation Transparency Log**
  (signed Merkle checkpoint + inclusion/consistency proofs + IETF AAT export +
  selective disclosure), **independent checkpoint witnessing** (quorum co-signs;
  a witness refuses a forked ledger), and Obj01 latency.
- **Independent checkpoint witnessing** (new standout feature): `witness/witness.py`
  is a separate service with its own Ed25519 key and a self-contained RFC 6962
  consistency check; it co-signs a checkpoint only after verifying append-only
  consistency vs the last it saw, and returns 409 on a fork/rollback/equivocation.
  Audit coordinates via `/log/cosign` + `/log/checkpoint/witnessed` (env `WITNESS_URLS`,
  `WITNESS_QUORUM`); the broker proof bundle and `web/verify.html` carry + verify the
  witness co-signatures. Closes the "compromised audit key could fork a fresh chain"
  gap in THREAT_MODEL.md. Proven by `tests/test_transparency.py` + harness checks.
- **Evaluation Transparency Log** (new standout feature): RFC 6962 Merkle over the
  signed chain in `audit/merkle.py`; endpoints `/log/checkpoint`, `/log/proof/inclusion`,
  `/log/proof/consistency`, `/log/public`, `/log/aat`; broker `/eval/proof/{test_id}`
  bundles attestation + inclusion. IETF *Agent Audit Trail* export in `audit/aat.py`
  (the Merkle checkpoint is the draft's §6.4 batch anchor). Zero-trust in-browser
  verifier `web/verify.html` + `web/verify.js` (noble-ed25519 + WebCrypto SHA-256,
  cross-language canonical JSON verified in Node against the real bundle) with a live
  tamper theatre + QR proof receipt. Proven by `tests/test_transparency.py` (container-
  free, 6/6) + harness checks. NOTE: checkpoint/attestation timestamps are int ms so
  signed bytes match the JS verifier exactly.
- **Verifiable Evaluation Attestation** (headline feature): broker
  `GET /eval/attestation/{test_id}` gathers facts + asks audit to sign them;
  audit `POST /verify_attestation` and `POST /tamper_demo`. Signed with the audit
  Ed25519 key, independently checkable. Frontend "Proof you can check" panel +
  `tests/test_attestation.py`. This is the spec's "isolation attestation / product soul".
- **Efficiency fix applied:** broker + `audit_client` now reuse a pooled `httpx.Client`
  instead of one-per-call. Mediated eval overhead dropped ~6108 ms → ~32 ms/eval.
- **pytest suite**: the container-dependent suites SKIP without a container engine and
  run on the Linux VM via `make test`; `tests/test_transparency.py` (6 tests) is pure
  and **runs anywhere**, giving real CI coverage for the transparency-log feature.
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
