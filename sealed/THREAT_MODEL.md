# Threat Model & Residual Risk

*Objective 06. This document states exactly what `sealed` protects against, what it
only partially mitigates, and where it fails. A safety tool you cannot trust about
its own limits is worthless — so the limits are stated as plainly as the guarantees.
Every "in scope" claim below names the test that proves it.*

## Trust boundaries

- **Trusted:** the host kernel, the container engine (rootless Podman / Docker),
  the **broker**, and the **audit service** (it holds the signing key).
- **Untrusted:** the three tenants — `red`, `blue`, and the `model` under test.
  Each is treated as potentially hostile and is isolated from the others.

## In scope (what we protect against — with the proof)

- **Cross-tenant network observation.** Each tenant shares a network only with the
  broker; no tenant can route or resolve any other tenant, and only the broker can
  reach the audit store. → `tests/test_isolation.py`, `tests/test_access.py::test_tenant_cannot_reach_monitor`
- **Cross-tenant process/filesystem observation.** Separate PID and mount
  namespaces; no shared volumes between tenants. → `tests/test_isolation.py`
- **Privilege escalation on breakout.** Rootless, non-root uid, `cap_drop: ALL`,
  `no-new-privileges`, read-only rootfs, and a seccomp profile blocking
  mount/ptrace/unshare/… reduce host impact. → `tests/test_isolation.py`
- **Premature disclosure.** Red's raw payloads are withheld from blue until the
  test concludes; blue is only ever handed the model output to classify. →
  `tests/test_access.py::test_blue_cannot_read_payload_mid_test`
- **Unauthorized cross-role calls.** Capability tokens scope which broker routes
  each tenant may call; a red attempt on a blue-only route is denied and logged. →
  `tests/test_access.py::test_red_denied_on_blue_only_route`
- **Cross-session model contamination.** Fresh context per test; no KV/conversation
  carryover. A secret planted in test A is not recoverable in test B. →
  `tests/test_contamination.py`
- **Audit tampering.** Append-only, SHA-256 hash-chained, Ed25519-signed log; any
  edit/insert/delete/reorder is detected at the exact entry. →
  `tests/test_audit.py`, `make verify-audit`, `make demo-tamper`
- **Silent boundary violations.** A one-way monitor records every policy violation
  to the audit log; tenants have no read path to it. →
  `tests/test_access.py::test_denial_is_recorded_and_monitored`

## Partially mitigated (reduced, NOT eliminated)

- **Timing side channels.** The broker can normalize response timing to a fixed
  quantum (`TIMING_QUANTUM_MS`); coarse channels remain possible. Overhead is
  measured in `tests/test_latency.py`.
- **Resource-contention channels.** cgroups v2 partition CPU/memory/pids per tenant;
  fine-grained contention signals may still persist on shared hardware.

## Out of scope (known gaps)

- **CPU microarchitectural side channels** (cache timing, MDS / L1TF-class) on
  shared physical cores. We do not claim to prevent these — they need confidential
  computing.
- **A compromised host kernel or container engine.**
- **A malicious broker.** The broker is trusted in this model (it mediates all
  traffic). A compromised broker defeats the guarantees.
- **A compromised audit service.** It holds the Ed25519 signing key, so it could
  forge a fresh chain. The chain protects against everyone *without* the key
  (tenants, storage, transport), not against the signer itself.

## Conditions under which guarantees fail

- Hyperthreading shares microarchitectural state across tenants on one core.
- Tenants are run as root or with added capabilities (defeats the isolation layer).
- Model sessions are reused across tests (defeats fresh-context / Objective 05).
- The nftables host ruleset is relied on without filling in the real subnets — the
  *compose network topology* is the enforced guarantee here; nftables is
  defense-in-depth (`isolation/nftables/`), not asserted by the tests.
- Capability tokens are shared between tenants, or `CAP_ENFORCE=0` (as the naive
  stack deliberately runs) — then any tenant can call any route.

## Future work

- **Confidential computing** (AMD SEV-SNP / Intel TDX) for hardware-backed tenant
  isolation, closing the microarchitectural-channel gap.
- **Per-tenant GPU partitioning** (MIG) so shared inference hardware can't leak.
- **Broker attestation + external signing** to remove the broker and the audit
  signer from the trusted base.
- **Default-deny seccomp** (allowlist) in place of the PoC's denylist profile.
- **Formal verification** of the broker's capability policy.
