# sealed — Secure Adversarial AI Testing Infrastructure

[![CI](https://github.com/ChethanValukuru/sealed-manali-/actions/workflows/ci.yml/badge.svg)](https://github.com/ChethanValukuru/sealed-manali-/actions/workflows/ci.yml)

Runs a **red team**, a **blue team**, and the **model under test** on one standard
Linux VM while keeping all three sealed off from each other, with a tamper-evident
audit log. Progress tracker: `CLAUDE.md`.

> **Build status:** all phases complete (scaffold, eval loop, isolation,
> tamper-evident audit, LLM-native fresh-context isolation, before/after demo,
> capability tokens + disclosure gating + timing + one-way monitor, threat model,
> latency report). Runtime confirmation needs one `make up` on
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

Real inference is an opt-in overlay — [`compose.ollama.yaml`](compose.ollama.yaml)
adds a self-contained **Ollama** service, pulls the model once, and points the
model wrapper at it. No host Ollama needed; the backend sits on its own network
reachable only by the model wrapper.

```bash
make up-ollama                  # same stack, real model (pulls llama3.2:1b, ~1.3GB)
make demo-secure                # now runs against the real model
make down-ollama                # tear down (removes the stack + model volume)
```

Pick a different model with `OLLAMA_MODEL` (e.g. `OLLAMA_MODEL=qwen2.5:0.5b make up-ollama`
for a smaller/faster pull, or `mistral`). The default stack (`make up`) stays on the
deterministic mock so tests and CI are fast; `make up-ollama` is for real runs.

CI also runs an **optional** `ollama-real` job that brings up this overlay with a tiny
model (`qwen2.5:0.5b`) and asserts one genuine generation through the broker — so the
real-model path is proven on every push (non-blocking, so a registry hiccup never reds CI).

## Real attack datasets (AdvBench)

```bash
make fetch-datasets     # downloads real AdvBench prompts -> datasets/advbench.json
make up                 # red now replays the AdvBench benchmark
```

Once fetched, the red tenant **automatically** replays the real **AdvBench**
benchmark — it prefers `advbench.json` and falls back to the bundled 5-prompt
sample if you haven't fetched yet (so the demo always runs). A safety-tuned model
(`make up-ollama`), and the mock model, refuse the great majority of these.

AdvBench prompts are harmful-behaviour *instructions* used only to test that the
model **refuses** them. They are **gitignored** (never committed) and fetched at
deploy time — the repo only ships the mild, safe sample probes.

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
gating, the one-way monitor, the tamper-evident audit chain, the signed attestation,
the audit write-hardening, the **Evaluation Transparency Log** (signed Merkle
checkpoint, inclusion + consistency proofs, IETF AAT export, selective disclosure),
and **independent checkpoint witnessing** (a quorum of witnesses co-signs the ledger
and refuses to co-sign a forked history) — **31/31 passing**, with a measured
mediated-eval overhead of ~30 ms. It does **not** cover the
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

## Console (optional)

The live console lives in [`../web/`](../web/) and is served with the project's
own static server:

```bash
cd ..            # the sealed-project root
node serve-web.js        # then open http://localhost:8080/console.html
```
Live protection status, the activity log, signed proofs, the public ledger and a
tamper demo. It reads the broker/audit/red APIs (CORS-enabled), so the stack must
be up &mdash; `python run-local.py` (no Docker needed) or `make up`.

## Evaluation Transparency Log (the standout feature)

A signed audit log proves *you* can't deny what happened. A **transparency log**
proves it to *everyone* — the same construction behind HTTPS Certificate
Transparency and Sigstore/Rekor, applied to AI-safety tests. On top of the hash
chain, the audit service now publishes a **Merkle tree** with:

- **a signed checkpoint** (Signed Tree Head) — the Merkle root over every record,
  Ed25519-signed: `GET /log/checkpoint`
- **inclusion proofs** — logarithmic proof that one test is in the ledger, under
  the signed root: `GET /log/proof/inclusion?seq=N`
- **consistency proofs** — proof the ledger is append-only and was never rewritten
  between two checkpoints: `GET /log/proof/consistency?first=A&second=B`
- **selective disclosure** — `GET /log/public` returns the ledger with payloads
  redacted to hashes (attack text is never stored in the clear anyway)
- **IETF-standard export** — `GET /log/aat` emits the log in the
  [Agent Audit Trail draft](docs/REFERENCES.md) format (mandatory fields + its own
  RFC 8785 / JCS hash chain). The Merkle checkpoint *is* that draft's optional
  §6.4 batch anchor.
- **independent checkpoint witnessing** — the audit service signs its own ledger, so
  in principle a *compromised audit key* could fork a fresh chain. A quorum of
  independent **witnesses** (separate services, separate keys, in `witness/`) each
  co-sign a checkpoint **only after verifying it is an append-only extension** of the
  one they last saw — and **refuse** on a fork. `GET /log/checkpoint/witnessed`
  returns the co-signed head; the per-test `GET /eval/proof/{id}` bundles the
  witness signatures too. Now no single key — not even sealed's own audit service —
  can rewrite witnessed history. This is Certificate Transparency's witness/gossip
  model, for AI-safety tests.

The broker bundles it all for a single test: `GET /eval/proof/{test_id}` returns the
signed attestation **plus** a Merkle inclusion proof.

**Verify it yourself — in the browser, trusting nothing.** `web/verify.html` is a
zero-trust verifier: paste or fetch a proof and it recomputes the Ed25519
signatures (audit **and** every independent witness), the Merkle inclusion, and the
quorum client-side (no server call is trusted), shows a step-by-step ✓/✗, renders a
scannable **proof receipt** QR, and has a **tamper theatre** — flip one byte (or
forge a witness) and watch verification fail at the exact step.

```bash
make up
curl http://localhost:8000/eval/proof/<test_id>   # a shareable, self-verifying proof
cd ../web && python -m http.server 8080            # open http://localhost:8080/verify.html
```

Proven by `tests/test_transparency.py` (runs with no container) and the transparency
checks in `tools/local_e2e.py`.

## Six objectives → where proven

| # | Objective | Proven by |
|---|---|---|
| 01 | Isolate without breaking function | `make latency` / `tests/test_latency.py` |
| 02 | Prevent information leakage | `tests/test_isolation.py`, `tests/test_access.py` |
| 03 | Audit integrity | `tests/test_audit.py`, `make verify-audit`, `make demo-tamper` |
| 04 | Deployable on standard cloud | `make up` on a stock Ubuntu VM |
| 05 | LLM-native threats | `tests/test_contamination.py` |
| 06 | Quantify residual risk | `THREAT_MODEL.md` |
