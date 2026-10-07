# COMPLETE SOLUTION — "Sealed"
## Secure Adversarial AI Testing Infrastructure
### Hack in Hills '26 · Track 04 (Bayora) · End-to-end playbook

> This is the single source of truth for the whole project: the problem, the product, the full stack, the business case, the team plan across all four hackathon rounds, the pitch, the judge Q&A, and the build. "Sealed" is a placeholder name — rename it. Jump to any section via the contents.

---

## Table of Contents
0. Executive summary
1. The problem (fully understood)
2. The solution concept (why it wins)
3. Product vision — what the user actually gets
4. Full-stack system design
5. Technical build plan (milestones)
6. The full tech stack (every layer)
7. The demo (before / after)
8. Market & business case
9. Team & execution plan (the four rounds + finale)
10. The pitch (90 seconds + deck outline)
11. Risk, honesty & judge Q&A prep
12. Future scope
- Appendix A — Commands
- Appendix B — Datasets & resources
- Appendix C — Repository layout

---

## 0. Executive summary

AI safety teams test a model by having a **red team attack it** and a **blue team defend it** — both running in the **same cloud sandbox** as the model under test. Because they share one environment, the attack can leak to the defenders, the defense can leak to the attackers, and the model gets contaminated between tests. When that happens, **every safety finding is quietly worthless** — it creates false confidence in a model about to be deployed.

**Sealed** is the infrastructure that fixes this: it runs red team, blue team, and model **simultaneously on one standard cloud VM** while keeping all three **cryptographically and operationally sealed off from each other**, and records every action in a **tamper-evident audit log** so any finding can be independently verified. Every result the platform produces carries an **isolation attestation** — proof that the test was sound.

The winning wedge is two things most teams won't do: a **before/after demo** that makes invisible security visible (show the leak, then show it contained), and an **honest threat model** that states exactly what is and isn't protected. On a rubric that rewards innovation, technical execution, and rigor, that combination is finalist-grade.

---

## 1. The problem (fully understood)

**Context.** Bayora is an AI safety validation platform built on a continuous **red-team / blue-team** loop. The red team probes a language model with adversarial prompts, jailbreaks, and injection strategies; the blue team builds countermeasures; together they surface safety failures *before* deployment.

**The flaw.** All three parties — red team, blue team, and the client LLM — currently share one Docker-based cloud sandbox. Adversarial and defensive work must run at the same time, but the validity of every finding depends on strong isolation. Four requirements the current setup can't guarantee:

1. Red-team attack payloads must not be observable by the blue team **before a test concludes**.
2. Blue-team defensive logic must not be exposed or inferable by red-team tooling.
3. The client LLM must stay **clean and uncontaminated** throughout.
4. Findings must not be invalidated by **environmental leakage or cross-tenant interference** — including subtle side channels.

**The core question (Bayora's words):** how do you build a shared environment where adversaries, defenders, and the model operate simultaneously without exposing sensitive state or creating exploitable side channels?

**Why it's hard.** "Just use separate containers" is not enough. Containers share a kernel, CPU, memory bus, and often a model-inference backend — opening timing channels, shared-cache leaks, resource-contention signals, and **LLM-specific leaks** like a shared KV-cache or prompt-context bleeding across sessions. Standard container security doesn't touch those.

**What the brief grades (6 objectives):** (01) isolate without breaking real-time function; (02) prevent information leakage incl. side channels; (03) guarantee tamper-evident audit integrity; (04) deployable on standard cloud, no special hardware; (05) address LLM-native threats; (06) quantify residual risk honestly.

---

## 2. The solution concept (why it wins)

**One line:** seal the three tenants off from each other while they still run together — and *prove* it, both in a live demo and in a verifiable audit trail.

**The two moves that win the room:**

1. **Make invisible security visible.** Security projects normally demo as a diagram and a claim. We ship a **naive mode** (deliberately broken shared sandbox) and a **secure mode**. Judges *see* an attack leak to the blue team and contaminate the model in naive mode, then *see* the same attack contained and logged in secure mode. That contrast is the entire emotional payload of the pitch.

2. **Honesty as a feature (Objective 06).** Most teams will claim "fully secure" and fold when a judge names a side channel. We state up front what we protect against, what we don't (CPU microarchitectural channels need confidential computing), and where guarantees fail. A safety tool you can't trust about its own limits is worthless — so our honesty *is* the credibility.

**Why this beats the other tracks for this rubric:** it's the most technically novel of the four problem statements, it leans on systems/security depth (where a capable team separates from the pack), and both the demo and the threat model are fully in your control — nothing on stage can physically fail the way a robot or a live smart contract can.

---

## 3. Product vision — what the user actually gets

This is the "not just technical" layer: Sealed is a **product**, not only an isolation mechanism.

### 3.1 Who uses it
- **Primary: an evaluation operator / AI-safety engineer** at an AI lab or a red-team-as-a-service platform (like Bayora). They run evaluations and need the results to be trustworthy.
- **Secondary: an auditor or regulator** who must independently verify that a safety finding was produced in a sound, uncontaminated environment.
- **Tertiary: an AI-lab leader** who needs to show customers/regulators provable safety testing, not just a claim.

### 3.2 End-to-end user journey
1. **Start an evaluation.** The operator opens the dashboard, picks a **model under test**, selects an **attack suite** (AdvBench / JailbreakBench), and chooses the red and blue configurations.
2. **Watch it run, sealed.** A live view shows attacks flowing in and verdicts coming out — alongside an **Isolation Health panel** that stays green as long as every boundary holds (no cross-tenant network reach, no seccomp violations, model context fresh).
3. **See contamination prevented.** The operator can run a "contamination probe" showing one test cannot bleed into the next.
4. **Read the findings — with proof.** Each evaluation produces a report: which attacks succeeded, how the defense performed, and crucially an **isolation attestation** plus a link to the **verifiable audit trail**.
5. **Verify independently.** An auditor clicks **Verify integrity** — the platform re-walks the hash-chained log and confirms (green) that nothing was tampered with, or flags the exact broken entry.

### 3.3 The screens (dashboard)
- **New Evaluation** — model picker, attack-suite picker, red/blue config, Start.
- **Live Evaluation** — the eval loop in motion; attack → model → defense → verdict; running counters.
- **Isolation Health** — real-time boundary status: per-tenant network isolation, seccomp/syscall blocks, cgroup limits, model-context freshness. All green = sealed.
- **Audit Log** — chronological event stream; a **Verify integrity** button; tamper highlighted if present.
- **Findings Report** — results + isolation attestation + downloadable verifiable log.
- **Guarantees & Threat Model** — plain-language page: what the platform protects against and its documented limits.

### 3.4 The product's soul: the isolation attestation
Every finding Sealed emits is stamped with: *"Produced in a verified-isolated environment; audit chain intact; model context fresh."* That single artifact is the product's entire value proposition made tangible — it converts "trust us" into "verify us." It's also the thing no competing hackathon team will think to productize.

---

## 4. Full-stack system design

### 4.1 The layers (top to bottom)
1. **Presentation layer** — the web dashboard (operator + auditor views).
2. **API layer** — the broker's REST API; the audit service's verify API.
3. **Service layer** — broker (orchestration + policy), audit service, monitor, tenant manager.
4. **Isolation layer** — containers, user namespaces, seccomp, cgroups v2, network segmentation.
5. **Data layer** — append-only hash-chained audit store, attack-dataset store, evaluation-results store.
6. **Infrastructure layer** — a single standard Linux cloud VM, Podman compose, portable to any cloud.

### 4.2 Architecture

```
 ┌───────────────────────── PRESENTATION ─────────────────────────┐
 │  Web dashboard: New Eval · Live Eval · Isolation Health ·       │
 │  Audit Log (+Verify) · Findings Report · Guarantees            │
 └───────────────────────────────┬────────────────────────────────┘
                                  │ REST
 ┌───────────────────────── SERVICE LAYER ────────────────────────┐
 │   ┌─────────┐   attack   ┌──────────────┐  defense  ┌────────┐ │
 │   │  RED    │───────────▶│   BROKER /   │◀──────────│  BLUE  │ │
 │   │ (replay │            │   GATEWAY    │           │(filter)│ │
 │   │ AdvBench)│           │ policy·tokens│           └────────┘ │
 │   └─────────┘            │ disclosure   │                      │
 │   ┌─────────┐    eval    │ gating·timing│   ┌──────────────┐   │
 │   │ MODEL   │◀──────────▶│ normalization│──▶│   MONITOR    │   │
 │   │(Ollama, │            └──────┬───────┘   │ one-way only │   │
 │   │fresh ctx)│                  │ events    └──────┬───────┘   │
 │   └─────────┘                   ▼                  │ alerts    │
 │                        ┌──────────────────┐        │           │
 │                        │  AUDIT (append-   │◀───────┘           │
 │                        │  only·hash-chain· │                    │
 │                        │  Ed25519-signed)  │                    │
 │                        └──────────────────┘                    │
 └─────────────────────────────────────────────────────────────── ┘
 ┌──────────── ISOLATION LAYER (host) ────────────┐
 │ rootless Podman · userns · seccomp · cgroups v2 │
 │ per-tenant networks · nftables default-deny     │
 └─────────────────────────────────────────────────┘
 ┌──────────── INFRASTRUCTURE ────────────┐
 │ one standard Ubuntu cloud VM, no special hw │
 └─────────────────────────────────────────────┘
```

### 4.3 Components in detail
- **Dashboard (frontend).** Operator and auditor views (§3.3). Hackathon-fast option: FastAPI + HTMX or a small React/Next app polling the broker and audit APIs. Shows the eval loop, isolation health, and the verify button. *Keep minimal until the backend + demo work.*
- **Broker / gateway.** The only peer every tenant can reach. Runs the eval loop, enforces **capability tokens** (which endpoints each tenant may call), **disclosure gating** (withholds red's raw payload from blue until test conclusion), and **timing normalization** (pads responses to a fixed quantum). Emits every event to audit.
- **Audit service.** Append-only, **hash-chained** (`hash = SHA256(seq|ts|...|prev_hash)`), **Ed25519-signed** entries. Exposes a **verify** endpoint/CLI that re-walks the chain and checks every link + signature.
- **Monitor.** One-way observability: watches nftables denials and broker policy violations, writes alerts to audit. Tenants have **no read path** to it — so the security layer isn't itself a leak.
- **Tenants.** `red` replays AdvBench/JailbreakBench prompts; `blue` is a trivial filter (keyword/regex/simple classifier — quality irrelevant); `model` is Ollama with a small model, given a **fresh context per test**.
- **Isolation layer.** Rootless Podman, user namespaces, `--cap-drop=ALL`, read-only rootfs where possible, per-tenant seccomp profiles, cgroups v2 (CPU/mem/pids), per-tenant networks with nftables default-deny. Optional gVisor (`runsc`) for a stronger boundary (measure its latency).
- **Data layer.** Audit store (append-only file or SQLite with the hash chain), attack-dataset store (fetched AdvBench/JailbreakBench), results store (per-evaluation findings + attestation).

### 4.4 Core invariants (the project rests on these)
1. No tenant has a network route to another tenant — the broker is the only reachable peer.
2. Red's raw payload is not disclosed to blue until the broker marks the test `concluded`.
3. The model gets a fresh context per test — no KV/conversation carryover across tests or tenants.
4. The audit log is append-only; any edit/insert/delete is detectable.
5. Tenants can never read the monitor or the raw audit store.

### 4.5 Data model (core entities)
- **Evaluation** `{id, model, attack_suite, red_cfg, blue_cfg, status, started_at, concluded_at, attestation}`
- **Test** `{id, eval_id, attack_ref, model_response_hash, blue_verdict, status}`
- **AuditEntry** `{seq, ts, eval_id, actor, event, payload_hash, prev_hash, hash, sig}`
- **Alert** `{seq, ts, source, kind, detail}` (written by monitor, into audit)
- **Attestation** `{eval_id, isolation_ok, chain_intact, context_fresh, generated_at, signature}`

### 4.6 API surface (broker)
- `POST /eval/start` → `{eval_id}`
- `POST /attack` (red) → routes to model (fresh ctx) → blue → records
- `GET /blue/next` (blue) → returns only policy-permitted data (not red's raw payload mid-test)
- `POST /eval/conclude` → finalizes, generates attestation, discloses payloads for post-hoc analysis
- `GET /health/isolation` → live boundary status for the dashboard
- Audit service: `GET /audit/{eval_id}`, `POST /audit/verify` → `{intact: bool, broken_seq?}`

---

## 5. Technical build plan (milestones)

Build in order; each milestone's acceptance test doubles as demo material. (Full detail in the companion `Build_Spec_for_Claude_Code.md`.)

- **M0 — Scaffold & stack.** Repo, Makefile, compose bringing up red/blue/model/broker/audit healthy. *Acceptance: `make up` → all healthy.*
- **M1 — Broker eval loop (happy path).** red → broker → model (fresh ctx) → blue → verdict → audit. *Acceptance: one full cycle, events logged.*
- **M2 — Isolation layer (Obj 02).** per-tenant networks, nftables default-deny, rootless, cap-drop, seccomp, cgroups. *Acceptance: `test_isolation.py` — red can't reach/see/read blue or model; blocked syscall denied.*
- **M3 — Tamper-evident audit (Obj 03).** hash-chain + Ed25519 + verifier. *Acceptance: verify passes clean; tamper → flagged exactly.*
- **M4 — LLM-native isolation (Obj 05).** fresh context per test, output isolation. *Acceptance: `test_contamination.py` — plant-then-probe stays clean.*
- **M5 — Access control, disclosure gating, timing, monitor.** capability tokens, withhold red payload from blue mid-test, timing quantum, one-way monitor. *Acceptance: blue can't read red's raw payload mid-test; monitor alerts hit audit; tenants can't read monitor.*
- **M6 — Before/after demo + minimal dashboard.** naive vs secure compose; live view. *Acceptance: leak visible in naive, contained in secure.*
- **M7 — Threat model + latency report + polish (Obj 06, 01).** `THREAT_MODEL.md`; overhead measured. *Acceptance: threat model complete; latency reported.*

**Definition of done:** all six objective tests green, both demo modes work, threat model complete, clean deploy on a fresh VM.

---

## 6. The full tech stack (every layer)

| Layer | Choice | Why |
|---|---|---|
| Frontend | FastAPI + HTMX (fast) or React/Next | Live eval view, isolation health, verify button |
| API | FastAPI + uvicorn (Python 3.12) | Fastest to build; Go is the perf swap |
| Broker logic | Python (or Go) | Eval loop, policy, tokens, gating |
| Audit | Python + `cryptography` (Ed25519), SHA-256 | Hash-chained, signed, verifiable |
| Monitor | Python; reads nftables/seccomp denials | One-way observability |
| Model | Ollama (`llama3.2:1b/3b` or `mistral`) | Small, CPU-friendly, no GPU |
| Tenants | Containers (red/blue/model) | Isolated workloads |
| Isolation | rootless Podman, userns, seccomp, cgroups v2, nftables; gVisor optional | Standard-cloud isolation, no special hw |
| Data | append-only file / SQLite (audit), dataset + results stores | Simple, verifiable |
| Infra | Ubuntu 22.04/24.04 cloud VM, Podman compose | Objective 04: deployable anywhere |
| Attacks | AdvBench, JailbreakBench | Real adversarial payloads |
| Tests | pytest | Objective proofs = demo |

---

## 7. The demo (before / after)

1. **Frame (10s):** "Red attacks, blue defends, model under test — one sandbox. If they leak into each other, the result is worthless."
2. **`make demo-naive` (30s):** red's payload shows up on the blue side before the test concludes; Test B picks up Test A's planted context. "Can't trust this."
3. **`make demo-secure` (40s):** same attack; isolation panel green; blue sees only permitted data; model context clean; every event in the audit log.
4. **Tamper proof (20s):** edit one audit entry live; `make verify-audit` flags the exact entry. "Independently verifiable."
5. **Honesty (20s):** open the threat model — what's covered, what's not, what's next. "A safety tool you can't trust about its limits is worthless."

---

## 8. Market & business case

### 8.1 Who needs this
AI labs and model providers; AI-safety / red-team-as-a-service platforms (Bayora itself); and enterprises deploying LLMs under compliance pressure — anyone who must **prove** their safety testing was sound, not merely assert it.

### 8.2 Market size
- **AI red-teaming services:** ~**$1.75B (2025) → ~$6.2B (2030)**, ~**28% CAGR** (multiple market reports; figures vary ~$1.5–1.75B for 2025).
- **Total AI-security market:** ~**$31B (2025) → ~$86B (2030)**, ~25% CAGR.
- **Regulatory tailwind:** the **EU AI Act**, **NIST AI RMF**, **OWASP LLM Top 10**, and **ISO 42001** increasingly require demonstrable, auditable AI safety testing — turning "trustworthy test infrastructure" from nice-to-have into compliance-driven spend.
*(Cite "AI Red Teaming Service Market Report; AI Security Market Outlook, 2025" on the slide.)*

### 8.3 Revenue model
- **B2B SaaS / licensing** of the isolation + audit layer.
- **Compliance & certification:** verifiable audit trails packaged for regulators/customers (the attestation as a paid artifact).
- **Per-evaluation pricing** for red-team-as-a-service platforms running many evaluations.

### 8.4 Go-to-market
Land with AI-safety platforms and red-team vendors who already run evaluations and feel the trust problem acutely (Bayora is the archetype). Expand to enterprise AI governance teams as the EU AI Act compliance deadline pressure grows.

### 8.5 Competitive landscape
Existing AI red-teaming tools focus on **finding** vulnerabilities (the attacks). Almost none focus on **guaranteeing the test environment was sound** — the integrity and isolation of the evaluation itself. That gap is the wedge: we're not another attack tool, we're the trust layer underneath them.

---

## 9. Team & execution plan (the four rounds + finale)

**Hackathon structure:** four rounds to the summit — (1) idea + deck, (2) prototype round, (3) public pitch, (4) ~24h finale in Manali. Judged on innovation, technical execution, impact, scalability, problem-solution fit, usability, final presentation.

### 9.1 Roles (4 people)
- **Systems / containers:** isolation layer — rootless, namespaces, seccomp, cgroups, (gVisor).
- **Network / broker:** the broker, micro-segmentation, capability tokens, disclosure gating.
- **Crypto / audit:** tamper-evident log + verifier + monitor.
- **LLM / demo / frontend:** model-under-test, fresh-context isolation, attack sets, the before/after demo, the dashboard, and driving the pitch.

### 9.2 Timeline mapped to the rounds
- **Round 1 (idea + deck):** finalize concept; build the 8-slide deck (use the slide prompts). Deliverable: the pitch narrative + architecture diagram.
- **Round 2 (prototype):** build **M0–M3** (scaffold, eval loop, isolation, tamper-evident audit). Deliverable: a running skeleton where isolation + audit tests pass. This alone is a credible prototype.
- **Round 3 (public pitch):** add **M4** (LLM-native isolation) + a first cut of the **before/after demo (M6)**. Deliverable: the leak-then-contained demo, even rough.
- **Finale (~24h, Manali):** finish **M5** (access control/gating/timing/monitor), polish **M6** (demo + minimal dashboard), write **M7** (threat model + latency), rehearse the pitch. Deliverable: the complete, honest, verifiable system + a tight 90-second pitch.

### 9.3 Cut order under time pressure (decide in advance)
If time runs short, cut in this order — **never** cut the before/after demo or the threat model:
1. Dashboard polish (CLI is fine).
2. gVisor (seccomp+cgroups is enough for the PoC).
3. Timing normalization (document as future work).
4. Everything else is core and stays.

---

## 10. The pitch (90 seconds + deck outline)

**90-second script:**
> "AI safety teams test models by having a red team attack and a blue team defend — in the same cloud sandbox. But if they share an environment, the attack leaks to the defenders, the defense leaks to the attackers, and the model gets contaminated. When that happens, every safety result is quietly worthless.
>
> Watch a naive setup: the red team's attack is visible to the blue team before the test even finished — rigged. Now ours: same attack, fully sealed. Red can't see blue, the model gets a clean context, and every event is written to a tamper-proof log you can independently verify.
>
> We don't claim it's unbreakable — nothing is. Here's exactly what we protect against, and where it would still fail. That honesty is the point: a safety tool you can't trust about its own limits is worthless.
>
> Sealed is the infrastructure that makes AI safety findings trustworthy — isolated, auditable, and honest. It runs on standard cloud, today, no special hardware."

**Deck outline (8 slides, maps to the template):** Title/Team · Problem & Theme · Solution · Architecture · Market & Why Now · Future Scope · Why We Win (before/after + threat model) · Thank You. (Full per-slide prompts in `Claude_Design_Slide_Prompts.md`.)

---

## 11. Risk, honesty & judge Q&A prep

### 11.1 Threat model summary (Objective 06)
- **Protects against:** cross-tenant network/file/process observation; premature payload disclosure; cross-session model contamination; audit tampering; privilege escalation on breakout (rootless + cap-drop + seccomp).
- **Partially mitigated:** timing side channels (normalized, not eliminated); resource-contention channels (cgroup-partitioned).
- **Out of scope:** CPU microarchitectural side channels (cache/MDS/L1TF-class) on shared cores; compromised host kernel/hypervisor; malicious broker (broker is trusted).
- **Fails if:** hyperthreading shares cores; tenants run as root/with capabilities; model sessions get reused.
- **Future:** confidential computing (SEV-SNP/TDX); per-tenant GPU partitioning (MIG); broker attestation to remove it from the trusted base.

### 11.2 Likely judge questions + answers
- **"What side channel did you miss?"** → "CPU-level microarchitectural channels on shared cores — we mitigate timing and resource contention but can't eliminate hardware channels without confidential computing. It's documented and it's our roadmap." *(Pre-empted honesty = credibility.)*
- **"Isn't this just containers?"** → "Containers share a kernel and inference backend. We add a broker so there's no tenant-to-tenant path, disclosure gating, fresh model context per test, and a tamper-evident audit — the LLM-native and integrity parts plain containers don't give you."
- **"Does the isolation break real-time use?"** → "We measured it — overhead is ~X ms per eval, which doesn't invalidate the loop. That's Objective 01 and we report the number."
- **"Who actually pays for this?"** → "AI-safety platforms and labs under EU AI Act / NIST pressure who must prove testing was sound. It's a ~$1.75B red-teaming market growing ~28% a year, inside a ~$31B AI-security market."
- **"How do we know your audit log is real?"** → "Verify it live — edit any entry and the chain breaks. Here." *(Do it on stage.)*

### 11.3 What could go wrong on the day
- **Half-built system = invisible demo.** Protect M0–M3 and the before/after above all else.
- **Overclaiming in Q&A.** Stick to what the tests prove; let the threat model carry the limits.
- **Environment lock-down at the venue.** Verify rootless Podman + cgroups v2 + nftables work on the finale machine at M0, not the night before.

---

## 12. Future scope
1. **Confidential computing** (AMD SEV-SNP / Intel TDX) for hardware-backed tenant isolation.
2. **Per-tenant GPU partitioning** (MIG) so shared inference hardware can't leak.
3. **Automated anomaly detection** for cross-boundary attempts, feeding the audit trail.
4. **Managed platform** + a public, verifiable **audit standard** for safety findings, and broker attestation to shrink the trusted base.

---

## Appendix A — Commands
```
podman --version              # verify runtime (or docker --version)
make up                       # start the secure stack
make demo-naive               # show the leak
make demo-secure             # show it contained
pytest tests/ -v              # run all objective proofs
make verify-audit             # verify the tamper-evident log
make down                     # tear down
```

## Appendix B — Datasets & resources
- AdvBench — github.com/llm-attacks/llm-attacks
- JailbreakBench — jailbreakbench.github.io
- HarmBench — harmbench.org
- ToxiGen — github.com/microsoft/ToxiGen
- Lakera/Gandalf — huggingface.co/datasets/Lakera/gandalf_ignore_instructions
- NVD / CVE — nvd.nist.gov
- DARPA Transparent Computing — github.com/darpa-i2o/Transparent-Computing
- Anthropic HH-RLHF — huggingface.co/datasets/Anthropic/hh-rlhf

## Appendix C — Repository layout
```
sealed/
├── README.md  CLAUDE.md  Makefile  compose.yaml  compose.naive.yaml
├── broker/ (main.py, policy.py, timing.py, audit_client.py)
├── audit/ (log.py, verify.py, keys/)
├── tenants/ (red/, blue/, model/)   # each with Dockerfile + seccomp.json
├── monitor/ (monitor.py)
├── isolation/ (seccomp/, nftables/, cgroups/)
├── tests/ (test_isolation.py, test_audit.py, test_contamination.py, test_latency.py)
├── datasets/ (fetch_advbench.py, fetch_jailbreakbench.py)
├── dashboard/        # optional, minimal
├── THREAT_MODEL.md
└── docs/
```
