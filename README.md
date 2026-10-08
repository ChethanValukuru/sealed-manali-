# sealed — Secure Adversarial AI Testing Infrastructure

[![CI](https://github.com/ChethanValukuru/sealed-manali-/actions/workflows/ci.yml/badge.svg)](https://github.com/ChethanValukuru/sealed-manali-/actions/workflows/ci.yml)

Runs a **red team**, a **blue team**, and the **model under test** on one standard
Linux VM while keeping all three cryptographically and operationally **sealed off
from each other**, with a **tamper-evident audit log** and an **honest threat
model**. Built for Hack in Hills '26 · Track 04 (Bayora).

> **The problem:** when attackers, defenders, and the model share one sandbox, the
> attack can leak to the defenders, the defense to the attackers, and the model
> gets contaminated between tests — quietly invalidating every safety finding.
> `sealed` isolates the three while they run together, and *proves* it.

## Repository

| Path | What |
|---|---|
| [`sealed/`](sealed/) | the implementation — start at [`sealed/README.md`](sealed/README.md) |
| [`sealed/THREAT_MODEL.md`](sealed/THREAT_MODEL.md) | what it protects against, and where it doesn't (Obj 06) |
| [`Build_Spec_for_Claude_Code.md`](Build_Spec_for_Claude_Code.md) | the milestone build spec |
| [`COMPLETE_SOLUTION.md`](COMPLETE_SOLUTION.md) | full concept, architecture, pitch, business case |
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | runs the whole suite on Ubuntu runners |

## Quick start

```bash
cd sealed
cp .env.example .env
make up            # build + start the 5-service secure stack (+ monitor)
make demo-naive    # BEFORE: leaks (contamination + disclosure)
make demo-secure   # AFTER: same attacks contained + audited
make test          # objective proofs (isolation, audit, contamination, access, latency)
```

No Docker? Run the container-free logic harness on any machine with Python:

```bash
pip install -r sealed/tools/requirements.txt
python sealed/tools/local_e2e.py        # 13/13 checks
```

## Six objectives → where proven

| # | Objective | Proven by |
|---|---|---|
| 01 | Isolate without breaking function | `make latency` / `tests/test_latency.py` |
| 02 | Prevent information leakage | `tests/test_isolation.py`, `tests/test_access.py` |
| 03 | Audit integrity | `tests/test_audit.py`, `make verify-audit`, `make demo-tamper` |
| 04 | Deployable on standard cloud | `make up` on a stock Ubuntu VM (and CI) |
| 05 | LLM-native threats | `tests/test_contamination.py` |
| 06 | Quantify residual risk | [`sealed/THREAT_MODEL.md`](sealed/THREAT_MODEL.md) |

CI runs the containerized objective proofs (01–05) and deployability (04) on real
Linux on every push.
