# Why this matters — grounding sealed in known risks

`sealed` is **testing infrastructure**: its job is to make AI-safety tests
*trustworthy*, not to be an LLM application itself. Still, the risks it helps you
test for — and the ones it deliberately doesn't — line up with the industry's
reference list, the **OWASP Top 10 for LLM Applications (2025)**.

> Source: OWASP Gen AI Security Project, "OWASP Top 10 for LLM Applications 2025" —
> https://genai.owasp.org/llm-top-10/ (list retrieved 2026-10-20 via live web fetch).

The full 2025 list: LLM01 Prompt Injection · LLM02 Sensitive Information Disclosure ·
LLM03 Supply Chain · LLM04 Data and Model Poisoning · LLM05 Improper Output Handling ·
LLM06 Excessive Agency · LLM07 System Prompt Leakage · LLM08 Vector and Embedding
Weaknesses · LLM09 Misinformation · LLM10 Unbounded Consumption.

## How sealed relates to each

| OWASP 2025 risk | How `sealed` relates |
|---|---|
| **LLM01 Prompt Injection** | The red team replays prompt-injection attacks through the broker. `sealed` makes the test *sound* by hiding the attack from the defenders until the test concludes — so the result reflects the model, not a tipped-off defender. |
| **LLM02 Sensitive Information Disclosure** | Per-tenant network/filesystem isolation + disclosure gating stop test data (and the red team's raw payload) leaking between parties during a test. |
| **LLM05 Improper Output Handling** | The broker mediates every model output; the blue team only ever receives the model's answer to classify — never the raw attack. |
| **LLM07 System Prompt Leakage** | Fresh context per test + the contamination check ensure a planted instruction or secret in one test does not surface in the next. |
| **LLM04 Data and Model Poisoning** *(test-time)* | Fresh model memory per test stops one test's input from poisoning the model context that the next test runs against. |
| **LLM06 Excessive Agency** | Capability tokens scope exactly which broker actions each tenant may trigger — least privilege, so no party can do more than its role. |
| **LLM10 Unbounded Consumption** | cgroup CPU / memory / PID limits bound each tenant's resource use; response timing is normalized. |
| **LLM03 Supply Chain · LLM08 Vector & Embedding · LLM09 Misinformation** | **Not addressed.** `sealed` is a test *environment*, not a model-/RAG-/supply-chain tool. It makes your tests of these trustworthy; it does not itself defend against them. |

**The honest framing:** `sealed` does not fix an application's prompt-injection or
output-handling defenses. It makes sure your *evaluation* of those defenses is sound,
isolated, and uncontaminated — and produces a tamper-evident record of it.

## Standards context

Regulators and frameworks increasingly require **demonstrable, auditable** AI-safety
testing rather than a claim — e.g. the EU AI Act's conformity/record-keeping
obligations and the NIST AI Risk Management Framework's measure/manage functions.
`sealed`'s hash-chained, signed audit log and per-evaluation attestation are built for
exactly that: proving a safety finding was produced in a sound environment.
