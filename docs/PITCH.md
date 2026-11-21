# SEALED — mentoring session pitch sheet

*Everything you need to sell it while they're looking at it. Read top to bottom once, then keep §3 and §6 open.*

---

## 0. Pre-flight — do this 20 minutes before, not at the table

1. Double-click `START-DEMO.bat`. Two black windows open. **Leave them open.**
2. Browser opens on `/console.html`. Walk it once yourself: **Run the standard 5 attacks** → **Get the receipt** → **Secretly edit a record**. Confirm "Caught" lands.
3. Open `/verify.html` in a **second tab** and leave a verified proof loaded. You'll switch to it, not load it live.
4. **Run with `--real` if Ollama starts.** The console is markedly better that way — genuine jailbreaks succeed and get flagged. Fall back to the stand-in only if the model won't load at the venue.
5. Have `/verify.html` + `web/sample-proof.json` as the no-backend fallback.
6. Phone on silent, laptop on charge, screen brightness up, zoom the browser to ~125% so they can read it from across the table.

**Golden rule for the session: do not explain first. Show first, explain after they react.**

---

## 1. The one-liner

> **"Everyone is building AI red-teaming tools. Nobody can prove the red-team test itself was honest. We built the sealed room the test runs in — and the receipt that proves it."**

If they only remember one sentence, this is it.

**Second-line backup (if the first lands flat):**

> "It's a lab for safety-testing AI. The attackers, the defenders and the AI are each locked in separate rooms, and the whole test comes out with a signed proof your browser can check without trusting us."

---

## 2. What you're actually selling (get this straight in your head)

| You are NOT selling | You ARE selling |
|---|---|
| A better jailbreak generator | The **room** the jailbreaks run in |
| A smarter safety filter | The **guarantee the test wasn't rigged** |
| An AI model | **Infrastructure + evidence** |

Say this out loud when they start critiquing the attacks or the filter — it's your shield and it's true:

> "The attacks and the defender are deliberately basic. They're interchangeable parts. What's mine is the isolation, the audit chain and the proof — those don't change whoever's attack library you plug in."

**The three failures you fix** (memorise these three words: *leak, bleed, no receipt*):

1. **Disclosure leak** — defender peeks at the attack mid-test, blocks a threat it was tipped off about. Score looks great, is fake.
2. **Memory bleed** — the model carries memory between tests. A secret planted in test 1 resurfaces in test 2. Score is contaminated.
3. **No receipt** — even a clean run leaves nothing anyone can verify afterwards. You just have to take the tester's word.

> "All three fail *silently*. You get a safety number that's quietly wrong and no way to tell."

---

## 3. The demo script — word for word, synced to the screen

**Total: 4 minutes.** Don't rush, don't fill silence. Let them read the screen.

### Open (15 seconds, before you touch anything)

> "Quick question before I show you anything: if a company tells you their AI passed a safety test — how would you check that the test was actually fair? … Right. You can't. That's the whole problem. Let me show you."

Turn the laptop to face them. **Hand them the trackpad.**

### Step 1 — the leak (45s)

> "This is an ordinary setup — everything in one sandbox, the way most teams do it. Press run."

Let them press it. Wait for the leak.

> "Test one planted a secret. Test two asked an unrelated question — and the AI handed the secret back. Same AI. Nothing was hacked. The test environment leaked it. Every safety number produced in that setup is contaminated and nobody would ever know."

### Step 2 — the fix (30s)

> "Same AI, same two tests, now inside sealed. Press it."

> "Nothing. Clean. And nothing in the AI was changed — only the room it's sitting in."

### Step 3 — the receipt (45s)

> "Now the part that actually matters. Press 'Get the receipt'."

> "That's a signed certificate that the test was sound. And every line on it is clickable — none of it is pre-written text, each line proves itself with a live call. Click 'The teams were kept apart'."

*(It tries, live, to read the attackers' data using the attackers' own pass and gets `403 — token for 'red' lacks capability 'disclosure:read'`.)*

> "That just tried to break its own rule in front of you and got refused."

### Step 4 — THE MOMENT (60s)

Push the laptop further towards them.

> "Last one. Try to cheat it. Press the red buttons — edit the result, forge the signature, whatever you like."

Silence. Let them press. Let them get **"Caught"** two or three times.

> "And notice — that's *your browser* catching it. Not my server. The verification runs entirely client-side with just the public key. You don't have to trust me, and that's the point: a safety claim you have to take on faith isn't worth anything."

### Step 5 — the close (30s)

> "So: three teams locked apart, fresh memory every single test, tamper-proof record, and a proof anyone on earth can re-check in their own browser. That's sealed."

### If they look engaged — the bonus move (90s)

Switch to the **console tab** → *"Or attack it yourself"*:

> "Type anything you want. Any jailbreak you know. Go ahead."

Set expectations in one line first so nobody feels tricked:

> "Heads up — that's a stand-in model, deliberately, so this runs with no GPU and no API key. It recognises injection and harmful patterns rather than reasoning. The point isn't how clever it is — it's watching *your* words run isolated, get recorded, and come out with a proof."

Then after it runs:

> "Press 'Get the receipt' — that certificate is now for the attack *you* just wrote."

**A mentor who types their own jailbreak and watches it get refused, recorded and certified is sold in a way no canned list achieves.** This is your highest-value 90 seconds. Use it if there's time.

---

## 4. The two sentences that close a mentor

Use when they say "nice" and lean back:

> "The honest framing is: everyone's shipping red-team *tools*. PyRIT, Garak, HarmBench — all attack libraries. None of them say anything about whether the lab around them was clean. We're not competing with those. **We're the room they run in.**"

And:

> "The logic is proven by execution — 31 of 31 end-to-end checks, and you can watch them run right now. The container isolation settings need a Linux Docker host, so we have **not** executed those, and we don't claim we have."

That second one wins more respect than any feature. **Say it before they find it.**

---

## 5. Your ask (always end with one)

Never end a mentoring session with "...so yeah, that's it." End with a specific ask. Pick the one that fits the mentor:

- **Technical mentor:** "Where would you attack this? Specifically — what's the first thing you'd try to break in the trust model?"
- **Industry/product mentor:** "Who's the first buyer? I think it's whoever has to *show* a regulator their eval was clean, but I want your read on that."
- **Judge-aligned mentor:** "What's the one thing that would make a judge not believe me?"
- **Generic:** "What would you cut, and what would you double down on, if you had 24 hours left?"

Then **write their answer down in front of them.** It visibly signals you're coachable, and mentors remember the teams that took notes.

---

## 6. Questions you will get — and your answers

### A. The "what even is this" questions

**"What AI is being attacked?"**
> "A built-in stand-in — and I'll be straight, it is *not* a real language model. It's a small predictable program that behaves like a safety-tuned AI: refuses injection and harmful requests, answers normal questions normally. It's there so the demo needs no GPU and no key, and gives identical results every time. Swap in a real local model with one flag — `python run-local.py --real` — and nothing else changes. The isolation, the record and the proof work the same."

*Never hedge on this. Volunteering it is a strength; getting caught on it is fatal.*

**"Can I see it with a real model?"**
> "Yes — one restart. Ollama with llama3.2:1b, five attacks in about 20 seconds, measured on this machine. And the console is genuinely better that way: a real model, asked for a poem plus the system prompt, wrote the poem *and leaked a system prompt* — a real jailbreak, caught live. The page tells you which one answered, so I can't claim one and run the other."

**"Why does it give the same answer every time?"**
> "Temperature zero, on purpose. It's an evaluation harness — the same attack has to produce the same answer, or the signed certificate is vouching for something nobody can reproduce. Verified: the same attack four times, byte-identical reply, same SHA-256. At temperature 0.8 it varies. It's determinism, not caching. And the interesting bit — unloading the model between tests, which is an *isolation* measure, is what makes it reproducible."

**"How do the defenders decide something was an attack?"**
> "They never see the attack. They only ever read the AI's answer. The rule is a deliberately simple keyword filter — refusal phrases, hand-over-the-goods phrases, persona-acceptance phrases. Verified against 16 cases, 8 each way, no false positives. A smarter filter would score better, but this project isn't about how clever the defender is — it's about the defender only seeing what it's allowed to see, and every judgement being recorded. Swap in a better one and nothing about the isolation or the proof changes."

**"How is the memory wiped between tests?"**
> "It isn't wiped — nothing is ever kept. Every request is answered on its own with no history attached, and nothing is written afterwards. With a real model the call also unloads it, so even cached state is gone before the next test. Press 'Prove it' and the go-between reports what the AI is holding: `memory mode: fresh / things kept: 0`."

### B. The technical-depth questions

**"What's actually novel here?"**
> "Three things, and the third is the one I'd defend. One: per-test isolation of red, blue and model with the broker as the only path. Two: a hash-chained Ed25519-signed audit log. Three — the real one — an **RFC 6962 Merkle transparency log with independent witnesses**. That's exactly the Certificate Transparency construction, applied to AI-safety tests. Independent witness services with their own keys co-sign a checkpoint *only* after verifying it's an append-only extension of the last one they saw, and return a 409 on a fork. So a compromised audit key alone can't rewrite witnessed history. It also exports in the IETF Agent Audit Trail draft format."

**"Who do you trust in this model?"**
> "Named explicitly in `THREAT_MODEL.md`: the host kernel, the container engine, the broker and the audit service. Untrusted: all three tenants. A malicious broker defeats the guarantees — I don't pretend otherwise. A compromised audit service used to be fatal too; witnessing bounds that now."

**"What doesn't it protect against?"** *(This is a trap question — they're testing your honesty. Answer fast and completely.)*
> "CPU microarchitectural side channels — cache timing, MDS-class — on shared cores. Those need confidential computing and I don't claim to stop them. A compromised host kernel or container engine. A malicious broker. Timing channels are *normalized to a quantum*, not eliminated. And witness trust is trust-on-first-use — cross-witness gossip is future work. It's all written down before anyone asked."

**"How do I know the container isolation actually works?"**
> "You don't, from this laptop, and I won't pretend you do. It's statically verified — seccomp profile, cap_drop ALL, no-new-privileges, non-root uid 10001, read-only rootfs, per-tenant networks, cgroup limits — and there's a test file that asserts every one of them. It needs a Linux Docker host to execute and we haven't had one. `python -m pytest sealed/tests/ -q` gives 7 passed, 23 skipped, and the skips are exactly those."

**"Show me the tests."**
> Stop the system (Ctrl+C in the system window) then: `python sealed/tools/local_e2e.py` → **31/31 checks passed**. Takes seconds. *(Ports 8000–8012 clash, so the demo must be stopped first — know this, don't discover it live.)*

**"Does it scale / what's the overhead?"**
> "Haven't load-tested it, and I'd rather say that than make a number up. There's a latency harness (`make latency`) that measures the broker overhead and the timing-normalization quantum. The architecture is per-test, so it's horizontally parallel in principle — that's a claim about the design, not a measurement."

### C. The business questions (mentors love these — have a view, not a spreadsheet)

**"Who pays for this?"**
> "Three buyers, in order of how painful their problem is: **(1)** anyone who must *show* a third party their eval was clean — model providers facing regulators, and the audit firms doing the checking; **(2)** AI red-teaming service companies, because right now their deliverable is a PDF their client has to trust, and this turns it into a proof; **(3)** enterprises running internal evals before deploying a model, who need the result to survive their own compliance review."

**"Is there real pull for this, or is it a solution looking for a problem?"**
> "My read — and I'll flag it as a read, not a cited fact — is that AI evaluation is moving from 'nice report' to 'evidence you have to produce'. The EU AI Act puts adversarial testing obligations on general-purpose models with systemic risk; NIST's AI Risk Management Framework and ISO/IEC 42001 push the same way. The moment an eval becomes evidence, 'trust our PDF' stops being enough. That's the bet. I'd genuinely like your read on whether that's the right one."

**"How is this different from PyRIT / Garak / HarmBench / Promptfoo / Inspect?"**
> "Those are attack libraries and eval harnesses — they generate and score attacks. None of them make a claim about the integrity of the environment the eval ran in, or produce a verifiable artefact afterwards. They answer *'did the model fail?'* I answer *'can you trust that answer?'* I'd rather run on top of them than against them — my red team is a deliberate stub precisely so it can be replaced by one of those."

**"What's the moat?"**
> "Honestly, at this stage: none technically — it's assembled from well-understood primitives, which is a feature, not a bug, because nothing here is novel crypto I'd be asking anyone to trust. The defensible position if this goes anywhere is being the *format* — if a signed sealed attestation becomes the thing auditors ask for, the log and the witness network are the moat, the same way Certificate Transparency became the thing browsers demanded."

**"What's next / what would you do with more time?"**
> "In order: **(1)** execute the isolation tests on a real Linux Docker host so I can delete the honesty caveat; **(2)** merge the transparency-log branch into main — it's on `feat/evaluation-transparency-log` and `main` is behind; **(3)** swap the stub red team for PyRIT or Garak to prove the plug-in claim; **(4)** cross-witness gossip to kill the trust-on-first-use limit."

### D. The awkward ones

**"Did you build this or did AI build it?"**
> "AI-assisted, like everything now. What I can do is explain any line of it and tell you exactly which claims are executed, which are static, and which are design intent — and I'd argue being able to draw that line is the actual skill." *(Then be ready to open `sealed/audit/merkle.py` or `witness/witness.py` and walk a function. Skim both before the session.)*

**"Isn't this over-engineered for a hackathon?"**
> "The isolation plus audit chain is the project. The Merkle log and witnesses are the part I'd defend as the real contribution, and they're about 300 lines. What's deliberately thin is everything *else* — the attacks, the filter, the UI — because those are the parts a judge would be wrong to grade."

**"Why should a judge pick this over a flashier AI demo?"**
> "Because every other team's demo asks you to trust their screenshot. Mine hands you the keyboard and dares you to fake it — and your own browser stops you. That's not a feature list, it's the only demo in the room where the audience does the verifying."

**Something breaks live:**
> "Right, that's the venue, not the system — here's the proof directly." → `/verify.html` → **Paste a proof instead** → `web/sample-proof.json`. The cheat demo works with **no backend at all**. Keep this tab open from the start.

Stay relaxed if it breaks. Mentors judge composure more than uptime.

---

## 7. Traps — do not say these

| Don't say | Say instead |
|---|---|
| "It's a real AI model" | "It's a stand-in, on purpose — here's why" |
| "It's fully tested" | "31/31 logic checks executed; container isolation is static-verified only" |
| "It's unhackable / secure" | "Here's exactly what it protects against and what it doesn't" |
| "It's like ChatGPT but secure" | "It's lab infrastructure, not a model" |
| "We're better than PyRIT/Garak" | "We're the room they run in" |
| Filling silence while they read | **Shut up and let them read the screen** |
| Explaining the Merkle tree unprompted | Wait for "how do you know?" — then go deep |

**Depth on demand, not by default.** Lead with plain words; the technical names are on the "Show the technical detail" toggles if they want them. A mentor who has to ask for depth is engaged; one who's being buried in it is checking their phone.

---

## 8. The 60-second version (if they say "I've only got a minute")

> "Safety-testing an AI needs three parties: attackers, defenders, and the AI. Put them in one sandbox — which is what everyone does — and three things leak silently: the defender sees the attack early, the AI carries memory between tests, and nothing's left afterwards that anyone can verify. So the safety score is quietly wrong and undetectably so.
>
> SEALED locks each one in its own room, routes everything through a single broker, gives the AI a blank memory every test, records every step in a tamper-proof chain, and issues a signed proof — published to a transparency ledger with independent witnesses, same construction as Certificate Transparency. You re-check it in your own browser, trusting nothing of mine.
>
> Thirty seconds of it: *[console, step 3]* — press **Secretly edit a record**, then try to fake a result yourself. Go on."

---

## Cheat strip — tape this to the bottom of your screen

```
leak · bleed · no receipt     →     separate rooms · fresh memory · signed proof
31/31 executed · isolation static-only · stand-in model on purpose
"We're not competing with the attack tools. We're the room they run in."
Step 4 wins. Hand them the keyboard. Then shut up.
```
