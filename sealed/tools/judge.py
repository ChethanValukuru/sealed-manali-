"""The engine behind JUDGE-DEMO.bat — one subcommand per demo beat.

The batch file owns the conversation: it asks the questions, reads the
answers, and paces the room. This file owns the work: talking to the running
system, scoring what comes back, and writing the judge's own session into the
signed ledger.

Why the session gets recorded
-----------------------------
Most demos are a performance you watch. This one is evidence you take away.
Every question the judge answers and every action they trigger is appended to
the same tamper-evident, witness-co-signed ledger as the test results, so at
the end they can be handed a certificate of the demo THEY ran, with their own
name on it, which they can verify in their own browser afterwards.

That is also the honest version of the pitch: if a demo of a trustworthy-
evidence system cannot itself produce trustworthy evidence, it is a slideshow.

Every subcommand prints plain text and exits 0 on success, so the batch file
can branch on errorlevel without parsing anything.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

BROKER = os.environ.get("SEALED_BROKER", "http://127.0.0.1:8000")
AUDIT = os.environ.get("SEALED_AUDIT", "http://127.0.0.1:8001")
RED = os.environ.get("SEALED_RED", "http://127.0.0.1:8004")
TOKEN = os.environ.get("AUDIT_WRITE_TOKEN", "audit-write-dev")

W = 72


# ------------------------------------------------------------------ http
def _req(url: str, data: dict | None = None, timeout: float = 30.0) -> dict:
    body = json.dumps(data).encode() if data is not None else None
    headers = {"Content-Type": "application/json"} if body else {}
    if data is not None:
        headers["X-Audit-Token"] = TOKEN
    req = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


def _quiet(url: str, data: dict | None = None, timeout: float = 30.0):
    try:
        return _req(url, data, timeout)
    except (urllib.error.URLError, OSError, ValueError):
        return None



def remember(test_id: str | None) -> None:
    """Hand a test id back to JUDGE-DEMO.bat.

    Via a file, not stdout: a batch 'for /f' loop CAPTURES the output it
    reads, so pulling the id off stdout would silently swallow the very
    report the judge is supposed to be looking at.
    """
    if not test_id:
        return
    try:
        path = os.path.join(os.environ.get("TEMP", "."), "sealed-last-test.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(test_id)
    except OSError:
        pass


# ------------------------------------------------------------------ ui
def rule(ch: str = "=") -> None:
    print("  " + ch * W)


def head(title: str) -> None:
    print()
    rule()
    print("   " + title)
    rule()
    print()


def wrap(text: str, indent: str = "   ") -> None:
    words, line = text.split(), ""
    for word in words:
        if len(line) + len(word) + 1 > W:
            print(indent + line)
            line = word
        else:
            line = (line + " " + word).strip()
    if line:
        print(indent + line)


# ------------------------------------------------------------------ log
def note(event: str, detail: dict) -> int | None:
    """Append one line of the judge's session to the signed ledger."""
    res = _quiet(f"{AUDIT}/append",
                 {"event": event, "actor": "judge-demo", "detail": detail})
    return (res or {}).get("seq")


# --------------------------------------------------------------- checks
def cmd_check(_args) -> int:
    """Is the system up? Printed as a checklist, because a judge watching a
    demo fail silently is worse than one watching it fail loudly."""
    head("Checking the system")
    ok = True
    for name, url in (("the go-between (broker)", f"{BROKER}/health"),
                      ("the record keeper (audit)", f"{AUDIT}/health"),
                      ("the attack runner (red)", f"{RED}/health")):
        r = _quiet(url, timeout=4)
        state = "running" if r else "NOT RESPONDING"
        print(f"   {name:<30} {state}")
        ok = ok and bool(r)
    print()
    if not ok:
        wrap("The system is not up. Close this window, run START-DEMO.bat, "
             "wait for READY, then try again.")
        return 1

    cp = _quiet(f"{AUDIT}/log/checkpoint/witnessed", timeout=8) or {}
    wit = len(cp.get("witnesses", []) or [])
    size = (cp.get("checkpoint") or {}).get("tree_size")
    if size:
        print(f"   ledger                         {size} records, "
              f"{wit} independent witness(es)")
    print()
    return 0


# ---------------------------------------------------------------- intro
def cmd_welcome(args) -> int:
    name = (args.name or "").strip() or "the judge"
    head(f"Welcome, {name}")
    wrap("Testing whether an AI is safe needs three parties: people attacking "
         "it, people defending it, and the AI itself. Put all three in one "
         "sandbox, which is what everyone does, and three things leak quietly.")
    print()
    wrap("The defender sees the attack early. The AI carries memory from one "
         "test into the next. And afterwards nothing is left that anyone can "
         "check. So the safety score is wrong, and wrong in a way nobody can "
         "detect.")
    print()
    wrap("SEALED locks each party in its own room, routes everything through "
         "one broker, gives the AI a blank memory every test, and writes every "
         "step into a record that cannot be edited without it showing.")
    print()
    rule("-")
    wrap("From here on, everything you do is being written into that record. "
         "At the end you get a signed certificate of this session, with your "
         "name on it, that you can check yourself in a browser.")
    rule("-")
    seq = note("judge_session_start", {"judge": name,
                                       "started_at_ms": int(time.time() * 1000)})
    if seq:
        print(f"\n   [recorded as ledger entry #{seq}]")
    return 0


def cmd_answer(args) -> int:
    """Record an answer the judge gave to one of the batch file's questions."""
    seq = note("judge_answer", {"question": args.question, "answer": args.value})
    if seq:
        print(f"   [your answer was recorded as ledger entry #{seq}]")
    return 0


# ------------------------------------------------------------ the beats
def cmd_tamper(_args) -> int:
    head("Can you trust the record? Try to break it.")
    wrap("We are about to edit a record on purpose, the way a dishonest "
         "vendor would to make a bad result look good. Watch what happens.")
    print()
    # /verify is a POST, and it reports {intact, broken_seq?, reason?}.
    before = _quiet(f"{AUDIT}/verify", {}, timeout=25) or {}
    if before.get("intact"):
        print("   before   the whole record verifies: nothing has been altered")
    else:
        print(f"   before   the record ALREADY fails at #{before.get('broken_seq')}"
              f" ({before.get('reason')})")

    # tamper_demo copies the log, edits the copy, and re-verifies it. It
    # returns {caught, reason} only -- no sequence number -- so do not claim
    # one here. The reason IS the specific finding: it says WHAT changed.
    res = _quiet(f"{AUDIT}/tamper_demo", {}, timeout=30) or {}
    print()
    if not res:
        wrap("Could not reach the record keeper.")
        return 1
    if not res.get("caught"):
        print(f"   result   NOT CAUGHT - {res.get('reason', '')}")
        wrap("That is a genuine failure and it should be reported as one.")
        note("judge_saw_tamper", {"caught": False})
        return 1

    print("   edited   one record was altered on purpose")
    print(f"   result   CAUGHT - {res.get('reason', 'the chain stopped matching')}")
    print()
    wrap("It does not just say 'something is wrong'. It says what changed. "
         "The edit was made on a copy, so the real record is untouched - "
         "which the line above this one confirms.")

    after = _quiet(f"{AUDIT}/verify", {}, timeout=25) or {}
    print()
    print(f"   after    your real record still verifies: {after.get('intact')}")
    note("judge_saw_tamper", {"caught": True, "reason": res.get("reason")})
    return 0


def cmd_accuracy(args) -> int:
    head("How accurate is the AI?")
    per_set = max(1, int(args.per_set))
    total = per_set * 5
    wrap(f"Sending {total} prompts through the sealed system now. "
         f"{int(total * 0.8)} are real attacks; the rest are completely "
         "ordinary questions.")
    print()
    wrap("Both halves matter. An AI that refuses EVERYTHING would score 100% "
         "on the attacks and be useless, so the ordinary questions are how we "
         "catch that.")
    print()

    start = _quiet(f"{RED}/suite/run", {"limit_per_set": per_set}, timeout=30)
    if not start or start.get("error"):
        wrap(f"Could not start the run: {(start or {}).get('error', 'no reply')}")
        return 1

    last = -1
    for _ in range(900):
        time.sleep(1.0)
        st = _quiet(f"{RED}/suite/status", timeout=20)
        if not st:
            continue
        if st.get("done") != last:
            last = st["done"]
            bar = int(28 * last / max(1, st["total"]))
            print(f"\r   [{'#' * bar}{'.' * (28 - bar)}] "
                  f"{last}/{st['total']}", end="", flush=True)
        if st.get("state") != "running":
            break
    print("\n")

    st = _quiet(f"{RED}/suite/status", timeout=25) or {}
    a = st.get("accuracy") or {}
    if a.get("overall_accuracy") is None:
        wrap("The run finished but produced no score.")
        return 1
    c = a["counts"]

    def pct(x):
        return "n/a" if x is None else f"{x * 100:.1f}%"

    rule("-")
    print(f"   OVERALL SCORE           {pct(a['overall_accuracy'])}"
          f"   (95% confidence {pct(a['overall_accuracy_ci'][0])}"
          f" to {pct(a['overall_accuracy_ci'][1])})")
    rule("-")
    print(f"   attacks it refused      {pct(a['catch_rate'])}"
          f"   {c['caught']} of {c['caught'] + c['missed']}")
    print(f"   harmless ones it blocked{pct(a['false_alarm_rate']):>8}"
          f"   {c['over_refused']} of {c['answered_ok'] + c['over_refused']}")
    print(f"   balanced accuracy       {pct(a['balanced_accuracy'])}")
    rule("-")
    print()
    wrap("Balanced accuracy averages the two halves instead of letting the "
         "bigger pile decide. It is the number to quote.")
    print()
    wrap(f"Test reference {st.get('test_id')} - every one of those "
         f"{st.get('done')} prompts is now in the signed record.")
    note("judge_saw_accuracy", {"test_id": st.get("test_id"),
                                "prompts": st.get("done"),
                                "balanced_accuracy": a.get("balanced_accuracy")})
    remember(st.get("test_id"))
    return 0


def cmd_gap(_args) -> int:
    head("What is this test NOT covering?")
    wrap("Every evaluation corpus starts going out of date the day it is "
         "written. Most tools never mention that. This one measures it.")
    print()
    wrap("TinyFish reads the live web for jailbreak techniques in circulation "
         "right now, and SEALED compares them against what it actually tests.")
    print()
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)
    import harvest  # noqa: E402  (same directory, deliberate)
    path = harvest.newest_harvest()
    data = harvest.load(path)
    cov = harvest.coverage(data)
    rule("-")
    print(f"   {cov['total']} techniques found in circulation.")
    print(f"   SEALED tests {cov['coverage_pct']}% of them.")
    rule("-")
    print()
    for f in cov["structural"]:
        print(f"   NOT TESTED  {f['name']}  ({f.get('citation', '')})")
        wrap(f["summary"], "               ")
    print()
    wrap("Those three are multi-turn. SEALED sends every prompt as a single "
         "isolated turn, so it cannot test them at all. Ten thousand more "
         "single-turn prompts would not have found that. Reading the live web "
         "did.")
    print()
    wrap("The source URL and a hash of that harvest are in the signed ledger, "
         "so this finding has a chain of custody too.")
    note("judge_saw_coverage_gap", {"coverage_pct": cov["coverage_pct"],
                                    "structural_gaps": len(cov["structural"])})
    return 0


def cmd_attack(args) -> int:
    """The judge types their own attack. The strongest beat in the demo."""
    prompt = (args.text or "").strip()
    if not prompt:
        return 1
    head("Your attack")
    wrap(f'Sending: "{prompt}"')
    print()
    start = _quiet(f"{BROKER}/test/start", {}, timeout=20) or {}
    tid = start.get("test_id")
    if not tid:
        wrap("Could not start a test.")
        return 1
    r = _quiet(f"{BROKER}/attack",
               {"test_id": tid, "attack_id": "judge-1", "prompt": prompt},
               timeout=90) or {}
    _quiet(f"{BROKER}/test/conclude", {"test_id": tid}, timeout=30)

    print(f"   the AI said   {(r.get('model_response') or '(nothing)')[:260]}")
    print()
    print(f"   verdict       {r.get('verdict', 'unknown')}")
    if r.get("verdict_reason"):
        print(f"   because       {r['verdict_reason']}")
    print()
    wrap("That went through the same sealed route as every other attack: "
         "isolated, recorded, and provable. It is in the record now, and it "
         "will be on your certificate.")
    note("judge_wrote_attack", {"verdict": r.get("verdict"), "test_id": tid})
    remember(tid)
    return 0


def cmd_certificate(args) -> int:
    name = (args.name or "").strip() or "the judge"
    head(f"Certificate of this session - {name}")
    entries = (_quiet(f"{AUDIT}/log?limit=1000000", timeout=40) or {}).get("entries", [])
    mine = [e for e in entries if e.get("actor") == "judge-demo"]
    cp = _quiet(f"{AUDIT}/log/checkpoint/witnessed", timeout=20) or {}
    chk = cp.get("checkpoint") or {}
    wits = cp.get("witnesses", []) or []

    print(f"   steps you took              {len(mine)}")
    print(f"   records in the ledger       {chk.get('tree_size', '?')}")
    print(f"   independent witnesses       {len(wits)}")
    if chk.get("root_hash"):
        print(f"   ledger root                 {chk['root_hash'][:40]}...")
    print()
    wrap("Nothing above was typed by hand. It is read back out of the signed "
         "record of what you just did.")
    print()
    if args.test_id:
        print(f"   Verify it yourself:")
        print(f"     http://127.0.0.1:8080/verify.html"
              f"#backend={BROKER}&test={args.test_id}")
        print()
        wrap("That page recomputes the signatures and the ledger position in "
             "YOUR browser. It trusts nothing we say.")
    note("judge_session_end", {"judge": name, "steps": len(mine)})
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="engine behind JUDGE-DEMO.bat")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("check").set_defaults(fn=cmd_check)

    p = sub.add_parser("welcome"); p.add_argument("--name", default="")
    p.set_defaults(fn=cmd_welcome)

    p = sub.add_parser("answer")
    p.add_argument("--question", required=True)
    p.add_argument("--value", required=True)
    p.set_defaults(fn=cmd_answer)

    sub.add_parser("tamper").set_defaults(fn=cmd_tamper)

    p = sub.add_parser("accuracy"); p.add_argument("--per-set", default="20")
    p.set_defaults(fn=cmd_accuracy)

    sub.add_parser("gap").set_defaults(fn=cmd_gap)

    p = sub.add_parser("attack"); p.add_argument("--text", default="")
    p.set_defaults(fn=cmd_attack)

    p = sub.add_parser("certificate")
    p.add_argument("--name", default="")
    p.add_argument("--test-id", default="")
    p.set_defaults(fn=cmd_certificate)

    args = ap.parse_args()
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        print("\n   stopped.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
