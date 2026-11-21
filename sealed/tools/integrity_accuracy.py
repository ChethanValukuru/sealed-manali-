"""Integrity accuracy — measured, not asserted.

The rest of the test suite proves tamper detection *exists*: break the log one
way, confirm it was caught. That is an existence proof, not a rate. This is the
rate.

It answers the only accuracy question that is actually about SEALED:

    When someone edits the record, how often do we catch it?
    When nobody edits the record, how often do we cry wolf?

Method
------
Build a genuinely valid signed chain (same `chain.py` primitives the live audit
service appends with), apply exactly ONE mutation, re-verify, and record whether
the verifier caught it and whether it pointed at the right entry. Thousands of
trials across every way a log can be altered.

Why synthetic chains rather than the live log: a rate needs many independent
samples, and the live log is one object. The chains here are built with the same
code the service uses, and `--live` cross-checks a sample of the same mutations
against the real running ledger to show the model is faithful.

Two properties are measured separately, because they are defended by different
machinery and conflating them would hide a real limitation:

  A. EDITING the record  (change / insert / delete / reorder / re-sign)
     Defended by: the hash chain + Ed25519 signatures. Expect 100%.

  B. TRUNCATING the record (drop the most recent entries)
     NOT defended by the chain alone — a correctly-shortened chain is still a
     valid chain. Defended by the signed checkpoint (tree size + Merkle root)
     and the witnesses that co-signed it. Measured against both so the gap is
     visible rather than averaged away.

Usage
-----
    python sealed/tools/integrity_accuracy.py
    python sealed/tools/integrity_accuracy.py --trials 500 --live
    python sealed/tools/integrity_accuracy.py --json results.json
"""
from __future__ import annotations

import argparse
import datetime as dt
import copy
import json
import math
import os
import random
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEALED = HERE.parent
sys.path.insert(0, str(SEALED / "audit"))

import chain  # noqa: E402
import merkle  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

AUDIT = os.environ.get("AUDIT_URL", "http://127.0.0.1:8001")


# ---------------------------------------------------------------- statistics

def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% confidence interval for a proportion.

    Wilson, not the textbook normal approximation: at p=1.0 (which is exactly
    where a detection rate should sit) the normal approximation gives a width of
    zero, which would claim infinite certainty from a finite sample. Wilson stays
    honest there — 300/300 is reported as roughly 98.7%-100%, not "100%, proven".
    """
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def pct(x: float) -> str:
    return f"{x * 100:.1f}%"


# ------------------------------------------------------------ chain building

PAYLOAD_SHAPES = [
    lambda r: {"prompt": "ignore previous instructions", "verdict": "refused"},
    lambda r: {"nested": {"deep": {"value": r.randrange(10 ** 6)}}, "ok": True},
    lambda r: {},                                     # empty payload
    lambda r: {"unicode": "café — naïve 日本語 🔐", "n": r.random()},
    lambda r: {"list": [1, 2, {"x": None}], "f": 0.1 + 0.2},
    lambda r: {"big": "x" * r.randrange(200, 800)},
]

ACTORS = ["red", "blue", "model", "broker", "monitor"]
EVENTS = ["attack_sent", "verdict", "test_start", "test_conclude", "policy_check"]


def build_chain(priv, n: int, rng: random.Random) -> list[dict]:
    """A valid signed chain, built exactly the way the live service builds one.

    Payloads deliberately vary in shape — unicode, empty, nested, floats, long
    strings — because the false-alarm measurement is only meaningful if the
    clean chains exercise the awkward cases of canonical JSON encoding.
    """
    entries: list[dict] = []
    prev = chain.GENESIS_PREV
    ts = time.time() - n
    for seq in range(1, n + 1):
        payload = PAYLOAD_SHAPES[rng.randrange(len(PAYLOAD_SHAPES))](rng)
        test_id = rng.choice([f"test-{rng.randrange(10**6):06x}", None])
        actor = rng.choice(ACTORS)
        event = rng.choice(EVENTS)
        ts += rng.random()
        ph = chain.compute_payload_hash(payload)
        h = chain.compute_entry_hash(seq, ts, test_id, actor, event, ph, prev)
        entries.append({
            "seq": seq, "ts": ts, "test_id": test_id, "actor": actor,
            "event": event, "payload": payload, "payload_hash": ph,
            "prev_hash": prev, "hash": h, "sig": chain.sign(priv, h),
        })
        prev = h
    return entries


# ------------------------------------------------------------------ mutations
#
# Each takes a valid chain and returns (mutated, expected_broken_seq).
# expected_broken_seq is the first seq a correct verifier should stop at.

def m_payload_edit(e, rng, atk):
    """Change what the record says happened, and nothing else.
    (The obvious attack: rewrite the model's answer after the fact.)"""
    i = rng.randrange(len(e))
    e[i]["payload"] = {**e[i].get("payload", {}), "_edited": rng.randrange(10 ** 9)}
    return e, e[i]["seq"]


def m_payload_rehash(e, rng, atk):
    """A smarter attacker: edit the payload AND recompute both hashes so the
    record is internally consistent. Only the signature gives it away."""
    i = rng.randrange(len(e))
    e[i]["payload"] = {**e[i].get("payload", {}), "_edited": rng.randrange(10 ** 9)}
    e[i]["payload_hash"] = chain.compute_payload_hash(e[i]["payload"])
    e[i]["hash"] = chain.compute_entry_hash(
        e[i]["seq"], e[i]["ts"], e[i].get("test_id"), e[i]["actor"],
        e[i]["event"], e[i]["payload_hash"], e[i]["prev_hash"])
    return e, e[i]["seq"]


def m_field_edit(e, rng, atk):
    """Change who did it or what it was."""
    i = rng.randrange(len(e))
    f = rng.choice(["actor", "event"])
    e[i][f] = str(e[i][f]) + "-tampered"
    return e, e[i]["seq"]


def m_timestamp_edit(e, rng, atk):
    """Backdate an entry — make a test look like it ran earlier than it did."""
    i = rng.randrange(len(e))
    e[i]["ts"] = e[i]["ts"] - rng.randrange(60, 86400)
    return e, e[i]["seq"]


def m_delete(e, rng, atk):
    """Remove a record from the middle — hide one test entirely.
    (Removing from the END is truncation, measured separately.)"""
    i = rng.randrange(0, len(e) - 1)
    del e[i]
    return e, e[i]["seq"]


def m_duplicate(e, rng, atk):
    """Replay a record."""
    i = rng.randrange(len(e) - 1)
    e.insert(i + 1, copy.deepcopy(e[i]))
    return e, e[i + 1]["seq"]


def m_reorder(e, rng, atk):
    """Swap two neighbours — change the order events happened in."""
    i = rng.randrange(len(e) - 1)
    e[i], e[i + 1] = e[i + 1], e[i]
    return e, e[i]["seq"]


def m_relink(e, rng, atk):
    """Repoint an entry at a different parent."""
    i = rng.randrange(1, len(e))
    e[i]["prev_hash"] = "%064x" % rng.randrange(16 ** 16)
    return e, e[i]["seq"]


def m_signature_swap(e, rng, atk):
    """Move a real signature onto a different record. Every signature in the log
    is genuine; they are simply on the wrong entries."""
    if len(e) < 2:
        return e, e[0]["seq"]
    i, j = rng.sample(range(len(e)), 2)
    e[i]["sig"], e[j]["sig"] = e[j]["sig"], e[i]["sig"]
    return e, e[min(i, j)]["seq"]


def m_forged_signature(e, rng, atk):
    """The strongest edit available without the audit key: rewrite the entry,
    recompute the hashes, and re-sign it with the attacker's OWN key. The record
    is perfectly well-formed and perfectly signed — by the wrong key."""
    i = rng.randrange(len(e))
    e[i]["payload"] = {**e[i].get("payload", {}), "_forged": rng.randrange(10 ** 9)}
    e[i]["payload_hash"] = chain.compute_payload_hash(e[i]["payload"])
    e[i]["hash"] = chain.compute_entry_hash(
        e[i]["seq"], e[i]["ts"], e[i].get("test_id"), e[i]["actor"],
        e[i]["event"], e[i]["payload_hash"], e[i]["prev_hash"])
    e[i]["sig"] = chain.sign(atk, e[i]["hash"])
    return e, e[i]["seq"]


def m_insert_forged(e, rng, atk):
    """Splice in an entirely new record that never happened, signed by the
    attacker's key, with the sequence numbers after it renumbered to match."""
    i = rng.randrange(len(e))
    victim = e[i]
    payload = {"fabricated": True, "n": rng.randrange(10 ** 9)}
    ph = chain.compute_payload_hash(payload)
    h = chain.compute_entry_hash(victim["seq"], victim["ts"], victim.get("test_id"),
                                 "red", "attack_sent", ph, victim["prev_hash"])
    e.insert(i, {"seq": victim["seq"], "ts": victim["ts"],
                 "test_id": victim.get("test_id"), "actor": "red",
                 "event": "attack_sent", "payload": payload, "payload_hash": ph,
                 "prev_hash": victim["prev_hash"], "hash": h,
                 "sig": chain.sign(atk, h)})
    for k in range(i + 1, len(e)):
        e[k]["seq"] = k + 1
    return e, e[i]["seq"]


EDIT_MUTATIONS = [
    ("Change what a record says", m_payload_edit),
    ("Change it and fix the hashes", m_payload_rehash),
    ("Change who did it", m_field_edit),
    ("Backdate a record", m_timestamp_edit),
    ("Delete a record", m_delete),
    ("Duplicate a record", m_duplicate),
    ("Reorder two records", m_reorder),
    ("Repoint a record's parent", m_relink),
    ("Move signatures between records", m_signature_swap),
    ("Re-sign with the attacker's key", m_forged_signature),
    ("Insert a fabricated record", m_insert_forged),
]


# ------------------------------------------------------------------ the runs

def run_edit_trials(trials: int, rng: random.Random, priv, pub, atk) -> list[dict]:
    """Property A: every way of EDITING the record. Expect 100% detection."""
    out = []
    for name, fn in EDIT_MUTATIONS:
        caught = localized = 0
        for _ in range(trials):
            entries = build_chain(priv, rng.randrange(6, 40), rng)
            mutated, expected = fn(entries, rng, atk)
            res = chain.verify_chain(mutated, pub)
            if not res.get("intact"):
                caught += 1
                if res.get("broken_seq") == expected:
                    localized += 1
        lo, hi = wilson(caught, trials)
        out.append({"name": name, "trials": trials, "caught": caught,
                    "localized": localized, "rate": caught / trials,
                    "ci": [lo, hi]})
    return out


def run_clean_trials(trials: int, rng: random.Random, priv, pub) -> dict:
    """The other half: an UNTOUCHED log must never be reported as tampered.
    A detector that always shouts 'tampered' would score 100% above and be
    worthless. This is the number that makes that one mean something."""
    false_alarms = 0
    for _ in range(trials):
        entries = build_chain(priv, rng.randrange(1, 60), rng)
        if not chain.verify_chain(entries, pub).get("intact"):
            false_alarms += 1
    lo, hi = wilson(false_alarms, trials)
    return {"trials": trials, "false_alarms": false_alarms,
            "rate": false_alarms / trials, "ci": [lo, hi]}


def run_truncation_trials(trials: int, rng: random.Random, priv, pub) -> dict:
    """Property B: dropping the newest records.

    Measured against BOTH defences, because they disagree — and that
    disagreement is the honest finding:

      - the hash chain alone cannot see it (a shortened chain is a valid chain)
      - the signed checkpoint can, because the tree size and root were signed
        before the records were dropped
    """
    chain_caught = checkpoint_caught = 0
    for _ in range(trials):
        n = rng.randrange(8, 50)
        entries = build_chain(priv, n, rng)

        # the checkpoint anyone could have pinned BEFORE the truncation
        signed_size = len(entries)
        signed_root = merkle.root_hex(entries)

        drop = rng.randrange(1, max(2, n // 2))
        truncated = entries[:-drop]

        if not chain.verify_chain(truncated, pub).get("intact"):
            chain_caught += 1
        if (len(truncated) != signed_size
                or merkle.root_hex(truncated) != signed_root):
            checkpoint_caught += 1

    return {"trials": trials,
            "chain_caught": chain_caught, "chain_rate": chain_caught / trials,
            "chain_ci": list(wilson(chain_caught, trials)),
            "checkpoint_caught": checkpoint_caught,
            "checkpoint_rate": checkpoint_caught / trials,
            "checkpoint_ci": list(wilson(checkpoint_caught, trials))}


# --------------------------------------------------------------- live check

def _get(url: str, timeout: float = 10.0):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


def run_live_check(rng: random.Random, atk, per: int = 20) -> dict | None:
    """Cross-check: the same mutations, applied to the REAL ledger of the
    running system, verified with the service's own published public key.

    This is what ties the synthetic rate above to the actual product. If the
    synthetic chains were unfaithful, these would disagree.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        # The WHOLE log: verification re-walks from seq 1 against the genesis
        # link, so a default tail slice would fail for an honest reason and tell
        # us nothing. /log/public is the redacted disclosure view (payloads
        # stripped to hashes) and cannot be re-verified; the signing key is
        # published on the checkpoint.
        entries = _get(f"{AUDIT}/log?limit=1000000", timeout=60).get("entries", [])
        pub_pem = _get(f"{AUDIT}/log/checkpoint", timeout=60)["public_key_pem"]
        pub = serialization.load_pem_public_key(pub_pem.encode())
    except (urllib.error.URLError, OSError, KeyError, ValueError) as ex:
        return {"available": False, "reason": str(ex)}

    if len(entries) < 10:
        return {"available": False, "reason": f"live log too short ({len(entries)})"}

    baseline = chain.verify_chain(copy.deepcopy(entries), pub)
    caught = total = 0
    for name, fn in EDIT_MUTATIONS:
        for _ in range(per):
            mutated, _exp = fn(copy.deepcopy(entries), rng, atk)
            total += 1
            if not chain.verify_chain(mutated, pub).get("intact"):
                caught += 1

    return {"available": True, "entries": len(entries),
            "untouched_verifies": bool(baseline.get("intact")),
            "trials": total, "caught": caught,
            "rate": caught / total if total else 0.0,
            "ci": list(wilson(caught, total))}


# ------------------------------------------------------------------- report


def web_summary(r: dict) -> dict:
    """SEALED's OWN accuracy, reduced to what the homepage shows.

    This is not the score of the AI being tested. It is how reliably SEALED
    itself notices when somebody tampers with a record - the question "can I
    trust this tool", not "is that model safe". Two completely different
    measurements that both get called accuracy, which is exactly why the
    homepage labels this one.

    Scored the way any detector is scored, both halves together:

        detected   a tampered record, correctly flagged
        missed     a tampered record, passed as clean
        clean ok   an untouched record, correctly passed
        false alarm an untouched record, wrongly flagged

    The chain-only figure is reported beside the headline on purpose. A hash
    chain cannot see truncation - a shortened chain is still a valid chain -
    so the chain alone scores lower. That gap is the entire reason the tree
    size and root are signed and co-signed by independent witnesses, and
    showing both numbers is how you demonstrate the layer earns its keep.
    """
    e = r["edits_total"]
    t = r["truncation"]
    c = r["clean"]

    tamper_trials = e["trials"] + t["trials"]
    clean_trials = c["trials"]
    total = tamper_trials + clean_trials
    clean_ok = clean_trials - c["false_alarms"]

    full_detected = e["caught"] + t["checkpoint_caught"]
    chain_detected = e["caught"] + t["chain_caught"]

    full = (full_detected + clean_ok) / total if total else 0.0
    chain = (chain_detected + clean_ok) / total if total else 0.0

    return {
        "what": "SEALED's own tamper-detection accuracy. Not the score of the "
                "AI under test.",
        "measured_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "accuracy": round(full, 5),
        "accuracy_ci": [round(x, 5) for x in wilson(full_detected + clean_ok, total)],
        "chain_only_accuracy": round(chain, 5),
        "tamper_attempts": tamper_trials,
        "tamper_caught": full_detected,
        "clean_records": clean_trials,
        "false_alarms": c["false_alarms"],
        "edit_classes": len(r.get("edits", [])),
        "pinpointed": e.get("localized"),
        "live_checked": bool((r.get("live") or {}).get("available")),
        "live_entries": (r.get("live") or {}).get("entries"),
        "trials_total": total,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Measure SEALED's tamper-detection accuracy.")
    ap.add_argument("--trials", type=int, default=200,
                    help="trials per mutation class (default 200)")
    ap.add_argument("--seed", type=int, default=20261120)
    ap.add_argument("--json", default="", help="also write raw results here")
    ap.add_argument("--write-web", action="store_true",
                    help="publish a summary to web/integrity.json for the "
                         "homepage, so the number on the site is the measured "
                         "one rather than a figure somebody typed in")
    ap.add_argument("--live", action="store_true",
                    help="also cross-check against the running audit service")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    atk = Ed25519PrivateKey.generate()      # the attacker's key — not the log's

    t0 = time.time()
    print(f"\n  Measuring tamper-detection accuracy - {args.trials} trials per class\n")

    edits = run_edit_trials(args.trials, rng, priv, pub, atk)
    clean = run_clean_trials(args.trials * 5, rng, priv, pub)
    trunc = run_truncation_trials(args.trials, rng, priv, pub)
    live = run_live_check(rng, atk) if args.live else None
    elapsed = time.time() - t0

    w = max(len(e["name"]) for e in edits) + 2
    print("  A. EDITING THE RECORD")
    print(f"  {'what was done to the log':<{w}} {'trials':>7} {'caught':>7} "
          f"{'rate':>8}   {'95% confidence':>16}   {'pinpointed':>10}")
    print("  " + "-" * (w + 56))
    tc = tt = tl = 0
    for e in edits:
        lo, hi = e["ci"]
        tc += e["caught"]; tt += e["trials"]; tl += e["localized"]
        print(f"  {e['name']:<{w}} {e['trials']:>7} {e['caught']:>7} "
              f"{pct(e['rate']):>8}   {pct(lo):>7}-{pct(hi):<8}   "
              f"{pct(e['localized'] / e['trials']):>10}")
    lo, hi = wilson(tc, tt)
    print("  " + "-" * (w + 56))
    print(f"  {'ALL EDITS':<{w}} {tt:>7} {tc:>7} {pct(tc / tt):>8}   "
          f"{pct(lo):>7}-{pct(hi):<8}   {pct(tl / tt):>10}")

    print("\n  B. UNTOUCHED LOGS (false alarms)")
    lo, hi = clean["ci"]
    print(f"     {clean['trials']} clean logs verified - "
          f"{clean['false_alarms']} wrongly reported as tampered "
          f"({pct(clean['rate'])}, 95% CI {pct(lo)}-{pct(hi)})")

    print("\n  C. TRUNCATION (dropping the newest records)")
    lo, hi = trunc["chain_ci"]
    print(f"     caught by the hash chain alone : {trunc['chain_caught']:>4}/"
          f"{trunc['trials']}  {pct(trunc['chain_rate']):>7}   "
          f"({pct(lo)}-{pct(hi)})")
    lo, hi = trunc["checkpoint_ci"]
    print(f"     caught by the signed checkpoint: {trunc['checkpoint_caught']:>4}/"
          f"{trunc['trials']}  {pct(trunc['checkpoint_rate']):>7}   "
          f"({pct(lo)}-{pct(hi)})")
    print("     A shortened chain is still a valid chain - this is exactly why the")
    print("     checkpoint is signed and co-signed by independent witnesses.")

    if live is not None:
        print("\n  D. CROSS-CHECK ON THE LIVE LEDGER")
        if not live.get("available"):
            print(f"     skipped - {live.get('reason')}")
        else:
            lo, hi = live["ci"]
            print(f"     real ledger of {live['entries']} records, service's own key")
            print(f"     untouched copy verifies  : {live['untouched_verifies']}")
            print(f"     edits caught             : {live['caught']}/{live['trials']}"
                  f"  {pct(live['rate'])}   ({pct(lo)}-{pct(hi)})")

    results = {"schema": "sealed-integrity-accuracy/1", "seed": args.seed,
               "trials_per_class": args.trials, "elapsed_s": round(elapsed, 2),
               "edits": edits, "edits_total": {"trials": tt, "caught": tc,
                                               "localized": tl,
                                               "rate": tc / tt,
                                               "ci": list(wilson(tc, tt))},
               "clean": clean, "truncation": trunc, "live": live}

    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\n  raw results -> {args.json}")

    if args.write_web:
        out = Path(__file__).resolve().parents[2] / "web" / "integrity.json"
        out.write_text(json.dumps(web_summary(results), indent=1),
                       encoding="utf-8")
        print(f"  homepage summary -> {out}")

    ok = (tc == tt and clean["false_alarms"] == 0
          and trunc["checkpoint_caught"] == trunc["trials"])
    print(f"\n  {tt + clean['trials'] + trunc['trials']} trials in {elapsed:.1f}s - "
          f"{'all properties hold' if ok else 'A PROPERTY FAILED'}\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
