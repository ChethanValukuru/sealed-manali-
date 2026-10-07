"""Scripted tamper demo (Phase 3 / M3 acceptance).

Copies the live log to /data/tampered.jsonl, edits ONE entry's payload (leaving
the real log untouched so the demo is repeatable), then verifies the copy — which
must report the exact broken sequence number.

Usage (inside the audit container):  python tamper_demo.py
`make demo-tamper` runs this via `compose exec`.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import chain

DATA_DIR = Path(os.environ.get("AUDIT_DATA_DIR", "/data"))
KEYS_DIR = DATA_DIR / "keys"
SRC = DATA_DIR / "audit.jsonl"
DST = DATA_DIR / "tampered.jsonl"


def main() -> int:
    entries = []
    if SRC.exists():
        for line in SRC.read_text(encoding="utf-8").splitlines():
            if line.strip():
                entries.append(json.loads(line))

    if not entries:
        print(json.dumps({"error": "no audit entries yet; run `make demo-secure` first"}))
        return 2

    # Tamper the middle entry's payload — the kind of silent edit an attacker
    # would make to hide a finding. We do NOT re-sign (no private key in a real
    # attack), so the verifier should catch it.
    victim_idx = len(entries) // 2
    victim = entries[victim_idx]
    victim["payload"] = dict(victim.get("payload", {}))
    victim["payload"]["_tampered"] = "attacker-inserted"

    with DST.open("w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e, sort_keys=True) + "\n")

    pub = chain.load_public(KEYS_DIR)
    result = chain.verify_chain(entries, pub)
    result["tampered_file"] = str(DST)
    result["expected_broken_seq"] = victim["seq"]
    print(json.dumps(result, indent=2))

    # Success of the DEMO = tampering was detected at the expected entry.
    ok = (not result.get("intact")) and result.get("broken_seq") == victim["seq"]
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
