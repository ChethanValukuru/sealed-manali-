"""CLI verifier for the tamper-evident audit log (Phase 3 / M3).

Usage (inside the audit container):
    python verify.py                 # verify the live log (/data/audit.jsonl)
    python verify.py /data/foo.jsonl # verify a specific file

Prints a JSON result and exits 0 if intact, 1 if tampering is detected.
`make verify-audit` runs this via `compose exec`.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import chain

DATA_DIR = Path(os.environ.get("AUDIT_DATA_DIR", "/data"))
KEYS_DIR = DATA_DIR / "keys"


def read_entries(path: Path) -> list[dict]:
    entries: list[dict] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def main() -> int:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else DATA_DIR / "audit.jsonl"
    pub = chain.load_public(KEYS_DIR)
    result = chain.verify_chain(read_entries(target), pub)
    result["file"] = str(target)
    print(json.dumps(result, indent=2))
    return 0 if result.get("intact") else 1


if __name__ == "__main__":
    raise SystemExit(main())
