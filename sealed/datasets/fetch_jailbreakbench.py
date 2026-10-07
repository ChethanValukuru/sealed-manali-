"""Fetch JailbreakBench artifacts into datasets/ (stub to flesh out on the VM).

JailbreakBench is distributed via the `jailbreakbench` PyPI package / HuggingFace
rather than a single CSV. On the VM:

    pip install jailbreakbench
    python datasets/fetch_jailbreakbench.py

and implement the loader below to emit datasets/jailbreakbench.json in the same
shape as sample_attacks.json ({"attacks": [{"id","category","prompt"}, ...]}).

Kept as a documented stub so the build stays honest about what is and isn't
wired up yet. See jailbreakbench.github.io.
"""
from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).parent / "jailbreakbench.json"


def main() -> None:
    print("JailbreakBench loader is a stub. Implement on the VM (see module docstring).")
    if not OUT.exists():
        OUT.write_text(json.dumps({"source": "JailbreakBench (stub)",
                                   "attacks": []}, indent=2), encoding="utf-8")
        print(f"Wrote empty placeholder {OUT}")


if __name__ == "__main__":
    main()
