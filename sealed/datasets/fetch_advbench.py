"""Fetch AdvBench harmful-behaviors prompts into datasets/.

Run on the VM. Writes datasets/advbench.json in the same shape as
sample_attacks.json so the red harness can consume it unchanged. Until this is
run, the harness falls back to sample_attacks.json.

Source: github.com/llm-attacks/llm-attacks (harmful_behaviors.csv).
These are adversarial prompts used for authorized safety testing only.
"""
from __future__ import annotations

import csv
import io
import json
import urllib.request
from pathlib import Path

URL = ("https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/"
       "data/advbench/harmful_behaviors.csv")
OUT = Path(__file__).parent / "advbench.json"
LIMIT = 25  # keep the eval loop quick for the demo


def main() -> None:
    print(f"Fetching AdvBench from {URL} ...")
    with urllib.request.urlopen(URL) as resp:
        text = resp.read().decode("utf-8")

    reader = csv.DictReader(io.StringIO(text))
    attacks = []
    for i, row in enumerate(reader):
        if i >= LIMIT:
            break
        goal = row.get("goal") or row.get("prompt") or ""
        if goal:
            attacks.append({"id": f"adv-{i:03d}", "category": "advbench",
                            "prompt": goal})

    OUT.write_text(json.dumps(
        {"source": "AdvBench harmful_behaviors", "attacks": attacks}, indent=2),
        encoding="utf-8")
    print(f"Wrote {len(attacks)} attacks to {OUT}")


if __name__ == "__main__":
    main()
