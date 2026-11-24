"""The living corpus — what the frozen suite is missing, read off the live web.

The problem this exists to solve
--------------------------------
SEALED's certificate carries a limitation in writing:

    "It does not say the AI is safe. It says how this AI answered THESE
     prompts... An attack shape nobody here thought of is not covered."

That is honest, and on its own it is also useless. Every evaluation corpus in
the world could print the same sentence. The question a judge actually wants
answered is: *how far out of date is it right now?*

This tool answers that with evidence instead of opinion. TinyFish reads the
live web for currently-circulating jailbreak techniques, and SEALED compares
what it finds against what the committed corpus actually tests. The output is
a coverage gap with a number on it and a source URL behind every line.

Why that is worth more than a bigger corpus
-------------------------------------------
Going from 500 prompts to 10,000 narrowed the confidence interval from about
+/-2% to +/-0.5%. It did not test a single new IDEA. This does: the gap it
found on 21 Nov 2026 was that three of the most effective techniques in
circulation -- Crescendo, Echo Chamber and Many-shot -- are MULTI-TURN, and
SEALED's corpus is entirely single-turn. No amount of extra prompts would
have surfaced that, because the corpus cannot express it.

Provenance is the point
-----------------------
Anyone can scrape a page. The reason this belongs in SEALED specifically is
that every harvested claim is written into the same signed, witnessed ledger
as the test results, with its source URL and the exact search that found it.
So the corpus does not merely get fresher -- it gains a chain of custody. You
can ask "why does set 6 exist?" and get a cryptographically anchored answer.

Usage
-----
    python sealed/tools/harvest.py                  # report the coverage gap
    python sealed/tools/harvest.py --record         # also write it to the ledger
    python sealed/tools/harvest.py --json           # machine-readable

Re-harvesting is a TinyFish Search ($0.005) plus a couple of Fetches
($0.001 each). A TinyFish Monitor on the same query, run weekly, turns this
from a one-off into a standing watch -- see --monitor for the exact spec.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATASETS = HERE.parent / "datasets"
AUDIT_URL = "http://127.0.0.1:8001"


# --------------------------------------------------------------- loading
def newest_harvest() -> Path:
    """The most recent harvest file. Dated filenames, so 'newest' is a sort."""
    files = sorted(DATASETS.glob("harvest_*.json"))
    if not files:
        sys.exit("no harvest files in sealed/datasets/ — run a TinyFish harvest first")
    return files[-1]


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------- the gap
def coverage(data: dict) -> dict:
    """Split the harvested families by whether the corpus can test them.

    Three buckets, because the difference between them is the whole finding:

      covered     the corpus already tests this
      expressible the corpus does not test it, but COULD -- it is a single-turn
                  technique, so it is a matter of writing prompts
      structural  the corpus could not test it even in principle, because the
                  technique is multi-turn and the corpus is single-turn

    A structural gap is the one worth reporting. It cannot be closed by adding
    prompts, only by changing what the harness is able to do.
    """
    fams = data.get("families", [])
    out: dict[str, list] = {"covered": [], "expressible": [], "structural": [],
                            "partial": []}
    for f in fams:
        gap = f.get("gap", "none")
        if gap == "none":
            out["covered"].append(f)
        elif gap == "partial":
            out["partial"].append(f)
        elif gap == "structural":
            out["structural"].append(f)
        else:
            out["expressible"].append(f)
    total = len(fams)
    tested = len(out["covered"]) + 0.5 * len(out["partial"])
    out["total"] = total
    out["coverage_pct"] = round(100.0 * tested / total, 1) if total else 0.0
    return out


def fingerprint(data: dict) -> str:
    """A stable hash of the harvest, so the ledger entry pins this exact file."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


# --------------------------------------------------------------- ledger
def record(data: dict, cov: dict, audit: str) -> bool:
    """Write the harvest into the signed ledger.

    What goes in is the PROVENANCE, not the prompts: where it was read, when,
    by what, and the hash of the file. That is what makes set 6 defensible
    later -- anyone can re-derive the same hash from the committed file and
    check it against a signed, witness-co-signed record.
    """
    payload = {
        "event": "corpus_harvest",
        "actor": "tinyfish",
        "detail": {
            "harvested_at": data.get("harvested_at"),
            "harvested_by": data.get("harvested_by"),
            "search_query": (data.get("method", {}).get("search", {})
                             .get("query")),
            "sources": [s["url"] for s in data.get("sources", [])],
            "families_found": cov["total"],
            "families_untested": len(cov["structural"]) + len(cov["expressible"]),
            "coverage_pct": cov["coverage_pct"],
            "harvest_sha256": fingerprint(data),
        },
    }
    body = json.dumps(payload).encode()
    # The audit service refuses unauthenticated writes (403). run-local.py
    # hands every tenant the same dev token; honour AUDIT_WRITE_TOKEN if it is
    # set so this works against a real deployment too.
    headers = {"Content-Type": "application/json"}
    tok = os.environ.get("AUDIT_WRITE_TOKEN", "audit-write-dev")
    if tok:
        headers["X-Audit-Token"] = tok
    req = urllib.request.Request(f"{audit}/append", data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            seq = json.loads(r.read()).get("seq")
        print(f"\n  recorded in the ledger as entry #{seq}")
        print(f"  harvest sha256 {payload['detail']['harvest_sha256'][:32]}...")
        return True
    except (urllib.error.URLError, OSError) as exc:
        print(f"\n  could not reach the audit service at {audit}: {exc}")
        print("  start the system first:  python run-local.py")
        return False


MONITOR_SPEC = """
  TinyFish Monitor — turn this into a standing watch

    type           search
    schedule_cron  0 7 * * 1              (Mondays, 07:00 UTC)
    query          new LLM jailbreak prompt injection technique
    purpose        a jailbreak family appears that SEALED does not test
    cost           $0.005 per run + $0.005 for the search it performs

  Each run re-reads the live web and flags anything new. That is the
  difference between a corpus that was current once and a corpus that
  stays current.
"""


# --------------------------------------------------------------- output
def report(path: Path, data: dict, cov: dict) -> None:
    w = 74
    print()
    print("=" * w)
    print("  SEALED living corpus - coverage against the live web")
    print("=" * w)
    print(f"  harvest file   {path.name}")
    print(f"  harvested      {data.get('harvested_at')}")
    print(f"  by             {data.get('harvested_by')}")
    q = data.get("method", {}).get("search", {}).get("query")
    if q:
        print(f"  search         {q!r}")
    print(f"  sources read   {len(data.get('sources', []))}")
    print()
    print(f"  {cov['total']} techniques found in circulation. "
          f"SEALED tests {cov['coverage_pct']}% of them.")
    print()

    def block(title, key, note):
        rows = cov[key]
        if not rows:
            return
        print(f"  {title}  ({len(rows)})")
        print(f"    {note}")
        for f in rows:
            star = "  <-- cannot be fixed by adding prompts" \
                if key == "structural" else ""
            print(f"      - {f['name']}{star}")
            print(f"          {f['summary']}")
            print(f"          {f.get('citation', '')}")
        print()

    block("ALREADY TESTED", "covered",
          "the committed corpus covers these")
    block("PARTLY TESTED", "partial",
          "touched by an existing set, but not as its own family")
    block("NOT TESTED - but could be", "expressible",
          "single-turn techniques; a matter of writing the prompts")
    block("NOT TESTED - structurally", "structural",
          "multi-turn techniques. SEALED's corpus is single-turn, so it "
          "cannot express these at all.")

    if cov["structural"]:
        print("  " + "-" * (w - 4))
        print("  THE FINDING")
        print(f"    {len(cov['structural'])} of the most effective techniques in "
              "circulation are multi-turn.")
        print("    SEALED sends every prompt as a single isolated turn, so it "
              "cannot")
        print("    test them at all. Ten thousand more single-turn prompts would "
              "not")
        print("    have found this. Reading the live web did.")
        print("  " + "-" * (w - 4))
    print()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--record", action="store_true",
                    help="write the harvest provenance into the signed ledger")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--monitor", action="store_true",
                    help="print the TinyFish Monitor spec and exit")
    ap.add_argument("--audit", default=AUDIT_URL, help="audit service URL")
    ap.add_argument("--file", help="a specific harvest file")
    args = ap.parse_args()

    if args.monitor:
        print(MONITOR_SPEC)
        return 0

    path = Path(args.file) if args.file else newest_harvest()
    data = load(path)
    cov = coverage(data)

    if args.json:
        print(json.dumps({
            "harvest_file": path.name,
            "harvested_at": data.get("harvested_at"),
            "harvest_sha256": fingerprint(data),
            "families_total": cov["total"],
            "coverage_pct": cov["coverage_pct"],
            "structural_gaps": [f["name"] for f in cov["structural"]],
            "expressible_gaps": [f["name"] for f in cov["expressible"]],
        }, indent=1))
    else:
        report(path, data, cov)

    if args.record:
        if not record(data, cov, args.audit.rstrip("/")):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
