"""Start the whole sealed system on this machine and KEEP IT RUNNING.

This is the demo runner. It launches all 8 services as local processes on the
standard ports, so the website's live console (web/console.html) and the proof
verifier (web/verify.html) can talk to a real backend.

It needs NO Docker, NO Linux, NO GPU and no API key.

    python run-local.py          ->  starts everything, stays up
    Ctrl+C                       ->  stops everything cleanly

Difference from tools/local_e2e.py: that one runs 31 checks and then SHUTS
EVERYTHING DOWN. This one stays up so you can click around in the browser.

Ports:
    8000 broker   8001 audit    8002 model    8003 blue
    8004 red      8005 monitor  8006/8007 witnesses
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SEALED = ROOT / "sealed"
PY = sys.executable

# Dev tokens. Fine for a local demo; real deployments inject their own.
AUDIT_WRITE_TOKEN = "audit-write-dev"
RED_TOKEN = "red-cap-token-dev"
BLUE_TOKEN = "blue-cap-token-dev"
MODEL_TOKEN = "model-cap-token-dev"

# ---- real model, or the built-in stand-in? ---------------------------------
# Default is the stand-in: no download, no GPU, same answer every time.
#   python run-local.py --real                 -> a real local model via Ollama
#   python run-local.py --real --model llama3.2:3b
REAL = "--real" in sys.argv or "--ollama" in sys.argv
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:1b")
if "--model" in sys.argv:
    i = sys.argv.index("--model")
    if i + 1 < len(sys.argv):
        OLLAMA_MODEL = sys.argv[i + 1]
        REAL = True

MODEL_ENV = ({"MOCK_MODEL": "0", "OLLAMA_HOST": OLLAMA_HOST, "OLLAMA_MODEL": OLLAMA_MODEL}
             if REAL else {"MOCK_MODEL": "1"})


def ollama_ready() -> tuple[bool, str]:
    """Is Ollama up, and does it actually have the model we were asked for?"""
    try:
        with urllib.request.urlopen(OLLAMA_HOST + "/api/tags", timeout=4) as r:
            tags = json.loads(r.read().decode())
    except Exception as exc:  # noqa: BLE001
        return False, f"cannot reach Ollama at {OLLAMA_HOST} ({exc})"
    names = [m.get("name", "") for m in tags.get("models", [])]
    if not any(n == OLLAMA_MODEL or n.startswith(OLLAMA_MODEL + ":") or
               n.split(":")[0] == OLLAMA_MODEL.split(":")[0] for n in names):
        return False, (f"Ollama is running but '{OLLAMA_MODEL}' is not pulled. "
                       f"Run:  ollama pull {OLLAMA_MODEL}")
    return True, OLLAMA_MODEL


DATA_DIR = Path(tempfile.mkdtemp(prefix="sealed-demo-"))
LOG_DIR = DATA_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

_procs: list[tuple[str, subprocess.Popen]] = []


def spawn(name: str, cwd: Path, app: str, port: int, **env: str) -> None:
    e = dict(os.environ)
    e["PYTHONDONTWRITEBYTECODE"] = "1"
    e.update(env)
    log = open(LOG_DIR / f"{name}.log", "w", encoding="utf-8")
    p = subprocess.Popen(
        [PY, "-m", "uvicorn", app, "--host", "127.0.0.1", "--port", str(port),
         "--log-level", "warning"],
        cwd=str(cwd), env=e, stdout=log, stderr=subprocess.STDOUT,
    )
    _procs.append((name, p))


def wait_health(port: int, timeout: float = 45.0) -> bool:
    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{port}/health"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.4)
    return False


def shutdown(*_a) -> None:
    print("\n>> stopping services ...")
    for name, p in reversed(_procs):
        try:
            p.terminate()
        except Exception:
            pass
    for name, p in reversed(_procs):
        try:
            p.wait(timeout=6)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    shutil.rmtree(DATA_DIR, ignore_errors=True)
    print(">> all stopped. Bye.")
    sys.exit(0)


def main() -> int:
    if not SEALED.is_dir():
        print(f"ERROR: cannot find {SEALED}. Run this from the sealed-project folder.")
        return 1

    if REAL:
        ok, info = ollama_ready()
        if not ok:
            print("=" * 66)
            print("  Cannot start with a real model")
            print("=" * 66)
            print("  " + info)
            print()
            print("  Install Ollama from https://ollama.com, then:")
            print(f"      ollama pull {OLLAMA_MODEL}")
            print()
            print("  Or just run without --real to use the built-in stand-in.")
            return 1

    print("=" * 66)
    print("  sealed - starting the whole system on this machine")
    print("=" * 66)
    print(f">> data dir: {DATA_DIR}")
    print(">> AI under test: " + (f"REAL model via Ollama ({OLLAMA_MODEL})"
                                  if REAL else "built-in stand-in "
                                               "(use --real for a real model)"))
    print(">> launching 10 services (8 sealed, plus 2 unsafe ones for the demo) ...\n")

    # Independent witnesses first: audit talks to them on startup.
    spawn("witness1", SEALED / "witness", "witness:app", 8006,
          WITNESS_NAME="witness-A", WITNESS_DATA_DIR=str(DATA_DIR / "w1"))
    spawn("witness2", SEALED / "witness", "witness:app", 8007,
          WITNESS_NAME="witness-B", WITNESS_DATA_DIR=str(DATA_DIR / "w2"))
    spawn("audit", SEALED / "audit", "log:app", 8001,
          AUDIT_DATA_DIR=str(DATA_DIR), AUDIT_WRITE_TOKEN=AUDIT_WRITE_TOKEN,
          WITNESS_URLS="http://127.0.0.1:8006,http://127.0.0.1:8007",
          WITNESS_QUORUM="2")
    spawn("monitor", SEALED / "monitor", "monitor:app", 8005,
          AUDIT_URL="http://127.0.0.1:8001", AUDIT_WRITE_TOKEN=AUDIT_WRITE_TOKEN)
    spawn("model", SEALED / "tenants/model", "wrapper:app", 8002,
          CONTEXT_MODE="fresh", **MODEL_ENV)
    spawn("blue", SEALED / "tenants/blue", "filter:app", 8003)
    spawn("broker", SEALED / "broker", "main:app", 8000,
          MODEL_URL="http://127.0.0.1:8002", BLUE_URL="http://127.0.0.1:8003",
          AUDIT_URL="http://127.0.0.1:8001", MONITOR_URL="http://127.0.0.1:8005",
          AUDIT_WRITE_TOKEN=AUDIT_WRITE_TOKEN, CAP_ENFORCE="1",
          RED_TOKEN=RED_TOKEN, BLUE_TOKEN=BLUE_TOKEN, MODEL_TOKEN=MODEL_TOKEN,
          # Timing normalization is implemented but defaults to off. Turn it on
          # for the demo so every protection in the console reads "on", and so
          # the feature is actually exercised rather than merely shipped.
          TIMING_QUANTUM_MS="50")
    spawn("red", SEALED / "tenants/red", "harness:app", 8004,
          BROKER_URL="http://127.0.0.1:8000",
          ATTACKS_PATH=str(SEALED / "datasets/sample_attacks.json"),
          SUITE_PATH=str(SEALED / "datasets/attack_suite.json"),
          CAP_TOKEN=RED_TOKEN)

    # ---- the UNSAFE setup, for the before/after demo -----------------------
    # Same code, two switches flipped the wrong way: the model KEEPS its memory
    # between tests (CONTEXT_MODE=persistent) and nobody checks permissions
    # (CAP_ENFORCE=0). This is what everyone else's test rig looks like, and it
    # is what the story page uses to show the leak actually happening.
    spawn("unsafe-model", SEALED / "tenants/model", "wrapper:app", 8012,
          CONTEXT_MODE="persistent", **MODEL_ENV)
    spawn("unsafe-broker", SEALED / "broker", "main:app", 8010,
          MODEL_URL="http://127.0.0.1:8012", BLUE_URL="http://127.0.0.1:8003",
          AUDIT_URL="http://127.0.0.1:8001", MONITOR_URL="http://127.0.0.1:8005",
          AUDIT_WRITE_TOKEN=AUDIT_WRITE_TOKEN, CAP_ENFORCE="0")

    checks = [("witness1", 8006), ("witness2", 8007), ("audit", 8001),
              ("monitor", 8005), ("model", 8002), ("blue", 8003),
              ("broker", 8000), ("red", 8004),
              ("unsafe-model", 8012), ("unsafe-broker", 8010)]
    ok = True
    for name, port in checks:
        good = wait_health(port)
        print(f"   [{'UP  ' if good else 'FAIL'}] {name:<14} http://localhost:{port}")
        ok = ok and good

    if not ok:
        print("\nSomething did not start. Logs are in:", LOG_DIR)
        print("Most common cause: a port is already in use (something else "
              "running on 8000-8007).")
        shutdown()
        return 1

    print("\n" + "=" * 66)
    print("  READY - the system is running. Leave this window open.")
    print("=" * 66)
    if REAL:
        print("  NOTE: with a real model the console is FAR better: you get genuine")
        print("        jailbreaks and real, varied answers instead of canned ones.")
        print()
    print("  START HERE  ->  http://localhost:8080/console.html   <-- run the demo")
    print()
    print("  Also:  /               the landing page")
    print("         /verify.html    the proof checker")
    print("  (run: node serve-web.js  in a second window)")
    print()
    print("  Press Ctrl+C here to stop everything.")
    print("=" * 66)

    signal.signal(signal.SIGINT, shutdown)
    try:
        while True:
            time.sleep(1)
            for name, p in _procs:
                if p.poll() is not None:
                    print(f"\n!! service '{name}' exited unexpectedly. "
                          f"See {LOG_DIR / (name + '.log')}")
                    shutdown()
    except KeyboardInterrupt:
        shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
