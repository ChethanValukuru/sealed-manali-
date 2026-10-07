"""Shared helpers for the objective-proof tests.

These tests drive the RUNNING stack (they exec into containers), so they are
meant to run on the Linux VM after `make up`. The container engine command is
read from $SEALED_COMPOSE (default "docker compose"); override for Podman:

    SEALED_COMPOSE="podman compose" pytest tests/ -v
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess

import pytest

COMPOSE = os.environ.get("SEALED_COMPOSE", "docker compose")
BROKER = os.environ.get("BROKER_URL", "http://localhost:8000")
RED = os.environ.get("RED_URL", "http://localhost:8004")
AUDIT = os.environ.get("AUDIT_URL", "http://localhost:8001")

# Capability tokens — must match the compose dev defaults.
RED_TOKEN = os.environ.get("RED_TOKEN", "red-cap-token-dev")
BLUE_TOKEN = os.environ.get("BLUE_TOKEN", "blue-cap-token-dev")


def _engine_available() -> bool:
    try:
        subprocess.run(shlex.split(COMPOSE) + ["ps"], capture_output=True,
                       timeout=20, check=False)
        return True
    except Exception:
        return False


requires_stack = pytest.mark.skipif(
    not _engine_available(),
    reason=f"container engine not available for '{COMPOSE}' (run on the VM after `make up`)",
)


def http_post(url: str, body: dict | None = None, headers: dict | None = None,
              timeout: int = 120) -> dict:
    import urllib.request
    data = json.dumps(body or {}).encode("utf-8")
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=data, method="POST", headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def http_get(url: str, headers: dict | None = None, timeout: int = 60) -> dict:
    import urllib.request
    req = urllib.request.Request(url, method="GET", headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def compose_exec(service: str, script: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run `python -c <script>` inside a service container."""
    cmd = shlex.split(COMPOSE) + ["exec", "-T", service, "python", "-c", script]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def compose_exec_file(service: str, module: str, *args: str,
                      timeout: int = 60) -> subprocess.CompletedProcess:
    """Run `python <module> [args]` inside a service container."""
    cmd = shlex.split(COMPOSE) + ["exec", "-T", service, "python", module, *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


@pytest.fixture(scope="session")
def ran_one_cycle():
    """Ensure the audit log has entries by running one eval cycle via red /run."""
    import urllib.request
    req = urllib.request.Request(f"{RED}/run", method="POST")
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))
