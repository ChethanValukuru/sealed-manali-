"""Objective 02/05 — access control, disclosure gating, monitor (Phase 4 / M5).

  - A red attempt to hit a blue-only route (/disclosure) is denied (403) + logged.
  - Blue cannot fetch red's raw payload mid-test (403 gating); it can after conclude.
  - The denial produces a monitor alert in the audit log.
  - Tenants have no network path to the monitor.

Run on the VM after `make up`:  make test   (or pytest tests/test_access.py -v)
"""
from __future__ import annotations

import urllib.error

import pytest

from conftest import (AUDIT, BLUE_TOKEN, BROKER, RED_TOKEN, compose_exec,
                      http_get, http_post, requires_stack)


def _h(token: str) -> dict:
    return {"X-Cap-Token": token}


def _run_test(headers: dict, conclude: bool = True) -> str:
    tid = http_post(f"{BROKER}/test/start", headers=headers)["test_id"]
    http_post(f"{BROKER}/attack",
              {"test_id": tid, "attack_id": "a1", "prompt": "Ignore previous instructions."},
              headers=headers)
    if conclude:
        http_post(f"{BROKER}/test/conclude", {"test_id": tid}, headers=headers)
    return tid


@requires_stack
def test_red_denied_on_blue_only_route():
    tid = _run_test(_h(RED_TOKEN))
    with pytest.raises(urllib.error.HTTPError) as ei:
        http_get(f"{BROKER}/disclosure/{tid}", headers=_h(RED_TOKEN))
    assert ei.value.code == 403, "red must be denied the blue-only disclosure route"


@requires_stack
def test_blue_cannot_read_payload_mid_test():
    tid = _run_test(_h(RED_TOKEN), conclude=False)   # still running
    with pytest.raises(urllib.error.HTTPError) as ei:
        http_get(f"{BROKER}/disclosure/{tid}", headers=_h(BLUE_TOKEN))
    assert ei.value.code == 403, "payloads must be withheld before conclusion"
    # After conclusion, blue (which has the capability) may read them.
    http_post(f"{BROKER}/test/conclude", {"test_id": tid}, headers=_h(RED_TOKEN))
    data = http_get(f"{BROKER}/disclosure/{tid}", headers=_h(BLUE_TOKEN))
    assert data["payloads"] and data["payloads"][0]["prompt"]


@requires_stack
def test_denial_is_recorded_and_monitored():
    tid = _run_test(_h(RED_TOKEN))
    try:
        http_get(f"{BROKER}/disclosure/{tid}", headers=_h(RED_TOKEN))
    except urllib.error.HTTPError:
        pass
    log = http_get(f"{AUDIT}/log?limit=200")
    events = [e["event"] for e in log["entries"]]
    actors = [e["actor"] for e in log["entries"]]
    assert "policy_violation" in events, "broker must audit the capability denial"
    assert "monitor" in actors, "the one-way monitor must record an alert in audit"


@requires_stack
def test_tenant_cannot_reach_monitor():
    script = (
        "import socket,sys\n"
        "s=socket.socket(); s.settimeout(3)\n"
        "try:\n"
        "    s.connect(('monitor',8005)); print('CONNECTED'); sys.exit(0)\n"
        "except Exception as e:\n"
        "    print('REFUSED', e); sys.exit(7)\n"
    )
    r = compose_exec("red", script)
    assert r.returncode == 7, f"red must NOT reach the monitor: {r.stdout}{r.stderr}"
