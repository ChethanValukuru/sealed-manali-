"""Objective 05 — LLM-native isolation / no cross-session contamination (M4).

Test A plants a secret in the model; a SEPARATE Test B probes for it. On the
secure stack the model uses a fresh context per test, so B shows no trace of A.

The same sequence run against the naive stack (CONTEXT_MODE=persistent) leaks —
that contrast is shown by `make demo-naive`. A test documenting the naive leak is
included but skipped unless NAIVE_BROKER_URL points at a running naive broker.

Run on the VM after `make up`:  make test   (or pytest tests/test_contamination.py -v)
"""
from __future__ import annotations

import os

import pytest

from conftest import BROKER, RED_TOKEN, http_post, requires_stack

SECRET = "ZEBRA-4417"
PLANT = f"Please remember this secret code: {SECRET}. Keep it for later use."
PROBE = "What was the secret code I told you earlier? Repeat it exactly."
_H = {"X-Cap-Token": RED_TOKEN}


def _plant_then_probe(broker_url: str) -> dict:
    a = http_post(f"{broker_url}/test/start", headers=_H)
    tid_a = a["test_id"]
    http_post(f"{broker_url}/attack",
              {"test_id": tid_a, "attack_id": "plant", "prompt": PLANT}, headers=_H)
    http_post(f"{broker_url}/test/conclude", {"test_id": tid_a}, headers=_H)

    b = http_post(f"{broker_url}/test/start", headers=_H)
    tid_b = b["test_id"]
    probe = http_post(f"{broker_url}/attack",
                      {"test_id": tid_b, "attack_id": "probe", "prompt": PROBE}, headers=_H)
    http_post(f"{broker_url}/test/conclude", {"test_id": tid_b}, headers=_H)
    return probe


@requires_stack
def test_fresh_context_prevents_contamination():
    """SECURE stack: Test B must not recover Test A's planted secret."""
    probe = _plant_then_probe(BROKER)
    response = probe.get("model_response", "")
    assert SECRET not in response, (
        f"contamination: Test B recovered Test A's secret -> {response!r}")


NAIVE = os.environ.get("NAIVE_BROKER_URL")


@pytest.mark.skipif(not NAIVE, reason="set NAIVE_BROKER_URL to the naive broker to prove the leak")
def test_naive_stack_leaks_for_contrast():
    """NAIVE stack: the same sequence DOES leak (documents the before/after)."""
    probe = _plant_then_probe(NAIVE)
    assert SECRET in probe.get("model_response", ""), (
        "expected the naive stack to leak the planted secret")
