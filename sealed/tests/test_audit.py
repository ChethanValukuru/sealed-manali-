"""Objective 03 — tamper-evident audit integrity (Phase 3 / M3).

  - A clean log verifies as intact.
  - A scripted tamper is detected at the exact broken sequence number.

Run on the VM after `make up`:  make test   (or pytest tests/test_audit.py -v)
"""
from __future__ import annotations

import json

from conftest import compose_exec_file, requires_stack


@requires_stack
def test_clean_log_verifies_intact(ran_one_cycle):
    # ran_one_cycle populates the audit log via red /run.
    r = compose_exec_file("audit", "verify.py")
    assert r.returncode == 0, f"clean log should verify: {r.stdout}{r.stderr}"
    result = json.loads(r.stdout)
    assert result["intact"] is True
    assert result["entries"] >= 1


@requires_stack
def test_tamper_is_detected_at_exact_entry(ran_one_cycle):
    r = compose_exec_file("audit", "tamper_demo.py")
    # tamper_demo exits 0 when detection matched the expected entry.
    assert r.returncode == 0, f"tamper demo failed: {r.stdout}{r.stderr}"
    result = json.loads(r.stdout)
    assert result["intact"] is False
    assert result["reason"] == "payload modified"
    assert result["broken_seq"] == result["expected_broken_seq"]
