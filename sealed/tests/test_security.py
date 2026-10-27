"""Red-team checks on the exposed audit surface (Phase 4 hardening).

The audit port is published for the operator console, so its WRITE endpoints
must not be usable by whoever can reach that port:
  - /append must reject log injection without the broker token.
  - /attest must reject forged (signed) attestations without the broker token.

Run on the VM after `make up`:  make test   (or pytest tests/test_security.py -v)
"""
from __future__ import annotations

import urllib.error

import pytest

from conftest import AUDIT, http_post, requires_stack


@requires_stack
def test_audit_append_rejects_unauthorized_writer():
    with pytest.raises(urllib.error.HTTPError) as ei:
        http_post(f"{AUDIT}/append",
                  {"actor": "attacker", "event": "forged_event", "payload": {"x": 1}})
    assert ei.value.code == 403, "anyone could inject audit entries"


@requires_stack
def test_audit_attest_rejects_forged_attestation():
    with pytest.raises(urllib.error.HTTPError) as ei:
        http_post(f"{AUDIT}/attest",
                  {"eval_id": "forged", "facts": {"network_isolated": True,
                                                  "model_context_fresh": True}})
    assert ei.value.code == 403, "anyone could mint a signed attestation with forged facts"
