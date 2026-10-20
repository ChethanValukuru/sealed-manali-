"""Verifiable evaluation attestation (the 'proof it was sound' feature).

  - The broker issues a signed attestation for a concluded evaluation.
  - The audit service verifies the signature.
  - A tampered attestation fails verification.
  - The live tamper-demo catches an edited record.

Run on the VM after `make up`:  make test   (or pytest tests/test_attestation.py -v)
"""
from __future__ import annotations

from conftest import AUDIT, BROKER, http_get, http_post, requires_stack


@requires_stack
def test_attestation_is_signed_and_verifiable(ran_one_cycle):
    tid = ran_one_cycle["test_id"]
    bundle = http_get(f"{BROKER}/eval/attestation/{tid}")
    att = bundle["attestation"]
    assert att["eval_id"] == tid
    assert att["chain_intact"] is True
    assert att["facts"]["model_context_fresh"] is True
    assert bundle["signature"] and bundle["public_key_pem"].startswith("-----BEGIN")

    ok = http_post(f"{AUDIT}/verify_attestation",
                   {"attestation": att, "signature": bundle["signature"]})
    assert ok["valid"] is True


@requires_stack
def test_tampered_attestation_is_rejected(ran_one_cycle):
    tid = ran_one_cycle["test_id"]
    bundle = http_get(f"{BROKER}/eval/attestation/{tid}")
    att = dict(bundle["attestation"])
    att["chain_intact"] = (not att["chain_intact"])  # forge a stronger claim
    bad = http_post(f"{AUDIT}/verify_attestation",
                    {"attestation": att, "signature": bundle["signature"]})
    assert bad["valid"] is False


@requires_stack
def test_live_tamper_demo_is_caught(ran_one_cycle):
    res = http_post(f"{AUDIT}/tamper_demo")
    assert res["caught"] is True
