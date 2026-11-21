"""Evaluation Transparency Log + IETF AAT export — pure unit tests.

Unlike the container-dependent suites, these exercise the Merkle (RFC 6962) and
AAT (draft-sharif-agent-audit-trail) logic directly, so they run anywhere under
`pytest` with no Docker/Podman host — real CI coverage for the standout feature.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

AUDIT = Path(__file__).resolve().parent.parent / "audit"
WITNESS = Path(__file__).resolve().parent.parent / "witness"
sys.path.insert(0, str(AUDIT))
sys.path.insert(0, str(WITNESS))

import aat        # noqa: E402
import chain      # noqa: E402
import merkle     # noqa: E402
import witness    # noqa: E402  (independent witness implementation)


def _entries(n: int) -> list[dict]:
    """Synthetic audit entries keyed by a deterministic per-entry hash."""
    out = []
    for i in range(n):
        h = hashlib.sha256(f"seal-{i}".encode()).hexdigest()
        out.append({"seq": i + 1, "ts": 1_700_000_000 + i, "test_id": f"t{i // 3}",
                    "actor": ["broker", "red", "model", "blue"][i % 4],
                    "event": ["test_start", "attack", "model_response", "verdict"][i % 4],
                    "payload": {"prompt_hash": h[:16]}, "payload_hash": h, "hash": h})
    return out


def test_merkle_inclusion_roundtrip():
    entries = _entries(13)
    leaves = merkle.leaves_from_entries(entries)
    root = merkle.merkle_root(leaves)
    for i in range(len(entries)):
        proof = merkle.inclusion_proof(leaves, i)
        assert merkle.verify_inclusion(i, len(entries), leaves[i], proof, root)
        # one corrupt step in the path must break it
        if proof:
            bad = list(proof)
            bad[0] = bytes([bad[0][0] ^ 1]) + bad[0][1:]
            assert not merkle.verify_inclusion(i, len(entries), leaves[i], bad, root)


def test_merkle_consistency_is_append_only():
    entries = _entries(20)
    leaves = merkle.leaves_from_entries(entries)
    for first in (1, 5, 8, 16, 19):
        first_root = merkle.merkle_root(leaves[:first])
        second_root = merkle.merkle_root(leaves)
        proof = merkle.consistency_proof(leaves, first)
        assert merkle.verify_consistency(first, 20, first_root, second_root, proof)
        # a rewritten history (last leaf swapped) must fail against the old proof
        rewritten = leaves[:-1] + [merkle.leaf_hash(hashlib.sha256(b"forged").hexdigest())]
        assert not merkle.verify_consistency(first, 20, first_root,
                                             merkle.merkle_root(rewritten), proof)


def test_signed_checkpoint_verifies_and_detects_forgery(tmp_path):
    priv, pub = chain.load_or_create_keys(tmp_path / "keys")
    entries = _entries(9)
    checkpoint = {"log_id": "sealed-evaluation-transparency-log", "tree_size": 9,
                  "root_hash": merkle.root_hex(entries), "timestamp_ms": 1_700_000_000_000}
    digest = chain.sha256_hex(chain.canonical(checkpoint))
    sig = chain.sign(priv, digest)
    assert chain.verify_sig(pub, digest, sig)
    # a forged root (same signature) must not verify
    forged = dict(checkpoint, root_hash="00" * 32)
    assert not chain.verify_sig(pub, chain.sha256_hex(chain.canonical(forged)), sig)


def test_aat_export_has_mandatory_fields_and_intact_chain():
    export = aat.export(_entries(11))
    assert export["format"].startswith("draft-")
    recs = export["records"]
    mandatory = ("record_id", "timestamp", "agent_id", "principal", "agent_version",
                 "session_id", "action_type", "action_detail", "outcome",
                 "trust_level", "prev_hash")
    for r in recs:
        for field in mandatory:
            assert field in r, f"missing AAT field {field}"
        assert r["action_type"] in {"tool_call", "tool_response", "decision",
                                     "delegation", "escalation", "error", "lifecycle"}
        assert r["outcome"] in {"success", "failure", "timeout", "denied", "escalated"}
        assert set(r["principal"]) == {"principal_type", "principal_id", "authority_ref"}
    assert recs[0]["prev_hash"] is None  # genesis
    assert aat.verify_aat_chain(recs)["intact"] is True


def test_aat_chain_detects_tampering():
    recs = aat.to_aat_records(_entries(8))
    recs[4]["outcome"] = "denied"  # flip a recorded outcome
    res = aat.verify_aat_chain(recs)
    assert res["intact"] is False and res["broken_index"] == 5


def test_selective_disclosure_keeps_only_hashes():
    recs = aat.to_aat_records(_entries(4))
    for r in recs:
        assert "payload_hash" in r["action_detail"]
        # the mapped payload carries hashes sealed already stores, never raw text
        assert "prompt" not in r["action_detail"]["payload"]


def test_witness_rejects_fork_accepts_append_only():
    """The independent witness implementation agrees with audit/merkle on a real
    consistency proof, and refuses a rewritten history or a missing proof —
    so a quorum of witnesses binds the audit service to one append-only ledger."""
    leaves = merkle.leaves_from_entries(_entries(16))
    first, second = 10, 16
    fr = merkle.merkle_root(leaves[:first])
    sr = merkle.merkle_root(leaves[:second])
    proof = merkle.consistency_proof(leaves[:second], first)
    assert witness._verify_consistency(first, second, fr, sr, proof) is True
    assert witness._verify_consistency(first, second, fr, b"\x00" * 32, proof) is False
    assert witness._verify_consistency(first, second, fr, sr, []) is False
