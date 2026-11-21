"""IETF *Agent Audit Trail* (AAT) export — standards-aligned audit records.

Maps sealed's native audit entries onto the record structure defined in
draft-sharif-agent-audit-trail (Agent Audit Trail: A Standard Logging Format for
Autonomous AI Systems), which specifies a JSON record with mandatory fields for
agent identity, the authorizing principal, action classification, outcome, and
trust level, linked by a SHA-256 hash chain over RFC 8785 (JCS) canonical bytes.

Why this matters: the draft is written to the EU AI Act's record-keeping mandate
for high-risk AI systems. Emitting sealed's log in this format means a regulator
or auditor can ingest a sealed evaluation with a standard, not a bespoke, parser —
and the Merkle checkpoint (merkle.py) is exactly the draft's optional S6.4 batch
anchor over these records.

The export recomputes an independent prev_hash chain over the AAT records, so the
exported log verifies on its own terms (verify_aat_chain). Records carry only the
hashed payloads sealed already stores — never raw attack text (S12 privacy).
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

SEALED_VERSION = "0.5.0"
AGENT_ID = "urn:agent:sealed:broker"
# Stable namespace so record_id / session_id are reproducible across exports.
_NS = uuid.UUID("5ea1ed00-0000-4000-8000-00000000a17a")

# sealed event -> (AAT action_type, AAT outcome)
_ACTION = {
    "test_start":         ("lifecycle", "success"),
    "test_conclude":      ("lifecycle", "success"),
    "attack":             ("tool_call", "success"),
    "model_response":     ("tool_response", "success"),
    "verdict":            ("decision", "success"),
    "policy_violation":   ("decision", "denied"),
    "disclosure_withheld":("decision", "denied"),
    "attack_rejected":    ("error", "failure"),
    "attestation_issued": ("lifecycle", "success"),
    "capability_denied":  ("escalation", "denied"),
}
_TRUSTED_ACTORS = {"broker", "audit", "monitor"}


def _jcs(obj: dict) -> bytes:
    """RFC 8785-style canonical JSON (approximation: sorted keys, compact,
    UTF-8). AAT records use only strings/ints/objects, so number canonicalization
    is not exercised."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _rfc3339(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") \
        + f"{int((ts % 1) * 1000):03d}Z"


def _to_record(entry: dict) -> dict:
    actor = entry.get("actor", "unknown")
    event = entry.get("event", "lifecycle")
    test_id = entry.get("test_id")
    action_type, outcome = _ACTION.get(event, ("lifecycle", "success"))
    return {
        "record_id": str(uuid.uuid5(_NS, f"{test_id}:{entry.get('seq')}")),
        "timestamp": _rfc3339(entry.get("ts", 0.0)),
        "agent_id": f"urn:agent:sealed:{actor}",
        "principal": {
            "principal_type": "service",
            "principal_id": "urn:sealed:operator",
            "authority_ref": f"urn:sealed:test:{test_id}" if test_id else None,
        },
        "agent_version": SEALED_VERSION,
        "session_id": str(uuid.uuid5(_NS, test_id or "sealed-session")),
        "action_type": action_type,
        "action_detail": {
            "sealed_event": event,
            "sealed_seq": entry.get("seq"),
            "actor": actor,
            # already hash-only in sealed's design — never raw attack text
            "payload": entry.get("payload", {}),
            "payload_hash": entry.get("payload_hash"),
        },
        "outcome": outcome,
        "trust_level": "trusted" if actor in _TRUSTED_ACTORS else "untrusted",
    }


def to_aat_records(entries: list[dict]) -> list[dict]:
    """Map sealed entries to AAT records and link them with an independent
    prev_hash chain over JCS canonical bytes (genesis prev_hash = null)."""
    records: list[dict] = []
    prev_hash = None
    for e in entries:
        rec = _to_record(e)
        rec["prev_hash"] = prev_hash
        records.append(rec)
        prev_hash = hashlib.sha256(_jcs(rec)).hexdigest()
    return records


def verify_aat_chain(records: list[dict]) -> dict:
    """Re-walk the AAT prev_hash chain (draft S6.3)."""
    prev = None
    for i, rec in enumerate(records):
        if rec.get("prev_hash") != prev:
            return {"intact": False, "broken_index": i, "reason": "prev_hash mismatch"}
        signed = {k: v for k, v in rec.items() if k != "prev_hash"}
        signed["prev_hash"] = rec.get("prev_hash")
        prev = hashlib.sha256(_jcs(rec)).hexdigest()
    return {"intact": True, "records": len(records)}


def export(entries: list[dict]) -> dict:
    return {
        "format": "draft-sharif-agent-audit-trail",
        "profile": "sealed/0.5",
        "canonicalization": "RFC8785-JCS",
        "hash": "SHA-256",
        "note": ("Standards-aligned export of the sealed audit log. The Merkle "
                 "checkpoint (/log/checkpoint) is the draft S6.4 batch anchor over "
                 "these records; raw attack text is never included (S12 privacy)."),
        "records": to_aat_records(entries),
    }
