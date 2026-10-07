"""Thin client the broker uses to record events to the audit service."""
from __future__ import annotations

import hashlib
import json
import os

import httpx

AUDIT_URL = os.environ.get("AUDIT_URL", "http://audit:8001")


def payload_hash(payload: dict) -> str:
    """Stable SHA-256 of a payload. In Phase 1 we store the hash alongside events
    so the audit log need not hold raw (possibly sensitive) attack text. Phase 3
    chains these hashes into the tamper-evident structure."""
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def record(actor: str, event: str, test_id: str | None = None,
           payload: dict | None = None) -> None:
    """Best-effort append. Never breaks the eval loop if audit is briefly down."""
    body = {"actor": actor, "event": event, "test_id": test_id,
            "payload": payload or {}}
    try:
        with httpx.Client(timeout=10.0) as client:
            client.post(f"{AUDIT_URL}/append", json=body)
    except Exception:  # noqa: BLE001 - audit is append-only; log-and-continue
        # Phase 4's monitor will surface audit outages; for M1 we stay resilient.
        pass
