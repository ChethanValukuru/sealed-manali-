"""One-way monitor (Phase 4 / M5).

Observes boundary violations and writes them to the audit log. It is one-way: its
only inbound is POST /alert (from the broker, and from a host nftables-log feeder)
plus /health; it never serves alert data back to anyone. Tenants are not on the
monitor's network, so they have no read path to it (invariant 5), and the
monitor's independent write to audit means boundary violations are recorded even
by a party other than the component that was violated.

nftables denials: on the host, pipe `sealed-drop:` log lines (see
isolation/nftables/default-deny.nft) to POST /alert with kind="nftables_drop".
The broker's policy violations are the live source wired here.
"""
from __future__ import annotations

import os

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

AUDIT_URL = os.environ.get("AUDIT_URL", "http://audit:8001")

app = FastAPI(title="sealed-monitor", version="0.4.0")

_alerts_seen = 0


class Alert(BaseModel):
    source: str              # broker | nftables | ...
    kind: str                # capability_denied | disclosure_withheld | nftables_drop
    detail: dict = {}


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "monitor", "alerts_seen": _alerts_seen}


@app.post("/alert")
def alert(a: Alert) -> dict:
    """Record a boundary-violation alert to the tamper-evident audit log."""
    global _alerts_seen
    _alerts_seen += 1
    try:
        with httpx.Client(timeout=10.0) as client:
            client.post(f"{AUDIT_URL}/append", json={
                "actor": "monitor",
                "event": "alert",
                "payload": {"source": a.source, "kind": a.kind, "detail": a.detail},
            })
    except Exception:  # noqa: BLE001 - never let alerting crash; stay one-way
        pass
    return {"recorded": True, "alerts_seen": _alerts_seen}
