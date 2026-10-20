"""Audit service (Phase 3 / M3) — tamper-evident, append-only, signed log.

Each append extends a SHA-256 hash chain and Ed25519-signs the entry (see
chain.py). The HTTP surface is unchanged from Phase 1 so the broker needs no
edits; a /verify endpoint is added for the dashboard/tests.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import chain

DATA_DIR = Path(os.environ.get("AUDIT_DATA_DIR", "/data"))
LOG_PATH = DATA_DIR / "audit.jsonl"
KEYS_DIR = DATA_DIR / "keys"

app = FastAPI(title="sealed-audit", version="0.4.0")
# CORS so the minimal dashboard (served on another port) can read + verify.
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"])

_lock = threading.Lock()
_seq = 0
_last_hash = chain.GENESIS_PREV
_priv = None
_pub = None


def _read_entries(path: Path) -> list[dict]:
    entries: list[dict] = []
    if path.exists():
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
    return entries


def _init() -> None:
    global _seq, _last_hash, _priv, _pub
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    _priv, _pub = chain.load_or_create_keys(KEYS_DIR)
    entries = _read_entries(LOG_PATH)
    if entries:
        _seq = entries[-1]["seq"]
        _last_hash = entries[-1]["hash"]


@app.on_event("startup")
def startup() -> None:
    _init()


class AppendReq(BaseModel):
    test_id: str | None = None
    actor: str
    event: str
    payload: dict = {}


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "audit", "entries": _seq, "signed": True}


@app.post("/append")
def append(req: AppendReq) -> dict:
    global _seq, _last_hash
    with _lock:
        seq = _seq + 1
        ts = time.time()
        payload_hash = chain.compute_payload_hash(req.payload)
        prev_hash = _last_hash
        h = chain.compute_entry_hash(seq, ts, req.test_id, req.actor, req.event,
                                     payload_hash, prev_hash)
        sig = chain.sign(_priv, h)
        entry = {
            "seq": seq, "ts": ts, "test_id": req.test_id, "actor": req.actor,
            "event": req.event, "payload": req.payload, "payload_hash": payload_hash,
            "prev_hash": prev_hash, "hash": h, "sig": sig,
        }
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        _seq = seq
        _last_hash = h
    return {"seq": seq, "hash": h}


@app.get("/log")
def get_log(test_id: str | None = None, limit: int = 200) -> dict:
    entries = _read_entries(LOG_PATH)
    if test_id is not None:
        entries = [e for e in entries if e.get("test_id") == test_id]
    return {"count": len(entries[-limit:]), "entries": entries[-limit:]}


@app.post("/verify")
def verify(path: str | None = None) -> dict:
    """Re-walk the chain and report integrity. Defaults to the live log."""
    target = Path(path) if path else LOG_PATH
    entries = _read_entries(target)
    return chain.verify_chain(entries, _pub)


class AttestReq(BaseModel):
    eval_id: str
    facts: dict = {}


@app.post("/attest")
def attest(req: AttestReq) -> dict:
    """Issue a signed attestation that an evaluation ran in a sound environment.

    The attestation bundles the broker-reported facts with a fresh check that the
    audit chain is intact, then Ed25519-signs the whole thing. Anyone with the
    public key can verify it later (via /verify_attestation) — turning "trust us"
    into "verify us".
    """
    entries = _read_entries(LOG_PATH)
    chk = chain.verify_chain(entries, _pub)
    attestation = {
        "eval_id": req.eval_id,
        "facts": req.facts,
        "chain_intact": bool(chk.get("intact")),
        "entries_recorded": len(entries),
        "issuer": "sealed-audit",
        "issued_at": time.time(),
    }
    digest = chain.sha256_hex(chain.canonical(attestation))
    signature = chain.sign(_priv, digest)
    append(AppendReq(test_id=req.eval_id, actor="audit", event="attestation_issued",
                     payload={"chain_intact": attestation["chain_intact"]}))
    pub_pem = (KEYS_DIR / "ed25519_public.pem").read_text(encoding="utf-8")
    return {"attestation": attestation, "signature": signature, "public_key_pem": pub_pem}


class VerifyAttReq(BaseModel):
    attestation: dict
    signature: str


@app.post("/verify_attestation")
def verify_attestation(req: VerifyAttReq) -> dict:
    """Re-check an attestation's signature against the audit public key."""
    digest = chain.sha256_hex(chain.canonical(req.attestation))
    return {"valid": chain.verify_sig(_pub, digest, req.signature)}


@app.post("/tamper_demo")
def tamper_demo() -> dict:
    """Prove tamper-evidence live: copy the log, silently edit one entry, and
    show the verifier catches it. The real log is untouched."""
    entries = _read_entries(LOG_PATH)
    if not entries:
        return {"caught": False, "reason": "no entries yet — run a test first"}
    victim = len(entries) // 2
    edited = [dict(e) for e in entries]
    edited[victim] = dict(edited[victim])
    edited[victim]["payload"] = {**edited[victim].get("payload", {}), "_tampered": "x"}
    result = chain.verify_chain(edited, _pub)
    return {"caught": not result.get("intact"), "reason": result.get("reason", "")}
