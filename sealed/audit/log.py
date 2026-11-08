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
import urllib.request
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import aat
import chain
import merkle

DATA_DIR = Path(os.environ.get("AUDIT_DATA_DIR", "/data"))
LOG_PATH = DATA_DIR / "audit.jsonl"
KEYS_DIR = DATA_DIR / "keys"
# Write endpoints (/append, /attest) are for trusted services only (broker,
# monitor). When this is set, those calls must carry the matching X-Audit-Token,
# so a party that can reach the published port cannot inject log entries or mint
# forged attestations. Read endpoints (/log, /verify, ...) stay open.
WRITE_TOKEN = os.environ.get("AUDIT_WRITE_TOKEN")
# Independent checkpoint witnesses (co-signing the transparency log). Comma-
# separated base URLs; a quorum co-signs before a checkpoint is "witnessed".
WITNESS_URLS = [u.strip() for u in os.environ.get("WITNESS_URLS", "").split(",") if u.strip()]
WITNESS_QUORUM = int(os.environ.get("WITNESS_QUORUM", "1"))


def _guard_write(token: str | None) -> None:
    if WRITE_TOKEN and token != WRITE_TOKEN:
        raise HTTPException(status_code=403, detail="audit write not permitted")

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


def _append_entry(req: AppendReq) -> dict:
    """Core append — extends the signed hash chain. Callers must already be
    authorized (the /append endpoint guards; internal callers are trusted)."""
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


@app.post("/append")
def append(req: AppendReq,
           x_audit_token: str | None = Header(default=None, alias="X-Audit-Token")) -> dict:
    _guard_write(x_audit_token)
    return _append_entry(req)


@app.get("/log")
def get_log(test_id: str | None = None, limit: int = 200) -> dict:
    entries = _read_entries(LOG_PATH)
    if test_id is not None:
        entries = [e for e in entries if e.get("test_id") == test_id]
    return {"count": len(entries[-limit:]), "entries": entries[-limit:]}


@app.post("/verify")
def verify() -> dict:
    """Re-walk the live audit chain and report integrity. (No caller-supplied
    path — that would be an arbitrary-file-read vector.)"""
    return chain.verify_chain(_read_entries(LOG_PATH), _pub)


class AttestReq(BaseModel):
    eval_id: str
    facts: dict = {}


@app.post("/attest")
def attest(req: AttestReq,
           x_audit_token: str | None = Header(default=None, alias="X-Audit-Token")) -> dict:
    """Issue a signed attestation that an evaluation ran in a sound environment.

    Broker-only (guarded): otherwise anyone reaching the published port could mint
    a signed attestation with forged facts. The attestation bundles the facts with
    a fresh check that the audit chain is intact, then Ed25519-signs the whole
    thing. Anyone with the public key can verify it (via /verify_attestation).
    """
    _guard_write(x_audit_token)
    entries = _read_entries(LOG_PATH)
    chk = chain.verify_chain(entries, _pub)
    attestation = {
        "eval_id": req.eval_id,
        "facts": req.facts,
        "chain_intact": bool(chk.get("intact")),
        "entries_recorded": len(entries),
        "issuer": "sealed-audit",
        # integer ms so the signed attestation verifies byte-for-byte in-browser.
        "issued_at_ms": int(time.time() * 1000),
    }
    digest = chain.sha256_hex(chain.canonical(attestation))
    signature = chain.sign(_priv, digest)
    _append_entry(AppendReq(test_id=req.eval_id, actor="audit", event="attestation_issued",
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


# ---- Evaluation Transparency Log (RFC 6962 Merkle over the signed chain) -----
#
# Turns the append-only audit log into a publicly verifiable ledger: a signed
# Merkle checkpoint (Signed Tree Head), logarithmic inclusion proofs that one test
# is in the ledger, and consistency proofs that the ledger was never rewritten.
# This is the IETF Agent Audit Trail draft's optional S6.4 batch-anchoring mode.
# Leaves commit to entry hashes only, so proofs never reveal raw attack text.

LOG_ID = "sealed-evaluation-transparency-log"


def _sign_checkpoint(entries: list[dict]) -> dict:
    tree_size = len(entries)
    root_hash = merkle.root_hex(entries)
    checkpoint = {
        "log_id": LOG_ID,
        "tree_size": tree_size,
        "root_hash": root_hash,
        # integer ms (not a float) so the signed bytes are identical in Python and
        # the in-browser JS verifier (web/verify.js) — floats serialize differently.
        "timestamp_ms": int(time.time() * 1000),
    }
    digest = chain.sha256_hex(chain.canonical(checkpoint))
    signature = chain.sign(_priv, digest)
    pub_pem = (KEYS_DIR / "ed25519_public.pem").read_text(encoding="utf-8")
    return {"checkpoint": checkpoint, "signature": signature, "public_key_pem": pub_pem}


@app.get("/log/checkpoint")
def log_checkpoint() -> dict:
    """Signed Tree Head: the Merkle root over every record, Ed25519-signed.
    Anyone can pin this and later demand inclusion/consistency proofs against it."""
    return _sign_checkpoint(_read_entries(LOG_PATH))


def _wreq(method: str, url: str, body: dict | None = None, timeout: float = 5.0) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _cosign_checkpoint(checkpoint: dict, signature: str) -> list[dict]:
    """Ask each witness to co-sign this checkpoint, supplying a consistency proof
    from the witness's last-seen size. A witness that is down, or that refuses
    because the history is inconsistent, simply does not count toward quorum."""
    if not WITNESS_URLS:
        return []
    entries = _read_entries(LOG_PATH)
    tree_size = checkpoint["tree_size"]
    pub_pem = (KEYS_DIR / "ed25519_public.pem").read_text(encoding="utf-8")
    out: list[dict] = []
    for w in WITNESS_URLS:
        try:
            latest = _wreq("GET", f"{w}/witness/latest")
            last = int(latest.get("last_size") or 0)
            consistency = None
            if 0 < last <= tree_size:
                consistency = {"first_size": last,
                               "proof": merkle.consistency_proof_hex(entries[:tree_size], last)}
            res = _wreq("POST", f"{w}/witness/cosign", {
                "checkpoint": checkpoint, "audit_signature": signature,
                "audit_public_key_pem": pub_pem, "consistency": consistency,
            })
            out.append({"name": res["name"], "public_key_pem": res["public_key_pem"],
                        "signature": res["signature"]})
        except Exception:  # noqa: BLE001 — a refusing/offline witness just abstains
            continue
    return out


class CosignReq(BaseModel):
    checkpoint: dict
    signature: str


@app.post("/log/cosign")
def log_cosign(req: CosignReq) -> dict:
    """Gather independent witness co-signatures for a given signed checkpoint."""
    w = _cosign_checkpoint(req.checkpoint, req.signature)
    return {"checkpoint": req.checkpoint, "audit_signature": req.signature,
            "witnesses": w, "witness_count": len(w), "quorum": WITNESS_QUORUM,
            "witnessed": len(w) >= WITNESS_QUORUM}


@app.get("/log/checkpoint/witnessed")
def log_checkpoint_witnessed() -> dict:
    """The current checkpoint plus independent witness co-signatures — the
    trust-minimized head of the ledger (no single key can rewrite history)."""
    bundle = _sign_checkpoint(_read_entries(LOG_PATH))
    w = _cosign_checkpoint(bundle["checkpoint"], bundle["signature"])
    return {**bundle, "witnesses": w, "witness_count": len(w),
            "quorum": WITNESS_QUORUM, "witnessed": len(w) >= WITNESS_QUORUM}


@app.get("/log/proof/inclusion")
def log_inclusion(seq: int) -> dict:
    """Prove that the record with this seq is in the ledger, against the signed
    root. `seq` is 1-based (matches the audit entry's seq)."""
    entries = _read_entries(LOG_PATH)
    index = seq - 1
    if not 0 <= index < len(entries):
        raise HTTPException(status_code=404, detail="seq out of range")
    bundle = _sign_checkpoint(entries)
    return {
        "leaf_index": index,
        "tree_size": len(entries),
        "entry_hash": entries[index]["hash"],
        "leaf_hash": merkle.leaf_hash(entries[index]["hash"]).hex(),
        "audit_path": merkle.inclusion_proof_hex(entries, index),
        **bundle,
    }


@app.get("/log/proof/consistency")
def log_consistency(first: int, second: int | None = None) -> dict:
    """Prove the size-`first` ledger is an append-only prefix of the size-`second`
    ledger — i.e. history was never edited or dropped between two checkpoints."""
    entries = _read_entries(LOG_PATH)
    n = len(entries)
    second = n if second is None else second
    if not 0 < first <= second <= n:
        raise HTTPException(status_code=400, detail="require 0 < first <= second <= tree_size")
    return {
        "first_size": first,
        "second_size": second,
        "first_root": merkle.root_hex(entries[:first]),
        "second_root": merkle.root_hex(entries[:second]),
        "proof": merkle.consistency_proof_hex(entries[:second], first),
    }


@app.get("/log/public")
def log_public(limit: int = 500) -> dict:
    """Selective-disclosure view: the ledger with raw payloads redacted to their
    hashes. Proves what happened without exposing the attack text (never stored
    in the clear anyway) — safe to publish."""
    entries = _read_entries(LOG_PATH)[-limit:]
    redacted = [{
        "seq": e["seq"], "ts": e["ts"], "test_id": e.get("test_id"),
        "actor": e["actor"], "event": e["event"],
        "payload_hash": e["payload_hash"], "hash": e["hash"],
    } for e in entries]
    return {"count": len(redacted), "entries": redacted,
            "note": "payloads redacted to hashes (selective disclosure)"}


@app.get("/log/aat")
def log_aat(limit: int = 500) -> dict:
    """Export the log in the IETF Agent Audit Trail draft format (standards-
    aligned record structure + its own prev_hash chain over RFC 8785 JCS)."""
    return aat.export(_read_entries(LOG_PATH)[-limit:])


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
