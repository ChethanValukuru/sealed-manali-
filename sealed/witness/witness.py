"""Independent checkpoint witness (trust-minimizing the transparency log).

The audit service signs its own ledger, so a *compromised audit key* could in
principle fork a fresh chain (see THREAT_MODEL.md). A **witness** removes that
single point of trust: it is a separate process, with its own Ed25519 key, that
co-signs the ledger's Merkle checkpoint **only after verifying the new checkpoint
is an append-only extension of the last one it saw**. Run a few, require a quorum,
and nobody — not even sealed's own audit service — can make a verifier accept a
rewritten history without also compromising the witnesses' independent keys.

This is the AI-safety analogue of Certificate Transparency's witness/gossip model
and Sigstore's log witnesses.

Deliberately self-contained: it shares no code with the audit service (its own
canonical-JSON, signatures, and RFC 6962 consistency check), so it is a genuinely
independent second implementation of the same math.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

NAME = os.environ.get("WITNESS_NAME", "witness")
DATA_DIR = Path(os.environ.get("WITNESS_DATA_DIR", "/data"))
STATE_PATH = DATA_DIR / "state.json"
KEYS_DIR = DATA_DIR / "keys"

_lock = threading.Lock()
_priv: Ed25519PrivateKey | None = None
_pub_pem: str = ""


# ---- independent crypto (not shared with the audit service, on purpose) ------

def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _verify_consistency(first_size: int, second_size: int, first_root: bytes,
                        second_root: bytes, proof: list[bytes]) -> bool:
    """RFC 6962 consistency verification (independent of audit/merkle.py)."""
    if first_size == 0:
        return True
    if first_size > second_size:
        return False
    if first_size == second_size:
        return first_root == second_root and proof == []
    path = list(proof)
    if first_size & (first_size - 1) == 0:
        path = [first_root] + path
    if not path:  # a missing/empty proof cannot establish consistency
        return False
    fn, sn = first_size - 1, second_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if (fn & 1) == 1 or fn == sn:
            fr = _node(c, fr)
            sr = _node(c, sr)
            if (fn & 1) == 0:
                while (fn & 1) == 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _node(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0


def _verify_pem_sig(pub_pem: str, hash_hex: str, sig_hex: str) -> bool:
    try:
        pub = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
        pub.verify(bytes.fromhex(sig_hex), hash_hex.encode("utf-8"))
        return True
    except Exception:  # noqa: BLE001
        return False


def _load_keys() -> None:
    global _priv, _pub_pem
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    priv_path = KEYS_DIR / "ed25519_private.pem"
    pub_path = KEYS_DIR / "ed25519_public.pem"
    if priv_path.exists():
        _priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    else:
        _priv = Ed25519PrivateKey.generate()
        priv_path.write_bytes(_priv.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        pub_path.write_bytes(_priv.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    _pub_pem = pub_path.read_text(encoding="utf-8")


def _state() -> dict:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    return {"last_size": 0, "last_root": None}


def _save_state(size: int, root_hex: str) -> None:
    STATE_PATH.write_text(json.dumps({"last_size": size, "last_root": root_hex}),
                          encoding="utf-8")


app = FastAPI(title="sealed-witness", version="0.5.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"])


@app.on_event("startup")
def startup() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    _load_keys()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "witness", "name": NAME,
            "co_signed_size": _state()["last_size"]}


@app.get("/witness/latest")
def latest() -> dict:
    st = _state()
    return {"name": NAME, "last_size": st["last_size"], "last_root": st["last_root"],
            "public_key_pem": _pub_pem}


class Consistency(BaseModel):
    first_size: int
    proof: list[str] = []


class CosignReq(BaseModel):
    checkpoint: dict
    audit_signature: str
    audit_public_key_pem: str
    consistency: Consistency | None = None


@app.post("/witness/cosign")
def cosign(req: CosignReq) -> dict:
    """Co-sign a checkpoint iff it is a genuine, append-only extension of the last
    one this witness saw. Refuses (409) on a fork, rollback, or equivocation."""
    digest = _sha256_hex(_canonical(req.checkpoint))
    if not _verify_pem_sig(req.audit_public_key_pem, digest, req.audit_signature):
        raise HTTPException(status_code=400, detail="audit signature does not match checkpoint")

    new_size = int(req.checkpoint["tree_size"])
    new_root_hex = req.checkpoint["root_hash"]
    new_root = bytes.fromhex(new_root_hex)

    with _lock:
        st = _state()
        last_size = st["last_size"]
        last_root = bytes.fromhex(st["last_root"]) if st["last_root"] else None

        if last_size == 0:
            pass  # trust on first use (like a fresh CT witness)
        elif new_size == last_size:
            if new_root != last_root:
                raise HTTPException(status_code=409,
                                    detail="equivocation: same size, different root")
        elif new_size > last_size:
            proof = [bytes.fromhex(h) for h in (req.consistency.proof if req.consistency else [])]
            if not _verify_consistency(last_size, new_size, last_root, new_root, proof):
                raise HTTPException(status_code=409,
                                    detail="inconsistent: append-only proof failed (possible fork)")
        else:
            raise HTTPException(status_code=409,
                                detail="rollback: new size below last co-signed size")

        signature = _priv.sign(digest.encode("utf-8")).hex()
        _save_state(new_size, new_root_hex)

    return {"name": NAME, "public_key_pem": _pub_pem, "signature": signature,
            "co_signed_size": new_size}
