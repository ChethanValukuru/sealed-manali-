"""Tamper-evident audit primitives (Phase 3 / M3).

Shared by the log service (append) and the verifier (re-walk). An entry is:

    {seq, ts, test_id, actor, event, payload, payload_hash, prev_hash, hash, sig}

where
    payload_hash = SHA256(canonical(payload))
    hash         = SHA256(canonical({seq, ts, test_id, actor, event,
                                     payload_hash, prev_hash}))
    sig          = Ed25519_sign(hash)                     [hex]

The hash chain (prev_hash links) makes insert/delete/reorder detectable; the
per-entry hash makes any field edit detectable; the Ed25519 signature makes a
re-signed forgery infeasible without the private key. Genesis prev_hash is 64
zeros.

Trust note (for THREAT_MODEL.md, Phase 4): the audit service holds the signing
key, so a compromised audit service could forge a fresh chain. The chain protects
against tampering by anyone WITHOUT the key (tenants, storage, transport).
Removing audit from the trusted base (external signing / attestation) is future
work.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

GENESIS_PREV = "0" * 64


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_payload_hash(payload: dict) -> str:
    return sha256_hex(canonical(payload))


def compute_entry_hash(seq: int, ts: float, test_id, actor: str, event: str,
                       payload_hash: str, prev_hash: str) -> str:
    return sha256_hex(canonical({
        "seq": seq,
        "ts": ts,
        "test_id": test_id,
        "actor": actor,
        "event": event,
        "payload_hash": payload_hash,
        "prev_hash": prev_hash,
    }))


# ---- keys -------------------------------------------------------------------

def load_or_create_keys(keys_dir: Path) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    keys_dir.mkdir(parents=True, exist_ok=True)
    priv_path = keys_dir / "ed25519_private.pem"
    pub_path = keys_dir / "ed25519_public.pem"

    if priv_path.exists():
        priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    else:
        priv = Ed25519PrivateKey.generate()
        priv_path.write_bytes(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        pub_path.write_bytes(priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    return priv, priv.public_key()


def load_public(keys_dir: Path) -> Ed25519PublicKey:
    pub_path = keys_dir / "ed25519_public.pem"
    return serialization.load_pem_public_key(pub_path.read_bytes())


def sign(priv: Ed25519PrivateKey, hash_hex: str) -> str:
    return priv.sign(hash_hex.encode("utf-8")).hex()


def verify_sig(pub: Ed25519PublicKey, hash_hex: str, sig_hex: str) -> bool:
    try:
        pub.verify(bytes.fromhex(sig_hex), hash_hex.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---- verification -----------------------------------------------------------

def verify_chain(entries: list[dict], pub: Ed25519PublicKey) -> dict:
    """Re-walk the chain. Returns {intact, broken_seq?, reason?}."""
    expected_prev = GENESIS_PREV
    expected_seq = 1

    for e in entries:
        seq = e.get("seq")

        if seq != expected_seq:
            return {"intact": False, "broken_seq": seq,
                    "reason": f"sequence gap: expected {expected_seq}, got {seq}"}

        # 1) payload integrity
        ph = compute_payload_hash(e.get("payload", {}))
        if ph != e.get("payload_hash"):
            return {"intact": False, "broken_seq": seq, "reason": "payload modified"}

        # 2) entry-field integrity
        h = compute_entry_hash(e["seq"], e["ts"], e.get("test_id"), e["actor"],
                               e["event"], e["payload_hash"], e["prev_hash"])
        if h != e.get("hash"):
            return {"intact": False, "broken_seq": seq, "reason": "entry fields modified"}

        # 3) signature
        if not verify_sig(pub, e["hash"], e.get("sig", "")):
            return {"intact": False, "broken_seq": seq, "reason": "signature invalid"}

        # 4) chain link
        if e.get("prev_hash") != expected_prev:
            return {"intact": False, "broken_seq": seq,
                    "reason": "broken chain link (insert/delete/reorder)"}

        expected_prev = e["hash"]
        expected_seq += 1

    return {"intact": True, "entries": len(entries)}
