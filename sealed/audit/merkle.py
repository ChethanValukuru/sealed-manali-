"""RFC 6962 Merkle tree — the Evaluation Transparency Log (standout feature).

This turns sealed's signed, hash-chained audit log into a *publicly verifiable,
append-only ledger* of evaluation records — the same construction behind HTTPS
Certificate Transparency and Sigstore/Rekor, now applied to AI-safety tests.

What it adds on top of the existing hash chain (chain.py):

  * a **Merkle root** over all records, published in a signed checkpoint (a
    "Signed Tree Head" / STH),
  * **inclusion proofs** — logarithmic-size proof that one specific test is in
    the ledger, verifiable against the signed root by anyone, offline,
  * **consistency proofs** — proof that a newer checkpoint is an append-only
    extension of an older one, so the operator cannot silently rewrite history.

This is exactly the OPTIONAL "Merkle batch anchoring" mode described in the IETF
*Agent Audit Trail* draft (draft-sharif-agent-audit-trail, S6.4): the per-record
hash chain gives total ordering, and the Merkle root gives logarithmic inclusion
proofs under a single signed anchor.

Leaf definition (must match the in-browser verifier, web/verify.js):
    leaf_data(entry) = bytes.fromhex(entry["hash"])        # the 32-byte entry hash
    leaf_hash        = SHA256(0x00 || leaf_data)           # RFC 6962 leaf prefix
    node_hash(l, r)  = SHA256(0x01 || l || r)              # RFC 6962 node prefix

Nothing here needs the raw payloads: the leaves commit to entry hashes only, so a
proof reveals that a test happened and passed — never the attack text behind it.
"""
from __future__ import annotations

import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(entry_hash_hex: str) -> bytes:
    """RFC 6962 leaf hash of a sealed audit entry, keyed by its chain hash."""
    return _sha256(LEAF_PREFIX + bytes.fromhex(entry_hash_hex))


def node_hash(left: bytes, right: bytes) -> bytes:
    return _sha256(NODE_PREFIX + left + right)


def _largest_power_of_two_below(n: int) -> int:
    """Largest k that is a power of two and k < n (n > 1)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Hash over a list of leaf hashes."""
    n = len(leaves)
    if n == 0:
        return _sha256(b"")
    if n == 1:
        return leaves[0]
    k = _largest_power_of_two_below(n)
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_proof(leaves: list[bytes], m: int) -> list[bytes]:
    """RFC 6962 PATH(m, D[n]) — audit path for the leaf at index m."""
    n = len(leaves)
    if not 0 <= m < n:
        raise IndexError(f"leaf index {m} out of range for tree size {n}")
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if m < k:
        return inclusion_proof(leaves[:k], m) + [merkle_root(leaves[k:])]
    return inclusion_proof(leaves[k:], m - k) + [merkle_root(leaves[:k])]


def verify_inclusion(index: int, tree_size: int, leaf: bytes,
                     proof: list[bytes], root: bytes) -> bool:
    """Recompute the root from a leaf + audit path (RFC 6962 S2.1.1)."""
    if not 0 <= index < tree_size:
        return False
    fn, sn = index, tree_size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            return False
        if (fn & 1) == 1 or fn == sn:
            r = node_hash(p, r)
            if (fn & 1) == 0:
                while (fn & 1) == 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def consistency_proof(leaves: list[bytes], m: int) -> list[bytes]:
    """RFC 6962 PROOF(m, D[n]) — proof that the size-m tree is a prefix of D[n]."""
    n = len(leaves)
    if not 0 < m <= n:
        raise ValueError(f"consistency: need 0 < m ({m}) <= n ({n})")
    if m == n:
        return []
    return _subproof(m, leaves, True)


def _subproof(m: int, leaves: list[bytes], b: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if b else [merkle_root(leaves)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [merkle_root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [merkle_root(leaves[:k])]


def verify_consistency(first_size: int, second_size: int, first_root: bytes,
                       second_root: bytes, proof: list[bytes]) -> bool:
    """Verify an append-only consistency proof between two checkpoints
    (RFC 6962 S2.1.2)."""
    if first_size == 0:
        return True
    if first_size > second_size:
        return False
    if first_size == second_size:
        return first_root == second_root and proof == []

    # If first_size is a power of two, the old root is implied, not sent.
    path = list(proof)
    if first_size & (first_size - 1) == 0:
        path = [first_root] + path

    fn, sn = first_size - 1, second_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    fr = path[0]
    sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if (fn & 1) == 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if (fn & 1) == 0:
                while (fn & 1) == 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1

    return fr == first_root and sr == second_root and sn == 0


# ---- hex convenience (proofs travel as hex over JSON) ------------------------

def leaves_from_entries(entries: list[dict]) -> list[bytes]:
    return [leaf_hash(e["hash"]) for e in entries]


def root_hex(entries: list[dict]) -> str:
    return merkle_root(leaves_from_entries(entries)).hex() if entries else _sha256(b"").hex()


def inclusion_proof_hex(entries: list[dict], index: int) -> list[str]:
    return [h.hex() for h in inclusion_proof(leaves_from_entries(entries), index)]


def consistency_proof_hex(entries: list[dict], first_size: int) -> list[str]:
    return [h.hex() for h in consistency_proof(leaves_from_entries(entries), first_size)]
