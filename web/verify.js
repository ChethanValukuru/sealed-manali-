/*  sealed — in-browser, zero-trust proof verifier.
 *
 *  Verifies a sealed Evaluation Transparency Log proof bundle entirely on the
 *  client, with only the public key. No call back to sealed is trusted: the
 *  signatures and the Merkle inclusion are recomputed here.
 *
 *  Checks performed:
 *    1. attestation signature  (Ed25519 over the canonical attestation)
 *    2. checkpoint signature    (Ed25519 over the Signed Tree Head)
 *    3. Merkle inclusion        (recompute the root from leaf + audit path)
 *    4. the attestation's own "chain_intact" claim
 *
 *  Canonicalization mirrors the Python side (json.dumps sort_keys, compact).
 *  The signed objects carry only ASCII strings/ints, so the bytes match exactly.
 */
import * as ed from "./vendor/noble-ed25519.js";

// ---- encoding helpers -------------------------------------------------------
const enc = new TextEncoder();

export function hexToBytes(hex) {
  const n = hex.length / 2, out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
export function bytesToHex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}
function concat(...arrs) {
  let len = 0; for (const a of arrs) len += a.length;
  const out = new Uint8Array(len); let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

// Canonical JSON: must byte-match Python json.dumps(sort_keys=True,
// separators=(",",":")). Signed objects are ASCII strings / ints / bools / null.
export function canonicalJSON(v) {
  if (v === null) return "null";
  const t = typeof v;
  if (t === "number") {
    if (!Number.isFinite(v)) throw new Error("non-finite number");
    return String(v);
  }
  if (t === "boolean") return v ? "true" : "false";
  if (t === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalJSON).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map(k => JSON.stringify(k) + ":" + canonicalJSON(v[k])).join(",") + "}";
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
async function sha256hex(bytes) { return bytesToHex(await sha256(bytes)); }

// ---- key + signature --------------------------------------------------------
// Extract the raw 32-byte Ed25519 key from an SPKI PEM (fixed 44-byte DER).
export function rawKeyFromPem(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return der.slice(der.length - 32);
}

// A sealed signature is Ed25519 over the UTF-8 bytes of the hex SHA-256 of the
// canonical object (matches audit/chain.py: sign(sha256hex(canonical(obj)))).
export async function verifySignedObject(obj, sigHex, rawPub) {
  const digestHex = await sha256hex(enc.encode(canonicalJSON(obj)));
  try {
    return await ed.verifyAsync(hexToBytes(sigHex), enc.encode(digestHex), rawPub);
  } catch (_) { return false; }
}

// ---- RFC 6962 Merkle inclusion ---------------------------------------------
async function leafHash(entryHashHex) {
  return sha256(concat(new Uint8Array([0x00]), hexToBytes(entryHashHex)));
}
async function nodeHash(l, r) {
  return sha256(concat(new Uint8Array([0x01]), l, r));
}
export async function verifyInclusion(index, size, entryHashHex, auditPathHex, rootHex) {
  if (!(index >= 0 && index < size)) return false;
  let fn = index, sn = size - 1;
  let r = await leafHash(entryHashHex);
  for (const ph of auditPathHex) {
    const p = hexToBytes(ph);
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = await nodeHash(p, r);
      if ((fn & 1) === 0) { while ((fn & 1) === 0) { fn >>= 1; sn >>= 1; } }
    } else {
      r = await nodeHash(r, p);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && bytesToHex(r) === rootHex;
}

// ---- full bundle ------------------------------------------------------------
export async function verifyBundle(bundle) {
  const steps = [];
  const pub = rawKeyFromPem(bundle.public_key_pem || bundle.inclusion.public_key_pem);
  const inc = bundle.inclusion;

  const attOk = await verifySignedObject(bundle.attestation, bundle.signature, pub);
  steps.push({ key: "attestation", label: "Attestation signature (Ed25519)", ok: attOk,
    detail: attOk ? "signed by the audit key" : "signature does not match" });

  const ckOk = await verifySignedObject(inc.checkpoint, inc.signature, pub);
  steps.push({ key: "checkpoint", label: "Transparency-log checkpoint signature", ok: ckOk,
    detail: ckOk ? `root ${inc.checkpoint.root_hash.slice(0, 16)}… over ${inc.checkpoint.tree_size} records`
                 : "checkpoint signature does not match" });

  const incOk = await verifyInclusion(inc.leaf_index, inc.tree_size, inc.entry_hash,
                                      inc.audit_path, inc.checkpoint.root_hash);
  steps.push({ key: "inclusion", label: "Merkle inclusion proof", ok: incOk,
    detail: incOk ? `record #${inc.leaf_index + 1} is in the signed ledger`
                  : "record is NOT provably in the ledger" });

  const chainClaim = bundle.attestation.chain_intact === true;
  steps.push({ key: "chain", label: "Attested: audit chain intact", ok: chainClaim,
    detail: chainClaim ? "the signed attestation asserts an intact chain" : "chain not asserted intact" });

  // Independent witnesses co-sign the SAME checkpoint. Each signature is checked
  // against that witness's own public key — so trust is spread across keys, not
  // concentrated in the audit service.
  if (Array.isArray(bundle.witnesses) && bundle.witnesses.length) {
    let valid = 0; const names = [];
    for (const w of bundle.witnesses) {
      if (await verifySignedObject(inc.checkpoint, w.signature, rawKeyFromPem(w.public_key_pem))) {
        valid++; names.push(w.name);
      }
    }
    const quorum = bundle.quorum || 1;
    steps.push({ key: "witnesses",
      label: `Independent witness co-signatures (${valid}/${bundle.witnesses.length})`,
      ok: valid >= quorum,
      detail: valid >= quorum
        ? `co-signed by ${names.join(", ")} — no single key can rewrite history`
        : `below the quorum of ${quorum} independent witnesses` });
  }

  return { ok: steps.every(s => s.ok), steps,
           facts: bundle.attestation.facts || {},
           root: inc.checkpoint.root_hash, treeSize: inc.checkpoint.tree_size };
}
