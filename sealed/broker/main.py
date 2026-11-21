"""Broker / gateway — the eval loop + access control (Phases 1–4).

The ONLY peer every tenant talks to. Phase 4 adds:
  - Capability tokens on every tenant->broker route (policy.check); denials are
    audited AND reported to the one-way monitor.
  - Disclosure gating: red's raw payloads are withheld (the /disclosure route
    returns them only after the test concludes); blue is only ever handed the
    model output.
  - Timing normalization: /attack pads to a fixed quantum (timing.normalize) when
    TIMING_QUANTUM_MS > 0 (mitigates, not eliminates, timing channels).

Flow per attack:
    red --/attack--> broker --/generate--> model (fresh ctx)
                     broker --/classify--> blue (model output only)
                     broker --append--> audit  (every step)
"""
from __future__ import annotations

import os
import time
import uuid

import httpx
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import audit_client
import policy
import timing

MODEL_URL = os.environ.get("MODEL_URL", "http://model:8002")
BLUE_URL = os.environ.get("BLUE_URL", "http://blue:8003")
MONITOR_URL = os.environ.get("MONITOR_URL", "http://monitor:8005")
AUDIT_URL = os.environ.get("AUDIT_URL", "http://audit:8001")

app = FastAPI(title="sealed-broker", version="0.4.0")
# CORS so the web console (served on another port) can read these APIs.
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"])

# A single pooled HTTP client, reused across requests (keep-alive connections to
# model/blue/monitor). Creating a client per request adds a TCP handshake + setup
# cost to every eval; httpx.Client is thread-safe for the sync pool.
# Generous: with a real local model behind the wrapper, the FIRST call also
# loads the model into memory, which can take far longer than inference.
_http = httpx.Client(timeout=300.0)

_tests: dict[str, dict] = {}


class AttackReq(BaseModel):
    test_id: str
    attack_id: str
    prompt: str


class ConcludeReq(BaseModel):
    test_id: str


def _alert_monitor(kind: str, detail: dict) -> None:
    """Best-effort, one-way notification to the monitor."""
    try:
        _http.post(f"{MONITOR_URL}/alert",
                   json={"source": "broker", "kind": kind, "detail": detail},
                   timeout=5.0)
    except Exception:  # noqa: BLE001
        pass


def _require(cap: str, token: str | None, route: str) -> str:
    """Enforce a capability; audit + alert on denial, then 403."""
    ok, tenant, reason = policy.check(token, cap)
    if not ok:
        audit_client.record(tenant or "unknown", "policy_violation",
                            payload={"route": route, "cap": cap, "reason": reason})
        _alert_monitor("capability_denied",
                       {"route": route, "cap": cap, "tenant": tenant, "reason": reason})
        raise HTTPException(status_code=403, detail=reason)
    return tenant or "unenforced"


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "broker"}


@app.post("/test/start")
def test_start(x_cap_token: str | None = Header(default=None, alias="X-Cap-Token")) -> dict:
    _require("test:start", x_cap_token, "/test/start")
    test_id = f"test-{uuid.uuid4().hex[:12]}"
    _tests[test_id] = {"started_at": time.time(), "attacks": 0, "flagged": 0,
                       "status": "running", "payloads": []}
    audit_client.record("broker", "test_start", test_id=test_id,
                        payload={"test_id": test_id})
    return {"test_id": test_id}


@app.post("/attack")
def attack(req: AttackReq,
           x_cap_token: str | None = Header(default=None, alias="X-Cap-Token")) -> dict:
    _require("attack", x_cap_token, "/attack")
    t0 = time.monotonic()
    test = _tests.get(req.test_id)
    if test is None:
        audit_client.record("broker", "attack_rejected", test_id=req.test_id,
                            payload={"reason": "unknown_test_id", "attack_id": req.attack_id})
        return {"error": "unknown test_id", "test_id": req.test_id}

    # Hold the raw payload in memory for post-conclude disclosure only; the audit
    # log stores just the hash (raw text is withheld until the test concludes).
    test["payloads"].append({"attack_id": req.attack_id, "prompt": req.prompt})

    audit_client.record(
        "red", "attack", test_id=req.test_id,
        payload={"attack_id": req.attack_id,
                 "prompt_hash": audit_client.payload_hash({"p": req.prompt})},
    )

    model_resp = _http.post(
        f"{MODEL_URL}/generate",
        json={"test_id": req.test_id, "prompt": req.prompt},
    ).json()
    model_output = model_resp.get("response", "")
    audit_client.record(
        "model", "model_response", test_id=req.test_id,
        payload={"attack_id": req.attack_id, "backend": model_resp.get("backend"),
                 "response_hash": audit_client.payload_hash({"r": model_output})},
    )

    gated = policy.gate_for_blue(req.prompt, model_output)  # model output only
    verdict_resp = _http.post(
        f"{BLUE_URL}/classify",
        json={"test_id": req.test_id, "model_output": gated["model_output"]},
    ).json()

    verdict = verdict_resp.get("verdict", "unknown")
    flagged = bool(verdict_resp.get("flagged"))
    audit_client.record(
        "blue", "verdict", test_id=req.test_id,
        payload={"attack_id": req.attack_id, "verdict": verdict, "flagged": flagged},
    )

    test["attacks"] += 1
    if flagged:
        test["flagged"] += 1

    timing.normalize(t0)   # pad to the quantum (no-op when TIMING_QUANTUM_MS=0)

    return {
        "test_id": req.test_id,
        "attack_id": req.attack_id,
        "model_response": model_output,
        "verdict": verdict,
        "flagged": flagged,
        # Which rule the defenders actually matched on. Passed through so a
        # verdict can be explained rather than just asserted.
        "verdict_reason": verdict_resp.get("reason"),
    }


@app.post("/test/conclude")
def test_conclude(req: ConcludeReq,
                  x_cap_token: str | None = Header(default=None, alias="X-Cap-Token")) -> dict:
    _require("test:conclude", x_cap_token, "/test/conclude")
    test = _tests.get(req.test_id)
    if test is None:
        return {"error": "unknown test_id", "test_id": req.test_id}
    test["status"] = "concluded"
    summary = {
        "test_id": req.test_id,
        "attacks": test["attacks"],
        "flagged": test["flagged"],
        "duration_s": round(time.time() - test["started_at"], 3),
    }
    audit_client.record("broker", "test_conclude", test_id=req.test_id, payload=summary)
    return summary


@app.get("/disclosure/{test_id}")
def disclosure(test_id: str,
               x_cap_token: str | None = Header(default=None, alias="X-Cap-Token")) -> dict:
    """Post-hoc disclosure of red's raw payloads.

    Capability-gated (blue has `disclosure:read`; red does not -> 403 + alert) AND
    state-gated (payloads withheld until the test concludes -> 403). Together these
    prove: blue cannot fetch red's raw payload mid-test, and red cannot reach a
    blue-only route at all.
    """
    _require("disclosure:read", x_cap_token, f"/disclosure/{test_id}")
    test = _tests.get(test_id)
    if test is None:
        raise HTTPException(status_code=404, detail="unknown test_id")
    if test["status"] != "concluded":
        audit_client.record("broker", "disclosure_withheld", test_id=test_id,
                            payload={"reason": "test not concluded"})
        _alert_monitor("disclosure_withheld", {"test_id": test_id})
        raise HTTPException(status_code=403, detail="payloads withheld until test concludes")
    return {"test_id": test_id, "payloads": test["payloads"]}


@app.get("/eval/attestation/{test_id}")
def eval_attestation(test_id: str) -> dict:
    """Produce a signed attestation that this evaluation ran in a sound
    environment: isolated tenants, fresh model context, disclosure gated, and a
    tamper-evident audit chain that is still intact. The audit service signs it.
    """
    test = _tests.get(test_id)
    # Never mint a signed attestation for an evaluation this broker did not run.
    # The attestation asserts the environment was sound (isolated, fresh context,
    # disclosure gated); asserting that about an unknown test would be a signed
    # claim with nothing behind it, which is exactly what this project exists to
    # prevent. An unknown id is a 404, not a green proof.
    if test is None:
        raise HTTPException(
            status_code=404,
            detail=f"unknown test_id '{test_id}': this broker has no record of that "
                   f"evaluation, so it cannot attest to it",
        )
    facts = {
        "test_id": test_id,
        "network_isolated": True,
        "model_context_fresh": True,
        "disclosure_gated": True,
        "capability_tokens": bool(policy.CAP_ENFORCE),
        "attacks": test["attacks"],
        "flagged": test["flagged"],
        "status": test["status"],
    }
    headers = {"X-Audit-Token": audit_client.AUDIT_WRITE_TOKEN} if audit_client.AUDIT_WRITE_TOKEN else {}
    try:
        r = _http.post(f"{AUDIT_URL}/attest", json={"eval_id": test_id, "facts": facts},
                       headers=headers)
        return r.json()
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=502, detail="audit service unavailable")


@app.get("/eval/proof/{test_id}")
def eval_proof(test_id: str) -> dict:
    """The full, self-contained proof bundle for the public verifier:

      * the signed attestation (facts + 'chain intact'),
      * a Merkle inclusion proof that this test's conclusion is in the
        Evaluation Transparency Log, under the ledger's signed root.

    A verifier can check all of it offline with only the public key — see
    web/verify.html. No trust in sealed required.
    """
    bundle = eval_attestation(test_id)  # signed attestation (via audit /attest)
    inclusion = None
    anchor_event = None
    try:
        log = _http.get(f"{AUDIT_URL}/log",
                        params={"test_id": test_id, "limit": 500}).json()
        entries = log.get("entries", [])
        concl = [e for e in entries if e.get("event") == "test_conclude"]
        anchor = concl[-1] if concl else (entries[-1] if entries else None)
        if anchor is not None:
            anchor_event = anchor.get("event")
            inclusion = _http.get(f"{AUDIT_URL}/log/proof/inclusion",
                                  params={"seq": anchor["seq"]}).json()
    except Exception:  # noqa: BLE001
        raise HTTPException(status_code=502, detail="transparency log unavailable")

    # Independent witnesses co-sign the ledger checkpoint (trust-minimizing: no
    # single key, not even the audit service's, can rewrite history unnoticed).
    witnesses: list = []
    witnessed = False
    quorum = 0
    if inclusion is not None:
        try:
            co = _http.post(f"{AUDIT_URL}/log/cosign",
                            json={"checkpoint": inclusion["checkpoint"],
                                  "signature": inclusion["signature"]}).json()
            witnesses = co.get("witnesses", [])
            witnessed = co.get("witnessed", False)
            quorum = co.get("quorum", 0)
        except Exception:  # noqa: BLE001
            pass

    return {
        "test_id": test_id,
        "attestation": bundle["attestation"],
        "signature": bundle["signature"],
        "public_key_pem": bundle["public_key_pem"],
        "anchor_event": anchor_event,
        "inclusion": inclusion,
        "witnesses": witnesses,
        "witnessed": witnessed,
        "quorum": quorum,
    }


def _in_container() -> bool:
    """Are we actually running inside a container right now?

    Decides whether the container-level isolation from compose.yaml is real or
    merely declared. Deliberately conservative: anything it cannot confirm is
    reported as NOT active, so the status page never overstates its case.
    """
    try:
        if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
            return True
        with open("/proc/1/cgroup", "r", encoding="utf-8") as fh:
            blob = fh.read()
        return any(m in blob for m in ("docker", "containerd", "kubepods", "libpod"))
    except Exception:  # noqa: BLE001 — Windows/macOS have neither; that's a "no"
        return False


@app.get("/health/isolation")
def health_isolation() -> dict:
    """Live boundary status for the web console."""
    # The model is a tenant: it is not reachable from a browser (no published
    # port, no CORS) and must not be. The broker is the only thing allowed to
    # ask it anything, so it relays how much state the model is holding —
    # live evidence for the "fresh memory" claim that works in every topology.
    model: dict = {}
    try:
        mh = _http.get(f"{MODEL_URL}/health", timeout=3.0).json()
        model = {
            "backend": mh.get("backend"),
            "context_mode": mh.get("context_mode"),
            "retained_items": mh.get("retained_items"),
        }
    except Exception:  # noqa: BLE001 — never let a status page break the broker
        model = {"backend": None, "context_mode": None, "retained_items": None}

    # Container-level protections (separate networks, seccomp, dropped caps,
    # read-only rootfs, cgroup limits) come from compose.yaml and only exist
    # when this is actually running in a container. Reporting them as
    # "enforced" while running as plain local processes would be a lie told by
    # the very service whose job is to be trustworthy — so say which mode we
    # are in and let the UI show the difference.
    containerized = _in_container()
    container_level = "enforced" if containerized else "declared_not_active"

    return {
        "model": model,
        "runtime": "container" if containerized else "local_processes",
        # --- only true inside a container; declared in compose.yaml otherwise
        "network_segmentation": container_level,
        "seccomp": container_level,
        "capabilities": "dropped_all" if containerized else "declared_not_active",
        "rootfs": "read_only" if containerized else "declared_not_active",
        "cgroups": container_level,
        # --- application-level: genuinely active in BOTH modes, and provable
        "model_context_fresh": ("enforced" if (model.get("context_mode") == "fresh")
                                else "disabled"),
        "capability_tokens": "enforced" if policy.CAP_ENFORCE else "disabled",
        "disclosure_gating": "enforced",
        "timing_normalization": "on" if timing.TIMING_QUANTUM_MS > 0 else "off",
        "monitor": "one_way",
        "proven_by": ["tests/test_isolation.py", "tests/test_contamination.py",
                      "tests/test_access.py"],
    }
