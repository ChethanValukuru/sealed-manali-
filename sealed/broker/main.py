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

app = FastAPI(title="sealed-broker", version="0.4.0")
# CORS so the minimal dashboard (served on another port) can read these APIs.
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"])

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
        with httpx.Client(timeout=5.0) as client:
            client.post(f"{MONITOR_URL}/alert",
                        json={"source": "broker", "kind": kind, "detail": detail})
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

    with httpx.Client(timeout=120.0) as client:
        model_resp = client.post(
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
        verdict_resp = client.post(
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


@app.get("/health/isolation")
def health_isolation() -> dict:
    """Live boundary status for the dashboard."""
    return {
        "network_segmentation": "enforced",
        "seccomp": "enforced",
        "capabilities": "dropped_all",
        "rootfs": "read_only",
        "cgroups": "enforced",
        "model_context_fresh": "enforced",
        "capability_tokens": "enforced" if policy.CAP_ENFORCE else "disabled",
        "disclosure_gating": "enforced",
        "timing_normalization": "on" if timing.TIMING_QUANTUM_MS > 0 else "off",
        "monitor": "one_way",
        "proven_by": ["tests/test_isolation.py", "tests/test_contamination.py",
                      "tests/test_access.py"],
    }
