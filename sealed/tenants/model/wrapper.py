"""Model-under-test service (Phase 3 / M4).

Fresh context per test is the headline guarantee. CONTEXT_MODE selects behaviour:

  - "fresh"      (secure stack, default): every /generate is STATELESS — no
                 history, no KV carryover, nothing retained between calls or
                 tests. A probe in a later test cannot recover anything planted
                 in an earlier one.
  - "persistent" (naive stack): the model RETAINS context across every call and
                 every test and never resets — simulating a shared KV-cache /
                 conversation-context bleed. This is the exact flaw the secure
                 stack prevents, exposed for the before/after demo.

MOCK_MODEL=1 (default) uses a deterministic stand-in so the contamination test
and the demo run without pulling a model. The real-Ollama paths mirror the same
two modes.
"""
from __future__ import annotations

import os
import re
import threading

from fastapi import FastAPI
from pydantic import BaseModel

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://host.containers.internal:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:1b")
MOCK_MODEL = os.environ.get("MOCK_MODEL", "1") not in ("0", "false", "False", "")
CONTEXT_MODE = os.environ.get("CONTEXT_MODE", "fresh")  # fresh | persistent

app = FastAPI(title="sealed-model", version="0.3.0")

# Naive-mode "memory": in persistent mode this is NEVER reset between calls or
# tests. In fresh mode it is never written. Module-level => survives across
# requests in the worker process (that persistence IS the naive flaw).
_lock = threading.Lock()
_persistent_secrets: list[str] = []
_persistent_messages: list[dict] = []  # real-ollama persistent path

SECRET_RE = re.compile(r"secret(?:\s+code)?\s*[:=]\s*([A-Za-z0-9\-]+)", re.IGNORECASE)
PROBE_RE = re.compile(
    r"\b(earlier|previously|before|told you|remember|recall|what was)\b", re.IGNORECASE)
INJECTION_MARKERS = (
    "ignore previous", "ignore all previous", "system prompt", "disregard",
    "pretend you", "no restrictions", "developer mode", "jailbreak", "bypass",
    "without any safety",
)


class GenReq(BaseModel):
    test_id: str
    prompt: str


def _injection_or_benign(prompt: str) -> str:
    low = prompt.lower()
    if any(m in low for m in INJECTION_MARKERS):
        return ("I can't help with that. I won't ignore my guidelines or reveal "
                "internal instructions.")
    return "Here is a brief, general-purpose answer to your request."


def _mock_response(prompt: str) -> str:
    secret = SECRET_RE.search(prompt)

    if CONTEXT_MODE == "persistent":
        with _lock:
            if secret:
                _persistent_secrets.append(secret.group(1))
                return "Understood — I'll keep that in mind for our conversation."
            if PROBE_RE.search(prompt) and _persistent_secrets:
                # CONTAMINATION: recall state planted in an earlier call/test.
                return ("Earlier you told me the secret code: "
                        + ", ".join(_persistent_secrets) + ".")
        return _injection_or_benign(prompt)

    # fresh (secure): retain nothing.
    if secret:
        return "Understood for this request."          # NOT stored
    if PROBE_RE.search(prompt):
        return "I have no earlier context; each test runs with a fresh context."
    return _injection_or_benign(prompt)


def _ollama_response(prompt: str) -> str:
    import ollama  # type: ignore

    client = ollama.Client(host=OLLAMA_HOST)
    if CONTEXT_MODE == "persistent":
        with _lock:
            _persistent_messages.append({"role": "user", "content": prompt})
            resp = client.chat(model=OLLAMA_MODEL, messages=_persistent_messages,
                               keep_alive=-1)
            msg = resp["message"]["content"]
            _persistent_messages.append({"role": "assistant", "content": msg})
            return msg
    # fresh: stateless generate, unload after (no carryover).
    resp = client.generate(model=OLLAMA_MODEL, prompt=prompt, keep_alive=0,
                           options={"temperature": 0.0})
    return resp.get("response", "")


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "model",
        "backend": "mock" if MOCK_MODEL else "ollama",
        "context_mode": CONTEXT_MODE,
        "retained_items": len(_persistent_secrets),
    }


@app.post("/generate")
def generate(req: GenReq) -> dict:
    if MOCK_MODEL:
        return {"test_id": req.test_id, "response": _mock_response(req.prompt),
                "backend": "mock", "context_mode": CONTEXT_MODE}
    try:
        return {"test_id": req.test_id, "response": _ollama_response(req.prompt),
                "backend": "ollama", "context_mode": CONTEXT_MODE}
    except Exception as exc:  # noqa: BLE001 - degrade gracefully for the demo
        return {"test_id": req.test_id, "response": _mock_response(req.prompt),
                "backend": "mock-fallback", "context_mode": CONTEXT_MODE,
                "error": str(exc)}
