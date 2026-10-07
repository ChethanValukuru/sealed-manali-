"""Capability tokens + disclosure gating (Phase 4 / M5).

Capability tokens: each tenant holds a bearer token (delivered via compose env,
sent as the `X-Cap-Token` header). The broker maps each known token to a tenant
and a set of capabilities, and checks the capability required by each route. A
tenant that presents no token, an unknown token, or a token lacking the required
capability is denied — so red cannot call blue-only routes, and vice versa.

A tenant only ever holds its OWN token (compose gives red only RED_TOKEN, etc.),
so it cannot forge another tenant's authority. The broker holds all three to
build the table. This is a bearer-capability model; it is unforgeable because the
tokens are secrets, not because of a signature (documented in THREAT_MODEL.md).

Disclosure gating: red's raw payloads are withheld from everyone until the test
concludes (enforced in main.py's /disclosure route using test state), and blue is
only ever handed the model output to classify, never red's raw prompt.
"""
from __future__ import annotations

import os

CAP_ENFORCE = os.environ.get("CAP_ENFORCE", "1") not in ("0", "false", "False", "")

# tenant -> capabilities
_CAPS = {
    "red": {"test:start", "attack", "test:conclude"},
    "blue": {"disclosure:read", "verdict"},
    "model": set(),
}


def _load_tokens() -> dict[str, str]:
    """token -> tenant, from env (broker is given every tenant's token)."""
    table: dict[str, str] = {}
    for tenant, env in (("red", "RED_TOKEN"), ("blue", "BLUE_TOKEN"),
                        ("model", "MODEL_TOKEN")):
        tok = os.environ.get(env)
        if tok:
            table[tok] = tenant
    return table


_TOKENS = _load_tokens()


def check(token: str | None, cap: str) -> tuple[bool, str | None, str | None]:
    """Return (ok, tenant, reason). reason is set only on denial."""
    if not CAP_ENFORCE:
        return True, "unenforced", None
    if not token:
        return False, None, "missing capability token"
    tenant = _TOKENS.get(token)
    if tenant is None:
        return False, None, "unknown capability token"
    if cap not in _CAPS.get(tenant, set()):
        return False, tenant, f"token for '{tenant}' lacks capability '{cap}'"
    return True, tenant, None


def gate_for_blue(attack_prompt: str, model_output: str) -> dict:
    """What blue is allowed to see mid-test: the model output only, never red's
    raw payload."""
    return {"model_output": model_output}
