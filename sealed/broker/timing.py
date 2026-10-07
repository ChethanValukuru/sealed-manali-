"""Response timing normalization.

PHASE 1 STUB. Phase 4 (M5) pads broker responses to a fixed quantum
(TIMING_QUANTUM_MS) to blunt timing-inference side channels. This MITIGATES,
does not eliminate, timing channels — documented honestly in THREAT_MODEL.md.

With the quantum at 0 (default now) this is a no-op.
"""
from __future__ import annotations

import os
import time

TIMING_QUANTUM_MS = int(os.environ.get("TIMING_QUANTUM_MS", "0"))


def normalize(started_at: float) -> None:
    """Sleep until the elapsed time reaches the next quantum boundary."""
    if TIMING_QUANTUM_MS <= 0:
        return
    elapsed_ms = (time.monotonic() - started_at) * 1000.0
    quantum = TIMING_QUANTUM_MS
    target = ((int(elapsed_ms) // quantum) + 1) * quantum
    remaining = (target - elapsed_ms) / 1000.0
    if remaining > 0:
        time.sleep(remaining)
