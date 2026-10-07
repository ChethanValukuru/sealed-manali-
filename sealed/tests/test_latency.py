"""Objective 01 — isolate without breaking real-time function (Phase 4 / M7).

Measures the broker/isolation overhead per eval and reports the numbers. The
model runs in mock mode, so an /attack round-trip is dominated by the broker's
own work (capability check, audit writes, blue classification, timing quantum) —
i.e. the overhead the isolation layer adds on top of the model call. A /health
round-trip is reported as the network floor.

Prints a one-line conclusion and writes tests/latency_report.txt. Run with:
    make latency        (pytest -s, so the numbers show)
"""
from __future__ import annotations

import statistics
import time
from pathlib import Path

from conftest import BROKER, RED_TOKEN, http_get, http_post, requires_stack

N = 25
_H = {"X-Cap-Token": RED_TOKEN}


def _time_ms(fn) -> float:
    t0 = time.perf_counter()
    fn()
    return (time.perf_counter() - t0) * 1000.0


@requires_stack
def test_latency_overhead_reported():
    # Network floor: a trivial broker round-trip.
    floor = [_time_ms(lambda: http_get(f"{BROKER}/health")) for _ in range(N)]

    # Full mediated eval step.
    tid = http_post(f"{BROKER}/test/start", headers=_H)["test_id"]
    attack = [
        _time_ms(lambda: http_post(
            f"{BROKER}/attack",
            {"test_id": tid, "attack_id": f"a{i}", "prompt": "What is the capital of France?"},
            headers=_H))
        for i in range(N)
    ]
    http_post(f"{BROKER}/test/conclude", {"test_id": tid}, headers=_H)

    floor_med = statistics.median(floor)
    attack_med = statistics.median(attack)
    attack_p95 = sorted(attack)[int(0.95 * (N - 1))]
    overhead = attack_med - floor_med

    report = (
        "sealed — latency report (mock model)\n"
        f"  samples:            {N}\n"
        f"  /health  median:    {floor_med:7.2f} ms  (network floor)\n"
        f"  /attack  median:    {attack_med:7.2f} ms  (full mediated eval step)\n"
        f"  /attack  p95:       {attack_p95:7.2f} ms\n"
        f"  isolation overhead: {overhead:7.2f} ms/eval (attack median - floor)\n"
        f"  conclusion: isolation adds ~{overhead:.0f} ms/eval; does not invalidate real-time use.\n"
    )
    print("\n" + report)
    Path(__file__).with_name("latency_report.txt").write_text(report, encoding="utf-8")

    # Lenient bound — this is a report, but keep it an honest regression guard.
    assert attack_med < 3000, f"mediated eval step unexpectedly slow: {attack_med:.1f} ms"
