"""Tamper detection as a RATE, not an anecdote.

test_audit.py and test_attestation.py each break the log one way and confirm
the break was caught. That proves detection exists. It does not say how often
it works, and "we tried it once" is not a measurement.

These tests run the measurement harness over many randomised trials and hold it
to the three properties the product actually claims:

  1. every way of EDITING the record is caught, every time
  2. an untouched record is NEVER wrongly reported as tampered
  3. truncation is caught by the signed checkpoint
     (and is NOT caught by the hash chain alone -- asserted explicitly, because
      that limitation is real and must not silently disappear if someone
      "fixes" it by accident)

Trial counts are kept modest so the suite stays fast; the full run lives in
sealed/tools/integrity_accuracy.py. No containers and no running services.
"""
from __future__ import annotations

import importlib.util
import random
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tools" / "integrity_accuracy.py"

TRIALS = 40          # per mutation class
SEED = 4417


def _harness():
    spec = importlib.util.spec_from_file_location("integrity_accuracy", HARNESS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def h():
    return _harness()


@pytest.fixture(scope="module")
def keys():
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key(), Ed25519PrivateKey.generate()


def test_harness_covers_every_way_of_editing_a_record(h):
    """If someone adds a tampering technique, it must be measured, not assumed.
    This pins the catalogue so the headline rate can't quietly narrow."""
    names = {n for n, _ in h.EDIT_MUTATIONS}
    assert len(h.EDIT_MUTATIONS) >= 11
    assert len(names) == len(h.EDIT_MUTATIONS), "duplicate mutation names"
    for must in ("Change what a record says", "Delete a record",
                 "Reorder two records", "Insert a fabricated record",
                 "Re-sign with the attacker's key"):
        assert must in names, f"missing mutation class: {must}"


def test_every_edit_is_caught(h, keys):
    priv, pub, atk = keys
    rng = random.Random(SEED)
    results = h.run_edit_trials(TRIALS, rng, priv, pub, atk)
    missed = [(r["name"], r["trials"] - r["caught"]) for r in results
              if r["caught"] != r["trials"]]
    assert not missed, f"tampering went undetected: {missed}"


def test_every_edit_is_pinpointed_to_the_right_record(h, keys):
    """Catching it is the claim; naming the exact record is what makes the
    claim useful to someone investigating."""
    priv, pub, atk = keys
    rng = random.Random(SEED + 1)
    results = h.run_edit_trials(TRIALS, rng, priv, pub, atk)
    vague = [(r["name"], r["localized"], r["trials"]) for r in results
             if r["localized"] != r["trials"]]
    assert not vague, f"detected but mislocated: {vague}"


def test_untouched_logs_are_never_called_tampered(h, keys):
    """The other half of the measurement. A verifier that always shouts
    'tampered' would score 100% above and be worthless."""
    priv, pub, _ = keys
    rng = random.Random(SEED + 2)
    clean = h.run_clean_trials(TRIALS * 10, rng, priv, pub)
    assert clean["false_alarms"] == 0, (
        f"{clean['false_alarms']} of {clean['trials']} untouched logs were "
        "wrongly reported as tampered")


def test_truncation_needs_the_checkpoint_not_the_chain(h, keys):
    """A deliberately uncomfortable test.

    Dropping the newest records leaves a shorter but perfectly valid chain, so
    the chain alone cannot see it. The signed checkpoint can, because the tree
    size and root were signed before the records went missing. Both halves are
    asserted so the limitation stays documented in code.
    """
    priv, pub, _ = keys
    rng = random.Random(SEED + 3)
    t = h.run_truncation_trials(TRIALS, rng, priv, pub)

    assert t["chain_caught"] == 0, (
        "the hash chain now appears to detect truncation -- if that is a real "
        "improvement, update this test and the threat model; if not, the "
        "truncation mutation has stopped truncating")
    assert t["checkpoint_caught"] == t["trials"], (
        f"the signed checkpoint missed {t['trials'] - t['checkpoint_caught']} "
        "truncations")


def test_confidence_interval_is_honest_at_the_boundary(h):
    """The reported rate carries a Wilson interval specifically so that a
    perfect score does not claim more certainty than the sample supports.
    A normal-approximation interval is zero-width at p=1, which would turn
    'we saw no failures' into 'failure is impossible'."""
    lo, hi = h.wilson(100, 100)
    assert hi == pytest.approx(1.0)
    assert lo < 1.0, "a perfect score must still report a lower bound below 100%"
    assert lo > 0.9, f"interval implausibly wide for n=100: {lo}"

    # more evidence must narrow it
    lo_big, _ = h.wilson(1000, 1000)
    assert lo_big > lo

    lo0, hi0 = h.wilson(0, 100)
    assert lo0 == 0.0 and 0.0 < hi0 < 0.1
