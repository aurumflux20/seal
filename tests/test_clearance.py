"""Clearance — the control plane. Tests that try to obtain permission dishonestly.

The product claim is "CLEARED is earned by continuous proof, not declared."
These tests exist to make that claim falsifiable.
"""
from __future__ import annotations

import os
import time

import psycopg
import pytest

from seal import Seal
from seal.clearance import (
    CLEARED, HOLD, REVOKED, Clearance, ClearanceDenied,
)
from seal.witness import CONFIRMED_ONE, UNKNOWN, CallableWitness, WitnessResult

DSN = os.environ.get("SEAL_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="SEAL_DSN not set")


@pytest.fixture()
def cl():
    s = Seal(DSN)
    s.setup()
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        c.execute("TRUNCATE seal_intents, seal_certs, seal_domains, seal_graphs, "
                  "seal_graph_children, seal_clearance, seal_proof, seal_events "
                  "RESTART IDENTITY")
    return Clearance(s)


def _green(cl, path="charge", n=1000):
    cl.record_proof(path, green=True, storm_n=n, executions=1)


# ── safe defaults ──────────────────────────────────────────────────────────

def test_unknown_path_defaults_to_hold(cl):
    """A tool nobody configured must not move money because someone forgot."""
    assert cl.status("charge")["effective"] == HOLD


def test_hold_blocks_admission(cl):
    with pytest.raises(ClearanceDenied):
        cl.seal.admit("charge", {"a": 1}, key="c1", path="charge")


# ── CLEARED must be EARNED ─────────────────────────────────────────────────

def test_cleared_without_proof_is_not_cleared(cl):
    """The core honesty property: declaring CLEARED is not enough."""
    cl.set_policy("charge", CLEARED, reason="ops signed off")
    st = cl.status("charge")
    assert st["status"] == CLEARED          # what the operator asked for
    assert st["effective"] == HOLD          # what is actually true
    assert "NO proof" in st["reason"]
    with pytest.raises(ClearanceDenied):
        cl.seal.admit("charge", {"a": 1}, key="c2", path="charge")


def test_cleared_with_green_proof_admits(cl):
    cl.set_policy("charge", CLEARED)
    _green(cl)
    assert cl.status("charge")["effective"] == CLEARED
    adm = cl.seal.admit("charge", {"a": 1}, key="c3", path="charge")
    assert adm.fresh


def test_red_proof_withdraws_clearance_immediately(cl):
    cl.set_policy("charge", CLEARED)
    _green(cl)
    assert cl.status("charge")["effective"] == CLEARED
    cl.record_proof("charge", green=False, storm_n=1000, executions=2)  # a double!
    st = cl.status("charge")
    assert st["effective"] == HOLD and "RED" in st["reason"]
    with pytest.raises(ClearanceDenied):
        cl.seal.admit("charge", {"a": 2}, key="c4", path="charge")


def test_stale_proof_expires_clearance_on_its_own(cl):
    """A permission that cannot expire is one nobody should trust."""
    cl.set_policy("charge", CLEARED, max_proof_age_sec=1.0)
    _green(cl)
    assert cl.status("charge")["effective"] == CLEARED
    time.sleep(1.2)
    st = cl.status("charge")
    assert st["effective"] == HOLD and "stale" in st["reason"]


# ── revoke ─────────────────────────────────────────────────────────────────

def test_revoke_is_instant(cl):
    cl.set_policy("charge", CLEARED)
    _green(cl)
    assert cl.seal.admit("charge", {"a": 1}, key="r1", path="charge").fresh
    cl.revoke("charge", reason="incident 42")
    with pytest.raises(ClearanceDenied):
        cl.seal.admit("charge", {"a": 2}, key="r2", path="charge")


def test_revoked_does_not_auto_recover_on_fresh_proof(cl):
    """Releasing a revocation is a human act, never an automatic one."""
    cl.set_policy("charge", CLEARED)
    _green(cl)
    cl.revoke("charge", reason="incident")
    _green(cl)                                   # CI goes green again
    assert cl.status("charge")["effective"] == REVOKED
    with pytest.raises(ClearanceDenied):
        cl.seal.admit("charge", {"a": 3}, key="r3", path="charge")


def test_revoke_all_is_one_switch(cl):
    for p in ("charge", "payout", "email"):
        cl.set_policy(p, CLEARED)
        _green(cl, p)
    n = cl.revoke_all(reason="security incident")
    assert n == 3
    for p in ("charge", "payout", "email"):
        assert cl.status(p)["effective"] == REVOKED


# ── heal-on-reclaim: the last double-fire window ───────────────────────────

def test_heal_on_reclaim_does_not_re_execute(cl):
    """A dead holder that already charged must NOT be re-run by the reclaimer.
    The world is probed first; a confirmed effect is healed, not repeated."""
    fast = Seal(DSN, lease_sec=0.05)
    fast.setup()
    a = fast.admit("charge", {"o": 9}, key="heal-1")
    assert a.fresh                      # holder wins... then "crashes" mid-effect
    time.sleep(0.15)                    # lease dies

    w = CallableWitness(lambda rec: WitnessResult(CONFIRMED_ONE, count=1,
                                                  evidence={"id": "pi_123"}))
    b = fast.admit("charge", {"o": 9}, key="heal-1", heal_with=w)
    assert not b.fresh                  # NOT handed a fresh claim to re-charge
    assert b.cert is not None and b.cert["healed"] is True
    assert fast.get(a.intent)["tier"] == "WORLD_FINAL"


def test_unknown_world_does_not_heal(cl):
    """UNKNOWN must never be treated as 'it happened' — that would fabricate a
    receipt for an effect we cannot see."""
    fast = Seal(DSN, lease_sec=0.05)
    fast.setup()
    a = fast.admit("charge", {"o": 10}, key="heal-2")
    time.sleep(0.15)
    w = CallableWitness(lambda rec: WitnessResult(UNKNOWN))
    b = fast.admit("charge", {"o": 10}, key="heal-2", heal_with=w)
    assert b.fresh                      # falls through to normal reclaim
    assert fast.get(a.intent)["state"] == "open"


# ── the artifact procurement reads ─────────────────────────────────────────

def test_range_report_counts_real_events(cl):
    cl.set_policy("charge", CLEARED)
    _green(cl)
    cl.seal.admit("charge", {"a": 1}, key="rep-1", path="charge")
    cl.set_policy("payout", HOLD)
    with pytest.raises(ClearanceDenied):
        cl.seal.admit("payout", {"a": 1}, key="rep-2", path="payout")

    r = cl.range_report()
    assert r["events"].get("admitted", 0) >= 1
    assert r["events"].get("blocked", 0) >= 1
    assert r["chain_verified"] is True
    paths = {p["path"]: p["effective"] for p in r["paths"]}
    assert paths["charge"] == CLEARED and paths["payout"] == HOLD
    assert "not insurance" in r["honesty"]
