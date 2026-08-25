"""settle() — deduplication is not settlement.

After an AmbiguousOutcome the intent sits `open`: witness() refuses it, and
before settle() the only resolution was a future admit(heal_with=…) nobody may
ever make. These tests pin the four verdicts — heal, release, diverge,
refuse-to-guess — and the two refusals (live lease, sealed passthrough).
"""
from __future__ import annotations

import os
import uuid

import psycopg
import pytest

from seal import Seal, SealError
from seal.authority import AmbiguousOutcome, Gateway
from seal.budget import Budget
from seal.clearance import Clearance, CLEARED
from seal.witness import (ABSENT, CONFIRMED_ONE, MULTIPLE, UNKNOWN,
                          CallableWitness, WitnessResult)

DSN = os.environ.get("SEAL_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="SEAL_DSN not set")


@pytest.fixture()
def s():
    seal = Seal(DSN, lease_sec=-1)      # every claim is instantly abandoned
    seal.setup()
    Budget(seal).setup()
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        for t in ("seal_certs", "seal_intents", "seal_spend", "seal_budget",
                  "seal_domains", "seal_events", "seal_tickets",
                  "seal_ticket_pending"):
            c.execute(f"TRUNCATE {t} RESTART IDENTITY")
    return seal


def _witness(state, count=None, evidence=None):
    return CallableWitness(
        lambda rec: WitnessResult(state, count=count, evidence=evidence or {}))


def _abandoned(s, domain=None):
    """An admitted intent whose holder died mid-effect (lease already dead)."""
    a = s.admit("charge", {"amt": 100}, key=f"o-{uuid.uuid4().hex[:8]}",
                domain=domain)
    assert a.fresh
    return a


# ── the four verdicts ─────────────────────────────────────────────────────
def test_confirmed_one_heals_without_reexecuting(s):
    a = _abandoned(s)
    out = s.settle(a.intent, _witness(CONFIRMED_ONE, 1, {"ids": ["pi_1"]}))
    assert out["resolution"] == "healed"
    assert out["cert"]["healed"] is True
    assert out["cert"]["tier"] == "WORLD_FINAL"
    assert s.get(a.intent)["state"] == "sealed"
    assert s.verify_chain()["ok"]


def test_absent_releases_the_claim_for_a_clean_retry(s):
    a = _abandoned(s)
    out = s.settle(a.intent, _witness(ABSENT, 0))
    assert out["resolution"] == "released"
    assert s.get(a.intent) is None
    # and the same logical action may now be admitted fresh
    b = s.admit("charge", {"amt": 100}, key="whatever-new")
    assert b.fresh


def test_multiple_diverges_and_freezes_the_domain(s):
    a = _abandoned(s, domain="charge")
    out = s.settle(a.intent, _witness(MULTIPLE, 2, {"ids": ["pi_a", "pi_b"]}))
    assert out["resolution"] == "diverged"
    assert s.get(a.intent)["tier"] == "WORLD_DIVERGED"
    assert s.domain_frozen("charge") is not None
    assert s.verify_chain()["ok"]


def test_unknown_never_guesses(s):
    """The whole product in one assertion: UNKNOWN changes NOTHING."""
    a = _abandoned(s)
    out = s.settle(a.intent, _witness(UNKNOWN, evidence={"error": "timeout"}))
    assert out["resolution"] == "unresolved"
    rec = s.get(a.intent)
    assert rec["state"] == "open"           # claim still standing
    # and settling again after the provider recovers still works
    out2 = s.settle(a.intent, _witness(CONFIRMED_ONE, 1))
    assert out2["resolution"] == "healed"


# ── the refusals ──────────────────────────────────────────────────────────
def test_a_live_lease_is_never_settled(s):
    alive = Seal(DSN, lease_sec=3600)
    a = alive.admit("charge", {"amt": 1}, key=f"o-{uuid.uuid4().hex[:8]}")
    with pytest.raises(SealError, match="lease"):
        alive.settle(a.intent, _witness(CONFIRMED_ONE, 1))
    # the mid-flight effect was not disturbed
    assert alive.get(a.intent)["state"] == "open"


def test_sealed_intent_delegates_to_witness(s):
    a = _abandoned(s)
    s2 = Seal(DSN, lease_sec=3600)
    b = s2.admit("charge", {"amt": 100}, key=f"o-{uuid.uuid4().hex[:8]}")
    s2.seal(b.intent, b.fence, {"ok": True})
    out = s2.settle(b.intent, _witness(CONFIRMED_ONE, 1))
    assert out["resolution"] == "witnessed"
    assert out["tier"] == "WORLD_FINAL"


def test_unknown_intent_is_refused(s):
    with pytest.raises(SealError):
        s.settle("no-such-intent", _witness(CONFIRMED_ONE, 1))


# ── budget integration: settle() finishes what reserve() started ──────────
def test_heal_settles_the_reserved_budget(s):
    b = Budget(s)
    b.set_limit("card", limit=1000, window_sec=86400)
    a = _abandoned(s)
    b.reserve("card", 250, intent=a.intent)

    s.settle(a.intent, _witness(CONFIRMED_ONE, 1))
    with psycopg.connect(DSN, autocommit=True) as c:
        states = [r[0] for r in c.execute(
            "SELECT state FROM seal_spend WHERE intent=%s", (a.intent,)).fetchall()]
    assert states == ["settled"]
    assert b.spent("card") == 250.0         # the money moved; it counts


def test_release_returns_the_reserved_budget(s):
    b = Budget(s)
    b.set_limit("card", limit=1000, window_sec=86400)
    a = _abandoned(s)
    b.reserve("card", 250, intent=a.intent)

    s.settle(a.intent, _witness(ABSENT, 0))
    assert b.spent("card") == 0.0           # nothing moved; headroom returned


# ── the gateway loop: AmbiguousOutcome → settle → terminal state ──────────
def test_gateway_ambiguous_outcome_then_settle_heals(s):
    path = "charge"
    Clearance(s).set_policy(path, CLEARED, max_proof_age_sec=1e9)
    Clearance(s).record_proof(path, green=True, storm_n=10, executions=1)

    g = Gateway(s, ticket_key=b"k")

    def exploding_executor(args):
        raise TimeoutError("socket closed AFTER the provider took the request")
    g.register_executor(path, exploding_executor)
    g.register_witness(path, _witness(CONFIRMED_ONE, 1, {"ids": ["pi_X"]}))

    p = g.propose(path, {"amt": 75.0}, key=f"o-{uuid.uuid4().hex[:8]}")
    with pytest.raises(AmbiguousOutcome):
        g.execute(p["ticket"], {"amt": 75.0})

    out = g.settle(p["intent"])
    assert out["resolution"] == "healed"
    assert s.get(p["intent"])["tier"] == "WORLD_FINAL"
    assert s.verify_chain()["ok"]


def test_gateway_settle_without_a_witness_is_refused(s):
    path = "charge"
    Clearance(s).set_policy(path, CLEARED, max_proof_age_sec=1e9)
    Clearance(s).record_proof(path, green=True, storm_n=10, executions=1)
    g = Gateway(s, ticket_key=b"k")
    g.register_executor(path, lambda a: {"ok": True})
    p = g.propose(path, {"amt": 1.0}, key=f"o-{uuid.uuid4().hex[:8]}")
    with pytest.raises(SealError, match="witness"):
        g.settle(p["intent"])
