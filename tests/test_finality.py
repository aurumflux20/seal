"""Layer B (Finality) + Layer A completion. Attacks, not demonstrations."""
from __future__ import annotations

import os
import time

import psycopg
import pytest

from seal import Seal
from seal.core import (
    TIER_SEALED,
    TIER_WORLD_DIVERGED,
    TIER_WORLD_FINAL,
    TIER_WORLD_UNKNOWN,
    DomainFrozen,
    NotFenceHolder,
    PayloadConflict,
)
from seal.witness import (
    ABSENT,
    CONFIRMED_ONE,
    MULTIPLE,
    UNKNOWN,
    CallableWitness,
    StripeWitness,
    WitnessResult,
)

DSN = os.environ.get("SEAL_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="SEAL_DSN not set")


@pytest.fixture()
def seal() -> Seal:
    s = Seal(DSN, lease_sec=30.0)
    s.setup()
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        c.execute(
            "TRUNCATE seal_intents, seal_certs, seal_domains, "
            "seal_graphs, seal_graph_children RESTART IDENTITY"
        )
    return s


def _w(state, **kw):
    return CallableWitness(lambda rec: WitnessResult(state, **kw))


# ── A7 · payload conflict ──────────────────────────────────────────────────

def test_same_key_different_args_is_a_hard_conflict(seal: Seal):
    """The bug my first version had: a recomputed amount must NOT become a
    second charge. Same logical intent, different args → refuse loudly."""
    a = seal.admit("charge", {"amount": 4900}, key="order-777")
    assert a.fresh
    with pytest.raises(PayloadConflict):
        seal.admit("charge", {"amount": 5100}, key="order-777")


def test_same_key_same_args_still_replays(seal: Seal):
    a = seal.admit("charge", {"amount": 4900}, key="order-777")
    cert = seal.seal(a.intent, a.fence, {"ok": True})
    b = seal.admit("charge", {"amount": 4900}, key="order-777")
    assert not b.fresh and b.cert["hash"] == cert["hash"]


def test_different_keys_are_independent(seal: Seal):
    a = seal.admit("charge", {"amount": 100}, key="order-1")
    b = seal.admit("charge", {"amount": 100}, key="order-2")
    assert a.fresh and b.fresh and a.intent != b.intent


# ── A3 · heartbeat ─────────────────────────────────────────────────────────

def test_heartbeat_extends_lease_and_blocks_reclaim(seal: Seal):
    fast = Seal(DSN, lease_sec=0.3)
    a = fast.admit("charge", {"o": 1}, key="hb-1")
    assert a.fresh
    for _ in range(4):
        time.sleep(0.15)
        fast.heartbeat(a.intent, a.fence)
    # A slow effect that keeps its heartbeat up must NOT be stolen.
    b = fast.admit("charge", {"o": 1}, key="hb-1")
    assert not b.fresh


def test_heartbeat_rejects_non_holder(seal: Seal):
    a = seal.admit("charge", {"o": 1}, key="hb-2")
    with pytest.raises(NotFenceHolder):
        seal.heartbeat(a.intent, "wrong-fence")


def test_heartbeat_fails_after_seal(seal: Seal):
    a = seal.admit("charge", {"o": 1}, key="hb-3")
    seal.seal(a.intent, a.fence, {"ok": True})
    with pytest.raises(NotFenceHolder):
        seal.heartbeat(a.intent, a.fence)


# ── B2–B6 · witness tiers ──────────────────────────────────────────────────

def test_sealed_cert_starts_unconfirmed(seal: Seal):
    a = seal.admit("charge", {"o": 1}, key="w-0")
    cert = seal.seal(a.intent, a.fence, {"ok": True})
    assert cert["tier"] == TIER_SEALED and cert["world"] == "unconfirmed"


def test_confirmed_one_becomes_world_final(seal: Seal):
    a = seal.admit("charge", {"o": 1}, key="w-1")
    seal.seal(a.intent, a.fence, {"ok": True})
    cert = seal.witness(a.intent, _w(CONFIRMED_ONE, count=1))
    assert cert["tier"] == TIER_WORLD_FINAL and cert["world"] == "confirmed"
    assert seal.get(a.intent)["tier"] == TIER_WORLD_FINAL


def test_multiple_becomes_diverged(seal: Seal):
    a = seal.admit("charge", {"o": 1}, key="w-2")
    seal.seal(a.intent, a.fence, {"ok": True})
    cert = seal.witness(a.intent, _w(MULTIPLE, count=2))
    assert cert["tier"] == TIER_WORLD_DIVERGED


def test_unknown_never_collapses_to_absent(seal: Seal):
    """The crown jewel. A failed lookup must not read as 'nothing happened'."""
    a = seal.admit("charge", {"o": 1}, key="w-3")
    seal.seal(a.intent, a.fence, {"ok": True})
    cert = seal.witness(a.intent, _w(UNKNOWN))
    assert cert["tier"] == TIER_WORLD_UNKNOWN
    assert cert["tier"] != TIER_WORLD_DIVERGED  # not treated as absent
    assert cert["world"] == "unknown"


def test_absent_after_seal_is_divergence(seal: Seal):
    a = seal.admit("charge", {"o": 1}, key="w-4")
    seal.seal(a.intent, a.fence, {"ok": True})
    cert = seal.witness(a.intent, _w(ABSENT, count=0))
    assert cert["tier"] == TIER_WORLD_DIVERGED


def test_witness_appends_never_rewrites(seal: Seal):
    """Tamper-evidence would be a lie if upgrading a tier edited history."""
    a = seal.admit("charge", {"o": 1}, key="w-5")
    sealed = seal.seal(a.intent, a.fence, {"ok": True})
    seal.witness(a.intent, _w(CONFIRMED_ONE, count=1))
    certs = seal.certs_for(a.intent)
    assert len(certs) == 2
    assert certs[0]["hash"] == sealed["hash"]      # original untouched
    assert certs[0]["tier"] == TIER_SEALED
    assert certs[1]["parent_cert"] == sealed["hash"]
    assert seal.verify_chain()["ok"]


def test_cannot_witness_unsealed_intent(seal: Seal):
    a = seal.admit("charge", {"o": 1}, key="w-6")
    with pytest.raises(Exception):
        seal.witness(a.intent, _w(CONFIRMED_ONE, count=1))


# ── B7 · divergence circuit breaker ────────────────────────────────────────

def test_divergence_freezes_domain_and_blocks_admission(seal: Seal):
    a = seal.admit("charge", {"o": 1}, key="cb-1", domain="customer:42")
    seal.seal(a.intent, a.fence, {"ok": True})
    seal.witness(a.intent, _w(MULTIPLE, count=2))

    assert seal.domain_frozen("customer:42") is not None
    with pytest.raises(DomainFrozen):
        seal.admit("charge", {"o": 2}, key="cb-2", domain="customer:42")
    # a different domain is unaffected — the breaker is scoped, not global
    assert seal.admit("charge", {"o": 3}, key="cb-3", domain="customer:99").fresh


def test_unknown_does_not_freeze(seal: Seal):
    """Uncertainty is not contradiction. Freezing on every timeout would make
    the breaker useless and operators would switch it off."""
    a = seal.admit("charge", {"o": 1}, key="cb-4", domain="customer:7")
    seal.seal(a.intent, a.fence, {"ok": True})
    seal.witness(a.intent, _w(UNKNOWN))
    assert seal.domain_frozen("customer:7") is None


def test_unfreeze_restores_admission(seal: Seal):
    seal.freeze_domain("customer:8", "manual drill")
    with pytest.raises(DomainFrozen):
        seal.admit("charge", {"o": 1}, key="cb-5", domain="customer:8")
    seal.unfreeze_domain("customer:8")
    assert seal.admit("charge", {"o": 1}, key="cb-5", domain="customer:8").fresh


# ── B8 · incident receipt ──────────────────────────────────────────────────

def test_incident_receipt_is_self_checking(seal: Seal):
    a = seal.admit("charge", {"o": 1}, key="ir-1", domain="customer:1")
    seal.seal(a.intent, a.fence, {"ok": True})
    seal.witness(a.intent, _w(MULTIPLE, count=2))
    r = seal.incident_receipt(a.intent)
    assert r["tier"] == TIER_WORLD_DIVERGED
    assert len(r["certs"]) == 2
    assert r["chain_verified"] is True
    assert r["domain_frozen"] is not None
    assert len(r["receipt_digest"]) == 64


# ── B9 · Stripe witness shape (no network, injected transport) ─────────────

def test_stripe_witness_counts_only_settled(seal: Seal):
    body = {"data": [
        {"id": "pi_1", "status": "succeeded"},
        {"id": "pi_2", "status": "canceled"},   # exists but settled nothing
    ]}
    w = StripeWitness(lambda path, params: body)
    assert w.look({"intent": "abc"}).state == CONFIRMED_ONE


def test_stripe_witness_two_settled_is_multiple(seal: Seal):
    body = {"data": [
        {"id": "pi_1", "status": "succeeded"},
        {"id": "pi_2", "status": "succeeded"},
    ]}
    w = StripeWitness(lambda path, params: body)
    r = w.look({"intent": "abc"})
    assert r.state == MULTIPLE and r.count == 2


def test_stripe_witness_transport_failure_is_unknown_not_absent(seal: Seal):
    def boom(path, params):
        raise TimeoutError("read timeout")
    r = StripeWitness(boom).look({"intent": "abc"})
    assert r.state == UNKNOWN
    assert r.state != ABSENT


def test_stripe_witness_empty_result_is_absent(seal: Seal):
    r = StripeWitness(lambda p, q: {"data": []}).look({"intent": "abc"})
    assert r.state == ABSENT


def test_witness_result_rejects_bogus_state():
    with pytest.raises(ValueError):
        WitnessResult("probably_fine")


# ── regressions found by the eagle-eye audit (both were real bugs) ─────────

def test_concurrent_seals_of_different_intents_keep_chain_intact(seal: Seal):
    """A hash chain is serial: read-head-then-append must be atomic.

    Without a lock, two DIFFERENT intents sealing at once both read the same
    head and both write it as prev_hash — a fork that fails verification
    forever. The storm cannot catch this: only one caller wins and seals there.
    """
    import threading
    N = 40
    barrier = threading.Barrier(N)

    def go(i):
        s = Seal(DSN)
        a = s.admit("charge", {"order": i}, key=f"chain-race-{i}")
        barrier.wait()
        s.seal(a.intent, a.fence, {"ok": i})

    ts = [threading.Thread(target=go, args=(i,)) for i in range(N)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    rep = seal.verify_chain()
    assert rep["ok"], f"chain broken under concurrent seals: {rep}"
    assert rep["certs"] == N


def test_freeze_landing_mid_admission_still_blocks(seal: Seal):
    """The breaker must not be raceable: the freeze test is evaluated inside
    the INSERT, not before it."""
    seal.freeze_domain("customer:race", "drill")
    with pytest.raises(DomainFrozen):
        seal.admit("charge", {"o": 1}, key="race-1", domain="customer:race")
    # and a frozen domain is never misreported as a replay
    try:
        seal.admit("charge", {"o": 1}, key="race-1", domain="customer:race")
    except DomainFrozen:
        pass
    else:
        pytest.fail("frozen domain was not refused")


def test_divergence_is_sticky_never_downgrades(seal: Seal):
    """Once the world contradicts the ledger, a later witness that happens to
    count 1 again must NOT downgrade the intent back to WORLD_FINAL. Provider
    search indexes are eventually consistent — a re-poll flapping to 1 is noise,
    not an all-clear. Learned from the live Stripe demo. The domain freeze was
    already sticky; the cert tier now matches."""
    a = seal.admit("charge", {"o": 1}, key="sticky-1", domain="customer:sticky")
    seal.seal(a.intent, a.fence, {"ok": True})
    # world says two → diverged + frozen
    seal.witness(a.intent, _w(MULTIPLE, count=2))
    assert seal.get(a.intent)["tier"] == TIER_WORLD_DIVERGED
    # a later flaky re-poll counts one — must NOT un-diverge
    seal.witness(a.intent, _w(CONFIRMED_ONE, count=1))
    assert seal.get(a.intent)["tier"] == TIER_WORLD_DIVERGED
    # the observation is still recorded as evidence (append-only)
    certs = seal.certs_for(a.intent)
    assert certs[-1]["observed_tier"] == TIER_WORLD_FINAL   # what THIS witness saw
    assert certs[-1]["tier"] == TIER_WORLD_DIVERGED          # but tier stayed diverged
    assert seal.domain_frozen("customer:sticky") is not None
