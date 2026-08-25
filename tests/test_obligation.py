"""Obligations — the alarm for what an agent FAILS to do.

The property under test, in one line: silence that should have been work is a
recorded, unforgeable, licence-suspending incident — never an empty dashboard.
"""
from __future__ import annotations

import os
import time
import uuid

import psycopg
import pytest

from seal import Seal
from seal.license import LicenceEngine
from seal.obligation import (BREACHED, CURED, DIVERGED, LATE, PENDING,
                             SATISFIED, SATISFIED_UNCONFIRMED,
                             ObligationError, Obligations)
from seal.witness import (CONFIRMED_ONE, MULTIPLE, CallableWitness,
                          WitnessResult)

DSN = os.environ.get("SEAL_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="SEAL_DSN not set")


@pytest.fixture()
def obs():
    s = Seal(DSN)
    s.setup()
    o = Obligations(s)
    o.setup()
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        for t in ("seal_certs", "seal_intents", "seal_events",
                  "seal_obligations", "seal_obligation_breaches"):
            c.execute(f"TRUNCATE {t} RESTART IDENTITY")
    return o


def _seal_effect(s, action, key):
    a = s.admit(action, {"k": key}, key=key)
    return s.seal(a.intent, a.fence, {"ok": True})


# ── one-shot duties ───────────────────────────────────────────────────────
def test_satisfied_on_time(obs):
    key = f"return-{uuid.uuid4().hex[:8]}"
    obs.expect(action="refund", key=key, due_in_sec=3600)
    _seal_effect(obs.seal, "refund", key)
    rep = obs.sweep()
    assert rep["verdict"] == "met"
    assert rep["items"][0]["status"] == SATISFIED


def test_pending_before_the_deadline(obs):
    obs.expect(action="refund", key="r1", due_in_sec=3600)
    rep = obs.sweep()
    assert rep["verdict"] == "met"
    assert rep["items"][0]["status"] == PENDING
    assert rep["items"][0]["seconds_remaining"] > 0


def test_missed_deadline_is_a_breach_on_the_chain(obs):
    """The core claim: the MISS itself becomes a tamper-evident cert."""
    ob = obs.expect(action="refund", key="r-missed", due_in_sec=0.01)
    time.sleep(0.05)
    rep = obs.sweep()
    assert rep["verdict"] == "breached"
    assert rep["items"][0]["status"] == BREACHED

    # the breach is a cert naming the intent that SHOULD have existed
    certs = obs.seal.certs_for(ob["expected_intent"])
    assert len(certs) == 1
    assert certs[0]["tier"] == "OBLIGATION_BREACHED"
    assert certs[0]["world"] == "missing"
    # and the chain (which now contains a miss) still verifies
    assert obs.seal.verify_chain()["ok"]


def test_breach_is_recorded_exactly_once(obs):
    obs.expect(action="refund", key="r-once", due_in_sec=0.01)
    time.sleep(0.05)
    obs.sweep()
    obs.sweep()
    obs.sweep()
    with psycopg.connect(DSN, autocommit=True) as c:
        n = c.execute("SELECT count(*) FROM seal_obligation_breaches").fetchone()[0]
        certs = c.execute("SELECT count(*) FROM seal_certs").fetchone()[0]
    assert n == 1 and certs == 1


def test_late_work_after_a_breach_is_cured_not_erased(obs):
    ob = obs.expect(action="refund", key="r-late", due_in_sec=0.01)
    time.sleep(0.05)
    assert obs.sweep()["items"][0]["status"] == BREACHED

    _seal_effect(obs.seal, "refund", "r-late")
    rep = obs.sweep()
    assert rep["items"][0]["status"] == CURED
    # cured means remediated — the breach cert stays on the chain forever
    tiers = [c["tier"] for c in obs.seal.certs_for(ob["expected_intent"])]
    assert "OBLIGATION_BREACHED" in tiers


def test_work_sealed_after_due_but_before_sweep_is_late(obs):
    obs.expect(action="refund", key="r-tardy", due_in_sec=0.01)
    time.sleep(0.05)
    _seal_effect(obs.seal, "refund", "r-tardy")     # lands late, pre-sweep
    rep = obs.sweep()
    assert rep["items"][0]["status"] == LATE
    assert rep["verdict"] == "met"                  # done is done; lateness is on record
    with psycopg.connect(DSN, autocommit=True) as c:
        n = c.execute("SELECT count(*) FROM seal_events "
                      "WHERE kind='obligation_late'").fetchone()[0]
    assert n == 1


def test_grace_period_holds_off_the_breach(obs):
    obs.expect(action="refund", key="r-grace", due_in_sec=0.01, grace_sec=3600)
    time.sleep(0.05)
    rep = obs.sweep()
    assert rep["items"][0]["status"] == PENDING     # inside grace: not breached


# ── UNKNOWN is never clean ────────────────────────────────────────────────
def test_require_world_local_seal_is_not_met(obs):
    key = "r-unconfirmed"
    obs.expect(action="refund", key=key, due_in_sec=3600, require_world=True)
    _seal_effect(obs.seal, "refund", key)
    rep = obs.sweep()
    assert rep["items"][0]["status"] == SATISFIED_UNCONFIRMED
    assert rep["verdict"] == "unconfirmed"          # not met — unproven

    # the provider confirming flips it to genuinely met
    intent = obs.get(rep["items"][0]["obligation_id"])["expected_intent"]
    obs.seal.witness(intent, CallableWitness(
        lambda r: WitnessResult(CONFIRMED_ONE, count=1)))
    assert obs.sweep()["verdict"] == "met"


def test_diverged_effect_never_reads_as_met(obs):
    key = "r-div"
    ob = obs.expect(action="refund", key=key, due_in_sec=3600)
    _seal_effect(obs.seal, "refund", key)
    obs.seal.witness(ob["expected_intent"], CallableWitness(
        lambda r: WitnessResult(MULTIPLE, count=2)), freeze_on_diverge=False)
    rep = obs.sweep()
    assert rep["items"][0]["status"] == DIVERGED
    assert rep["verdict"] == "breached"


# ── recurring duties ──────────────────────────────────────────────────────
def test_recurring_missing_window_breaches_and_present_window_does_not(obs):
    now = time.time()
    obs.expect_recurring(action="renewal", every_sec=10,
                         anchor_at=now - 25)        # windows 0 and 1 elapsed
    # an effect only in window 0
    with psycopg.connect(DSN, autocommit=True) as c:
        a = obs.seal.admit("renewal", {"n": 1}, key="ren-1")
        obs.seal.seal(a.intent, a.fence, {"ok": True})
        c.execute("UPDATE seal_intents SET created_at=%s WHERE intent=%s",
                  (now - 22, a.intent))
    rep = obs.sweep(now=now)
    by_window = {i["window"]: i["status"] for i in rep["items"]}
    assert by_window[0] == SATISFIED
    assert by_window[1] == BREACHED


def test_recurring_each_window_is_judged_exactly_once(obs):
    now = time.time()
    ob = obs.expect_recurring(action="renewal", every_sec=10, anchor_at=now - 25)
    obs.sweep(now=now)
    rep2 = obs.sweep(now=now)
    assert rep2["duties_checked"] == 0              # windows 0,1 already judged
    assert obs.get(ob["obligation_id"])["next_window"] == 2
    with psycopg.connect(DSN, autocommit=True) as c:
        n = c.execute("SELECT count(*) FROM seal_obligation_breaches").fetchone()[0]
    assert n == 2


# ── the levers agents must not have ───────────────────────────────────────
def test_deactivation_is_not_on_the_mcp_surface(obs):
    """An obligation an agent could cancel is not an obligation."""
    from seal.mcp_server import Server
    server = Server(obs.seal)
    names = {t["name"] for t in server.tools}
    assert "seal_expect" in names
    assert "seal_obligations" in names
    assert not any("cancel" in n or "release" in n or "deactivate" in n
                   for n in names)


def test_operator_deactivation_works_and_is_evented(obs):
    ob = obs.expect(action="refund", key="r-op", due_in_sec=0.01)
    obs.deactivate(ob["obligation_id"], by="cfo", reason="return withdrawn")
    time.sleep(0.05)
    rep = obs.sweep()
    assert rep["duties_checked"] == 0               # released duties not swept
    with pytest.raises(ObligationError):
        obs.deactivate(ob["obligation_id"], by="cfo", reason="twice")


def test_resolve_breach_records_who_and_why_but_keeps_the_chain(obs):
    obs.expect(action="refund", key="r-res", due_in_sec=0.01)
    time.sleep(0.05)
    rep = obs.sweep()
    breach_id = rep["items"][0]["breach_id"]
    obs.resolve_breach(breach_id, by="ops-lead", note="refunded manually via dashboard")
    assert obs.sweep()["open_breaches"] == 0
    assert obs.seal.verify_chain()["ok"]            # breach cert still there
    with pytest.raises(ObligationError):
        obs.resolve_breach(breach_id, by="ops-lead", note="again")


# ── the licence loop: silence costs autonomy ──────────────────────────────
def test_breach_suspends_the_earned_licence(obs):
    path = "refund"
    # build a modest clean record on the path first
    for i in range(3):
        _seal_effect(obs.seal, path, f"ok-{i}")
    before = LicenceEngine(obs.seal).evaluate(path)
    assert not before.suspended

    obs.expect(action=path, key="r-silent", due_in_sec=0.01)
    time.sleep(0.05)
    obs.sweep()

    after = LicenceEngine(obs.seal).evaluate(path)
    assert after.suspended
    assert after.suspended_reason and "obligation_breached" in str(after.suspended_reason)


def test_breach_on_one_path_does_not_suspend_another(obs):
    obs.expect(action="refund", key="r-x", due_in_sec=0.01)
    time.sleep(0.05)
    obs.sweep()
    for i in range(2):
        _seal_effect(obs.seal, "charge", f"c-{i}")
    lic = LicenceEngine(obs.seal).evaluate("charge")
    assert not lic.suspended
