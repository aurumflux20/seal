"""Earned autonomy drives the gateway — tests that attack the wheel.

Before this, the licence (L0–L5) was computed and displayed while the gateway's
execute-or-ask decision ran on operator-typed thresholds alone. These tests pin
the loop: the record earns the wheel, a breach takes it back instantly, and an
execution with an unknown outcome makes the path pull over until the world has
answered. The dangerous direction of error is always the same — money moving
unattended on a path that has not earned it, or while nobody knows what the
last attempt did.
"""
from __future__ import annotations

import itertools
import os
import time

import psycopg
import pytest

from seal import Seal
from seal.authority import AmbiguousOutcome, Gateway
from seal.budget import Budget
from seal.clearance import CLEARED, Clearance
from seal.graduated import APPROVE, LICENCE, GraduatedClearance
from seal.license import L0, L3, LicenceEngine
from seal.mcp_server import Server
from seal.reconcile import CallableLister, Reconciler
from seal.witness import CONFIRMED_ONE, CallableWitness, WitnessResult

DSN = os.environ.get("SEAL_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="SEAL_DSN not set")

PATH = "charge"
_SEQ = itertools.count()


def _fresh_seal() -> Seal:
    s = Seal(DSN)
    s.setup()
    Budget(s).setup()
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        c.execute("TRUNCATE seal_intents, seal_certs, seal_domains, seal_graphs, "
                  "seal_graph_children, seal_clearance, seal_proof, seal_events, "
                  "seal_budget, seal_spend, seal_thresholds, seal_approvals, "
                  "seal_approval_votes, seal_tickets RESTART IDENTITY")
    Clearance(s).set_policy(PATH, CLEARED)
    Clearance(s).record_proof(PATH, green=True, storm_n=1000, executions=1)
    return s


def _gateway(seal: Seal, *, earned_autonomy: bool, executor=None) -> Gateway:
    g = Gateway(seal, ticket_key=b"test-fixed-key-not-random",
                earned_autonomy=earned_autonomy)
    calls: list[dict] = []

    def charge(args):
        calls.append(dict(args))
        return {"charged": args["amount"], "provider": "stripe-test"}

    g.register_executor(PATH, executor or charge)
    g._test_calls = calls
    return g


def _confirmed_effect(seal: Seal, n: int) -> None:
    """Settle n effects on PATH and have the provider confirm each — the raw
    material a licence is earned from."""
    for _ in range(n):
        i = next(_SEQ)
        adm = seal.admit(PATH, {"amount": 100 + i}, key=f"k-{PATH}-{i}", domain=PATH)
        seal.seal(adm.intent, adm.fence, {"charged": 100 + i})
        seal.witness(adm.intent, CallableWitness(
            lambda intent: WitnessResult(CONFIRMED_ONE, count=1, evidence="ok")))


def _earn_l3(seal: Seal) -> None:
    _confirmed_effect(seal, 50)
    Reconciler(seal).sweep(CallableLister(lambda a, b: []), since=time.time() - 60)
    assert LicenceEngine(seal).evaluate(PATH).level == L3


# ── the switch ──────────────────────────────────────────────────────────────

def test_default_off_preserves_the_existing_contract():
    """A fresh path with an amount is cleared when earned autonomy is off —
    exactly as every existing integration expects. Nothing changes unless the
    operator turns it on."""
    seal = _fresh_seal()
    gw = _gateway(seal, earned_autonomy=False)
    prop = gw.propose(PATH, {"amount": 50}, key="off-1", amount=50)
    assert prop["status"] == "cleared"


def test_a_path_that_has_earned_nothing_may_move_no_money_unattended():
    """L0 OBSERVED: every money action needs a human. The amount is tiny and
    would be AUTO under any static threshold — the record, not the number,
    decides."""
    seal = _fresh_seal()
    gw = _gateway(seal, earned_autonomy=True)
    prop = gw.propose(PATH, {"amount": 50}, key="l0-1", amount=50)
    assert prop["status"] == "needs_approval"
    assert prop["tier"] == LICENCE
    assert prop["level"] == L0
    assert "not yet licensed" in prop["reason"]
    assert gw._test_calls == []                       # the provider was never touched

    # The refusal is a counted control event, not a silent branch.
    with psycopg.connect(DSN, autocommit=True) as c:
        kinds = [r[0] for r in c.execute(
            "SELECT kind FROM seal_events WHERE path=%s ORDER BY at", (PATH,)).fetchall()]
    assert "approval_required" in kinds


def test_non_money_actions_are_not_gated_by_the_licence():
    """L1 semantics: the licence governs money. A propose with no amount on a
    fresh path still clears — autonomy over non-money work is unaffected."""
    seal = _fresh_seal()
    gw = _gateway(seal, earned_autonomy=True)
    prop = gw.propose(PATH, {"amount": 50}, key="nomoney-1")   # no amount= stated
    assert prop["status"] == "cleared"


# ── the car drives ──────────────────────────────────────────────────────────

def test_an_l3_path_moves_money_unattended():
    """The human stops clicking: a path that has proven itself — 50 confirmed
    effects and a clean sweep — executes within its ceiling with no approval."""
    seal = _fresh_seal()
    _earn_l3(seal)
    gw = _gateway(seal, earned_autonomy=True)
    prop = gw.propose(PATH, {"amount": 50}, key="l3-1", amount=50)
    assert prop["status"] == "cleared"
    res = gw.execute(prop["ticket"], {"amount": 50})
    assert res["status"] == "executed"
    assert len(gw._test_calls) == 1


def test_the_licence_widens_room_only_inside_the_operators_ceiling():
    """Earned autonomy never raises the operator's own limit. An L3 path still
    hits DUAL for an amount above auto_ceiling — a ceiling is a ceiling."""
    seal = _fresh_seal()
    _earn_l3(seal)
    GraduatedClearance(seal).set_thresholds(PATH, auto_ceiling=100, dual_ceiling=10_000,
                                            required_approvers=2, by="cfo")
    gw = _gateway(seal, earned_autonomy=True)
    assert gw.propose(PATH, {"amount": 50}, key="in-1", amount=50)["status"] == "cleared"
    big = gw.propose(PATH, {"amount": 5000}, key="over-1", amount=5000)
    assert big["status"] == "needs_approval"
    assert big["tier"] == "DUAL"


# ── the wheel is taken back ─────────────────────────────────────────────────

def test_a_breach_hands_the_wheel_back_instantly():
    """Money moved behind the gateway's back. The licence is suspended on the
    spot and the very next money action on the path needs a human — however
    clean the fifty before it were."""
    seal = _fresh_seal()
    _earn_l3(seal)
    gw = _gateway(seal, earned_autonomy=True)
    assert gw.propose(PATH, {"amount": 50}, key="pre-1", amount=50)["status"] == "cleared"

    seal.record_event("out_of_band_spend", path=PATH,
                      detail={"domain": PATH, "amount": 999, "source": "leaked key"})

    prop = gw.propose(PATH, {"amount": 50}, key="post-1", amount=50)
    assert prop["status"] == "needs_approval"
    assert prop["tier"] == LICENCE
    assert "suspended" in prop["reason"]


def test_an_unknown_outcome_makes_the_path_pull_over_until_the_world_answers():
    """THE pull-over. An execution reaches the provider and then fails
    ambiguously. The claim stands (existing behaviour) — and now the path also
    HOLDS: no further money moves unattended until settle() has asked the
    provider what happened. Once the witness confirms the effect landed once,
    the hold lifts by itself and the path drives again. The level was never
    touched: nothing was proven wrong, something was merely unknown."""
    seal = _fresh_seal()
    _earn_l3(seal)

    def flaky_charge(args):
        raise TimeoutError("read timed out after the provider was called")

    gw = _gateway(seal, earned_autonomy=True, executor=flaky_charge)
    prop = gw.propose(PATH, {"amount": 60}, key="amb-1", amount=60)
    assert prop["status"] == "cleared"
    with pytest.raises(AmbiguousOutcome):
        gw.execute(prop["ticket"], {"amount": 60})
    assert seal.get(prop["intent"])["state"] == "open"        # claim stands

    lic = LicenceEngine(seal).evaluate(PATH)
    assert lic.level == L3                                     # not a breach
    assert lic.held is True
    assert lic.unattended is False
    assert prop["intent"] in lic.evidence["open_ambiguous_intents"]

    # The next money action on this path is refused unattended — with the
    # reason that says exactly why.
    nxt = gw.propose(PATH, {"amount": 10}, key="amb-2", amount=10)
    assert nxt["status"] == "needs_approval"
    assert nxt["tier"] == LICENCE
    assert "unknown outcome" in nxt["reason"]

    # The world answers: the provider confirms the charge landed exactly once.
    # settle() heals the intent; the hold lifts with nothing else recorded.
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("UPDATE seal_intents SET lease_until=%s WHERE intent=%s",
                  (time.time() - 1, prop["intent"]))            # lease expired → settleable
    gw.register_witness(PATH, CallableWitness(
        lambda rec: WitnessResult(CONFIRMED_ONE, count=1, evidence="stripe says one")))
    out = gw.settle(prop["intent"])
    assert out["resolution"] == "healed"

    lic = LicenceEngine(seal).evaluate(PATH)
    assert lic.held is False
    assert lic.unattended is True
    again = gw.propose(PATH, {"amount": 10}, key="amb-3", amount=10)
    assert again["status"] == "cleared"


# ── supervision: a human takes the wheel ────────────────────────────────────

def test_a_human_approval_lets_an_unlicensed_path_act_once():
    """FSD with a driver: an L0 path may still move money when a person
    approves this exact action. The approval is validated and consumed like a
    graduated one, so it cannot be spent twice."""
    seal = _fresh_seal()
    gw = _gateway(seal, earned_autonomy=True)
    refused = gw.propose(PATH, {"amount": 50}, key="sup-1", amount=50)
    assert refused["status"] == "needs_approval" and refused["tier"] == LICENCE

    gc = GraduatedClearance(seal)
    r = gc.request(PATH, 50, maker="agent-7", intent=refused["intent"], tier=LICENCE)
    gc.add_vote(r["id"], "alice", APPROVE)
    gc.add_vote(r["id"], "bob", APPROVE)

    ok = gw.propose(PATH, {"amount": 50}, key="sup-1", amount=50, approval_id=r["id"])
    assert ok["status"] == "cleared"
    assert gw.execute(ok["ticket"], {"amount": 50})["status"] == "executed"


# ── the supervisor's dashboard ──────────────────────────────────────────────

def test_seal_paths_reports_each_paths_earned_licence():
    seal = _fresh_seal()
    gw = _gateway(seal, earned_autonomy=True)
    out = Server(seal, gw).call("seal_paths", {})
    assert out["earned_autonomy"] is True
    entry = next(p for p in out["paths"] if p["path"] == PATH)
    assert entry["licence"]["level"] == L0
    assert entry["licence"]["unattended"] is False
    assert entry["licence"]["held"] is False

    _earn_l3(seal)
    entry = next(p for p in Server(seal, gw).call("seal_paths", {})["paths"]
                 if p["path"] == PATH)
    assert entry["licence"]["level"] == L3
    assert entry["licence"]["unattended"] is True
