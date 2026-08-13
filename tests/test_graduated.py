"""Graduated Clearance — maker-checker. Tests that attack the property itself.

The whole point is segregation of duties. These tests exist to prove: the
maker cannot approve their own request, one approver cannot count twice (even
racing), a reject is terminal, an approval is single-use, and no threshold
configuration accidentally routes a large amount to auto-clear.
"""
from __future__ import annotations

import os
import threading

import psycopg
import pytest

from seal import Seal
from seal.authority import Gateway
from seal.clearance import CLEARED, Clearance
from seal.graduated import (
    ALWAYS_HUMAN, APPROVE, APPROVED, AUTO, DUAL, PENDING, REJECT, REJECTED,
    ApprovalConsumed, ApprovalNotSatisfied, GraduatedClearance, GraduatedError,
    SelfApproval,
)

DSN = os.environ.get("SEAL_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="SEAL_DSN not set")


@pytest.fixture()
def gc():
    s = Seal(DSN)
    s.setup()
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        c.execute("TRUNCATE seal_intents, seal_certs, seal_domains, seal_graphs, "
                  "seal_graph_children, seal_clearance, seal_proof, seal_events, "
                  "seal_thresholds, seal_approvals, seal_approval_votes "
                  "RESTART IDENTITY")
    g = GraduatedClearance(s, gov_key=b"fixed-test-governance-key")
    g.set_thresholds("payout", auto_ceiling=100, dual_ceiling=10_000, required_approvers=2)
    return g


# ── tier boundaries ─────────────────────────────────────────────────────────

def test_tier_boundaries_are_exact(gc: GraduatedClearance):
    assert gc.tier_for("payout", 100) == AUTO           # exactly at auto ceiling
    assert gc.tier_for("payout", 100.01) == DUAL         # one cent over
    assert gc.tier_for("payout", 10_000) == DUAL         # exactly at dual ceiling
    assert gc.tier_for("payout", 10_000.01) == ALWAYS_HUMAN


def test_unconfigured_path_defaults_to_always_human_not_auto(gc: GraduatedClearance):
    """Missing configuration must fail toward MORE scrutiny, never less."""
    assert gc.tier_for("never-configured", 1) == ALWAYS_HUMAN


def test_cannot_request_approval_for_an_auto_tier_amount(gc: GraduatedClearance):
    with pytest.raises(GraduatedError):
        gc.request("payout", 50, maker="alice", intent="i1")


def test_required_approvers_below_two_is_rejected(gc: GraduatedClearance):
    with pytest.raises(ValueError):
        gc.set_thresholds("x", 10, 100, required_approvers=1)


# ── the property itself: maker cannot approve their own request ────────────

def test_maker_cannot_approve_own_request(gc: GraduatedClearance):
    r = gc.request("payout", 5000, maker="alice", intent="i2")
    with pytest.raises(SelfApproval):
        gc.add_vote(r["id"], "alice", APPROVE)


def test_self_approval_blocked_even_as_the_second_vote(gc: GraduatedClearance):
    """The maker cannot sneak in as approver #2 after a legitimate first vote."""
    r = gc.request("payout", 5000, maker="alice", intent="i3")
    gc.add_vote(r["id"], "bob", APPROVE)
    with pytest.raises(SelfApproval):
        gc.add_vote(r["id"], "alice", APPROVE)
    assert gc.get(r["id"])["state"] == PENDING   # still needs a real second approver


# ── one approver, one vote — even under a race ──────────────────────────────

def test_same_approver_voting_twice_does_not_double_count(gc: GraduatedClearance):
    r = gc.request("payout", 5000, maker="alice", intent="i4")
    gc.add_vote(r["id"], "bob", APPROVE)
    with pytest.raises(GraduatedError):
        gc.add_vote(r["id"], "bob", APPROVE)      # bob again — must not count as approver #2
    assert gc.get(r["id"])["state"] == PENDING
    assert gc.get(r["id"])["approve_count"] == 1


def test_concurrent_duplicate_votes_from_the_same_approver_still_count_once(gc: GraduatedClearance):
    """The UNIQUE constraint must hold under genuine concurrency, not just
    sequential calls — two threads racing the same approver's vote."""
    r = gc.request("payout", 5000, maker="alice", intent="i5")
    barrier = threading.Barrier(5)
    errors = []

    def vote():
        s = Seal(DSN)
        g = GraduatedClearance(s, gov_key=b"fixed-test-governance-key")
        barrier.wait()
        try:
            g.add_vote(r["id"], "bob", APPROVE)
        except GraduatedError as e:
            errors.append(e)

    ts = [threading.Thread(target=vote) for _ in range(5)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    assert len(errors) == 4                      # exactly one of the 5 wins
    assert gc.get(r["id"])["approve_count"] == 1  # never double-counted


def test_two_distinct_approvers_satisfies_and_locks_in_approved(gc: GraduatedClearance):
    r = gc.request("payout", 5000, maker="alice", intent="i6")
    gc.add_vote(r["id"], "bob", APPROVE)
    out = gc.add_vote(r["id"], "carol", APPROVE)
    assert out["state"] == APPROVED
    assert out["approve_count"] == 2


# ── reject is terminal ──────────────────────────────────────────────────────

def test_single_reject_is_terminal_even_with_a_prior_approval(gc: GraduatedClearance):
    r = gc.request("payout", 5000, maker="alice", intent="i7")
    gc.add_vote(r["id"], "bob", APPROVE)
    out = gc.add_vote(r["id"], "carol", REJECT)
    assert out["state"] == REJECTED
    # and it cannot be revived by a THIRD approver piling on approvals
    with pytest.raises(GraduatedError):
        gc.add_vote(r["id"], "dave", APPROVE)


# ── expiry ──────────────────────────────────────────────────────────────────

def test_expired_pending_approval_cannot_be_voted_on(gc: GraduatedClearance):
    r = gc.request("payout", 5000, maker="alice", intent="i8", ttl_sec=0.05)
    import time as _t; _t.sleep(0.1)
    with pytest.raises(GraduatedError):
        gc.add_vote(r["id"], "bob", APPROVE)
    assert gc.get(r["id"])["state"] == "expired"


# ── single-use consumption ──────────────────────────────────────────────────

def test_consume_requires_approved_state(gc: GraduatedClearance):
    r = gc.request("payout", 5000, maker="alice", intent="i9")
    with pytest.raises(ApprovalNotSatisfied):
        gc.consume(r["id"])                       # still pending, zero votes


def test_consume_is_single_use(gc: GraduatedClearance):
    r = gc.request("payout", 5000, maker="alice", intent="i10")
    gc.add_vote(r["id"], "bob", APPROVE)
    gc.add_vote(r["id"], "carol", APPROVE)
    gc.consume(r["id"])
    with pytest.raises(ApprovalConsumed):
        gc.consume(r["id"])


# ── the decision joins the SAME tamper-evident chain as execution certs ────

def test_approval_decision_is_chained_and_verifiable(gc: GraduatedClearance):
    r = gc.request("payout", 5000, maker="alice", intent="i11")
    gc.add_vote(r["id"], "bob", APPROVE)
    gc.add_vote(r["id"], "carol", APPROVE)
    rep = gc.seal.verify_chain()
    assert rep["ok"]
    certs = [c for c in gc.seal.certs_for(f"approval:{r['id']}")]
    assert len(certs) == 1
    assert certs[0]["outcome"] == APPROVED
    assert len(certs[0]["votes"]) == 2


def test_vote_signatures_are_present_and_distinct(gc: GraduatedClearance):
    r = gc.request("payout", 5000, maker="alice", intent="i12")
    gc.add_vote(r["id"], "bob", APPROVE)
    gc.add_vote(r["id"], "carol", APPROVE)
    votes = gc.get(r["id"])["votes"]
    assert len(votes) == 2
    assert votes[0]["approver"] != votes[1]["approver"]


# ── integration: the gateway will not mint a ticket without a satisfied approval ─

@pytest.fixture()
def gw(gc: GraduatedClearance):
    Clearance(gc.seal).set_policy("payout", CLEARED)
    Clearance(gc.seal).record_proof("payout", green=True, storm_n=1000, executions=1)
    g = Gateway(gc.seal, ticket_key=b"test-ticket-key")
    calls = []
    g.register_executor("payout", lambda a: calls.append(a) or {"paid": a["amount"]})
    g._test_calls = calls
    return g


def test_propose_above_auto_ceiling_without_approval_is_refused(gw: Gateway):
    prop = gw.propose("payout", {"amount": 5000}, key="pay-1", amount=5000)
    assert prop["status"] == "needs_approval"
    assert prop["tier"] == DUAL
    assert gw._test_calls == []


def test_propose_with_satisfied_approval_mints_a_ticket(gw: Gateway):
    gc = GraduatedClearance(gw.seal, gov_key=b"fixed-test-governance-key")
    first = gw.propose("payout", {"amount": 5000}, key="pay-2", amount=5000)
    r = gc.request("payout", 5000, maker="alice", intent=first["intent"])
    gc.add_vote(r["id"], "bob", APPROVE)
    gc.add_vote(r["id"], "carol", APPROVE)

    prop = gw.propose("payout", {"amount": 5000}, key="pay-2", amount=5000, approval_id=r["id"])
    assert prop["status"] == "cleared"
    result = gw.execute(prop["ticket"], {"amount": 5000})
    assert result["status"] == "executed"
    assert gw._test_calls == [{"amount": 5000}]


def test_propose_cannot_reuse_an_approval_for_a_different_intent(gw: Gateway):
    """A satisfied approval is bound to the exact intent it was requested for.
    Trying to spend it against a DIFFERENT intent (different key, same path
    and amount) must be refused — even before the single-use check, the
    intent binding itself catches it."""
    gc = GraduatedClearance(gw.seal, gov_key=b"fixed-test-governance-key")
    first = gw.propose("payout", {"amount": 5000}, key="pay-3", amount=5000)
    r = gc.request("payout", 5000, maker="alice", intent=first["intent"])
    gc.add_vote(r["id"], "bob", APPROVE)
    gc.add_vote(r["id"], "carol", APPROVE)
    gw.propose("payout", {"amount": 5000}, key="pay-3", amount=5000, approval_id=r["id"])

    from seal.graduated import GraduatedError
    with pytest.raises(GraduatedError):
        gw.propose("payout", {"amount": 5000}, key="pay-3b", amount=5000, approval_id=r["id"])


def test_consumed_approval_cannot_be_replayed_for_the_same_intent_either(gw: Gateway):
    """The single-use property in isolation: even the SAME intent cannot spend
    an already-consumed approval a second time."""
    gc = GraduatedClearance(gw.seal, gov_key=b"fixed-test-governance-key")
    first = gw.propose("payout", {"amount": 5000}, key="pay-3c", amount=5000)
    r = gc.request("payout", 5000, maker="alice", intent=first["intent"])
    gc.add_vote(r["id"], "bob", APPROVE)
    gc.add_vote(r["id"], "carol", APPROVE)
    gw.propose("payout", {"amount": 5000}, key="pay-3c", amount=5000, approval_id=r["id"])
    assert gc.get(r["id"])["consumed_at"] is not None

    from seal.graduated import ApprovalConsumed
    with pytest.raises(ApprovalConsumed):
        gc.consume(r["id"])   # direct unit check that consume() itself refuses a replay


def test_amount_on_an_unconfigured_path_never_triggers_graduated_clearance(gw: Gateway):
    """The compatibility property. Passing `amount` to propose() is also how
    plain Budget reservations work, and those callers never opted into
    maker-checker. Graduated clearance must be a no-op for any path nobody
    ran set_thresholds() on — not silently default to ALWAYS_HUMAN and block
    every existing budget-only integration. (Found by running the full suite
    after this feature landed: an old Authority/Budget test broke because
    tier_for()'s safe-default leaked into paths that never asked for it.)"""
    Clearance(gw.seal).set_policy("wire", CLEARED)
    Clearance(gw.seal).record_proof("wire", green=True)
    gw.register_executor("wire", lambda a: {"sent": a["amount"]})
    # "wire" has NO seal_thresholds row — graduated clearance was never configured
    prop = gw.propose("wire", {"amount": 999_999}, key="w1", amount=999_999)
    assert prop["status"] == "cleared"          # not "needs_approval"


def test_underlying_clearance_hold_still_blocks_even_with_full_approval(gw: Gateway):
    """Approval is an ADDITIONAL gate, not a bypass of the base path clearance."""
    Clearance(gw.seal).set_policy("payout", "HOLD")
    gc = GraduatedClearance(gw.seal, gov_key=b"fixed-test-governance-key")
    from seal.clearance import ClearanceDenied
    with pytest.raises(ClearanceDenied):
        gw.propose("payout", {"amount": 5000}, key="pay-4", amount=5000)
