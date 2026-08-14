"""Seal Mandate — tests for the hard gate.

Scope pinned by these tests: "no money tool executes without a Mandate" is
true ONLY on a path an operator marked `require_mandate`, and ONLY for the
in-process bypass (bare admit() skipping the Gateway). A process holding its
own credential and never touching Seal at all is out of scope for any
in-process gate — that is reconcile.py's job, not this one's.
"""
from __future__ import annotations

import os
import time

import psycopg
import pytest

from seal import Seal
from seal.authority import Gateway
from seal.clearance import CLEARED, Clearance
from seal.graduated import APPROVE, GraduatedClearance
from seal.mandate import (
    ACTIVE, CONSUMED, MandateAlreadyConsumed, MandateError, MandateRequired,
    Mandates,
)

DSN = os.environ.get("SEAL_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="SEAL_DSN not set")


@pytest.fixture()
def seal():
    s = Seal(DSN)
    s.setup()
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        c.execute("TRUNCATE seal_intents, seal_certs, seal_domains, seal_graphs, "
                  "seal_graph_children, seal_clearance, seal_proof, seal_events, "
                  "seal_thresholds, seal_approvals, seal_approval_votes, seal_tickets, "
                  "seal_mandate_paths, seal_mandates RESTART IDENTITY")
    return s


@pytest.fixture()
def gw(seal):
    Clearance(seal).set_policy("charge", CLEARED)
    Clearance(seal).record_proof("charge", green=True, storm_n=1000, executions=1)
    g = Gateway(seal, ticket_key=b"fixed-test-ticket-key")
    g.register_executor("charge", lambda a: {"paid": a["amount"]})
    return g


# ── the hard gate ─────────────────────────────────────────────────────────
def test_bare_admit_is_refused_on_a_required_path(seal):
    Clearance(seal).set_policy("charge", CLEARED)   # clear clearance first, so
    Clearance(seal).record_proof("charge", green=True)  # the ONLY thing blocking
    Mandates(seal).require("charge", True)              # this call is the Mandate gate
    with pytest.raises(MandateRequired):
        seal.admit("charge", {"amount": 100}, key="bypass-1", path="charge")


def test_bare_admit_is_unaffected_on_a_path_with_no_mandate_requirement(seal):
    """Backward compatible: a path nobody put under Mandate behaves exactly
    as before. This is what keeps existing budget-only integrations working."""
    Clearance(seal).set_policy("charge", CLEARED)
    Clearance(seal).record_proof("charge", green=True)
    adm = seal.admit("charge", {"amount": 100}, key="free-1", path="charge")
    assert adm.fresh is True


def test_gateway_path_still_works_when_the_path_requires_a_mandate(seal, gw):
    """The gate stops the BYPASS, not the Gateway itself — Gateway.propose()
    is where a Mandate actually gets minted."""
    Mandates(seal).require("charge", True)
    prop = gw.propose("charge", {"amount": 50}, key="via-gw-1", amount=50)
    assert prop["status"] == "cleared"
    assert "mandate_id" in prop
    res = gw.execute(prop["ticket"], {"amount": 50})
    assert res["status"] == "executed"


def test_require_has_no_agent_facing_tool(seal):
    """Deliberate: a gate a caller could release is not a gate. Confirms the
    ONLY writer of seal_mandate_paths is the operator-facing Mandates.require()."""
    import inspect
    from seal import mcp_server
    src = inspect.getsource(mcp_server)
    assert "mandate_require" not in src and "require_mandate" not in src.replace("_", "")


# ── minting via the gateway ──────────────────────────────────────────────
def test_propose_mints_a_mandate_that_matches_the_ticket(seal, gw):
    prop = gw.propose("charge", {"amount": 50}, key="mint-1", amount=50)
    m = Mandates(seal).get(prop["mandate_id"])
    assert m["state"] == ACTIVE
    assert m["intent"] == prop["intent"]
    assert m["path"] == "charge"
    assert m["amount"] == 50


def test_dual_tier_mandate_records_the_actual_approvers(seal, gw):
    gc = GraduatedClearance(seal, gov_key=b"fixed-test-key")
    gc.set_thresholds("charge", auto_ceiling=100, dual_ceiling=10_000, required_approvers=2)
    first = gw.propose("charge", {"amount": 5000}, key="dual-1", amount=5000)
    assert first["status"] == "needs_approval"
    req = gc.request("charge", 5000, maker="agent:x", intent=first["intent"])
    gc.add_vote(req["id"], "dana@finance", APPROVE)
    gc.add_vote(req["id"], "sam@ops", APPROVE)

    prop2 = gw.propose("charge", {"amount": 5000}, key="dual-1", amount=5000,
                       approval_id=req["id"])
    m = Mandates(seal).get(prop2["mandate_id"])
    assert set(m["approvers"]) == {"dana@finance", "sam@ops"}
    assert m["tier"] == "DUAL"


def test_auto_tier_mandate_records_no_approvers(seal, gw):
    """AUTO-tier had no human sign-off — the mandate must not fabricate one."""
    gc = GraduatedClearance(seal, gov_key=b"fixed-test-key")
    gc.set_thresholds("charge", auto_ceiling=100, dual_ceiling=10_000, required_approvers=2)
    prop = gw.propose("charge", {"amount": 50}, key="auto-1", amount=50)
    m = Mandates(seal).get(prop["mandate_id"])
    assert m["approvers"] == []
    assert m["tier"] is None or m["tier"] == "AUTO"


# ── consuming ─────────────────────────────────────────────────────────────
def test_execute_consumes_the_mandate(seal, gw):
    prop = gw.propose("charge", {"amount": 50}, key="cons-1", amount=50)
    gw.execute(prop["ticket"], {"amount": 50})
    m = Mandates(seal).get(prop["mandate_id"])
    assert m["state"] == CONSUMED
    assert m["consumed_at"] is not None


def test_mandate_cannot_be_consumed_twice_even_bypassing_the_ticket_guard(seal):
    """The mandate's own single-use claim, not just the ticket's — proven by
    calling Mandates.consume() directly, independent of the gateway path."""
    adm = seal_admit_helper(seal, "charge", {"amount": 10}, "direct-1")
    mands = Mandates(seal)
    m = mands.mint(intent=adm.intent, path="charge", args_digest="digest-x", amount=10)
    mands.consume(m["mandate_id"], intent=adm.intent, args_digest="digest-x")
    with pytest.raises(MandateAlreadyConsumed):
        mands.consume(m["mandate_id"], intent=adm.intent, args_digest="digest-x")


def test_consume_refuses_mismatched_args(seal):
    adm = seal_admit_helper(seal, "charge", {"amount": 10}, "mismatch-1")
    mands = Mandates(seal)
    m = mands.mint(intent=adm.intent, path="charge", args_digest="digest-a", amount=10)
    with pytest.raises(MandateError):
        mands.consume(m["mandate_id"], intent=adm.intent, args_digest="digest-DIFFERENT")


def test_two_processes_racing_the_same_mandate_only_one_wins(seal):
    """Same idiom as the ticket claim: the guard must live in the store, not
    in memory, or two 'processes' (simulated here as two Mandates instances)
    could both spend one mandate."""
    adm = seal_admit_helper(seal, "charge", {"amount": 10}, "race-1")
    m = Mandates(seal).mint(intent=adm.intent, path="charge", args_digest="d", amount=10)

    a = Mandates(seal)   # process A
    b = Mandates(seal)   # process B, independent instance, no shared memory
    a.consume(m["mandate_id"], intent=adm.intent, args_digest="d")
    with pytest.raises(MandateAlreadyConsumed):
        b.consume(m["mandate_id"], intent=adm.intent, args_digest="d")


def seal_admit_helper(seal, action, args, key):
    return seal.admit(action, args, key=key)
