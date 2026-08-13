"""Exclusive Authority — the tests that try to bypass custody.

The claim is "an agent that only ever sees tickets cannot call the provider."
These tests exist to attack that claim: forge a ticket, replay one, steal one
for a different intent, race two executions off one ticket, and confirm the
secret genuinely never leaves the gateway process.
"""
from __future__ import annotations

import os
import threading
import time

import psycopg
import pytest

from seal import Seal
from seal.authority import (
    Gateway, InvalidTicket, NoSuchExecutor, Ticket,
)
from seal.budget import Budget, BudgetExceeded
from seal.clearance import CLEARED, Clearance

DSN = os.environ.get("SEAL_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="SEAL_DSN not set")

SECRET = "sk_live_totally_real_do_not_leak"


@pytest.fixture()
def gw():
    s = Seal(DSN)
    s.setup()
    Budget(s).setup()
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        c.execute("TRUNCATE seal_intents, seal_certs, seal_domains, seal_graphs, "
                  "seal_graph_children, seal_clearance, seal_proof, seal_events, "
                  "seal_budget, seal_spend RESTART IDENTITY")
    g = Gateway(s, ticket_key=b"test-fixed-key-not-random")
    Clearance(s).set_policy("charge", CLEARED)
    Clearance(s).record_proof("charge", green=True, storm_n=1000, executions=1)

    calls = []

    def stripe_charge(args):
        # THE SECRET IS ONLY REACHABLE INSIDE THIS CLOSURE.
        calls.append({"amount": args["amount"], "used_secret": SECRET})
        return {"charged": args["amount"], "provider": "stripe-test"}

    g.register_executor("charge", stripe_charge)
    g._test_calls = calls
    return g


# ── the core claim: no secret without a ticket ─────────────────────────────

def test_execute_requires_a_valid_ticket(gw: Gateway):
    with pytest.raises(TypeError):
        gw.execute({}, {"amount": 100})           # not even shaped like a ticket


def test_agent_never_receives_the_secret(gw: Gateway):
    """The whole point. Propose a charge, inspect everything returned, and
    confirm the secret string appears nowhere in it."""
    prop = gw.propose("charge", {"amount": 4900}, key="order-1", budget_key=None)
    assert prop["status"] == "cleared"
    assert SECRET not in str(prop)
    result = gw.execute(prop["ticket"], {"amount": 4900})
    assert result["status"] == "executed"
    assert SECRET not in str(result)
    # the secret only ever appeared inside the executor's own recorded call
    assert gw._test_calls == [{"amount": 4900, "used_secret": SECRET}]


def test_unregistered_path_cannot_run_at_all(gw: Gateway):
    """A path nobody registered an executor for is not a policy question — it
    is structurally impossible to run."""
    Clearance(gw.seal).set_policy("payout", CLEARED)
    Clearance(gw.seal).record_proof("payout", green=True)
    with pytest.raises(NoSuchExecutor):
        gw.propose("payout", {"amount": 1}, key="p1")


# ── forgery and theft ───────────────────────────────────────────────────────

def test_forged_ticket_is_rejected(gw: Gateway):
    fake = Ticket(intent="x" * 20, path="charge", fence="not-real",
                  args_digest="y" * 20, expires_at=time.time() + 300, sig="0" * 64)
    with pytest.raises(InvalidTicket):
        gw.execute(fake, {"amount": 100})


def test_ticket_signed_by_a_different_key_is_rejected(gw: Gateway):
    prop = gw.propose("charge", {"amount": 100}, key="order-2")
    other_gw = Gateway(gw.seal, ticket_key=b"a-completely-different-key")
    other_gw.register_executor("charge", lambda a: {"ok": True})
    with pytest.raises(InvalidTicket):
        other_gw.execute(prop["ticket"], {"amount": 100})


def test_tampered_path_field_breaks_the_signature(gw: Gateway):
    prop = gw.propose("charge", {"amount": 100}, key="order-3")
    t = dict(prop["ticket"])
    t["path"] = "payout"
    with pytest.raises(InvalidTicket):
        gw.execute(t, {"amount": 100})


def test_amount_substitution_is_refused(gw: Gateway):
    """THE hole a real attacker would go for: propose a small, cleared,
    budgeted amount, then try to spend the ticket on a much larger one. Found
    by attacking our own v0 — the first cut signed intent/path/fence but never
    bound the args, so this call went straight through to the executor."""
    prop = gw.propose("charge", {"amount": 1}, key="order-3b")
    with pytest.raises(InvalidTicket):
        gw.execute(prop["ticket"], {"amount": 999999})
    assert gw._test_calls == []          # the executor must never have run


def test_correct_args_still_execute_normally(gw: Gateway):
    """The fix must not be so strict it breaks the honest path."""
    prop = gw.propose("charge", {"amount": 250}, key="order-3c")
    result = gw.execute(prop["ticket"], {"amount": 250})
    assert result["status"] == "executed"
    assert gw._test_calls == [{"amount": 250, "used_secret": SECRET}]


def test_ticket_is_single_use(gw: Gateway):
    """A stolen ticket buys ONE already-authorised action, not a blank cheque."""
    prop = gw.propose("charge", {"amount": 4900}, key="order-4")
    gw.execute(prop["ticket"], {"amount": 4900})
    with pytest.raises(InvalidTicket):
        gw.execute(prop["ticket"], {"amount": 4900})   # replay


def test_expired_ticket_is_rejected(gw: Gateway):
    short = Gateway(gw.seal, ticket_key=b"test-fixed-key-not-random", ticket_ttl_sec=0.05)
    short.register_executor("charge", lambda a: {"ok": True})
    prop = short.propose("charge", {"amount": 1}, key="order-5")
    time.sleep(0.1)
    with pytest.raises(InvalidTicket):
        short.execute(prop["ticket"], {"amount": 1})


def test_ticket_for_one_intent_cannot_execute_a_different_intent(gw: Gateway):
    """Stealing a valid ticket for order-6 must not authorise order-7, even
    though both are the same path with a valid signature shape."""
    p6 = gw.propose("charge", {"amount": 10}, key="order-6")
    p7 = gw.propose("charge", {"amount": 10}, key="order-7")
    frankenstein = dict(p6["ticket"])
    frankenstein["intent"] = p7["ticket"]["intent"]   # swap in someone else's intent
    with pytest.raises(InvalidTicket):
        gw.execute(frankenstein, {"amount": 10})


# ── composition with what's already built ──────────────────────────────────

def test_execute_seals_through_the_normal_seal_kernel(gw: Gateway):
    """A ticket execution is a real Seal admission underneath — replays,
    certs, verify_chain all still work exactly as before."""
    prop = gw.propose("charge", {"amount": 500}, key="order-8")
    result = gw.execute(prop["ticket"], {"amount": 500})
    assert gw.seal.get(result["intent"])["state"] == "sealed"
    assert gw.seal.verify_chain()["ok"]


def test_propose_on_a_held_path_is_refused_by_clearance(gw: Gateway):
    """Clearance is enforced INSIDE propose — no separate check an agent could
    forget to call."""
    from seal.clearance import ClearanceDenied
    Clearance(gw.seal).set_policy("refund", "HOLD")
    gw.register_executor("refund", lambda a: {"ok": True})
    with pytest.raises(ClearanceDenied):
        gw.propose("refund", {"amount": 1}, key="r1")


def test_revoke_stops_new_tickets_even_with_existing_valid_one_in_hand(gw: Gateway):
    """REVOKE = freeze admission + drop execute rights going forward. A ticket
    already issued before the revoke can still be spent once (it represents
    work already cleared); no NEW ticket can be minted after."""
    from seal.clearance import ClearanceDenied
    Clearance(gw.seal).revoke("charge", reason="incident")
    with pytest.raises(ClearanceDenied):
        gw.propose("charge", {"amount": 1}, key="order-9")


def test_second_agent_cannot_double_click_through_the_gateway(gw: Gateway):
    """The property this whole system exists for, now through the gateway:
    two agents propose the same intent at once; only one gets a spendable
    ticket, and only one execution reaches the provider."""
    barrier = threading.Barrier(2)
    outcomes = []
    lock = threading.Lock()

    def agent():
        g = Gateway(gw.seal, ticket_key=b"test-fixed-key-not-random")
        g.register_executor("charge", gw._executors["charge"])
        barrier.wait()
        prop = g.propose("charge", {"amount": 999}, key="race-order")
        with lock:
            outcomes.append(prop["status"])
        if prop["status"] == "cleared":
            g.execute(prop["ticket"], {"amount": 999})

    ts = [threading.Thread(target=agent) for _ in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    assert sorted(outcomes) == ["already_done", "cleared"] or \
           sorted(outcomes) == ["cleared", "in_flight"]
    assert len(gw._test_calls) == 1                # exactly one real charge


def test_budget_is_reserved_before_ticket_and_released_on_executor_failure(gw: Gateway):
    Budget(gw.seal).set_limit("cust:9", limit=100, window_sec=3600)

    def failing(args):
        raise RuntimeError("provider timeout")

    gw.register_executor("payout", failing)
    Clearance(gw.seal).set_policy("payout", CLEARED)
    Clearance(gw.seal).record_proof("payout", green=True)

    prop = gw.propose("payout", {"amount": 60}, key="pay-1",
                       budget_key="cust:9", amount=60)
    assert Budget(gw.seal).remaining("cust:9") == 40    # reserved

    with pytest.raises(RuntimeError):
        gw.execute(prop["ticket"], {"amount": 60})

    assert Budget(gw.seal).remaining("cust:9") == 100   # released, effect never happened


def test_budget_exceeded_refuses_the_ticket_not_just_the_charge(gw: Gateway):
    Budget(gw.seal).set_limit("cust:10", limit=50, window_sec=3600)
    with pytest.raises(BudgetExceeded):
        gw.propose("charge", {"amount": 4900}, key="order-10",
                   budget_key="cust:10", amount=999)
    # the intent must not be left dangling half-admitted after the refusal
    assert Budget(gw.seal).remaining("cust:10") == 50
