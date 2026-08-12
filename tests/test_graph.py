"""Layer C (Apex) — effect graphs and compensating seals.

The tests that matter here are the ones that try to make the graph LIE:
claim FINAL while a child is unconfirmed, or refund twice.
"""
from __future__ import annotations

import os
import threading

import psycopg
import pytest

from seal import Seal
from seal.core import TIER_WORLD_FINAL
from seal.graph import (
    GRAPH_COMPENSATED,
    GRAPH_DIVERGED,
    GRAPH_EXECUTING,
    GRAPH_FINAL,
    EffectGraph,
    GraphError,
)
from seal.witness import CONFIRMED_ONE, MULTIPLE, UNKNOWN, CallableWitness, WitnessResult

DSN = os.environ.get("SEAL_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="SEAL_DSN not set")


@pytest.fixture()
def g():
    s = Seal(DSN, lease_sec=30.0)
    s.setup()
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        c.execute(
            "TRUNCATE seal_intents, seal_certs, seal_domains, "
            "seal_graphs, seal_graph_children RESTART IDENTITY"
        )
    return EffectGraph(s)


def _w(state, **kw):
    return CallableWitness(lambda rec: WitnessResult(state, **kw))


CHILDREN = [
    {"key": "charge", "action": "charge", "args": {"amount": 4900}, "required": True},
    {"key": "email", "action": "email", "args": {"to": "a@b.c"}, "required": True},
]


def _run(g: EffectGraph, graph_id: str, child_key: str, result=None):
    adm = g.admit_child(graph_id, child_key)
    assert adm.fresh
    return g.commit_child(graph_id, child_key, adm.intent, adm.fence, result or {"ok": True})


# ── C1/C2 · the GRAPH_FINAL rule ───────────────────────────────────────────

def test_graph_not_final_while_children_only_sealed(g: EffectGraph):
    """Sealed is not settled. A root that says FINAL here is the
    'paid but never fulfilled' lie."""
    g.create("checkout:1", CHILDREN)
    _run(g, "checkout:1", "charge")
    _run(g, "checkout:1", "email")
    assert g.evaluate("checkout:1")["state"] == GRAPH_EXECUTING


def test_graph_final_only_when_all_required_world_final(g: EffectGraph):
    g.create("checkout:2", CHILDREN)
    c1 = _run(g, "checkout:2", "charge")
    c2 = _run(g, "checkout:2", "email")
    ch = g.get("checkout:2")["children"]
    ints = {c["child_key"]: c["intent"] for c in ch}

    g.seal.witness(ints["charge"], _w(CONFIRMED_ONE, count=1))
    assert g.evaluate("checkout:2")["state"] == GRAPH_EXECUTING  # email still unconfirmed

    g.seal.witness(ints["email"], _w(CONFIRMED_ONE, count=1))
    out = g.evaluate("checkout:2")
    assert out["state"] == GRAPH_FINAL
    assert all(t == TIER_WORLD_FINAL for t in out["required_tiers"].values())


def test_unknown_child_blocks_final(g: EffectGraph):
    g.create("checkout:3", CHILDREN)
    _run(g, "checkout:3", "charge")
    _run(g, "checkout:3", "email")
    ints = {c["child_key"]: c["intent"] for c in g.get("checkout:3")["children"]}
    g.seal.witness(ints["charge"], _w(CONFIRMED_ONE, count=1))
    g.seal.witness(ints["email"], _w(UNKNOWN))
    assert g.evaluate("checkout:3")["state"] == GRAPH_EXECUTING


def test_diverged_child_makes_graph_diverged(g: EffectGraph):
    g.create("checkout:4", CHILDREN)
    _run(g, "checkout:4", "charge")
    _run(g, "checkout:4", "email")
    ints = {c["child_key"]: c["intent"] for c in g.get("checkout:4")["children"]}
    g.seal.witness(ints["charge"], _w(MULTIPLE, count=2))
    assert g.evaluate("checkout:4")["state"] == GRAPH_DIVERGED


def test_optional_child_does_not_block_final(g: EffectGraph):
    g.create("checkout:5", [
        {"key": "charge", "action": "charge", "args": {"a": 1}, "required": True},
        {"key": "crm", "action": "crm", "args": {"a": 1}, "required": False},
    ])
    _run(g, "checkout:5", "charge")
    ints = {c["child_key"]: c["intent"] for c in g.get("checkout:5")["children"]}
    g.seal.witness(ints["charge"], _w(CONFIRMED_ONE, count=1))
    assert g.evaluate("checkout:5")["state"] == GRAPH_FINAL


def test_create_is_idempotent(g: EffectGraph):
    """A graph builder that resets state on a retry is its own double bug."""
    g.create("checkout:6", CHILDREN)
    _run(g, "checkout:6", "charge")
    g.create("checkout:6", CHILDREN)  # retry
    ch = {c["child_key"]: c for c in g.get("checkout:6")["children"]}
    assert ch["charge"]["state"] == "sealed"  # not reset to pending


def test_same_action_in_two_graphs_is_two_intents(g: EffectGraph):
    g.create("checkout:7", CHILDREN)
    g.create("checkout:8", CHILDREN)
    a = g.admit_child("checkout:7", "charge")
    b = g.admit_child("checkout:8", "charge")
    assert a.fresh and b.fresh and a.intent != b.intent


# ── C3/C4 · compensating seals ─────────────────────────────────────────────

def test_compensation_runs_once_and_links_to_forward_cert(g: EffectGraph):
    g.create("checkout:9", CHILDREN)
    fwd = _run(g, "checkout:9", "charge")
    ints = {c["child_key"]: c["intent"] for c in g.get("checkout:9")["children"]}
    g.seal.witness(ints["charge"], _w(CONFIRMED_ONE, count=1))

    # the second step fails for real
    adm = g.admit_child("checkout:9", "email")
    g.fail_child("checkout:9", "email", adm.intent, adm.fence, "smtp down")

    calls = {"n": 0}

    def refund():
        calls["n"] += 1
        return {"refunded": 4900}

    cert = g.compensate("checkout:9", "refund", "charge", "refund", {"amount": 4900}, refund)
    assert calls["n"] == 1
    assert cert["compensates_cert"] == fwd["hash"]
    assert g.get("checkout:9")["state"] == GRAPH_COMPENSATED


def test_compensation_never_double_refunds(g: EffectGraph):
    """An undo that double-fires is as dangerous as a double charge."""
    g.create("checkout:10", CHILDREN)
    _run(g, "checkout:10", "charge")
    calls = {"n": 0}

    def refund():
        calls["n"] += 1
        return {"refunded": 4900}

    for _ in range(5):  # caller retries the compensation five times
        g.compensate("checkout:10", "refund", "charge", "refund", {"amount": 4900}, refund)
    assert calls["n"] == 1


def test_concurrent_compensations_run_once(g: EffectGraph):
    g.create("checkout:11", CHILDREN)
    _run(g, "checkout:11", "charge")
    calls = {"n": 0}
    lock = threading.Lock()
    barrier = threading.Barrier(20)

    def refund():
        with lock:
            calls["n"] += 1
        return {"refunded": 4900}

    def racer():
        gg = EffectGraph(Seal(DSN))
        barrier.wait()
        gg.compensate("checkout:11", "refund", "charge", "refund", {"amount": 4900}, refund)

    ts = [threading.Thread(target=racer) for _ in range(20)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert calls["n"] == 1


def test_cannot_compensate_a_child_that_never_sealed(g: EffectGraph):
    g.create("checkout:12", CHILDREN)
    with pytest.raises(GraphError):
        g.compensate("checkout:12", "refund", "charge", "refund", {"a": 1}, lambda: {})


def test_compensation_cert_is_in_the_verified_chain(g: EffectGraph):
    g.create("checkout:13", CHILDREN)
    _run(g, "checkout:13", "charge")
    g.compensate("checkout:13", "refund", "charge", "refund", {"amount": 4900}, lambda: {"r": 1})
    assert g.seal.verify_chain()["ok"]


def test_retried_compensation_still_ends_compensated(g: EffectGraph):
    """Idempotent means the STATE repeats too, not just the side effect.
    A retry used to leave the graph stuck in GRAPH_COMPENSATING — found by the
    end-to-end demo, which the unit tests had missed."""
    g.create("checkout:14", CHILDREN)
    _run(g, "checkout:14", "charge")
    for _ in range(5):
        g.compensate("checkout:14", "refund", "charge", "refund", {"a": 1}, lambda: {"r": 1})
    assert g.get("checkout:14")["state"] == GRAPH_COMPENSATED


def test_concurrent_compensations_end_compensated(g: EffectGraph):
    import threading
    g.create("checkout:15", CHILDREN)
    _run(g, "checkout:15", "charge")
    barrier = threading.Barrier(15)

    def racer():
        gg = EffectGraph(Seal(DSN))
        barrier.wait()
        gg.compensate("checkout:15", "refund", "charge", "refund", {"a": 1}, lambda: {"r": 1})

    ts = [threading.Thread(target=racer) for _ in range(15)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert g.get("checkout:15")["state"] == GRAPH_COMPENSATED
