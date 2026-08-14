"""Pre-commit World Freeze (B1) — the locked spec's feature that was in the
schema and not enforced. `read_set` was accepted and stored by admit() but
never checked; a caller who believed they had staleness protection had none.

These tests pin the fix: a `checker.fresh(read_set)` that returns False must
refuse admission BEFORE a fence is granted — nothing runs on stale facts —
and a read_set given with no checker must stay honestly inert rather than
silently appear enforced.
"""
from __future__ import annotations

import os

import psycopg
import pytest

from seal import Seal, StaleWorldRead
from seal.freshness import CallableChecker

DSN = os.environ.get("SEAL_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="SEAL_DSN not set")


@pytest.fixture()
def seal():
    s = Seal(DSN)
    s.setup()
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        c.execute("TRUNCATE seal_intents, seal_certs, seal_domains, seal_graphs, "
                  "seal_graph_children RESTART IDENTITY")
    return s


def test_stale_read_set_is_refused_before_any_fence_is_granted(seal):
    """The whole point: refusal happens BEFORE admission, not after the
    effect ran. No fence means the caller never had permission to act."""
    always_stale = CallableChecker(lambda rs: False)
    with pytest.raises(StaleWorldRead):
        seal.admit("charge", {"amount": 5000}, key="o-1",
                   read_set={"cart_total": 5000}, checker=always_stale)

    # and nothing was admitted — a caller retrying with the SAME key and a
    # fresh checker must succeed, proving the refusal left no residue
    always_fresh = CallableChecker(lambda rs: True)
    adm = seal.admit("charge", {"amount": 5000}, key="o-1",
                     read_set={"cart_total": 5000}, checker=always_fresh)
    assert adm.fresh is True


def test_fresh_read_set_is_admitted_normally(seal):
    checker = CallableChecker(lambda rs: rs.get("cart_total") == 5000)
    adm = seal.admit("charge", {"amount": 5000}, key="o-2",
                     read_set={"cart_total": 5000}, checker=checker)
    assert adm.fresh is True
    assert adm.fence


def test_checker_receives_the_exact_read_set_passed():
    """The checker must see what the caller actually captured, not a
    reconstruction — otherwise a check against the wrong snapshot could pass
    when it shouldn't."""
    seen = []
    checker = CallableChecker(lambda rs: seen.append(rs) or True)
    s = Seal(DSN); s.setup()
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        c.execute("TRUNCATE seal_intents, seal_certs RESTART IDENTITY")
    s.admit("charge", {"amount": 1}, key="o-rs",
            read_set={"inventory": 3, "price": 999}, checker=checker)
    assert seen == [{"inventory": 3, "price": 999}]


def test_read_set_without_a_checker_is_honestly_inert(seal):
    """A read_set with no checker is still accepted and stored — Seal cannot
    invent a freshness rule for facts it does not understand — but it must
    NOT silently enforce anything. This is the exact prior behaviour; the
    point of this test is that adding enforcement did not change it, so an
    existing caller who never opted in is unaffected."""
    adm = seal.admit("charge", {"amount": 1}, key="o-noop",
                     read_set={"whatever": "not checked"})
    assert adm.fresh is True   # admitted despite no checker verifying anything


def test_checker_is_never_consulted_without_a_read_set(seal):
    """No read_set means nothing to freeze — the checker must not be called
    at all, so a checker with side effects (a network call) is never charged
    for admissions that never opted into freshness."""
    calls = []
    checker = CallableChecker(lambda rs: calls.append(rs) or True)
    seal.admit("charge", {"amount": 1}, key="o-none", checker=checker)
    assert calls == []


def test_stale_read_set_does_not_block_a_different_key(seal):
    """A refusal is scoped to the one intent it was checked for — it must not
    become an accidental domain-wide freeze."""
    with pytest.raises(StaleWorldRead):
        seal.admit("charge", {"amount": 1}, key="o-a",
                   read_set={"x": 1}, checker=CallableChecker(lambda rs: False))
    adm = seal.admit("charge", {"amount": 1}, key="o-b",
                     read_set={"x": 1}, checker=CallableChecker(lambda rs: True))
    assert adm.fresh is True
