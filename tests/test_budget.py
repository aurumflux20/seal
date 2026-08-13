"""Cross-process budget — the test the in-memory SpendLimiter would FAIL.

A payments engineer reviewing our code pointed out that once-kernel's budget is
an in-memory array, so it bounds one process and nothing more. He was right.
These tests exist to prove the replacement actually holds under the concurrency
we claim to survive.
"""
from __future__ import annotations

import os
import threading

import psycopg
import pytest

from seal import Seal
from seal.budget import Budget, BudgetExceeded

DSN = os.environ.get("SEAL_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="SEAL_DSN not set")


@pytest.fixture()
def b():
    s = Seal(DSN)
    s.setup()
    bud = Budget(s)
    bud.setup()
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        c.execute("TRUNCATE seal_budget, seal_spend RESTART IDENTITY")
    return bud


def test_reserve_refuses_over_ceiling(b):
    b.set_limit("cust:1", limit=100, window_sec=3600)
    b.reserve("cust:1", 60).settle()
    with pytest.raises(BudgetExceeded):
        b.reserve("cust:1", 50)


def test_release_returns_headroom(b):
    b.set_limit("cust:2", limit=100, window_sec=3600)
    r = b.reserve("cust:2", 90)
    r.release()
    assert b.remaining("cust:2") == 100
    b.reserve("cust:2", 90).settle()          # now fits again


def test_reservation_counts_before_settle(b):
    """Money in flight is money you cannot spend twice — the whole point of
    reserving BEFORE the effect instead of recording after."""
    b.set_limit("cust:3", limit=100, window_sec=3600)
    r = b.reserve("cust:3", 80)               # in flight, not settled
    with pytest.raises(BudgetExceeded):
        b.reserve("cust:3", 30)
    r.settle()


def test_context_manager_releases_on_failure(b):
    b.set_limit("cust:4", limit=100, window_sec=3600)
    try:
        with b.reserve("cust:4", 100):
            raise RuntimeError("provider refused")
    except RuntimeError:
        pass
    assert b.remaining("cust:4") == 100


# ── THE ONE THAT MATTERS ───────────────────────────────────────────────────

def test_concurrent_reserves_never_breach_the_ceiling(b):
    """40 concurrent callers, each from its OWN Seal connection, racing one
    budget. An in-memory limiter gives each its own ceiling and lets them all
    through. Enforced in the store, exactly 10 of 40 can win."""
    b.set_limit("cust:race", limit=100, window_sec=3600)
    N, AMOUNT = 40, 10          # only 10 should fit
    barrier = threading.Barrier(N)
    granted, refused = [], []
    lock = threading.Lock()

    def racer():
        bud = Budget(Seal(DSN))
        barrier.wait()
        try:
            r = bud.reserve("cust:race", AMOUNT)
            r.settle()
            with lock:
                granted.append(1)
        except BudgetExceeded:
            with lock:
                refused.append(1)

    ts = [threading.Thread(target=racer) for _ in range(N)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    assert len(granted) == 10, f"expected exactly 10 grants, got {len(granted)}"
    assert len(refused) == N - 10
    assert b.spent("cust:race") == 100        # never a penny over
    assert b.remaining("cust:race") == 0


def test_budgets_are_independent(b):
    b.set_limit("cust:a", limit=50, window_sec=3600)
    b.set_limit("cust:b", limit=50, window_sec=3600)
    b.reserve("cust:a", 50).settle()
    b.reserve("cust:b", 50).settle()          # unaffected by a's exhaustion
    assert b.remaining("cust:a") == 0 and b.remaining("cust:b") == 0
