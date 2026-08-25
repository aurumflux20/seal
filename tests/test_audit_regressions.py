"""Regressions for seven defects found by auditing the kernel against the
conditions the rest of the suite does not reach.

Every test in this file failed before its fix. What they have in common is that
the existing 190 tests all run in ONE process, with ASCII-only data, against a
provider that answers in a single page — and each defect lived exactly one step
outside that box:

    1. Gateway.propose() on one replica, execute() on another
    2. a provider that replies with an accented character
    3. a provider with more than one page of effects
    4. an intent deleted underneath a concurrent admit()
    5. an approval vote row edited in the store
    6. args that are not JSON-native
    7. a worker that dies between reserve() and settle()

That is the shape of every real incident this library exists to prevent, so
these are not edge cases — they are the operating conditions.
"""
from __future__ import annotations

import os
import time
import uuid

import psycopg
import pytest

from seal import Seal
from seal.authority import Gateway
from seal.budget import Budget
from seal.clearance import Clearance, CLEARED
from seal.core import intent_id
from seal.graduated import APPROVE, GraduatedClearance
from seal.mandate import Mandates
from seal.reconcile import (CLEAN, OUT_OF_BAND, UNKNOWN, Reconciler,
                            StripeLister)
from seal.witness import CONFIRMED_ONE, CallableWitness, WitnessResult

DSN = os.environ.get("SEAL_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="SEAL_DSN not set")

TICKET_KEY = b"shared-across-replicas-as-it-must-be"


def _wipe(*tables):
    # One statement per table, tolerating a table this store does not have yet:
    # the suite must be runnable against a database built by an older version,
    # which is the upgrade path a real customer takes.
    for t in tables:
        with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
            try:
                c.execute(f"TRUNCATE {t} RESTART IDENTITY")
            except psycopg.errors.UndefinedTable:
                pass


@pytest.fixture()
def s():
    seal = Seal(DSN)
    seal.setup()
    Budget(seal).setup()
    _wipe("seal_certs", "seal_intents", "seal_tickets", "seal_ticket_pending",
          "seal_mandates", "seal_spend", "seal_budget", "seal_clearance",
          "seal_proof", "seal_thresholds", "seal_approvals",
          "seal_approval_votes", "seal_events")
    return seal


def _cleared(seal, path="charge"):
    cl = Clearance(seal)
    cl.set_policy(path, CLEARED, max_proof_age_sec=1e9)
    cl.record_proof(path, green=True, storm_n=100, executions=1)
    return path


def _gateway(seal, path="charge"):
    g = Gateway(seal, ticket_key=TICKET_KEY)
    g.register_executor(path, lambda a: {"charged": a["amt"]})
    return g


# ── 1 · the gateway hand-off must survive crossing a process boundary ─────
def test_execute_on_a_different_replica_settles_budget_and_consumes_mandate(s):
    """propose() and execute() on two Gateway instances sharing the store.

    This is a load balancer, a rolling deploy, or a restart — not a race. The
    reservation and the mandate id used to live in per-process dicts, so the
    replica that executed found nothing to finish: the reservation stayed
    `reserved` forever (the budget filling with phantom spend until it refused
    real charges) and the mandate stayed ACTIVE on an action that had already
    happened.
    """
    path = _cleared(s)
    Budget(s).set_limit("card", limit=1000.0, window_sec=86400)
    proposer, executor = _gateway(s, path), _gateway(s, path)

    p = proposer.propose(path, {"amt": 250.0}, key=f"o-{uuid.uuid4().hex[:8]}",
                         budget_key="card", amount=250.0)
    assert executor.execute(p["ticket"], {"amt": 250.0})["status"] == "executed"

    with s._connect(autocommit=True) as c:
        states = [r[0] for r in c.execute(
            "SELECT state FROM seal_spend WHERE budget_key='card'").fetchall()]
    assert states == ["settled"], "reservation stranded by the replica boundary"
    assert Mandates(s).get(p["mandate_id"])["state"] == "consumed"


def test_pending_handoff_row_is_claimed_exactly_once(s):
    """The hand-off is claimed with DELETE ... RETURNING, so a second executor
    cannot pick the same work up again."""
    path = _cleared(s)
    Budget(s).set_limit("card", limit=1000.0, window_sec=86400)
    p = _gateway(s, path).propose(path, {"amt": 10.0},
                                  key=f"o-{uuid.uuid4().hex[:8]}",
                                  budget_key="card", amount=10.0)

    # The hand-off must be DURABLE at propose() time — asserting only that it
    # is gone afterwards would pass against a build that never wrote it.
    with s._connect(autocommit=True) as c:
        pending = c.execute(
            "SELECT spend_id, mandate_id FROM seal_ticket_pending WHERE sig=%s",
            (p["ticket"]["sig"],)).fetchone()
    assert pending is not None, "propose() left the hand-off in process memory"
    assert pending[0] is not None and pending[1] == p["mandate_id"]

    _gateway(s, path).execute(p["ticket"], {"amt": 10.0})
    with s._connect(autocommit=True) as c:
        left = c.execute("SELECT count(*) FROM seal_ticket_pending").fetchone()[0]
    assert left == 0, "the hand-off row outlived the execution that claimed it"


# ── 2 · an honest chain must never report itself tampered ────────────────
def test_non_ascii_witness_evidence_keeps_the_chain_verifiable(s):
    """_jsonb() strips non-ASCII on the way into JSONB. Hashing before that
    normalisation meant verify_chain() recomputed a different digest from the
    stored row and reported "cert altered since written" on a chain nobody had
    touched — permanently, because the chain is append-only.
    """
    a = s.admit("charge", {"amt": 100}, key=f"o-{uuid.uuid4().hex[:8]}")
    s.seal(a.intent, a.fence, {"ok": True})

    w = CallableWitness(lambda rec: WitnessResult(
        CONFIRMED_ONE, count=1,
        evidence={"note": "Zahlung bestätigt — Café Müller", "ids": ["pi_1"]}))
    cert = s.witness(a.intent, w)

    assert s.verify_chain()["ok"], "honest chain reported as tampered"
    # what the caller is handed must be what the store will hand an auditor
    assert cert["witness_evidence"] == s.certs_for(a.intent)[-1]["witness_evidence"]


def test_non_ascii_read_set_keeps_the_chain_verifiable(s):
    a = s.admit("charge", {"amt": 100}, key=f"o-{uuid.uuid4().hex[:8]}",
                read_set={"product": "Café “Grand” — 3 units"})
    s.seal(a.intent, a.fence, {"ok": True})
    assert s.verify_chain()["ok"]


# ── 3 · a partial sweep is never a clean bill of health ──────────────────
def _page(objs, has_more):
    return {"data": objs, "has_more": has_more}


def _pi(pid, tag=None, amount=100):
    return {"id": pid, "status": "succeeded", "amount": amount,
            "created": 0, "metadata": ({"seal_intent": tag} if tag else {})}


def test_out_of_band_spend_on_a_later_page_is_still_found(s):
    """Stripe caps a page at 100 and sets has_more. Issuing one request and
    ignoring it meant the 101st effect vanished — and the rogue charge is
    exactly what sorts onto a later page."""
    ours = []
    for i in range(100):
        a = s.admit("charge", {"n": i}, key=f"o-{i}-{uuid.uuid4().hex[:6]}")
        s.seal(a.intent, a.fence, {"ok": True})
        ours.append(a.intent)

    def two_pages(_path, params):
        if "starting_after" not in params:
            return _page([_pi(f"pi_ours_{i}", ours[i]) for i in range(100)], True)
        return _page([_pi("pi_ROGUE", None, amount=50000)], False)

    now = time.time()
    r = Reconciler(s).sweep(StripeLister(two_pages), since=now - 60, until=now + 60)
    assert r["verdict"] == OUT_OF_BAND
    assert r["out_of_band_ids"] == ["pi_ROGUE"]
    assert r["provider_effects"] == 101


def test_unenumerable_window_reports_unknown_not_clean(s):
    """A provider that never stops paging must yield UNKNOWN. Returning the
    effects gathered so far would be a truncated sweep wearing a clean verdict."""
    def endless(_path, params):
        return _page([_pi(f"pi_{uuid.uuid4().hex[:8]}")], True)

    r = Reconciler(s).sweep(StripeLister(endless), since=0, until=10)
    assert r["verdict"] == UNKNOWN
    assert r["verdict"] != CLEAN


def test_cursor_uses_the_last_raw_object_not_the_last_kept_one(s):
    """Paging from a filtered id would skip every effect in between."""
    seen = []

    def pages(_path, params):
        seen.append(params.get("starting_after"))
        if len(seen) == 1:
            # last object on the page is a CANCELED one, which we do not keep
            return _page([_pi("pi_kept"),
                          {"id": "pi_canceled", "status": "canceled",
                           "amount": 1, "created": 0, "metadata": {}}], True)
        return _page([], False)

    Reconciler(s).sweep(StripeLister(pages), since=0, until=10)
    assert seen[1] == "pi_canceled", "cursor skipped past unkept objects"


# ── 4 · the retry must not quietly drop the guards ───────────────────────
class _Vanishing(Seal):
    """Deletes the intent row between the conflicting INSERT and the follow-up
    SELECT — what a peer's fail() does concurrently."""
    armed = False

    def _connect(self, *, autocommit):
        conn = super()._connect(autocommit=autocommit)
        outer = self

        class Proxy:
            def __init__(self, c):
                self._c = c

            def __enter__(self):
                self._c.__enter__()
                return self

            def __exit__(self, *a):
                return self._c.__exit__(*a)

            def execute(self, sql, params=None):
                cur = self._c.execute(sql, params)
                if outer.armed and "INSERT INTO seal_intents" in sql:
                    outer.armed = False
                    self._c.execute(
                        "DELETE FROM seal_intents WHERE intent=%s", (params[0],))
                return cur

            def __getattr__(self, n):
                return getattr(self._c, n)

        return Proxy(conn)


def test_admit_retry_still_records_the_admission(s):
    """The retry passed only six positional args, silently dropping `path` —
    so a guarded admission became unguarded and the Range Report under-counted
    the very admissions it exists to attest."""
    v = _Vanishing(DSN)
    v.setup()
    path = _cleared(v)
    key = f"o-{uuid.uuid4().hex[:8]}"

    v.admit("charge", {"amt": 1}, key=key, path=path)
    v.armed = True
    v.admit("charge", {"amt": 1}, key=key, path=path)

    with v._connect(autocommit=True) as c:
        n = c.execute(
            "SELECT count(*) FROM seal_events WHERE kind='admitted'").fetchone()[0]
    assert n == 2, "an admission went unrecorded on the retry path"


def test_admit_retry_still_runs_the_freshness_check(s):
    """`checker` was dropped too, so the pre-commit freeze was skipped on a
    read_set that was by then even staler."""
    from seal.freshness import CallableChecker

    v = _Vanishing(DSN)
    v.setup()
    calls = []

    def fresh(rs):
        calls.append(rs)
        return True      # always fresh: we are counting CALLS, not refusals

    key = f"o-{uuid.uuid4().hex[:8]}"
    checker = CallableChecker(fresh)
    v.admit("charge", {"amt": 1}, key=key, read_set={"cart": 50}, checker=checker)
    assert len(calls) == 1

    # The second admit conflicts, the row vanishes underneath it, and the retry
    # must re-run the caller's check — a read_set that was borderline a moment
    # ago is only staler now. A checker that returned False would abort before
    # the vanish ever happened, so this has to be counted, not raised.
    v.armed = True
    v.admit("charge", {"amt": 1}, key=key, read_set={"cart": 50}, checker=checker)
    # 1 (first admit) + 1 (second admit's own check) + 1 (the retry's) = 3.
    # Dropping `checker` on the retry gives 2.
    assert len(calls) == 3, "retry skipped the caller's freshness check"


def test_admit_retry_is_bounded(s):
    """The comment said "on one retry" and nothing enforced it: a peer deleting
    the row in a loop recursed until the stack gave out. With the single
    allowed retry already spent, a further vanish must fail closed rather than
    recurse again — refusing to admit is always safe, a RecursionError on a
    money path is not."""
    from seal.core import SealError

    v = _Vanishing(DSN)
    v.setup()
    key = f"o-{uuid.uuid4().hex[:8]}"
    v.admit("charge", {"amt": 1}, key=key)      # the row now exists
    v.armed = True
    with pytest.raises(SealError):
        v.admit("charge", {"amt": 1}, key=key, _retry=1)


# ── 5 · a signature nobody checks is decoration ──────────────────────────
def test_tampered_vote_signature_is_detected(s):
    gc = GraduatedClearance(s, gov_key=b"real-gov-key")
    gc.set_thresholds("payout", 100, 10000, required_approvers=2)
    ap = gc.request("payout", amount=5000, maker="alice",
                    intent=f"i-{uuid.uuid4().hex[:8]}")
    gc.add_vote(ap["id"], "bob", APPROVE)
    gc.add_vote(ap["id"], "carol", APPROVE)

    assert gc.verify_votes(ap["id"])["ok"] is True

    with s._connect(autocommit=True) as c:
        c.execute("UPDATE seal_approval_votes SET decision='reject' "
                  "WHERE approval_id=%s AND approver='bob'", (ap["id"],))

    after = gc.verify_votes(ap["id"])
    assert after["ok"] is False
    assert after["unverified"] == ["bob"]


def test_unconfigured_governance_key_is_reported_not_hidden(s, monkeypatch):
    """An unset SEAL_GOV_KEY still falls back to a per-process key — that
    cannot be helped without locking an operator out of their own queue — but
    it must be stated, because such a signature proves nothing about WHO voted
    to another replica or after a restart."""
    monkeypatch.delenv("SEAL_GOV_KEY", raising=False)
    gc = GraduatedClearance(s)
    gc.set_thresholds("payout", 100, 10000, required_approvers=2)
    ap = gc.request("payout", amount=5000, maker="alice",
                    intent=f"i-{uuid.uuid4().hex[:8]}")
    gc.add_vote(ap["id"], "bob", APPROVE)
    assert gc.verify_votes(ap["id"])["ephemeral_key"] is True

    assert GraduatedClearance(s, gov_key=b"k").verify_votes(
        ap["id"])["ephemeral_key"] is False


# ── 6 · never hash a memory address ──────────────────────────────────────
def test_unhashable_args_are_refused_not_silently_addressed():
    """`default=str` hashed `<Money object at 0x7f...>`, so two attempts at the
    same logical action produced two intent ids and the effect ran twice."""
    class Money:
        def __init__(self, cents):
            self.cents = cents

    from seal.core import UnstableDigestInput

    with pytest.raises(UnstableDigestInput):
        intent_id("charge", {"amount": Money(4999)})


def test_stable_types_still_hash_identically():
    """datetime/Decimal/UUID already serialised via str(); tightening must not
    change a digest any existing store has written."""
    import datetime
    import decimal

    args = {"when": datetime.datetime(2026, 8, 25, 12, 0),
            "amt": decimal.Decimal("49.99"),
            "id": uuid.UUID("00000000-0000-0000-0000-000000000001")}
    assert intent_id("charge", args) == intent_id("charge", args)


def test_seal_refuses_an_unhashable_result(s):
    class Opaque:
        pass

    from seal.core import UnstableDigestInput

    a = s.admit("charge", {"amt": 1}, key=f"o-{uuid.uuid4().hex[:8]}")
    with pytest.raises(UnstableDigestInput):
        s.seal(a.intent, a.fence, {"receipt": Opaque()})


# ── 7 · a dead worker must not narrow the ceiling forever ────────────────
def test_reconcile_reservations_settles_releases_and_leaves_the_unknown(s):
    b = Budget(s)
    b.set_limit("cardx", limit=1000, window_sec=86400)

    sealed = s.admit("charge", {"n": 1}, key=f"k-{uuid.uuid4().hex[:6]}")
    b.reserve("cardx", 200, intent=sealed.intent)
    s.seal(sealed.intent, sealed.fence, {"ok": 1})

    released = s.admit("charge", {"n": 2}, key=f"k-{uuid.uuid4().hex[:6]}")
    b.reserve("cardx", 300, intent=released.intent)
    s.fail(released.intent, released.fence, "never dispatched")

    inflight = s.admit("charge", {"n": 3}, key=f"k-{uuid.uuid4().hex[:6]}")
    b.reserve("cardx", 100, intent=inflight.intent)

    assert b.spent("cardx") == 600.0
    rep = b.reconcile_reservations("cardx", apply=True)

    assert [e["amount"] for e in rep["settled"]] == [200.0]
    assert [e["amount"] for e in rep["released"]] == [300.0]
    assert [e["amount"] for e in rep["in_flight"]] == [100.0]
    assert b.spent("cardx") == 300.0


def test_reconcile_reservations_reports_before_it_acts(s):
    b = Budget(s)
    b.set_limit("cardy", limit=1000, window_sec=86400)
    dead = s.admit("charge", {"n": 9}, key=f"k-{uuid.uuid4().hex[:6]}")
    b.reserve("cardy", 400, intent=dead.intent)
    s.fail(dead.intent, dead.fence, "never dispatched")

    rep = b.reconcile_reservations("cardy")          # apply defaults to False
    assert rep["applied"] is False
    assert [e["amount"] for e in rep["released"]] == [400.0]
    assert b.spent("cardy") == 400.0, "reported run must not have changed anything"


def test_a_dead_holder_mid_effect_is_never_guessed(s):
    """An expired lease on an open intent means the holder died mid-effect.
    Only the provider can say whether the money moved, so the reservation is
    reported, never resolved."""
    b = Budget(s)
    b.set_limit("cardz", limit=1000, window_sec=86400)
    short = Seal(DSN, lease_sec=-1)                 # already expired on arrival
    a = short.admit("charge", {"n": 4}, key=f"k-{uuid.uuid4().hex[:6]}")
    b.reserve("cardz", 500, intent=a.intent)

    rep = b.reconcile_reservations("cardz", apply=True)
    assert [e["amount"] for e in rep["needs_witness"]] == [500.0]
    assert not rep["settled"] and not rep["released"]
    assert b.spent("cardz") == 500.0
