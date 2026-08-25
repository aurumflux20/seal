"""Seal test suite. Mostly attacks — the suite's job is to break the property.

Needs a real Postgres (SEAL_DSN). Exactly-once across processes cannot be
proven against a mock: the whole claim is that the store arbitrates, so the
store must be present. CI provides one; locally, see README "Running the proof".
"""
from __future__ import annotations

import json
import os
import threading
import time

import psycopg
import pytest

from seal import Seal, intent_id

DSN = os.environ.get("SEAL_DSN")
pytestmark = pytest.mark.skipif(
    not DSN, reason="SEAL_DSN not set — these tests require a real Postgres"
)


@pytest.fixture()
def seal() -> Seal:
    s = Seal(DSN, lease_sec=30.0)
    s.setup()
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        # RESTART IDENTITY so BIGSERIAL seq resets to 1 between tests — the
        # ledger-tamper tests address certs by absolute seq, and a climbing
        # serial would make them poke at rows that don't exist.
        c.execute("TRUNCATE seal_intents, seal_certs RESTART IDENTITY")
    return s


# ── the property itself ────────────────────────────────────────────────────

def test_second_caller_replays_not_reruns(seal: Seal):
    a1 = seal.admit("charge", {"order": 1})
    assert a1.fresh
    cert = seal.seal(a1.intent, a1.fence, {"charged": 4900})

    a2 = seal.admit("charge", {"order": 1})
    assert not a2.fresh
    assert a2.cert is not None and a2.cert["hash"] == cert["hash"]


def test_different_args_are_different_intents(seal: Seal):
    a1 = seal.admit("charge", {"order": 1})
    a2 = seal.admit("charge", {"order": 2})
    assert a1.fresh and a2.fresh
    assert a1.intent != a2.intent


def test_storm_50_concurrent_one_execution(seal: Seal):
    executed = {"n": 0}
    lock = threading.Lock()
    barrier = threading.Barrier(50)
    outcomes: list[str] = []

    def racer():
        barrier.wait()
        adm = Seal(DSN).admit("charge", {"order": "storm"})
        if adm.fresh:
            with lock:
                executed["n"] += 1
            time.sleep(0.01)
            Seal(DSN).seal(adm.intent, adm.fence, {"ok": True})
            r = "fresh"
        else:
            r = "loser"
        with lock:
            outcomes.append(r)

    ts = [threading.Thread(target=racer) for _ in range(50)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    assert executed["n"] == 1
    assert outcomes.count("fresh") == 1
    assert outcomes.count("loser") == 49


# ── authority attacks ──────────────────────────────────────────────────────

def test_wrong_fence_cannot_seal(seal: Seal):
    a = seal.admit("charge", {"order": 3})
    with pytest.raises(PermissionError):
        seal.seal(a.intent, "not-the-fence", {"forged": True})


def test_cannot_seal_twice(seal: Seal):
    a = seal.admit("charge", {"order": 4})
    seal.seal(a.intent, a.fence, {"ok": 1})
    with pytest.raises(PermissionError):
        seal.seal(a.intent, a.fence, {"ok": 2})


def test_fail_releases_for_legitimate_retry(seal: Seal):
    a1 = seal.admit("charge", {"order": 5})
    seal.fail(a1.intent, a1.fence, "provider 503, nothing sent")
    a2 = seal.admit("charge", {"order": 5})
    assert a2.fresh  # the effect never ran; retrying it must be allowed


def test_dead_lease_is_reclaimed(seal: Seal):
    fast = Seal(DSN, lease_sec=0.05)
    fast.setup()
    a1 = fast.admit("charge", {"order": 6})
    assert a1.fresh
    time.sleep(0.1)  # holder "crashed" — lease expires
    a2 = fast.admit("charge", {"order": 6})
    assert a2.fresh  # reclaimed
    # the zombie's old fence must no longer be able to seal
    with pytest.raises(PermissionError):
        fast.seal(a1.intent, a1.fence, {"zombie": True})


# ── ledger attacks: the auditor's guarantees ───────────────────────────────

def _sealed(seal: Seal, n: int):
    for i in range(n):
        a = seal.admit("charge", {"order": f"chain-{i}"})
        seal.seal(a.intent, a.fence, {"i": i})


def test_chain_verifies_clean(seal: Seal):
    _sealed(seal, 3)
    assert seal.verify_chain() == {"ok": True, "certs": 3, "signed": 0}


def test_edited_cert_breaks_chain(seal: Seal):
    _sealed(seal, 3)
    with psycopg.connect(DSN, autocommit=True) as c:
        body = c.execute("SELECT body FROM seal_certs WHERE seq=2").fetchone()[0]
        body["result_digest"] = "0" * 64  # rewrite history
        c.execute("UPDATE seal_certs SET body=%s WHERE seq=2", (json.dumps(body),))
    rep = seal.verify_chain()
    assert not rep["ok"] and rep["why"] == "cert altered since written"


def test_deleted_cert_breaks_chain(seal: Seal):
    _sealed(seal, 3)
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("DELETE FROM seal_certs WHERE seq=2")
    assert not seal.verify_chain()["ok"]


def test_rehashed_forgery_still_breaks_chain(seal: Seal):
    """The sophisticated attack: edit a cert AND recompute its hash locally.
    The next cert's prev_hash no longer matches, so the chain still breaks."""
    _sealed(seal, 3)
    from seal.core import _digest

    with psycopg.connect(DSN, autocommit=True) as c:
        body = c.execute("SELECT body FROM seal_certs WHERE seq=2").fetchone()[0]
        body["result_digest"] = "f" * 64
        core = {k: body[k] for k in ("intent", "args_digest", "result_digest", "world", "prev_hash", "at")}
        body["hash"] = _digest(core)
        c.execute(
            "UPDATE seal_certs SET body=%s, hash=%s WHERE seq=2",
            (json.dumps(body), body["hash"]),
        )
    assert not seal.verify_chain()["ok"]


# ── honesty boundary ───────────────────────────────────────────────────────

def test_cert_never_claims_world_settlement(seal: Seal):
    a = seal.admit("charge", {"order": 7})
    cert = seal.seal(a.intent, a.fence, {"ok": True})
    assert cert["world"] == "unconfirmed"


def test_intent_id_is_content_addressed():
    assert intent_id("charge", {"a": 1, "b": 2}) == intent_id("charge", {"b": 2, "a": 1})
    assert intent_id("charge", {"a": 1}) != intent_id("refund", {"a": 1})
