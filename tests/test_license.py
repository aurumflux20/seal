"""Earned autonomy — tests that attack the ladder.

The dangerous failure is not refusing autonomy to a good agent. It is granting
unattended money authority to one that has not earned it, or leaving a licence
standing after money moved behind the gateway's back. Every test below exists
because that direction of error is the one that costs somebody real money.
"""
from __future__ import annotations

import itertools
import os
import time

import psycopg
import pytest

from seal import Seal
from seal.license import L0, L1, L2, L3, LicenceEngine
from seal.reconcile import CallableLister, ProviderEffect, Reconciler
from seal.witness import CONFIRMED_ONE, CallableWitness, WitnessResult

DSN = os.environ.get("SEAL_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="SEAL_DSN not set")

PATH = "charge"


@pytest.fixture()
def seal():
    s = Seal(DSN)
    s.setup()
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        c.execute("TRUNCATE seal_intents, seal_certs, seal_domains, seal_graphs, "
                  "seal_graph_children, seal_clearance, seal_proof, seal_events, "
                  "seal_thresholds, seal_approvals, seal_approval_votes, seal_tickets "
                  "RESTART IDENTITY")
    return s


_SEQ = itertools.count()


def _confirmed_effect(seal, n: int, path: str = PATH) -> None:
    """Settle n effects and have the provider confirm each one.

    Keys must be unique across calls: a repeated key is correctly deduped by
    Seal into a replay with no fence, which is the library working, not a
    fixture we may reuse carelessly.
    """
    for _ in range(n):
        i = next(_SEQ)
        adm = seal.admit("charge", {"amount": 100 + i}, key=f"k-{path}-{i}",
                         domain=path)
        seal.seal(adm.intent, adm.fence, {"charged": 100 + i})
        seal.witness(adm.intent, CallableWitness(
            lambda intent: WitnessResult(CONFIRMED_ONE, count=1, evidence="ok")))


def _clean_sweep(seal) -> None:
    Reconciler(seal).sweep(CallableLister(lambda a, b: []), since=time.time() - 60)


def test_a_fresh_path_has_no_autonomy(seal):
    lic = LicenceEngine(seal).evaluate(PATH)
    assert lic.level == L0
    assert lic.unattended is False


def test_autonomy_is_earned_not_assigned(seal):
    eng = LicenceEngine(seal)
    _confirmed_effect(seal, 1)
    assert eng.evaluate(PATH).level == L1
    _confirmed_effect(seal, 9)          # 10 total
    assert eng.evaluate(PATH).level == L2


def test_unattended_spend_requires_a_clean_sweep(seal):
    """L3 is where the human stops clicking. It must not be reachable on
    volume alone — the gateway has to have proved nothing moved behind it."""
    eng = LicenceEngine(seal)
    _confirmed_effect(seal, 50)
    assert eng.evaluate(PATH).level == L2      # volume alone is not enough
    assert eng.evaluate(PATH).unattended is False
    _clean_sweep(seal)
    lic = eng.evaluate(PATH)
    assert lic.level == L3
    assert lic.unattended is True


def test_locally_sealed_but_unconfirmed_spend_does_not_climb(seal):
    """A local success is a claim. Only the provider agreeing is evidence."""
    for i in range(20):
        adm = seal.admit("charge", {"amount": 10 + i}, key=f"u-{i}", domain=PATH)
        seal.seal(adm.intent, adm.fence, {"charged": 10 + i})   # never witnessed
    _clean_sweep(seal)
    lic = LicenceEngine(seal).evaluate(PATH)
    assert lic.confirmed == 0
    assert lic.level == L1          # cannot pass the L2 confirmation ratio
    assert lic.unattended is False


def test_out_of_band_spend_suspends_the_licence_instantly(seal):
    """The whole point. A licence earned over 50 settlements is gone the moment
    money moves without passing the gateway."""
    eng = LicenceEngine(seal)
    _confirmed_effect(seal, 50)
    _clean_sweep(seal)
    assert eng.evaluate(PATH).unattended is True

    Reconciler(seal).sweep(
        CallableLister(lambda a, b: [ProviderEffect(id="pi_rogue", amount=25000)]),
        since=time.time() - 60, freeze_domain=PATH,
    )

    lic = eng.evaluate(PATH)
    assert lic.suspended is True
    assert lic.level == L0
    assert lic.unattended is False
    assert "out_of_band_spend" in lic.suspended_reason


def test_suspension_survives_more_good_behaviour(seal):
    """A breach is not served by waiting it out, and not washed off by volume."""
    eng = LicenceEngine(seal)
    _confirmed_effect(seal, 50)
    _clean_sweep(seal)
    Reconciler(seal).sweep(
        CallableLister(lambda a, b: [ProviderEffect(id="pi_rogue", amount=999)]),
        since=time.time() - 60, freeze_domain=PATH,
    )
    # The domain is frozen, so the path cannot even transact again — good.
    with pytest.raises(Exception):
        _confirmed_effect(seal, 1)
    # And clean sweeps afterwards do not wash the breach off the record.
    _clean_sweep(seal)
    _clean_sweep(seal)
    assert eng.evaluate(PATH).suspended is True


def test_requires_human_answers_the_operators_real_question(seal):
    eng = LicenceEngine(seal)
    d = eng.requires_human(PATH, 5000)
    assert d["human_required"] is True
    _confirmed_effect(seal, 50)
    _clean_sweep(seal)
    d = eng.requires_human(PATH, 5000)
    assert d["human_required"] is False
    assert d["level"] == L3


def test_a_licence_reports_what_it_still_needs(seal):
    _confirmed_effect(seal, 1)
    lic = LicenceEngine(seal).evaluate(PATH)
    assert lic.next_level == L2
    assert any("more world-confirmed" in n for n in lic.needs)


def test_one_paths_breach_does_not_revoke_an_unrelated_path(seal):
    eng = LicenceEngine(seal)
    _confirmed_effect(seal, 50, path="payout")
    _clean_sweep(seal)
    Reconciler(seal).sweep(
        CallableLister(lambda a, b: [ProviderEffect(id="pi_rogue", amount=1)]),
        since=time.time() - 60, freeze_domain="charge",
    )
    assert eng.evaluate("payout").suspended is False
    assert eng.evaluate("charge").suspended is True
