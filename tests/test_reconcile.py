"""Out-of-band spend detection — tests that attack the property.

The dangerous failure here is not missing a rogue charge. It is reporting a
breach as CLEAN. Every test below exists because that direction of error is the
one that gets someone robbed quietly.
"""
from __future__ import annotations

import os
import time

import psycopg
import pytest

from seal import Seal
from seal.reconcile import (
    CLEAN, OUT_OF_BAND, UNKNOWN,
    CallableLister, ProviderEffect, Reconciler,
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
                  "seal_thresholds, seal_approvals, seal_approval_votes, seal_tickets "
                  "RESTART IDENTITY")
    return s


def test_effect_we_admitted_is_matched_not_flagged(seal):
    adm = seal.admit("charge", {"amount": 500}, key="ok-1")
    now = time.time()
    lister = CallableLister(lambda a, b: [
        ProviderEffect(id="pi_1", amount=500, intent_tag=adm.intent),
    ])
    r = Reconciler(seal).sweep(lister, since=now - 60)
    assert r["verdict"] == CLEAN
    assert r["matched_our_certs"] == 1
    assert r["out_of_band"] == 0


def test_untagged_provider_charge_is_out_of_band(seal):
    """The whole point: money moved and the gateway never saw it."""
    now = time.time()
    lister = CallableLister(lambda a, b: [
        ProviderEffect(id="pi_rogue", amount=999_00, intent_tag=None),
    ])
    r = Reconciler(seal).sweep(lister, since=now - 60)
    assert r["verdict"] == OUT_OF_BAND
    assert r["out_of_band"] == 1
    assert r["out_of_band_amount"] == 999_00
    assert "pi_rogue" in r["out_of_band_ids"]


def test_tag_we_have_no_record_of_is_also_flagged(seal):
    """A seal tag from a store we don't own is not proof of admission."""
    now = time.time()
    lister = CallableLister(lambda a, b: [
        ProviderEffect(id="pi_x", amount=100, intent_tag="intent-from-somewhere-else"),
    ])
    r = Reconciler(seal).sweep(lister, since=now - 60)
    assert r["verdict"] == OUT_OF_BAND
    assert r["tagged_but_unknown_to_us"] == 1


def test_provider_failure_is_UNKNOWN_never_clean(seal):
    """The failure that would get someone robbed: a broken lookup read as 'all good'."""
    def boom(a, b):
        raise RuntimeError("stripe 500")
    r = Reconciler(seal).sweep(CallableLister(boom), since=time.time() - 60)
    assert r["verdict"] == UNKNOWN
    assert r["verdict"] != CLEAN
    assert "NOT a clean result" in r["reason"]


def test_empty_provider_answer_is_clean_but_a_raise_is_not(seal):
    """An answered-and-empty window IS clean; only a raise is UNKNOWN."""
    r = Reconciler(seal).sweep(CallableLister(lambda a, b: []), since=time.time() - 60)
    assert r["verdict"] == CLEAN
    assert r["provider_effects"] == 0


def test_admitted_but_unsealed_intent_still_counts_as_ours(seal):
    """STORM-PROOF #2: a lost seal must not make our own charge look rogue."""
    adm = seal.admit("charge", {"amount": 700}, key="unsealed-1")
    # deliberately do NOT seal it
    lister = CallableLister(lambda a, b: [
        ProviderEffect(id="pi_ours", amount=700, intent_tag=adm.intent),
    ])
    r = Reconciler(seal).sweep(lister, since=time.time() - 60)
    assert r["verdict"] == CLEAN, "an admitted-but-unsealed intent is still ours"


def test_detection_can_freeze_the_domain(seal):
    """Detection without a lever is just a nicer way to find out later."""
    now = time.time()
    lister = CallableLister(lambda a, b: [ProviderEffect(id="pi_bad", amount=50, intent_tag=None)])
    r = Reconciler(seal).sweep(lister, since=now - 60, freeze_domain="customer:42")
    assert r["verdict"] == OUT_OF_BAND
    assert r.get("domain_frozen") == "customer:42"

    from seal.core import DomainFrozen
    with pytest.raises(DomainFrozen):
        seal.admit("charge", {"amount": 1}, key="after-freeze", domain="customer:42")


def test_out_of_band_is_recorded_as_an_event(seal):
    lister = CallableLister(lambda a, b: [ProviderEffect(id="pi_e", amount=10, intent_tag=None)])
    Reconciler(seal).sweep(lister, since=time.time() - 60)
    with seal._connect(autocommit=True) as c:
        row = c.execute(
            "SELECT detail FROM seal_events WHERE kind='out_of_band_spend'"
        ).fetchone()
    assert row is not None, "a breach that is not recorded cannot reach a report"
    assert row[0]["count"] == 1


def test_breach_reaches_the_report_a_buyer_reads(seal):
    """A breach recorded but absent from the Range Report is a breach nobody reads."""
    from seal.clearance import Clearance
    lister = CallableLister(lambda a, b: [
        ProviderEffect(id="pi_r1", amount=2500, intent_tag=None),
        ProviderEffect(id="pi_r2", amount=1500, intent_tag=None),
    ])
    Reconciler(seal).sweep(lister, since=time.time() - 60)

    rep = Clearance(seal).range_report()
    oob = rep["out_of_band_spend"]
    assert oob["incidents"] == 1
    assert oob["effects"] == 2
    assert oob["amount"] == 4000


def test_unreadable_sweep_shows_in_the_report_too(seal):
    """A month of failed reconciliation must not look identical to a clean one."""
    from seal.clearance import Clearance
    def boom(a, b):
        raise RuntimeError("provider down")
    Reconciler(seal).sweep(CallableLister(boom), since=time.time() - 60)

    rep = Clearance(seal).range_report()
    assert rep["out_of_band_spend"]["unreadable_sweeps"] == 1
    assert rep["out_of_band_spend"]["incidents"] == 0
