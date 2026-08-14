"""Agent Authorization Receipt — tests for the document a dispute actually
reads, not just the JSON an auditor already trusts.

The dangerous failure here is a receipt that reads as clean when it isn't.
Every status-derivation test exists because that direction of error is the
one that gets a real dispute lost.
"""
from __future__ import annotations

import os
import time

import psycopg
import pytest

from seal import Seal
from seal.authority import Gateway
from seal.clearance import CLEARED, Clearance
from seal.graduated import APPROVE, REJECT, GraduatedClearance
from seal.receipt import (
    ALLOWED_ONCE, ALLOWED_ONCE_WORLD_UNKNOWN, BLOCKED, DIVERGED, OFF_RAIL,
    Receipt, ReceiptError,
)
from seal.reconcile import CallableLister, ProviderEffect, Reconciler
from seal.witness import CallableWitness, WitnessResult, CONFIRMED_ONE, MULTIPLE, UNKNOWN as W_UNKNOWN

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


# ── the free sample ──────────────────────────────────────────────────────
def test_sample_is_clearly_labelled_and_needs_no_database():
    r = Receipt.sample()
    assert r["SAMPLE"] is True
    assert "fabricated" in r["sample_notice"].lower()
    assert r["status"] == ALLOWED_ONCE
    for block in ("allowed", "once", "world_id", "off_rail_check"):
        assert block in r


def test_sample_never_claims_to_be_real():
    r = Receipt.sample()
    assert "SAMPLE" in r and r["SAMPLE"] is True
    # a downstream reader keying off SAMPLE cannot mistake it for real evidence
    assert r.get("receipt_id", "").startswith("sample_")


# ── unknown intent ───────────────────────────────────────────────────────
def test_unknown_intent_raises_rather_than_fabricating(seal):
    with pytest.raises(ReceiptError):
        Receipt(seal).build("no-such-intent")


# ── ALLOWED block ─────────────────────────────────────────────────────────
def test_auto_tier_shows_no_human_signoff_required(seal):
    adm = seal.admit("charge", {"amount": 50}, key="auto-1")
    seal.seal(adm.intent, adm.fence, {"ok": True})
    r = Receipt(seal).build(adm.intent)
    assert "no human sign-off" in r["allowed"]["note"].lower()


def test_dual_tier_lists_the_actual_approvers_and_blocks_self_approval(seal):
    gc = GraduatedClearance(seal, gov_key=b"fixed-test-key")
    gc.set_thresholds("charge", auto_ceiling=100, dual_ceiling=10_000, required_approvers=2)
    adm = seal.admit("charge", {"amount": 5000}, key="dual-1")
    req = gc.request("charge", 5000, maker="agent:x", intent=adm.intent)
    gc.add_vote(req["id"], "dana@finance", APPROVE)
    gc.add_vote(req["id"], "sam@ops", APPROVE)
    seal.seal(adm.intent, adm.fence, {"ok": True})

    r = Receipt(seal).build(adm.intent)
    a = r["allowed"]
    assert set(a["approved_by"]) == {"dana@finance", "sam@ops"}
    assert a["self_approval_blocked"] is True
    assert a["requested_by"] == "agent:x"


# ── ONCE block ────────────────────────────────────────────────────────────
def test_once_block_reflects_a_verified_chain(seal):
    adm = seal.admit("charge", {"amount": 10}, key="once-1")
    cert = seal.seal(adm.intent, adm.fence, {"ok": True})
    r = Receipt(seal).build(adm.intent)
    assert r["once"]["executed"] is True
    assert r["once"]["cert_hash"] == cert["hash"]
    assert r["once"]["chain_verified"] is True


# ── STATUS derivation — the part that must never lean toward false-clean ──
def test_blocked_when_never_executed(seal):
    adm = seal.admit("charge", {"amount": 10}, key="blocked-1")
    # deliberately never sealed
    r = Receipt(seal).build(adm.intent)
    assert r["status"] == BLOCKED


def test_allowed_once_when_world_confirms(seal):
    adm = seal.admit("charge", {"amount": 10}, key="clean-1")
    seal.seal(adm.intent, adm.fence, {"ok": True})
    w = CallableWitness(lambda rec: WitnessResult(CONFIRMED_ONE, count=1))
    seal.witness(adm.intent, w)
    r = Receipt(seal).build(adm.intent)
    assert r["status"] == ALLOWED_ONCE
    assert r["world_id"]["state"] == "WORLD_FINAL"


def test_world_unknown_never_reported_as_clean(seal):
    adm = seal.admit("charge", {"amount": 10}, key="unk-1")
    seal.seal(adm.intent, adm.fence, {"ok": True})
    w = CallableWitness(lambda rec: WitnessResult(W_UNKNOWN))
    seal.witness(adm.intent, w)
    r = Receipt(seal).build(adm.intent)
    assert r["status"] == ALLOWED_ONCE_WORLD_UNKNOWN
    assert r["status"] != ALLOWED_ONCE


def test_diverged_status_when_world_contradicts_ledger(seal):
    adm = seal.admit("charge", {"amount": 10}, key="div-1", domain="cust:99")
    seal.seal(adm.intent, adm.fence, {"ok": True})
    w = CallableWitness(lambda rec: WitnessResult(MULTIPLE, count=2))
    seal.witness(adm.intent, w)
    r = Receipt(seal).build(adm.intent)
    assert r["status"] == DIVERGED


def test_off_rail_status_when_reconciler_found_a_breach_on_same_domain(seal):
    adm = seal.admit("charge", {"amount": 10}, key="oob-1", domain="cust:7")
    seal.seal(adm.intent, adm.fence, {"ok": True})
    w = CallableWitness(lambda rec: WitnessResult(CONFIRMED_ONE, count=1))
    seal.witness(adm.intent, w)

    lister = CallableLister(lambda a, b: [ProviderEffect(id="pi_rogue", amount=999, intent_tag=None)])
    Reconciler(seal).sweep(lister, since=time.time() - 60, freeze_domain="cust:7")

    r = Receipt(seal).build(adm.intent)
    assert r["status"] == OFF_RAIL
    assert r["off_rail_check"]["domain_matched"] == 1


def test_off_rail_on_a_DIFFERENT_domain_does_not_taint_this_receipt(seal):
    """A breach on someone else's domain must not make an unrelated receipt
    look compromised — that would make every receipt worthless the moment
    ANY breach occurs anywhere."""
    adm = seal.admit("charge", {"amount": 10}, key="safe-1", domain="cust:1")
    seal.seal(adm.intent, adm.fence, {"ok": True})
    w = CallableWitness(lambda rec: WitnessResult(CONFIRMED_ONE, count=1))
    seal.witness(adm.intent, w)

    lister = CallableLister(lambda a, b: [ProviderEffect(id="pi_rogue", amount=999, intent_tag=None)])
    Reconciler(seal).sweep(lister, since=time.time() - 60, freeze_domain="cust:OTHER")

    r = Receipt(seal).build(adm.intent)
    assert r["status"] == ALLOWED_ONCE
    assert r["off_rail_check"]["domain_matched"] == 0


def test_unscoped_sweep_is_flagged_not_silently_dropped(seal):
    """An out-of-band event with no domain tag (older/global sweep) is
    surfaced for review rather than excluded — over-flagging is the safe
    failure direction here, the opposite of CLEAN/UNKNOWN."""
    adm = seal.admit("charge", {"amount": 10}, key="unscoped-1", domain="cust:5")
    seal.seal(adm.intent, adm.fence, {"ok": True})
    w = CallableWitness(lambda rec: WitnessResult(CONFIRMED_ONE, count=1))
    seal.witness(adm.intent, w)

    lister = CallableLister(lambda a, b: [ProviderEffect(id="pi_x", amount=1, intent_tag=None)])
    Reconciler(seal).sweep(lister, since=time.time() - 60)   # no freeze_domain -> unscoped

    r = Receipt(seal).build(adm.intent)
    assert r["off_rail_check"]["unscoped_in_window"] == 1
    assert "review" in r["off_rail_check"]["note"].lower()


def test_unreadable_reconciliation_in_window_is_UNKNOWN_not_clean(seal):
    adm = seal.admit("charge", {"amount": 10}, key="rd-1", domain="cust:2")
    seal.seal(adm.intent, adm.fence, {"ok": True})

    def boom(a, b):
        raise RuntimeError("provider down")
    Reconciler(seal).sweep(CallableLister(boom), since=time.time() - 60)

    r = Receipt(seal).build(adm.intent)
    assert r["off_rail_check"]["readable"] is False


# ── the receipt itself is tamper-evident ───────────────────────────────────
def test_receipt_carries_a_digest_over_its_own_content(seal):
    adm = seal.admit("charge", {"amount": 10}, key="dig-1")
    seal.seal(adm.intent, adm.fence, {"ok": True})
    r = Receipt(seal).build(adm.intent)
    assert "receipt_digest" in r and len(r["receipt_digest"]) > 20


# ── HTML rendering — the shareable artifact ──────────────────────────────
def test_sample_renders_to_self_contained_html():
    from seal.receipt import render_html
    html = render_html(Receipt.sample())
    assert html.startswith("<!DOCTYPE html>")
    # self-contained: nothing fetched over the network, or it breaks offline
    # and when emailed, and a proof document cannot depend on a third party
    for bad in ("http://", "https://cdn", "<script", "@import", "src="):
        assert bad not in html.lower().replace("github.com", ""), f"external/unsafe: {bad}"
    assert "Agent Authorization Receipt" in html


def test_render_escapes_html_so_a_receipt_cannot_be_forged_visually(seal):
    """Approver names and paths are attacker-influenced. If they render as raw
    HTML, someone could inject markup that makes a DIVERGED receipt LOOK clean
    — forging the exact document a dispute relies on."""
    from seal.receipt import render_html
    gc = GraduatedClearance(seal, gov_key=b"fixed-test-key")
    gc.set_thresholds("charge", auto_ceiling=100, dual_ceiling=10_000, required_approvers=2)
    adm = seal.admit("charge", {"amount": 5000}, key="xss-1")
    req = gc.request("charge", 5000, maker="agent:x", intent=adm.intent)
    gc.add_vote(req["id"], '<script>alert(1)</script>', APPROVE)
    gc.add_vote(req["id"], "sam@ops", APPROVE)
    seal.seal(adm.intent, adm.fence, {"ok": True})

    html = render_html(Receipt(seal).build(adm.intent))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_rendered_status_matches_the_receipt_status(seal):
    """The badge a human reads must never disagree with the machine status."""
    from seal.receipt import render_html
    adm = seal.admit("charge", {"amount": 10}, key="render-blocked")
    html = render_html(Receipt(seal).build(adm.intent))   # never sealed -> BLOCKED
    assert "BLOCKED" in html


def test_diverged_receipt_renders_as_diverged_not_clear(seal):
    from seal.receipt import render_html
    adm = seal.admit("charge", {"amount": 10}, key="render-div", domain="cust:9")
    seal.seal(adm.intent, adm.fence, {"ok": True})
    seal.witness(adm.intent, CallableWitness(lambda rec: WitnessResult(MULTIPLE, count=2)))
    html = render_html(Receipt(seal).build(adm.intent))
    assert "DIVERGED" in html
    assert "CLEAR" not in html


def test_sample_never_promises_fields_a_real_receipt_cannot_produce(seal):
    """A sample that advertises fields the product doesn't deliver is the same
    over-promise we report to other projects. Locks sample/real parity."""
    gc = GraduatedClearance(seal, gov_key=b"fixed-test-key")
    gc.set_thresholds("refund", auto_ceiling=100, dual_ceiling=10_000, required_approvers=2)
    adm = seal.admit("refund", {"amount": 4900}, key="parity-1", domain="cus_1")
    req = gc.request("refund", 4900, maker="agent:bot", intent=adm.intent)
    gc.add_vote(req["id"], "dana@finance", APPROVE)
    gc.add_vote(req["id"], "sam@ops", APPROVE)
    seal.seal(adm.intent, adm.fence, {"ok": True})
    seal.witness(adm.intent, CallableWitness(
        lambda r: WitnessResult(CONFIRMED_ONE, count=1, evidence={"ids": ["re_x"]})))

    real = Receipt(seal).build(adm.intent)
    sample = Receipt.sample()
    ignore_top = {"SAMPLE", "sample_notice"}
    assert not (set(sample) - set(real) - ignore_top), \
        f"sample promises top-level fields real lacks: {set(sample)-set(real)-ignore_top}"
    for blk in ("action", "allowed", "once", "world_id", "off_rail_check"):
        missing = set(sample.get(blk, {})) - set(real.get(blk, {}))
        assert not missing, f"sample.{blk} promises fields real lacks: {sorted(missing)}"


def test_real_receipt_carries_amount_and_execution_time(seal):
    """A dispute document about money must show the amount and when it ran."""
    gc = GraduatedClearance(seal, gov_key=b"fixed-test-key")
    gc.set_thresholds("refund", auto_ceiling=100, dual_ceiling=10_000, required_approvers=2)
    adm = seal.admit("refund", {"amount": 4900}, key="amt-1", domain="cus_2")
    req = gc.request("refund", 4900, maker="agent:bot", intent=adm.intent)
    gc.add_vote(req["id"], "dana@finance", APPROVE)
    gc.add_vote(req["id"], "sam@ops", APPROVE)
    seal.seal(adm.intent, adm.fence, {"ok": True})

    r = Receipt(seal).build(adm.intent)
    assert r["action"]["amount"] == 4900
    assert r["once"]["executed_at"] is not None
    assert r["once"]["chain_position"] is not None
    assert "4,900.00" in r["summary"]


def test_auto_tier_omits_amount_rather_than_guessing(seal):
    """No amount is stored for AUTO-tier intents. Omit it; never invent one."""
    adm = seal.admit("charge", {"amount": 50}, key="auto-amt")
    seal.seal(adm.intent, adm.fence, {"ok": True})
    r = Receipt(seal).build(adm.intent)
    assert r["action"]["amount"] is None


def test_checked_at_absent_until_a_witness_actually_ran(seal):
    """Dating a provider check that never happened would imply confirmation."""
    adm = seal.admit("charge", {"amount": 10}, key="nocheck-1")
    seal.seal(adm.intent, adm.fence, {"ok": True})
    r = Receipt(seal).build(adm.intent)
    assert r["world_id"]["checked_at"] is None


# ── Mandate integration ──────────────────────────────────────────────────
def test_receipt_shows_on_rail_when_a_mandate_covers_this_intent(seal):
    from seal.authority import Gateway
    from seal.mandate import Mandates
    Clearance(seal).set_policy("charge", CLEARED)
    Clearance(seal).record_proof("charge", green=True)
    gw = Gateway(seal, ticket_key=b"k")
    gw.register_executor("charge", lambda a: {"paid": a["amount"]})

    prop = gw.propose("charge", {"amount": 50}, key="rcpt-mand-1", amount=50)
    gw.execute(prop["ticket"], {"amount": 50})

    r = Receipt(seal).build(prop["intent"])
    assert r["allowed"]["on_rail"] is True
    assert r["allowed"]["mandate_id"] == prop["mandate_id"]


def test_receipt_shows_off_rail_when_no_mandate_exists(seal):
    """An intent admitted with bare admit() (no path under Mandate) still gets
    a receipt — it just honestly reports it was not on-rail."""
    adm = seal.admit("charge", {"amount": 10}, key="rcpt-nomand-1")
    seal.seal(adm.intent, adm.fence, {"ok": True})
    r = Receipt(seal).build(adm.intent)
    assert r["allowed"]["on_rail"] is False
    assert r["allowed"]["mandate_id"] is None
    assert "No Mandate is on record" in r["allowed"]["note"]
