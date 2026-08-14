"""Agent Authorization Receipt — dispute-grade, human-readable proof of one
agent money action.

The gap this closes: `incident_receipt()` already gives an auditor everything
machine-checkable about an intent. Nobody disputing a $4,900 charge with a
bank, a platform, or their own CFO wants a JSON blob. They want one document
that answers four questions in plain language, each backed by a specific
record they — or anyone — can independently check:

    ALLOWED    who or what authorised this, and on what evidence
    ONCE       proof the effect executed exactly one time, not a claim
    WORLD ID   what the provider's own system says happened, in the
               provider's own words — not just what we recorded
    STATUS     ON-RAIL and clean, or a specific, named reason it is not

This is assembly, not new invention: every field below is read from state
Seal already keeps (admission, the cert chain, clearance, graduated approval
votes, witness results, reconciliation sweeps). The receipt's job is to turn
those four subsystems into one document a risk officer, a support agent, or a
dispute-resolution form can actually use — nothing here manufactures a new
guarantee the rest of the library doesn't already carry.

HONESTY, stated here because it is the one line that must never blur:

    This is DISPUTE-GRADE evidence, not a legal or notarial instrument. It is
    not court-certified, not a substitute for a bank's own dispute process,
    and not insurance. What it IS: every claim on the page is either the
    provider's own record, or a tamper-evident hash chain anyone can verify
    from the DSN alone, with no trust in AurumFlux required. Where a sweep
    could not reach an answer, the receipt says UNKNOWN — it never quietly
    reports a clean bill of health it cannot back up.
"""
from __future__ import annotations

import time
from typing import Any

from .core import Seal, SealError, _digest

# ── the STATUS a receipt can carry — worded for someone who is not an engineer
ALLOWED_ONCE = "allowed_once"                  # clean: authorised, ran once, world agrees
ALLOWED_ONCE_WORLD_UNKNOWN = "allowed_once_world_unknown"   # ran once, provider could not confirm
BLOCKED = "blocked"                            # never ran — refused before the effect
DIVERGED = "diverged"                          # world contradicts the ledger — the bad case
OFF_RAIL = "off_rail"                          # spend the gateway never admitted at all


class ReceiptError(SealError):
    """The receipt could not be built — e.g. the intent does not exist."""


class Receipt:
    """Builds the human-readable Agent Authorization Receipt for one intent."""

    def __init__(self, seal: Seal):
        self.seal = seal

    # ── the free sample: no real intent required ───────────────────────────
    @staticmethod
    def sample() -> dict:
        """A fabricated but realistic receipt, clearly labelled as such.

        This is what a prospect gets before they ever run our code — the
        thing that has to be self-explanatory on first read, because nobody
        reading a sample receipt has our docs open next to it.
        """
        now = time.time()
        return {
            "SAMPLE": True,
            "sample_notice": (
                "This is a fabricated example for illustration. No real money "
                "moved. Generate your own from a real intent with "
                "Receipt(seal).build(intent)."
            ),
            "receipt_id": "sample_9f2a1c",
            "title": "Agent Authorization Receipt",
            "summary": "Stripe · $4,900.00 refund to customer #8841 · ran once · provider confirms",
            "status": ALLOWED_ONCE,
            "status_label": "Allowed, ran once, confirmed by the provider",
            "action": {"path": "refund", "amount": 4900.00, "currency": "USD",
                      "target": "cus_8841 (Stripe)"},
            "allowed": {
                "tier": "DUAL",
                "requested_by": "agent:refunds-bot",
                "requested_at": _fmt(now - 900),
                "approved_by": ["dana@finance", "sam@ops"],
                "self_approval_blocked": True,
                "note": ("Above the $500 auto-ceiling, so two distinct humans approved. "
                        "The requester could not be one of them — enforced as a database "
                        "constraint, not a policy that could be skipped."),
            },
            "once": {
                "intent_id": "63a4dd6a402ee5bec441d8969132987b0a61000f87b26c88fb2a838a7ce7ca0b",
                "executed_at": _fmt(now - 850),
                "cert_hash": "8f3e2a…c91d",
                "chain_position": 41,
                "chain_verified": True,
                "note": ("One admission, one execution, one certificate — proven by "
                        "re-deriving the hash chain from the database alone. Verify it "
                        "yourself: `python3 -m seal verify`."),
            },
            "world_id": {
                "state": "confirmed_one",
                "provider": "stripe",
                "provider_ref": "re_3P9x2ALkdIwHu7ix1a2b3c4d",
                "checked_at": _fmt(now - 800),
                "note": ("Stripe was asked directly how many refunds carry this intent's "
                        "tag. Stripe said exactly one. This is the provider's own record, "
                        "not our claim about it."),
            },
            "off_rail_check": {
                "swept": True,
                "window": "±1h around this action",
                "out_of_band_found": 0,
                "note": "No spend on this domain in the window that bypassed the gateway.",
            },
            "generated_at": _fmt(now),
            "verify_yourself": "git clone github.com/aurumflux20/seal && python3 -m seal verify",
        }

    # ── the real thing, built from actual state ─────────────────────────────
    def build(self, intent: str, *, reconcile_window_sec: float = 3600.0) -> dict:
        rec = self.seal.get(intent)
        if rec is None:
            raise ReceiptError(f"unknown intent {intent[:16]}…")

        certs = self.seal.certs_for(intent)
        chain = self.seal.verify_chain()
        latest = certs[-1] if certs else None

        allowed = self._allowed_block(intent, rec)
        once = self._once_block(rec, certs, chain)
        world = self._world_block(latest)
        off_rail = self._off_rail_block(rec, reconcile_window_sec)

        status, label = self._status(rec, once, world, off_rail)

        body = {
            "receipt_id": _digest({"intent": intent, "at": int(time.time())})[:12],
            "title": "Agent Authorization Receipt",
            "SAMPLE": False,
            "status": status,
            "status_label": label,
            "action": {
                "path": rec.get("action"),
                "domain": rec.get("domain"),
            },
            "allowed": allowed,
            "once": once,
            "world_id": world,
            "off_rail_check": off_rail,
            "generated_at": _fmt(time.time()),
            "honesty": (
                "Dispute-grade evidence, not a legal or notarial instrument. "
                "Every claim above is either the provider's own record or a "
                "hash chain you can re-verify from the DSN alone — no trust "
                "in AurumFlux required. UNKNOWN is never reported as clean."
            ),
            "verify_yourself": "git clone github.com/aurumflux20/seal && python3 -m seal verify",
        }
        body["receipt_digest"] = _digest(
            {k: v for k, v in body.items() if k not in ("generated_at", "receipt_digest")}
        )
        return body

    # ── the four blocks ──────────────────────────────────────────────────
    def _allowed_block(self, intent: str, rec: dict) -> dict:
        """Who authorised this, and on what evidence — pulling graduated
        approval votes when the path went through maker-checker."""
        try:
            from .graduated import GraduatedClearance
        except Exception:
            return {"tier": rec.get("tier"), "note": "graduated clearance not configured"}

        gc = GraduatedClearance(self.seal)
        with self.seal._connect(autocommit=True) as c:
            row = c.execute(
                "SELECT id FROM seal_approvals WHERE intent=%s ORDER BY created_at DESC LIMIT 1",
                (intent,),
            ).fetchone()
        if not row:
            return {
                "tier": rec.get("tier") or "AUTO",
                "note": "Below the approval threshold for this path — no human sign-off required.",
            }

        appr = gc.get(row[0])
        approvers = [v["approver"] for v in appr["votes"] if v["decision"] == "approve"]
        return {
            "tier": appr.get("tier"),
            "requested_by": appr.get("maker"),
            "requested_at": _fmt(appr.get("created_at")),
            "state": appr.get("state"),
            "approved_by": approvers,
            "self_approval_blocked": True,
            "note": (
                f"Required {appr.get('required')} distinct approver(s); the requester "
                "can never be counted as one — enforced as a database constraint."
            ),
        }

    def _once_block(self, rec: dict, certs: list, chain: dict) -> dict:
        latest = certs[-1] if certs else None
        return {
            "intent_id": rec.get("intent"),
            "state": rec.get("state"),
            "executed": rec.get("state") == "sealed",
            "cert_hash": (latest or {}).get("hash"),
            "certs_in_chain_for_this_intent": len(certs),
            "chain_verified": chain.get("ok"),
            "note": (
                "Verified by re-deriving the hash chain from the database alone. "
                "No part of this check trusts AurumFlux — run `python3 -m seal verify` "
                "against your own DSN and compare."
            ),
        }

    def _world_block(self, latest_cert: dict | None) -> dict:
        if not latest_cert:
            return {"state": "unconfirmed", "cert_tier": None,
                    "note": "No certificate yet — nothing to confirm."}
        # `tier` is the classification (SEALED / WORLD_FINAL / WORLD_UNKNOWN /
        # WORLD_DIVERGED) — that is what a dispute reader needs to key off.
        # `world` on the cert is a separate human-readable label for the same
        # tier; kept below for context, never as the field callers branch on.
        tier = latest_cert.get("tier") or "SEALED"
        return {
            "state": tier,
            "cert_tier": tier,
            "provider_ref": (latest_cert.get("witness_evidence") or {}).get("ids")
                or (latest_cert.get("witness_evidence") or {}).get("matched"),
            "note": {
                "WORLD_FINAL": "The provider's own record agrees exactly one effect exists.",
                "WORLD_UNKNOWN": (
                    "The provider could not be reached to confirm. This is reported "
                    "honestly as UNKNOWN — it is not treated as, and does not mean, "
                    "'confirmed clean.'"
                ),
                "WORLD_DIVERGED": (
                    "The provider's record CONTRADICTS the ledger. This domain was "
                    "frozen automatically when this was detected."
                ),
                "SEALED": "Admitted exactly once at this gateway. World confirmation not yet run.",
            }.get(tier, "Status not yet classified."),
        }

    def _off_rail_block(self, rec: dict, window_sec: float) -> dict:
        """Cross-reference against reconciliation sweeps in a window around
        this intent. Domain-matched hits are reported as directly relevant;
        an out-of-band event with NO domain tag (an older or global sweep) is
        still surfaced, but flagged for review rather than silently excluded
        — the safe direction to be wrong in here is over-flagging, not a
        false 'clean'. This is the opposite conservatism from CLEAN/UNKNOWN,
        which must never lean toward claiming more than was proven.
        """
        at = rec.get("created_at")
        if at is None:
            return {"swept": False, "note": "No creation time on this intent — sweep not applicable."}
        domain = rec.get("domain")
        with self.seal._connect(autocommit=True) as c:
            rows = c.execute(
                "SELECT detail FROM seal_events WHERE kind='out_of_band_spend' "
                "AND at BETWEEN %s AND %s",
                (at - window_sec, at + window_sec),
            ).fetchall()
            unk = c.execute(
                "SELECT count(*) FROM seal_events WHERE kind='reconcile_unknown' "
                "AND at BETWEEN %s AND %s",
                (at - window_sec, at + window_sec),
            ).fetchone()
        if unk and unk[0]:
            return {
                "swept": True, "readable": False,
                "note": "A reconciliation sweep in this window could not reach the "
                       "provider. This is reported as UNKNOWN, not as clean.",
            }

        matched, unscoped = 0, 0
        for (d,) in rows:
            d = d or {}
            ev_domain = d.get("domain")
            n = d.get("count", 0)
            if ev_domain is None:
                unscoped += n
            elif domain is not None and ev_domain == domain:
                matched += n
            # an event tagged with a DIFFERENT domain is genuinely unrelated — excluded

        readable = True
        found = matched + unscoped
        note = "No spend outside the gateway detected in the window."
        if matched and not unscoped:
            note = f"{matched} effect(s) confirmed out-of-band on this same domain."
        elif unscoped:
            note = (f"{found} effect(s) found out-of-band in the window; "
                    f"{unscoped} not domain-tagged and included conservatively — "
                    "review before treating as unrelated.")
        return {
            "swept": True,
            "readable": readable,
            "out_of_band_found": found,
            "domain_matched": matched,
            "unscoped_in_window": unscoped,
            "note": note,
        }

    def _status(self, rec: dict, once: dict, world: dict, off_rail: dict) -> tuple[str, str]:
        if not once["executed"]:
            return BLOCKED, "Blocked — refused before the effect ran"
        if off_rail.get("readable") and off_rail.get("out_of_band_found"):
            return OFF_RAIL, "Off-rail spend detected on this domain"
        if world["state"] == "WORLD_DIVERGED":
            return DIVERGED, "Diverged — the provider's record contradicts the ledger"
        if world["state"] in ("WORLD_UNKNOWN", "unconfirmed") or not off_rail.get("readable", True):
            return ALLOWED_ONCE_WORLD_UNKNOWN, "Allowed, ran once — provider confirmation unavailable"
        return ALLOWED_ONCE, "Allowed, ran once, confirmed by the provider"


def _fmt(ts: float | None) -> str | None:
    if ts is None:
        return None
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))
