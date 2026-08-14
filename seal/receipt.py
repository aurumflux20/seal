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
            "summary": "refund · $4,900.00 · cus_8841 · allowed, ran once, confirmed by the provider",
            "status": ALLOWED_ONCE,
            "status_label": "Allowed, ran once, confirmed by the provider",
            "action": {"path": "refund", "domain": "cus_8841", "amount": 4900.00},
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
                "state": "WORLD_FINAL",
                "cert_tier": "WORLD_FINAL",
                "provider_ref": ["re_3P9x2ALkdIwHu7ix1a2b3c4d"],
                "checked_at": _fmt(now - 800),
                "note": ("The provider was asked directly how many refunds carry this "
                        "intent's tag, and answered exactly one. This is the provider's "
                        "own record, not our claim about it."),
            },
            "off_rail_check": {
                "swept": True,
                "readable": True,
                "out_of_band_found": 0,
                "domain_matched": 0,
                "unscoped_in_window": 0,
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

        from .mandate import Mandates
        mandate = Mandates(self.seal).for_intent(intent)
        allowed["mandate_id"] = mandate["mandate_id"] if mandate else None
        allowed["on_rail"] = mandate is not None
        allowed["note"] = (
            (allowed.get("note") or "") +
            ("" if mandate else
             " No Mandate is on record for this intent — either the path was "
             "not under Mandate, or it was admitted outside the Gateway.")
        ).strip()

        status, label = self._status(rec, once, world, off_rail)

        # Amount is only known when the path went through graduated approval —
        # an AUTO-tier intent stores no amount anywhere, so we say nothing
        # rather than guess. A receipt that invents a figure is worse than one
        # that omits it.
        amount = allowed.get("amount")
        body = {
            "receipt_id": _digest({"intent": intent, "at": int(time.time())})[:12],
            "title": "Agent Authorization Receipt",
            "SAMPLE": False,
            "summary": self._summary(rec, amount, label),
            "status": status,
            "status_label": label,
            "action": {
                "path": rec.get("action"),
                "domain": rec.get("domain"),
                "amount": amount,
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
            "amount": appr.get("amount"),
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
        # The FIRST cert is when the effect actually executed; later certs are
        # witness observations appended to the same chain. A dispute asks
        # "when did the money move", not "when did we last re-check it".
        first = certs[0] if certs else None
        with self.seal._connect(autocommit=True) as c:
            pos = c.execute(
                "SELECT seq FROM seal_certs WHERE hash=%s",
                ((latest or {}).get("hash"),),
            ).fetchone() if latest else None
        return {
            "intent_id": rec.get("intent"),
            "state": rec.get("state"),
            "executed": rec.get("state") == "sealed",
            "executed_at": _fmt((first or {}).get("at")),
            "cert_hash": (latest or {}).get("hash"),
            "chain_position": pos[0] if pos else None,
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
        # `checked_at` is only meaningful when a witness actually ran — a cert
        # that was merely sealed has never been checked against the provider,
        # and dating it would imply confirmation that never happened.
        checked = _fmt(latest_cert.get("at")) if latest_cert.get("witness_state") else None
        return {
            "state": tier,
            "cert_tier": tier,
            "checked_at": checked,
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

    def _summary(self, rec: dict, amount: float | None, label: str) -> str:
        """One line a human reads first. Built only from what we actually know —
        no provider name is asserted, because the witness does not record which
        provider answered, and naming one would be a guess on a document whose
        whole value is that nothing on it is guessed."""
        bits = [str(rec.get("action") or "action")]
        if amount is not None:
            bits.append(f"${amount:,.2f}")
        if rec.get("domain"):
            bits.append(str(rec["domain"]))
        bits.append(label.lower())
        return " · ".join(bits)

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


# ── rendering ────────────────────────────────────────────────────────────
# Self-contained HTML on purpose: no CDN, no webfont, no external stylesheet.
# This file gets emailed to a risk officer, opened offline, and printed to PDF
# with Cmd+P. Anything fetched over the network would break all three, and a
# document about provable claims cannot depend on a third party being up.

_STATUS_STYLE = {
    ALLOWED_ONCE:               ("#0a6b3d", "#e8f5ee", "CLEAR"),
    ALLOWED_ONCE_WORLD_UNKNOWN: ("#8a6100", "#fdf4e0", "UNCONFIRMED"),
    BLOCKED:                    ("#33415c", "#eef1f6", "BLOCKED"),
    DIVERGED:                   ("#a1121f", "#fdeaec", "DIVERGED"),
    OFF_RAIL:                   ("#a1121f", "#fdeaec", "OFF-RAIL"),
}


def _esc(v: Any) -> str:
    s = "" if v is None else str(v)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


def _row(label: str, value: Any) -> str:
    if value is None or value == [] or value == "":
        return ""
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value)
    if isinstance(value, bool):
        value = "yes" if value else "no"
    return (f'<tr><td class="k">{_esc(label)}</td>'
            f'<td class="v">{_esc(value)}</td></tr>')


def render_html(receipt: dict) -> str:
    """Render a receipt as one self-contained, printable HTML page."""
    status = receipt.get("status", "")
    fg, bg, short = _STATUS_STYLE.get(status, ("#33415c", "#eef1f6", "UNKNOWN"))
    a = receipt.get("allowed", {}) or {}
    o = receipt.get("once", {}) or {}
    w = receipt.get("world_id", {}) or {}
    f = receipt.get("off_rail_check", {}) or {}
    act = receipt.get("action", {}) or {}
    is_sample = bool(receipt.get("SAMPLE"))

    sample_banner = (
        f'<div class="sample">SAMPLE — {_esc(receipt.get("sample_notice", ""))}</div>'
        if is_sample else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Agent Authorization Receipt — {_esc(receipt.get('receipt_id',''))}</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:32px 20px; background:#f4f5f7; color:#16202e;
         font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
  .page {{ max-width:760px; margin:0 auto; background:#fff; border:1px solid #dfe3e8;
           border-radius:10px; padding:36px 40px; }}
  h1 {{ font-size:21px; margin:0 0 2px; letter-spacing:-.2px; }}
  .sub {{ color:#5b6878; font-size:13px; margin-bottom:22px; }}
  .sample {{ background:#fff6d8; border:1px solid #e6c86a; color:#6b4e00;
             padding:10px 14px; border-radius:7px; font-size:13px; margin-bottom:20px; }}
  .status {{ display:flex; align-items:center; gap:12px; background:{bg};
             border:1px solid {fg}33; border-radius:8px; padding:14px 18px; margin-bottom:8px; }}
  .badge {{ background:{fg}; color:#fff; font-weight:700; font-size:12px;
            letter-spacing:.7px; padding:5px 11px; border-radius:5px; white-space:nowrap; }}
  .status .lbl {{ color:{fg}; font-weight:600; font-size:15px; }}
  .summary {{ color:#3d4b5c; font-size:14px; margin:0 0 26px; }}
  h2 {{ font-size:12px; letter-spacing:1.1px; text-transform:uppercase; color:#6b7A8d;
        margin:26px 0 8px; padding-bottom:6px; border-bottom:1px solid #e8ebef; }}
  table {{ width:100%; border-collapse:collapse; }}
  td {{ padding:5px 0; vertical-align:top; font-size:14px; }}
  td.k {{ color:#63718a; width:200px; padding-right:14px; }}
  td.v {{ color:#16202e; word-break:break-word; }}
  .note {{ background:#f7f9fb; border-left:3px solid #c9d3de; padding:9px 13px;
           margin-top:9px; font-size:13px; color:#465468; border-radius:0 5px 5px 0; }}
  .foot {{ margin-top:30px; padding-top:18px; border-top:1px solid #e8ebef;
           font-size:12.5px; color:#5b6878; }}
  code {{ background:#eef1f5; padding:2px 6px; border-radius:4px;
          font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace; }}
  @media print {{
    body {{ background:#fff; padding:0; }}
    .page {{ border:none; border-radius:0; padding:0; max-width:none; }}
    h2 {{ break-after:avoid; }} table {{ break-inside:avoid; }}
  }}
</style></head><body><div class="page">

  <h1>Agent Authorization Receipt</h1>
  <div class="sub">Receipt {_esc(receipt.get('receipt_id',''))} · generated {_esc(receipt.get('generated_at',''))}</div>
  {sample_banner}

  <div class="status">
    <span class="badge">{_esc(short)}</span>
    <span class="lbl">{_esc(receipt.get('status_label',''))}</span>
  </div>
  <p class="summary">{_esc(receipt.get('summary') or _esc(act.get('path') or ''))}</p>

  <h2>Was it allowed?</h2>
  <table>
    {_row("Action", act.get("path"))}
    {_row("Amount", act.get("amount"))}
    {_row("Domain", act.get("domain"))}
    {_row("On-rail (under a Seal Mandate)", a.get("on_rail"))}
    {_row("Mandate id", a.get("mandate_id"))}
    {_row("Authorisation tier", a.get("tier"))}
    {_row("Requested by", a.get("requested_by"))}
    {_row("Requested at", a.get("requested_at"))}
    {_row("Approved by", a.get("approved_by"))}
    {_row("Self-approval blocked", a.get("self_approval_blocked"))}
    {_row("Approval state", a.get("state"))}
  </table>
  {f'<div class="note">{_esc(a.get("note"))}</div>' if a.get("note") else ""}

  <h2>Did it run exactly once?</h2>
  <table>
    {_row("Intent id", o.get("intent_id"))}
    {_row("Executed", o.get("executed"))}
    {_row("Executed at", o.get("executed_at"))}
    {_row("Certificate", o.get("cert_hash"))}
    {_row("Chain verified", o.get("chain_verified"))}
  </table>
  {f'<div class="note">{_esc(o.get("note"))}</div>' if o.get("note") else ""}

  <h2>What does the provider say?</h2>
  <table>
    {_row("Confirmation state", w.get("state"))}
    {_row("Provider reference", w.get("provider_ref"))}
    {_row("Checked at", w.get("checked_at"))}
  </table>
  {f'<div class="note">{_esc(w.get("note"))}</div>' if w.get("note") else ""}

  <h2>Did anything bypass the gateway?</h2>
  <table>
    {_row("Window swept", f.get("swept"))}
    {_row("Sweep readable", f.get("readable"))}
    {_row("Out-of-band effects found", f.get("out_of_band_found"))}
    {_row("Matched this domain", f.get("domain_matched"))}
    {_row("Unscoped in window", f.get("unscoped_in_window"))}
  </table>
  {f'<div class="note">{_esc(f.get("note"))}</div>' if f.get("note") else ""}

  <div class="foot">
    <p><strong>Verify this yourself.</strong> Nothing here requires trusting AurumFlux —
    the certificate chain re-derives from your own database:<br>
    <code>{_esc(receipt.get('verify_yourself',''))}</code></p>
    <p>{_esc(receipt.get('honesty') or
        'Dispute-grade evidence, not a legal or notarial instrument. Not court-certified, '
        'not insurance. UNKNOWN is never reported as clean.')}</p>
    {f"<p>Receipt digest: <code>{_esc(receipt.get('receipt_digest'))}</code></p>" if receipt.get("receipt_digest") else ""}
  </div>

</div></body></html>"""
