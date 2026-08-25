"""Clearance — the range-safety authority for irreversible agent tools.

The product a company actually buys is not "we prevent doubles." It is:
**you may turn multi-agent money automation ON, and keep it on** — because a
control plane decides which tool paths may fire unattended, and that permission
survives only while continuous proof stays green.

    CLEARED   agents may execute unattended through the fence
    HOLD      agents may propose; a human or policy must approve. The DEFAULT.
    REVOKED   nothing on this path runs. One switch, after any incident.

Two rules make this honest rather than a toggle with a nice name:

1. **CLEARED IS EARNED, NOT DECLARED.** A path is only actually cleared if a
   green proof (storm on that path → exactly one execution) has been recorded
   recently enough. Let the proof go stale and `status()` reports HOLD on its
   own — nobody has to remember to downgrade it. A permission that cannot
   expire is a permission nobody should trust.

2. **REVOKE IS INSTANT AND BLUNT.** `revoke_all()` stops every path at the
   choke. After an incident the honest move is to halt, not to reason about
   blast radius while money moves.

Deliberately NOT insurance. This is best-effort once-execution + continuous
test + a kill switch, and the docs say exactly that. Companies trust systems
that can say no.
"""
from __future__ import annotations

import json
import time
from typing import Any, Optional

from .core import Seal, SealError, _jsonb

CLEARED = "CLEARED"
HOLD = "HOLD"
REVOKED = "REVOKED"

# A path nobody has ruled on is HOLD. Safe by default: an unknown tool does not
# get to move money because someone forgot to configure it.
DEFAULT_STATUS = HOLD

# CLEARED expires this long after the last green proof unless the policy says
# otherwise. One day: long enough for a daily CI storm to keep it alive, short
# enough that a broken pipeline visibly withdraws permission.
DEFAULT_MAX_PROOF_AGE_SEC = 24 * 60 * 60


class ClearanceDenied(SealError):
    """This tool path is not cleared to fire unattended."""

    def __init__(self, path: str, status: str, reason: str | None = None):
        self.path = path
        self.status = status
        self.reason = reason
        super().__init__(
            f"path {path!r} is {status}"
            + (f": {reason}" if reason else "")
            + " — agents may propose, not execute"
        )


class Clearance:
    """The control plane. Sits above the fence; sells to ops/risk, not eng."""

    def __init__(self, seal: Seal):
        self.seal = seal

    # ── policy ────────────────────────────────────────────────────────────
    def set_policy(self, path: str, status: str, reason: str | None = None,
                   max_proof_age_sec: float | None = None, by: str = "operator") -> dict:
        if status not in (CLEARED, HOLD, REVOKED):
            raise ValueError(f"status must be CLEARED, HOLD or REVOKED — got {status!r}")
        now = time.time()
        age = DEFAULT_MAX_PROOF_AGE_SEC if max_proof_age_sec is None else max_proof_age_sec
        with self.seal._connect(autocommit=True) as c:
            c.execute(
                """
                INSERT INTO seal_clearance (path, status, reason, max_proof_age_sec, updated_at, updated_by)
                VALUES (%s,%s,%s,%s,%s,%s)
                ON CONFLICT (path) DO UPDATE SET
                    status=EXCLUDED.status, reason=EXCLUDED.reason,
                    max_proof_age_sec=EXCLUDED.max_proof_age_sec,
                    updated_at=EXCLUDED.updated_at, updated_by=EXCLUDED.updated_by
                """,
                (path, status, reason, age, now, by),
            )
        self.seal.record_event("policy", path=path, detail={"status": status, "reason": reason, "by": by})
        return self.status(path)

    def revoke(self, path: str, reason: str, by: str = "operator") -> dict:
        return self.set_policy(path, REVOKED, reason=reason, by=by)

    def revoke_all(self, reason: str, by: str = "operator") -> int:
        """The one switch. Every known path stops at the choke."""
        now = time.time()
        with self.seal._connect(autocommit=True) as c:
            n = c.execute(
                "UPDATE seal_clearance SET status=%s, reason=%s, updated_at=%s, updated_by=%s "
                "WHERE status <> %s",
                (REVOKED, reason, now, by, REVOKED),
            ).rowcount
        self.seal.record_event("revoked", detail={"scope": "ALL", "reason": reason, "by": by, "paths": n})
        return n

    # ── continuous proof ──────────────────────────────────────────────────
    def record_proof(self, path: str, green: bool, storm_n: int | None = None,
                     executions: int | None = None, detail: Any = None) -> None:
        """Record a storm result for a path. This is what keeps CLEARED alive.

        Wire it to CI: every release, storm the money path and post the result.
        A red proof does not just fail to refresh — `status()` reports HOLD
        immediately, because the last thing we know about that path is that it
        broke.
        """
        with self.seal._connect(autocommit=True) as c:
            c.execute(
                "INSERT INTO seal_proof (path, green, storm_n, executions, detail, at) "
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (path, green, storm_n, executions,
                 _jsonb(detail) if detail is not None else None, time.time()),
            )

    def latest_proof(self, path: str) -> Optional[dict]:
        with self.seal._connect(autocommit=True) as c:
            row = c.execute(
                "SELECT green, storm_n, executions, detail, at FROM seal_proof "
                "WHERE path=%s ORDER BY at DESC LIMIT 1",
                (path,),
            ).fetchone()
        if row is None:
            return None
        return {"green": row[0], "storm_n": row[1], "executions": row[2],
                "detail": row[3], "at": row[4]}

    # ── the question everything else asks ─────────────────────────────────
    def status(self, path: str) -> dict:
        """Effective status — policy AND proof together.

        A path is only CLEARED if an operator cleared it *and* a green proof is
        fresh. Otherwise it degrades to HOLD on its own, with the reason stated.
        REVOKED always wins and never auto-recovers: releasing it is a human act.
        """
        with self.seal._connect(autocommit=True) as c:
            row = c.execute(
                "SELECT status, reason, max_proof_age_sec, updated_at, updated_by "
                "FROM seal_clearance WHERE path=%s",
                (path,),
            ).fetchone()

        if row is None:
            return {"path": path, "status": DEFAULT_STATUS, "effective": DEFAULT_STATUS,
                    "reason": "no policy set — safe default", "proof": None}

        policy, reason, max_age, updated_at, by = row
        out = {"path": path, "status": policy, "reason": reason,
               "updated_at": updated_at, "updated_by": by}

        if policy != CLEARED:
            out["effective"] = policy
            out["proof"] = self.latest_proof(path)
            return out

        proof = self.latest_proof(path)
        out["proof"] = proof
        if proof is None:
            out["effective"] = HOLD
            out["reason"] = "cleared by policy but NO proof recorded — clearance not earned"
        elif not proof["green"]:
            out["effective"] = HOLD
            out["reason"] = "last storm on this path was RED — clearance withdrawn"
        elif (time.time() - proof["at"]) > (max_age or DEFAULT_MAX_PROOF_AGE_SEC):
            out["effective"] = HOLD
            age_h = (time.time() - proof["at"]) / 3600
            out["reason"] = f"proof is stale ({age_h:.1f}h old) — clearance expired"
        else:
            out["effective"] = CLEARED
        return out

    def check(self, path: str) -> dict:
        """Raise unless this path is effectively CLEARED. The choke point."""
        st = self.status(path)
        if st["effective"] != CLEARED:
            self.seal.record_event("blocked", path=path,
                                   detail={"status": st["effective"], "reason": st.get("reason")})
            raise ClearanceDenied(path, st["effective"], st.get("reason"))
        return st

    # ── the artifact procurement reads ────────────────────────────────────
    def range_report(self, since: float | None = None) -> dict:
        """Monthly Range Report: what was cleared, what was blocked, what healed.

        Deliberately made of counted events and provider-cited certs, not
        adjectives. This is the export for a security questionnaire or a CFO.
        """
        since = since if since is not None else time.time() - 30 * 24 * 3600
        with self.seal._connect(autocommit=True) as c:
            counts = c.execute(
                "SELECT kind, count(*) FROM seal_events WHERE at >= %s GROUP BY kind",
                (since,),
            ).fetchall()
            paths = c.execute(
                "SELECT path, status, reason, updated_at FROM seal_clearance ORDER BY path"
            ).fetchall()
            tiers = c.execute(
                "SELECT tier, count(*) FROM seal_intents WHERE tier IS NOT NULL GROUP BY tier"
            ).fetchall()
            frozen = c.execute(
                "SELECT domain, reason, frozen_at FROM seal_domains WHERE frozen"
            ).fetchall()
            # Approvals in money terms. A count of "2 approval_decided events"
            # answers nothing a CFO asked; "$12,000 approved by two people,
            # $8,000 stopped" does.
            appr = c.execute(
                "SELECT state, count(*), coalesce(sum(amount),0) "
                "FROM seal_approvals WHERE created_at >= %s GROUP BY state",
                (since,),
            ).fetchall()
            # Spend that never came through the gateway, and sweeps that could
            # not answer. A breach recorded but absent from the report is a
            # breach nobody reads — and an UNKNOWN sweep must appear too, or a
            # month of failed reconciliation looks identical to a clean one.
            oob = c.execute(
                "SELECT detail FROM seal_events "
                "WHERE kind='out_of_band_spend' AND at >= %s ORDER BY at DESC",
                (since,),
            ).fetchall()
            unk = c.execute(
                "SELECT count(*) FROM seal_events WHERE kind='reconcile_unknown' AND at >= %s",
                (since,),
            ).fetchone()

        report = {
            "period_start": since,
            "generated_at": time.time(),
            "events": {k: n for k, n in counts},
            "paths": [
                {"path": p, "policy": s, "reason": r, "updated_at": u,
                 "effective": self.status(p)["effective"]}
                for p, s, r, u in paths
            ],
            "cert_tiers": {t: n for t, n in tiers},
            "approvals": {
                s: {"count": n, "amount": float(a)} for s, n, a in appr
            },
            "out_of_band_spend": {
                "incidents": len(oob),
                "effects": sum((d[0] or {}).get("count", 0) for d in oob),
                "amount": sum((d[0] or {}).get("amount", 0) or 0 for d in oob),
                "unreadable_sweeps": (unk[0] if unk else 0),
                "note": (
                    "Effects the provider performed that this gateway never "
                    "admitted — i.e. something moved money outside the rail. "
                    "`unreadable_sweeps` counts reconciliations that could NOT "
                    "reach an answer; those are not clean months, they are "
                    "unmeasured ones."
                ),
            },
            "frozen_domains": [
                {"domain": d, "reason": r, "at": a} for d, r, a in frozen
            ],
            "chain_verified": self.seal.verify_chain()["ok"],
            "honesty": (
                "Best-effort once-execution at this gateway, continuous storm proof, "
                "and world confirmation against the provider's own records. "
                "This is a control with continuous attestation — it is not insurance, "
                "and it does not bind processes that bypass the gateway."
            ),
        }
        return report
