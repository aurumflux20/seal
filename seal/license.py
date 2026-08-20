"""Earned autonomy — an agent's licence to act unattended, computed from its record.

Every other control plane in this space hands you a *lock*: a cap a human sets
once and forgets. The cap never learns. An agent that has settled ten thousand
clean payments is trusted exactly as little as one installed this morning, and
the human keeps clicking Approve.

This module is the opposite. It reads what a path has actually *proven* — sealed
certs, world-confirmed settlements, clean reconciliation sweeps, human approvals
it never abused — and computes the autonomy it has earned. Evidence in, licence
out. Nobody types the level.

    L0  OBSERVED     no record yet. every action needs a human.
    L1  SUPERVISED   proving itself. human approves anything that moves money.
    L2  ASSISTED     small unattended spend; larger amounts still need a second pair of eyes.
    L3  DELEGATED    unattended on proven paths, up to its earned ceiling.
    L4  TRUSTED      broad unattended authority; only exceptional amounts escalate.
    L5  AUTONOMOUS   full unattended money authority on this path.

The ladder is climbed slowly and fallen down instantly. One out-of-band charge —
money that moved without passing this gateway — or one divergence and the licence
is suspended to L0 on the spot, with the evidence attached. A record takes weeks
to build and one breach to lose, which is the only incentive structure that makes
a track record mean anything.

HONEST LIMITS. A licence is a summary of what this gateway can see. It cannot
speak for spend on rails it never brokered, and it is not a safety proof: a level
says "this path has behaved" and never "this path cannot misbehave". Static
thresholds still bound every tier — the licence decides how much room a path is
allowed inside them, never more than the operator's own ceiling.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

L0, L1, L2, L3, L4, L5 = "L0", "L1", "L2", "L3", "L4", "L5"

LEVEL_NAMES = {
    L0: "OBSERVED", L1: "SUPERVISED", L2: "ASSISTED",
    L3: "DELEGATED", L4: "TRUSTED", L5: "AUTONOMOUS",
}

# Sealed, world-confirmed effects a path must accumulate to reach each level.
# Deliberately steep: autonomy over money should be slow to earn.
_PROVEN_REQUIRED = {L1: 1, L2: 10, L3: 50, L4: 250, L5: 1000}

# Fraction of a path's settlements that must be world-confirmed (not merely
# sealed locally) before it may run unattended. Local success is a claim; the
# provider agreeing is evidence.
_CONFIRMED_RATIO_REQUIRED = {L1: 0.0, L2: 0.5, L3: 0.8, L4: 0.9, L5: 0.95}

# A licence above this level requires at least one clean out-of-band sweep:
# proof that nothing moved money behind the gateway's back.
_SWEEP_REQUIRED_FROM = L3

SUSPENDING_EVENTS = ("out_of_band_spend", "diverged", "revoked")


@dataclass
class Licence:
    path: str
    level: str
    proven: int = 0
    confirmed: int = 0
    confirmed_ratio: float = 0.0
    clean_sweeps: int = 0
    suspended: bool = False
    suspended_reason: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    next_level: str | None = None
    needs: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return LEVEL_NAMES[self.level]

    @property
    def unattended(self) -> bool:
        """May this path execute money actions without a human in the loop?"""
        return (not self.suspended) and self.level in (L3, L4, L5)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path, "level": self.level, "name": self.name,
            "unattended": self.unattended, "proven": self.proven,
            "confirmed": self.confirmed,
            "confirmed_ratio": round(self.confirmed_ratio, 3),
            "clean_sweeps": self.clean_sweeps, "suspended": self.suspended,
            "suspended_reason": self.suspended_reason,
            "next_level": self.next_level, "needs": self.needs,
            "evidence": self.evidence,
        }


class LicenceEngine:
    """Compute the autonomy a path has earned from its own sealed history."""

    def __init__(self, seal):
        self.seal = seal

    # -- evidence gathering -------------------------------------------------

    def _history(self, path: str, since: float | None) -> dict[str, Any]:
        """Count what this path actually proved. Reads certs, never claims."""
        since = 0.0 if since is None else since
        with self.seal._connect(autocommit=True) as c:
            # One effect can carry several certs (sealing appends one, a later
            # witness appends another). The unit of evidence is the intent, not
            # the cert row — otherwise witnessing an effect would count twice.
            row = c.execute(
                "SELECT count(DISTINCT s.intent) FROM seal_certs s "
                "JOIN seal_intents i ON i.intent = s.intent "
                "WHERE i.domain = %s AND s.created_at >= %s",
                (path, since),
            ).fetchone()
            proven = row[0] if row else 0
            # Confirmed means the provider agreed the effect happened exactly
            # once. A locally sealed effect is a claim; "unknown" never counts.
            row = c.execute(
                "SELECT count(DISTINCT s.intent) FROM seal_certs s "
                "JOIN seal_intents i ON i.intent = s.intent "
                "WHERE i.domain = %s AND s.created_at >= %s "
                "AND s.body->>'world' = 'confirmed'",
                (path, since),
            ).fetchone()
            confirmed = row[0] if row else 0
            events = c.execute(
                "SELECT kind, detail, at FROM seal_events "
                "WHERE (path = %s OR path IS NULL) AND at >= %s "
                "ORDER BY at DESC",
                (path, since),
            ).fetchall()
        breach = None
        clean_sweeps = 0
        for kind, detail, at in events:
            if kind == "reconcile_clean":
                clean_sweeps += 1
            if breach is None and kind in SUSPENDING_EVENTS:
                # Only a breach naming this path (or a global one) suspends it.
                d = detail if isinstance(detail, dict) else {}
                if d.get("domain") in (None, path) or kind == "diverged":
                    breach = {"kind": kind, "at": at, "detail": d}
        return {"proven": proven, "confirmed": confirmed,
                "clean_sweeps": clean_sweeps, "breach": breach}

    # -- the ladder ---------------------------------------------------------

    def _earned(self, proven: int, ratio: float, sweeps: int) -> str:
        level = L0
        for candidate in (L1, L2, L3, L4, L5):
            if proven < _PROVEN_REQUIRED[candidate]:
                break
            if ratio < _CONFIRMED_RATIO_REQUIRED[candidate]:
                break
            if candidate >= _SWEEP_REQUIRED_FROM and sweeps < 1:
                break
            level = candidate
        return level

    def _shortfall(self, level: str, proven: int, ratio: float,
                   sweeps: int) -> tuple[str | None, list[str]]:
        order = [L0, L1, L2, L3, L4, L5]
        i = order.index(level)
        if i == len(order) - 1:
            return None, []
        nxt = order[i + 1]
        needs = []
        gap = _PROVEN_REQUIRED[nxt] - proven
        if gap > 0:
            needs.append(f"{gap} more world-confirmed effect(s)")
        need_ratio = _CONFIRMED_RATIO_REQUIRED[nxt]
        if ratio < need_ratio:
            needs.append(
                f"confirmation ratio {ratio:.0%} → {need_ratio:.0%} "
                "(settlements the provider agrees happened)"
            )
        if nxt >= _SWEEP_REQUIRED_FROM and sweeps < 1:
            needs.append("one clean out-of-band sweep (no spend behind the gateway)")
        return nxt, needs

    def evaluate(self, path: str, *, since: float | None = None) -> Licence:
        """The licence this path has earned, from evidence alone."""
        h = self._history(path, since)
        proven, confirmed = h["proven"], h["confirmed"]
        ratio = (confirmed / proven) if proven else 0.0
        breach = h["breach"]

        if breach is not None:
            return Licence(
                path=path, level=L0, proven=proven, confirmed=confirmed,
                confirmed_ratio=ratio, clean_sweeps=h["clean_sweeps"],
                suspended=True,
                suspended_reason=(
                    f"licence suspended: {breach['kind']} at "
                    f"{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(breach['at']))}Z"
                ),
                evidence={"breach": breach},
                next_level=None,
                needs=["operator review — a suspension is not served by waiting"],
            )

        level = self._earned(proven, ratio, h["clean_sweeps"])
        nxt, needs = self._shortfall(level, proven, ratio, h["clean_sweeps"])
        return Licence(
            path=path, level=level, proven=proven, confirmed=confirmed,
            confirmed_ratio=ratio, clean_sweeps=h["clean_sweeps"],
            evidence={"proven_effects": proven, "world_confirmed": confirmed,
                      "clean_sweeps": h["clean_sweeps"]},
            next_level=nxt, needs=needs,
        )

    def requires_human(self, path: str, amount: float,
                       *, since: float | None = None) -> dict[str, Any]:
        """Would this action need a human right now, and why?

        The licence widens or narrows the room a path has *inside* the
        operator's own thresholds. It never grants more than the operator
        allowed — a ceiling is a ceiling.
        """
        lic = self.evaluate(path, since=since)
        if lic.suspended:
            return {"human_required": True, "level": lic.level,
                    "reason": lic.suspended_reason}
        if not lic.unattended:
            return {"human_required": True, "level": lic.level,
                    "reason": f"{lic.name}: not yet licensed for unattended spend",
                    "needs": lic.needs}
        return {"human_required": False, "level": lic.level,
                "reason": f"{lic.name}: earned unattended authority on this path"}
