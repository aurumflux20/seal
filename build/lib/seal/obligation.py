"""Obligations — the alarm for what an agent FAILS to do.

Every guard in this codebase — and in effectfence, and in every agent-safety
tool we surveyed — watches commission: the double-charge, the stale read, the
overspend, the contradiction, the out-of-band charge. Nothing anywhere watches
omission. An agent that crashed, lost its key, sat in HOLD, or silently
stopped looks EXACTLY like an agent with nothing to do — until payroll doesn't
go out, the renewal that funds the business never fires, or the refund that
was legally due in 14 days quietly doesn't happen and becomes a violation
instead of a bug.

This project already knows silence is not success. conftest.py refuses a test
run where everything skipped and the exit code is green: "a green exit code
that proves nothing is precisely the failure mode this project exists to
prevent." This module is that same sentence, applied to production money.

It is the DUAL of reconcile.py. Reconcile sweeps the provider for effects
that exist and shouldn't (spend behind the gateway's back). Obligations sweep
the ledger for effects that should exist and don't:

    reconcile:    provider effects  −  admitted intents  =  out-of-band
    obligations:  declared duties   −  sealed intents    =  BREACH

Two kinds of duty:

    once       "intent (action, key) must be SEALED by due_at."
               Declared at decision time — an agent that accepts a return
               binds its future self to the refund, right then.
    recurring  "path P must seal ≥ N effects every W seconds."
               Payroll on the 1st. Renewals daily. The heartbeat of the
               business, not of the process.

What makes this an enforcement kernel rather than a dashboard:

* **A breach is a CERT.** When a duty is missed, the miss itself is appended
  to the tamper-evident chain. Deleting the breach breaks the chain by
  arithmetic — a missed payroll cannot be quietly tidied away, and neither
  can proof of on-time performance be forged after the fact.
* **A breach SUSPENDS the licence.** `obligation_breached` joins
  out_of_band_spend and diverged as a suspending event in license.py: a path
  that goes silent loses its earned autonomy exactly like a path that
  double-charged. Before this, an L5 agent that stopped working entirely
  kept L5 forever.
* **An obligation an agent could cancel is not an obligation.** Declaring
  duties is open to anyone — more oversight is always safe. Deactivating one
  is an operator act with no agent-facing tool, the same rule as unfreeze
  and mandate release.
* **UNKNOWN is never clean.** With `require_world`, a duty satisfied only by
  a locally sealed cert reports `satisfied_unconfirmed`, not met — local
  success is a claim; the provider agreeing is evidence. Same rule as
  everywhere else in this codebase.

Deliberate non-lever, stated because it will be asked: a breach does NOT
freeze or HOLD the path. Freezing is the right lever for divergence (stop the
bleeding); for omission it deepens the wound — a frozen refund path cannot
cure the missed refund. The levers are evidence, alarm, and the licence.

Honest limits: this sweeps the gateway's own ledger, so it can only miss work
routed around the gateway entirely — reconcile.py's territory, not ours. And
a duty nobody declared is a duty nobody is watching; declaring them is the
operator's (or the agent's own, at decision time) one responsibility.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Optional

from .core import Seal, SealError, _jsonb, intent_id

# Per-duty statuses a sweep can report.
SATISFIED = "satisfied"                       # sealed on time (and confirmed, if required)
SATISFIED_UNCONFIRMED = "satisfied_unconfirmed"   # sealed on time; world has not confirmed
LATE = "late"                                 # sealed, but after due_at
CURED = "cured"                               # breached first, sealed later
PENDING = "pending"                           # not due yet
BREACHED = "breached"                         # past due + grace, nothing sealed
DIVERGED = "diverged"                         # sealed, but the world contradicts it

TIER_OBLIGATION_BREACHED = "OBLIGATION_BREACHED"

OBLIGATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS seal_obligations (
    obligation_id   TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,             -- 'once' | 'recurring'
    action          TEXT NOT NULL,
    intent_key      TEXT,                      -- once: the expected intent key
    expected_intent TEXT,                      -- once: computed intent id
    due_at          DOUBLE PRECISION,          -- once
    every_sec       DOUBLE PRECISION,          -- recurring: window length
    min_count       INTEGER NOT NULL DEFAULT 1,
    grace_sec       DOUBLE PRECISION NOT NULL DEFAULT 0,
    require_world   BOOLEAN NOT NULL DEFAULT FALSE,
    description     TEXT,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    anchor_at       DOUBLE PRECISION NOT NULL, -- recurring: window origin
    next_window     BIGINT NOT NULL DEFAULT 0, -- recurring: first unevaluated window
    created_at      DOUBLE PRECISION NOT NULL,
    created_by      TEXT NOT NULL,
    satisfied_at    DOUBLE PRECISION,          -- once: when the effect sealed
    satisfied_tier  TEXT,
    deactivated_at  DOUBLE PRECISION,
    deactivated_by  TEXT
);
CREATE TABLE IF NOT EXISTS seal_obligation_breaches (
    id            BIGSERIAL PRIMARY KEY,
    obligation_id TEXT NOT NULL,
    window_n      BIGINT NOT NULL DEFAULT -1,  -- -1 for 'once'
    action        TEXT NOT NULL,
    due_at        DOUBLE PRECISION NOT NULL,
    detected_at   DOUBLE PRECISION NOT NULL,
    cert_hash     TEXT,
    resolved_at   DOUBLE PRECISION,
    resolved_by   TEXT,
    resolution    TEXT,
    UNIQUE (obligation_id, window_n)           -- one breach record per miss
);
"""


class ObligationError(SealError):
    """Refusals specific to obligations."""


class Obligations:
    """Declare duties; sweep for the silence; make the misses unforgeable."""

    def __init__(self, seal: Seal):
        self.seal = seal

    def setup(self) -> None:
        with self.seal._connect(autocommit=True) as c:
            c.execute(OBLIGATION_SCHEMA)

    # ── declaring duties (open to anyone — oversight is always safe) ──────
    def expect(self, *, action: str, key: str, due_at: float | None = None,
               due_in_sec: float | None = None, grace_sec: float = 0.0,
               require_world: bool = False, description: str | None = None,
               by: str = "operator") -> dict:
        """One effect (action, key) MUST be sealed by a deadline.

        Meant to be called at decision time: the moment an agent accepts a
        return, it declares the refund duty — binding its future self while
        the commitment is fresh, instead of hoping someone mines it out of a
        contract later.
        """
        if (due_at is None) == (due_in_sec is None):
            raise ObligationError("pass exactly one of due_at / due_in_sec")
        now = time.time()
        due = due_at if due_at is not None else now + float(due_in_sec)
        if due <= now:
            raise ObligationError("due_at is already in the past")
        oid = uuid.uuid4().hex
        expected = intent_id(action, None, key)
        with self.seal._connect(autocommit=True) as c:
            c.execute(
                "INSERT INTO seal_obligations (obligation_id, kind, action, "
                "intent_key, expected_intent, due_at, grace_sec, require_world, "
                "description, anchor_at, created_at, created_by) "
                "VALUES (%s,'once',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (oid, action, key, expected, due, grace_sec, require_world,
                 description, now, now, by),
            )
        self.seal.record_event("obligation_declared", path=action,
                               detail={"obligation_id": oid, "key": key,
                                       "due_at": due, "by": by})
        return self.get(oid)

    def expect_recurring(self, *, action: str, every_sec: float,
                         min_count: int = 1, grace_sec: float = 0.0,
                         require_world: bool = False,
                         description: str | None = None,
                         anchor_at: float | None = None,
                         by: str = "operator") -> dict:
        """At least `min_count` effects on `action` must seal every window."""
        if every_sec <= 0 or min_count < 1:
            raise ObligationError("every_sec must be > 0 and min_count >= 1")
        now = time.time()
        oid = uuid.uuid4().hex
        with self.seal._connect(autocommit=True) as c:
            c.execute(
                "INSERT INTO seal_obligations (obligation_id, kind, action, "
                "every_sec, min_count, grace_sec, require_world, description, "
                "anchor_at, created_at, created_by) "
                "VALUES (%s,'recurring',%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (oid, action, every_sec, min_count, grace_sec, require_world,
                 description, anchor_at if anchor_at is not None else now,
                 now, by),
            )
        self.seal.record_event("obligation_declared", path=action,
                               detail={"obligation_id": oid,
                                       "every_sec": every_sec, "by": by})
        return self.get(oid)

    def get(self, obligation_id: str) -> Optional[dict]:
        with self.seal._connect(autocommit=True) as c:
            row = c.execute(
                "SELECT obligation_id, kind, action, intent_key, expected_intent, "
                "due_at, every_sec, min_count, grace_sec, require_world, "
                "description, active, anchor_at, next_window, created_at, "
                "created_by, satisfied_at, satisfied_tier, deactivated_at "
                "FROM seal_obligations WHERE obligation_id=%s",
                (obligation_id,),
            ).fetchone()
        if row is None:
            return None
        keys = ("obligation_id", "kind", "action", "intent_key",
                "expected_intent", "due_at", "every_sec", "min_count",
                "grace_sec", "require_world", "description", "active",
                "anchor_at", "next_window", "created_at", "created_by",
                "satisfied_at", "satisfied_tier", "deactivated_at")
        return dict(zip(keys, row))

    # ── operator-only releases ────────────────────────────────────────────
    def deactivate(self, obligation_id: str, *, by: str, reason: str) -> None:
        """Stop watching a duty. OPERATOR ACT — deliberately absent from the
        MCP surface, for the reason the module docstring states: an agent
        that could cancel its own duties has no duties."""
        with self.seal._connect(autocommit=True) as c:
            n = c.execute(
                "UPDATE seal_obligations SET active=FALSE, deactivated_at=%s, "
                "deactivated_by=%s WHERE obligation_id=%s AND active",
                (time.time(), by, obligation_id),
            ).rowcount
        if not n:
            raise ObligationError(f"no active obligation {obligation_id!r}")
        self.seal.record_event("obligation_released",
                               detail={"obligation_id": obligation_id,
                                       "by": by, "reason": reason})

    def resolve_breach(self, breach_id: int, *, by: str, note: str) -> None:
        """Mark a breach remediated. This records WHO decided the miss was
        handled and how — it does not remove the breach cert from the chain
        (nothing can), and it does not un-suspend the licence (good behaviour
        afterwards does not wash off an incident; reinstatement is a separate
        human act, same as every other suspending event)."""
        with self.seal._connect(autocommit=True) as c:
            n = c.execute(
                "UPDATE seal_obligation_breaches SET resolved_at=%s, "
                "resolved_by=%s, resolution=%s WHERE id=%s AND resolved_at IS NULL",
                (time.time(), by, note, breach_id),
            ).rowcount
        if not n:
            raise ObligationError(f"no unresolved breach {breach_id!r}")

    # ── the sweep: the dual of reconcile ──────────────────────────────────
    def sweep(self, now: float | None = None) -> dict:
        """Walk every active duty and answer: did the promised work happen?

        Every miss becomes a breach ROW (idempotent — one per duty/window),
        a breach CERT on the chain, and an `obligation_breached` event that
        license.py treats as suspending. The report's verdict is `met` only
        when nothing is owed, nothing is missed, and nothing is unconfirmed
        that was required to be confirmed.
        """
        now = time.time() if now is None else now
        items: list[dict] = []
        with self.seal._connect(autocommit=True) as c:
            rows = c.execute(
                "SELECT obligation_id FROM seal_obligations WHERE active "
                "ORDER BY created_at",
            ).fetchall()
        for (oid,) in rows:
            ob = self.get(oid)
            if ob["kind"] == "once":
                items.append(self._sweep_once(ob, now))
            else:
                items.extend(self._sweep_recurring(ob, now))

        with self.seal._connect(autocommit=True) as c:
            open_breaches = c.execute(
                "SELECT count(*) FROM seal_obligation_breaches "
                "WHERE resolved_at IS NULL",
            ).fetchone()[0]

        statuses = [i["status"] for i in items]
        if open_breaches or DIVERGED in statuses:
            verdict = "breached"
        elif SATISFIED_UNCONFIRMED in statuses:
            verdict = "unconfirmed"
        else:
            verdict = "met"
        return {
            "verdict": verdict,
            "at": now,
            "duties_checked": len(items),
            "open_breaches": open_breaches,
            "items": items,
            "note": (
                "A breach means declared work did NOT happen by its deadline. "
                "The miss is on the cert chain and cannot be quietly removed. "
                "`unconfirmed` means the work sealed locally but the provider "
                "has not confirmed it — that is not `met`, it is unproven."
            ),
        }

    # -- one-shot duties ----------------------------------------------------
    def _sealed_state(self, intent: str) -> tuple[float, str] | None:
        """(sealed_at, tier) for a sealed intent, else None. sealed_at is the
        first cert's timestamp — when the effect was recorded, not when it
        was later witnessed."""
        with self.seal._connect(autocommit=True) as c:
            row = c.execute(
                "SELECT i.tier, (SELECT MIN(created_at) FROM seal_certs s "
                " WHERE s.intent = i.intent) "
                "FROM seal_intents i WHERE i.intent=%s AND i.state='sealed'",
                (intent,),
            ).fetchone()
        if row is None or row[1] is None:
            return None
        return (float(row[1]), row[0])

    def _sweep_once(self, ob: dict, now: float) -> dict:
        item = {"obligation_id": ob["obligation_id"], "kind": "once",
                "action": ob["action"], "key": ob["intent_key"],
                "due_at": ob["due_at"], "description": ob["description"]}
        sealed = self._sealed_state(ob["expected_intent"])
        deadline = ob["due_at"] + ob["grace_sec"]

        if sealed is None:
            if now <= deadline:
                item["status"] = PENDING
                item["seconds_remaining"] = ob["due_at"] - now
                return item
            item["status"] = BREACHED
            item["breach_id"] = self._record_breach(ob, window_n=-1,
                                                    due_at=ob["due_at"], now=now)
            return item

        sealed_at, tier = sealed
        self._mark_satisfied(ob, sealed_at, tier)
        was_breached = self._breach_row(ob["obligation_id"], -1)

        if tier == "WORLD_DIVERGED":
            item["status"] = DIVERGED
        elif was_breached is not None:
            item["status"] = CURED
            self._cure(ob, was_breached, sealed_at)
        elif sealed_at > ob["due_at"]:
            item["status"] = LATE
            self.seal.record_event("obligation_late", path=ob["action"],
                                   detail={"obligation_id": ob["obligation_id"],
                                           "late_by_sec": sealed_at - ob["due_at"]})
        elif ob["require_world"] and tier != "WORLD_FINAL":
            item["status"] = SATISFIED_UNCONFIRMED
        else:
            item["status"] = SATISFIED
        item["sealed_at"] = sealed_at
        item["tier"] = tier
        return item

    # -- recurring duties ---------------------------------------------------
    def _sweep_recurring(self, ob: dict, now: float) -> list[dict]:
        """Evaluate every window whose deadline has fully passed, exactly once.

        A window's verdict is final at evaluation time: an effect that lands
        after the window closed does not cure it (last month's payroll run
        this month is still a miss for last month). Operators mark breaches
        remediated via resolve_breach(); history stays history.
        """
        out: list[dict] = []
        every, anchor = ob["every_sec"], ob["anchor_at"]
        n = ob["next_window"]
        tier_clause = " AND tier='WORLD_FINAL'" if ob["require_world"] else ""
        while anchor + (n + 1) * every + ob["grace_sec"] <= now:
            start, end = anchor + n * every, anchor + (n + 1) * every
            with self.seal._connect(autocommit=True) as c:
                count = c.execute(
                    "SELECT count(*) FROM seal_intents WHERE action=%s "
                    "AND state='sealed' AND created_at >= %s AND created_at < %s"
                    + tier_clause,
                    (ob["action"], start, end),
                ).fetchone()[0]
            item = {"obligation_id": ob["obligation_id"], "kind": "recurring",
                    "action": ob["action"], "window": n,
                    "window_start": start, "window_end": end,
                    "sealed_in_window": count, "required": ob["min_count"]}
            if count >= ob["min_count"]:
                item["status"] = SATISFIED
            else:
                item["status"] = BREACHED
                item["breach_id"] = self._record_breach(ob, window_n=n,
                                                        due_at=end, now=now)
            out.append(item)
            n += 1
        with self.seal._connect(autocommit=True) as c:
            c.execute(
                "UPDATE seal_obligations SET next_window=%s WHERE obligation_id=%s",
                (n, ob["obligation_id"]),
            )
        return out

    # -- breach mechanics ---------------------------------------------------
    def _breach_row(self, obligation_id: str, window_n: int):
        with self.seal._connect(autocommit=True) as c:
            return c.execute(
                "SELECT id, resolved_at FROM seal_obligation_breaches "
                "WHERE obligation_id=%s AND window_n=%s",
                (obligation_id, window_n),
            ).fetchone()

    def _record_breach(self, ob: dict, *, window_n: int, due_at: float,
                       now: float) -> int:
        """One breach per miss, decided in the store; the cert and the
        suspending event are written only by the sweep that wins the insert,
        so concurrent sweeps cannot double-report a silence."""
        existing = self._breach_row(ob["obligation_id"], window_n)
        if existing is not None:
            return existing[0]
        with self.seal._connect(autocommit=True) as c:
            row = c.execute(
                "INSERT INTO seal_obligation_breaches "
                "(obligation_id, window_n, action, due_at, detected_at) "
                "VALUES (%s,%s,%s,%s,%s) "
                "ON CONFLICT (obligation_id, window_n) DO NOTHING RETURNING id",
                (ob["obligation_id"], window_n, ob["action"], due_at, now),
            ).fetchone()
        if row is None:                       # a concurrent sweep won
            return self._breach_row(ob["obligation_id"], window_n)[0]
        breach_id = row[0]

        # The miss goes ON THE CHAIN. For a one-shot duty the cert names the
        # intent that should have existed, so a later incident export for
        # that intent surfaces the breach alongside whatever else is known.
        subject = (ob["expected_intent"] if window_n == -1
                   else f"{ob['obligation_id']}:w{window_n}")
        body = {
            "intent": subject,
            "action": ob["action"],
            "kind": "obligation_breach",
            "obligation_id": ob["obligation_id"],
            "window": None if window_n == -1 else window_n,
            "tier": TIER_OBLIGATION_BREACHED,
            "world": "missing",
            "due_at": due_at,
            "detected_at": now,
            "description": ob["description"],
            "at": now,
        }
        with self.seal._connect(autocommit=True) as c:
            with c.transaction():
                cert = self.seal._append_cert(c, body)
            c.execute(
                "UPDATE seal_obligation_breaches SET cert_hash=%s WHERE id=%s",
                (cert["hash"], breach_id),
            )
        # `domain` in the detail is what lets license.py scope the suspension
        # to exactly this path — same shape as out_of_band_spend.
        self.seal.record_event(
            "obligation_breached", path=ob["action"], intent=subject,
            detail={"obligation_id": ob["obligation_id"], "domain": ob["action"],
                    "window": None if window_n == -1 else window_n,
                    "due_at": due_at, "cert": cert["hash"]},
        )
        return breach_id

    def _cure(self, ob: dict, breach_row, sealed_at: float) -> None:
        breach_id, resolved_at = breach_row
        if resolved_at is None:
            with self.seal._connect(autocommit=True) as c:
                c.execute(
                    "UPDATE seal_obligation_breaches SET resolved_at=%s, "
                    "resolved_by='sweep', resolution='effect sealed after breach' "
                    "WHERE id=%s AND resolved_at IS NULL",
                    (sealed_at, breach_id),
                )
            self.seal.record_event("obligation_cured", path=ob["action"],
                                   detail={"obligation_id": ob["obligation_id"],
                                           "sealed_at": sealed_at})

    def _mark_satisfied(self, ob: dict, sealed_at: float, tier: str | None) -> None:
        if ob["satisfied_at"] is None:
            with self.seal._connect(autocommit=True) as c:
                c.execute(
                    "UPDATE seal_obligations SET satisfied_at=%s, satisfied_tier=%s "
                    "WHERE obligation_id=%s AND satisfied_at IS NULL",
                    (sealed_at, tier, ob["obligation_id"]),
                )
            self.seal.record_event("obligation_satisfied", path=ob["action"],
                                   detail={"obligation_id": ob["obligation_id"],
                                           "sealed_at": sealed_at, "tier": tier})
