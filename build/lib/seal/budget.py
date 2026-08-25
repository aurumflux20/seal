"""Cross-process spend budget — the guarantee actually enforced in the store.

WHY THIS EXISTS. `once-kernel`'s SpendLimiter keeps its entries in an in-memory
array. That bounds spend inside ONE process and nothing more: run two workers,
or a second MCP server, and each gets its own full budget. We had been pointing
findings at it as the cross-process fix, which was wrong — and a payments
engineer reviewing our own code told us so. He was right.

So the budget lives where the arbitration lives: in Postgres, with the check and
the write inside one transaction holding a lock on the budget row. Two processes
cannot both see headroom, because the second one waits for the first to commit.
That is the same discipline the fence uses, applied to money instead of identity.

    RESERVE  -> lock budget row, sum the window, refuse or insert a reservation
    SETTLE   -> the effect happened; the reservation stands
    RELEASE  -> the effect did NOT happen; the reservation is removed

Reserve BEFORE the effect, settle after. Checking a running total and then
acting is the exact check-then-act race we sell against; reserving first means
a concurrent caller sees the reservation, not a stale total.

Honest limit: this bounds spend that goes THROUGH the gateway. A process
holding raw provider credentials can still spend around it — see Exclusive
Authority. This is a control, not a law of physics.
"""
from __future__ import annotations

import time
from typing import Optional

from .core import Seal, SealError

BUDGET_SCHEMA = """
CREATE TABLE IF NOT EXISTS seal_budget (
    budget_key TEXT PRIMARY KEY,
    limit_amt  DOUBLE PRECISION NOT NULL,
    window_sec DOUBLE PRECISION NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS seal_spend (
    id         BIGSERIAL PRIMARY KEY,
    budget_key TEXT NOT NULL,
    intent     TEXT,
    amount     DOUBLE PRECISION NOT NULL,
    state      TEXT NOT NULL,          -- reserved | settled
    at         DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS seal_spend_key_at ON seal_spend (budget_key, at DESC);
"""


class BudgetExceeded(SealError):
    """This spend would breach the ceiling for its window."""

    def __init__(self, budget_key: str, limit: float, spent: float, attempted: float):
        self.budget_key, self.limit, self.spent, self.attempted = (
            budget_key, limit, spent, attempted)
        super().__init__(
            f"budget {budget_key!r} would be breached: "
            f"spent {spent} + attempted {attempted} > limit {limit}"
        )


class Reservation:
    def __init__(self, budget: "Budget", row_id: int, amount: float):
        self._b, self.id, self.amount = budget, row_id, amount
        self._resolved = False

    def settle(self) -> None:
        """The effect happened. The reservation becomes committed spend."""
        if self._resolved:
            return
        with self._b.seal._connect(autocommit=True) as c:
            c.execute("UPDATE seal_spend SET state='settled' WHERE id=%s", (self.id,))
        self._resolved = True

    def release(self) -> None:
        """The effect did NOT happen. Give the headroom back.

        Only safe when nothing irreversible occurred. If the effect may have
        fired, leave the reservation standing and let a witness decide —
        releasing budget for money that actually moved is how a cap silently
        drifts upward.
        """
        if self._resolved:
            return
        with self._b.seal._connect(autocommit=True) as c:
            c.execute("DELETE FROM seal_spend WHERE id=%s AND state='reserved'", (self.id,))
        self._resolved = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *_):
        # An exception before settle() means the effect did not complete.
        if exc_type is not None:
            self.release()
        return False


class Budget:
    """A spend ceiling enforced across every process sharing the store."""

    def __init__(self, seal: Seal):
        self.seal = seal

    def setup(self) -> None:
        with self.seal._connect(autocommit=True) as c:
            c.execute(BUDGET_SCHEMA)

    def set_limit(self, budget_key: str, limit: float, window_sec: float) -> None:
        if limit <= 0 or window_sec <= 0:
            raise ValueError("limit and window must be positive")
        with self.seal._connect(autocommit=True) as c:
            c.execute(
                """
                INSERT INTO seal_budget (budget_key, limit_amt, window_sec, updated_at)
                VALUES (%s,%s,%s,%s)
                ON CONFLICT (budget_key) DO UPDATE SET
                  limit_amt=EXCLUDED.limit_amt, window_sec=EXCLUDED.window_sec,
                  updated_at=EXCLUDED.updated_at
                """,
                (budget_key, limit, window_sec, time.time()),
            )

    def spent(self, budget_key: str) -> float:
        """Committed + reserved spend inside the window. Reservations count —
        money that is in flight is money you cannot spend twice."""
        with self.seal._connect(autocommit=True) as c:
            row = c.execute(
                "SELECT window_sec FROM seal_budget WHERE budget_key=%s", (budget_key,)
            ).fetchone()
            if row is None:
                return 0.0
            cutoff = time.time() - row[0]
            tot = c.execute(
                "SELECT COALESCE(SUM(amount),0) FROM seal_spend "
                "WHERE budget_key=%s AND at > %s",
                (budget_key, cutoff),
            ).fetchone()[0]
        return float(tot)

    def remaining(self, budget_key: str) -> float:
        with self.seal._connect(autocommit=True) as c:
            row = c.execute(
                "SELECT limit_amt FROM seal_budget WHERE budget_key=%s", (budget_key,)
            ).fetchone()
        if row is None:
            return 0.0
        return max(0.0, float(row[0]) - self.spent(budget_key))

    def reconcile_reservations(self, budget_key: str | None = None,
                               apply: bool = False) -> dict:
        """Resolve reservations whose worker never came back.

        A process that dies between `reserve()` and `settle()`/`release()`
        leaves a `reserved` row, and `spent()` counts it for the whole window —
        so every crash permanently narrows the ceiling until it ages out. On a
        30-day window that is 30 days of headroom lost per crash.

        The resolution is driven by the intent's own state, never by a guess,
        because the dangerous mistake here is releasing budget for money that
        actually moved:

            intent sealed        -> SETTLE. The effect is on the chain.
            intent gone          -> RELEASE. fail() deletes the row only when
                                    nothing irreversible happened.
            open, lease alive    -> leave it. Still in flight.
            open, lease expired  -> leave it, and REPORT it. The holder died
                                    mid-effect; only a witness can say whether
                                    the money moved, and guessing either way is
                                    the double-charge this library exists to
                                    stop.

        Reports by default. Pass `apply=True` to act.
        """
        where = "WHERE s.state='reserved'"
        params: list = []
        if budget_key is not None:
            where += " AND s.budget_key=%s"
            params.append(budget_key)

        now = time.time()
        settle, release, in_flight, needs_witness = [], [], [], []
        with self.seal._connect(autocommit=True) as c:
            rows = c.execute(
                f"SELECT s.id, s.budget_key, s.amount, s.intent, i.state, i.lease_until "
                f"FROM seal_spend s LEFT JOIN seal_intents i ON i.intent = s.intent "
                f"{where}",
                tuple(params),
            ).fetchall()

            for sid, bkey, amount, intent, istate, lease in rows:
                entry = {"spend_id": sid, "budget_key": bkey,
                         "amount": float(amount), "intent": intent}
                if intent is None:
                    in_flight.append(entry)          # not tied to an intent
                elif istate == "sealed":
                    settle.append(entry)
                elif istate is None:
                    release.append(entry)
                elif istate == "open" and lease is not None and lease < now:
                    needs_witness.append(entry)
                else:
                    in_flight.append(entry)

            if apply:
                if settle:
                    c.execute("UPDATE seal_spend SET state='settled' WHERE id = ANY(%s)",
                              ([e["spend_id"] for e in settle],))
                if release:
                    c.execute("DELETE FROM seal_spend WHERE state='reserved' AND id = ANY(%s)",
                              ([e["spend_id"] for e in release],))

        return {
            "applied": apply,
            "settled": settle,
            "released": release,
            "in_flight": in_flight,
            "needs_witness": needs_witness,
            "note": (
                "`needs_witness` reservations are NOT resolved automatically: "
                "the holder died mid-effect, and only the provider can say "
                "whether the money moved. Witness the intent, then settle or "
                "release deliberately."
            ),
        }

    def reserve(self, budget_key: str, amount: float, intent: str | None = None) -> Reservation:
        """Take headroom BEFORE the effect, atomically across processes.

        The budget row is locked FOR UPDATE, so a concurrent reserve on the same
        budget blocks until this one commits and then sums a total that already
        includes it. That is what makes the ceiling real rather than advisory.
        """
        if amount < 0:
            raise ValueError("amount must be >= 0")
        now = time.time()
        with self.seal._connect(autocommit=False) as c:
            with c.transaction():
                row = c.execute(
                    "SELECT limit_amt, window_sec FROM seal_budget "
                    "WHERE budget_key=%s FOR UPDATE",
                    (budget_key,),
                ).fetchone()
                if row is None:
                    raise SealError(f"no budget configured for {budget_key!r}")
                limit, window = float(row[0]), float(row[1])
                cutoff = now - window
                spent = float(c.execute(
                    "SELECT COALESCE(SUM(amount),0) FROM seal_spend "
                    "WHERE budget_key=%s AND at > %s",
                    (budget_key, cutoff),
                ).fetchone()[0])

                if spent + amount > limit:
                    raise BudgetExceeded(budget_key, limit, spent, amount)

                rid = c.execute(
                    "INSERT INTO seal_spend (budget_key, intent, amount, state, at) "
                    "VALUES (%s,%s,%s,'reserved',%s) RETURNING id",
                    (budget_key, intent, amount, now),
                ).fetchone()[0]
        return Reservation(self, rid, amount)
