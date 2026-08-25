"""Seal Mandate — the precondition a money tool cannot execute without.

Scoped honestly, and the scope is the whole point:

    On a Seal Gateway path, money tools cannot execute without a Mandate —
    and every Mandate is exportable proof of allowed · once · (optionally)
    world-checked · on this rail.

NOT "agent money is not allowed to run without Seal industry-wide." We do not
own the rail everyone else runs on, we cannot enforce anything on a process
that never talks to us, and claiming otherwise would be the exact overclaim
this library exists to argue against. What we CAN say — and back — is that on
a path the operator has put under Mandate, execution without one is refused.

What a Mandate actually is: one durable row binding the four things that were
separately true at propose() time —

    clearance   the path was CLEARED (and the proof behind that was green)
    approval    the amount's tier was satisfied — for DUAL, by distinct humans
    ticket      an args-bound, single-use authorisation to call the provider
    identity    the exact intent and args digest it is valid for

Before this module those four were enforced, but only *implicitly*, spread
across `propose()` and `execute()`. Nothing recorded WHY an execution was
permitted, and nothing could refuse an agent that skipped the gateway and used
bare `admit()` + its own credential. A Mandate makes the precondition explicit,
auditable, and — when a path is marked `require_mandate` — mandatory.

The gate it closes, stated plainly: `require_mandate` makes bypass *fail*
rather than merely being discouraged. It still cannot stop a process that holds
the credential and never touches Seal at all — nothing in software can — but it
removes the accidental path, and `reconcile.py` detects the deliberate one.
"""
from __future__ import annotations

import time
import uuid
from typing import Any

from .core import Seal, SealError, _digest

# Mandate lifecycle
ACTIVE = "active"        # minted, not yet spent
CONSUMED = "consumed"    # spent on exactly one execution
EXPIRED = "expired"      # TTL passed without being spent


class MandateError(SealError):
    """A Mandate was required and was missing, invalid, or already spent."""


class MandateRequired(MandateError):
    """This path is under Mandate and the caller did not present one.

    Raised by `admit()` when an agent tries to bypass the gateway and claim an
    intent directly. This is the hard gate.
    """


class MandateAlreadyConsumed(MandateError):
    """This Mandate was already spent. One Mandate authorises one execution."""


class Mandates:
    """Mint, verify and consume Mandates; mark paths as requiring one."""

    def __init__(self, seal: Seal, ttl_sec: float = 900.0):
        self.seal = seal
        self._ttl = ttl_sec

    # ── operator config: which paths are under Mandate ────────────────────
    def require(self, path: str, required: bool = True, by: str = "operator") -> None:
        """Put a path under Mandate (or take it out).

        Deliberately an operator action with no agent-facing tool: a path that
        could take itself out from under the gate is not a gate. `mcp_server`
        exposes no equivalent, for the same reason it exposes no unfreeze.
        """
        with self.seal._connect(autocommit=True) as c:
            c.execute(
                """
                INSERT INTO seal_mandate_paths (path, required, updated_at, updated_by)
                VALUES (%s,%s,%s,%s)
                ON CONFLICT (path) DO UPDATE SET
                  required=EXCLUDED.required, updated_at=EXCLUDED.updated_at,
                  updated_by=EXCLUDED.updated_by
                """,
                (path, bool(required), time.time(), by),
            )
        self.seal.record_event(
            "mandate_path_required" if required else "mandate_path_released",
            path=path, detail={"by": by},
        )

    def is_required(self, path: str) -> bool:
        with self.seal._connect(autocommit=True) as c:
            row = c.execute(
                "SELECT required FROM seal_mandate_paths WHERE path=%s", (path,)
            ).fetchone()
        return bool(row[0]) if row else False

    # ── minting ────────────────────────────────────────────────────────────
    def mint(self, *, intent: str, path: str, args_digest: str,
             amount: float | None = None, tier: str | None = None,
             approval_id: str | None = None, approvers: list | None = None,
             clearance: str | None = None) -> dict:
        """Record why this execution is permitted, at the moment it is permitted.

        Called by the Gateway after — and only after — clearance, admission and
        graduated approval have all passed. It does not re-check them; it is the
        durable evidence that they did pass, which is what a receipt later reads
        and what a dispute actually needs.
        """
        mid = uuid.uuid4().hex
        now = time.time()
        with self.seal._connect(autocommit=True) as c:
            c.execute(
                """
                INSERT INTO seal_mandates
                  (mandate_id, intent, path, args_digest, amount, tier,
                   approval_id, approvers, clearance, created_at, expires_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (mid, intent, path, args_digest, amount, tier, approval_id,
                 _jsonb_list(approvers), clearance, now, now + self._ttl),
            )
        self.seal.record_event("mandate_minted", path=path, intent=intent,
                               detail={"mandate_id": mid, "amount": amount, "tier": tier})
        return self.get(mid)

    def get(self, mandate_id: str) -> dict | None:
        with self.seal._connect(autocommit=True) as c:
            row = c.execute(
                "SELECT mandate_id, intent, path, args_digest, amount, tier, "
                "approval_id, approvers, clearance, created_at, expires_at, consumed_at "
                "FROM seal_mandates WHERE mandate_id=%s",
                (mandate_id,),
            ).fetchone()
        if row is None:
            return None
        (mid, intent, path, ad, amount, tier, appr_id, approvers,
         clearance, created, expires, consumed) = row
        state = (CONSUMED if consumed else
                 (EXPIRED if time.time() > expires else ACTIVE))
        return {
            "mandate_id": mid, "intent": intent, "path": path,
            "args_digest": ad, "amount": amount, "tier": tier,
            "approval_id": appr_id, "approvers": approvers or [],
            "clearance": clearance, "created_at": created,
            "expires_at": expires, "consumed_at": consumed, "state": state,
        }

    def for_intent(self, intent: str) -> dict | None:
        """The Mandate covering this intent, if any. Used by the receipt."""
        with self.seal._connect(autocommit=True) as c:
            row = c.execute(
                "SELECT mandate_id FROM seal_mandates WHERE intent=%s "
                "ORDER BY created_at DESC LIMIT 1",
                (intent,),
            ).fetchone()
        return self.get(row[0]) if row else None

    # ── spending ───────────────────────────────────────────────────────────
    def consume(self, mandate_id: str, *, intent: str, args_digest: str) -> dict:
        """Spend a Mandate. Atomic, single-use, and bound to intent + args.

        The UPDATE carries `consumed_at IS NULL` in its WHERE clause, so two
        processes racing the same Mandate cannot both win — same idiom as the
        ticket claim, and for the same reason: a guard that lives anywhere but
        the store is not a guard across processes.
        """
        m = self.get(mandate_id)
        if m is None:
            raise MandateError(f"no such mandate {mandate_id!r}")
        if m["intent"] != intent:
            raise MandateError("mandate is for a different intent")
        if m["args_digest"] != args_digest:
            raise MandateError(
                "args at execute() do not match what this mandate authorised"
            )
        if m["state"] == EXPIRED:
            raise MandateError(f"mandate {mandate_id!r} expired")

        now = time.time()
        with self.seal._connect(autocommit=True) as c:
            n = c.execute(
                "UPDATE seal_mandates SET consumed_at=%s "
                "WHERE mandate_id=%s AND consumed_at IS NULL",
                (now, mandate_id),
            ).rowcount
        if not n:
            raise MandateAlreadyConsumed(
                f"mandate {mandate_id!r} was already spent — one mandate, one execution"
            )
        self.seal.record_event("mandate_consumed", path=m["path"], intent=intent,
                               detail={"mandate_id": mandate_id})
        return self.get(mandate_id)


def _jsonb_list(v: list | None):
    from .core import _jsonb
    return _jsonb(v) if v is not None else None
