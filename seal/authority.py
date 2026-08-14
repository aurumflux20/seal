"""Exclusive Authority — the gateway is the only holder of write credentials.

THE POWER SHIFT. Everything else in Seal is a control an agent can walk around
if it holds `sk_live` itself. Clearance is policy; the fence is a seatbelt;
both assume cooperation. Exclusive Authority removes the assumption:

    BEFORE   agent --holds sk_live--> Stripe        (Seal optional, bypassable)
    AFTER    agent --propose only---> Gateway --sk_live--> Stripe
                                        + admit / clear / budget / witness

An agent never receives a provider secret. It receives a TICKET: proof that an
intent was admitted, cleared and funded. It hands the ticket back to execute.
Bypass stops being a discipline problem and becomes theft from a vault.

CUSTODY MODEL — read this before selling it. The gateway holds the secret, and
the gateway runs INSIDE THE CUSTOMER'S OWN INFRASTRUCTURE. AurumFlux never
holds, sees, or transports a customer's live key. We ship software that takes
custody away from the agents; we do not take custody ourselves. Hosted custody
would make us a credential vault, which is a different company with a different
breach radius. Self-hosted custody delivers the same SOC story — "irreversible
writes require the gateway; agents cannot call the provider directly" — with
none of that liability.

HONEST LIMITS, stated because a security reviewer will ask:
  * A process on the same host that can read the gateway's environment can
    still steal the secret. This raises the bar to "steal from the vault"; it
    does not make bypass physically impossible.
  * The gateway becomes the critical path. If it is down, money stops. That is
    the price of a real rail, and it is why every failure here is fail-safe:
    unreachable means refuse, never guess.
  * Tickets are bearer proof. They are single-use and bound to one intent, so a
    stolen ticket buys one already-authorised action, not a blank cheque.
"""
from __future__ import annotations

import hmac
import os
import secrets
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Callable, Optional

from .core import Seal, SealError, _digest
from .clearance import Clearance


class AuthorityError(SealError):
    """The gateway refused to execute."""


class NoSuchExecutor(AuthorityError):
    """No executor is registered for this path — nothing can run."""


class InvalidTicket(AuthorityError):
    """The ticket is forged, expired, already spent, or for another intent."""


class TicketAlreadySpent(InvalidTicket):
    """This exact ticket has already been executed — proven from the STORE.

    Subclasses InvalidTicket so existing callers that catch InvalidTicket keep
    working. It is separate because it means something stronger and more
    useful: not "this ticket looks wrong" but "another process already called
    the provider with it, and we refused to do it again."
    """


@dataclass(frozen=True)
class Ticket:
    """What an agent gets instead of a credential.

    Carries no secret. Names one intent, and is worth exactly one execution of
    it — for the EXACT args that were proposed and cleared, not whatever args
    happen to be passed to execute() later. `args_digest` is bound into `sig`,
    so a caller cannot request a $1 charge, get it cleared and budgeted, then
    spend the ticket on a $999,999 charge. (Found by attacking our own build:
    the first version signed only intent/path/fence and let execute() take a
    fresh, unverified `args` — a real amount-substitution hole, not a demo one.)
    """
    intent: str
    path: str
    fence: str
    args_digest: str
    expires_at: float
    sig: str

    def to_dict(self) -> dict:
        return {"intent": self.intent, "path": self.path, "fence": self.fence,
                "args_digest": self.args_digest, "expires_at": self.expires_at,
                "sig": self.sig}


class Gateway:
    """The only principal that may call the provider.

    Executors are registered here — each one closes over the secret it needs, so
    the secret exists only inside the gateway process. `propose()` returns a
    ticket; `execute()` spends it. An agent that only ever sees tickets cannot
    call the provider even if it wants to.
    """

    def __init__(self, seal: Seal, ticket_key: bytes | None = None,
                 ticket_ttl_sec: float = 300.0):
        self.seal = seal
        self.clearance = Clearance(seal)
        # The ticket key never leaves the gateway. Generated if not supplied so
        # a misconfigured deployment fails closed rather than using a default.
        self._key = ticket_key or os.environ.get("SEAL_TICKET_KEY", "").encode() or secrets.token_bytes(32)
        self._ttl = ticket_ttl_sec
        self._executors: dict[str, Callable[[dict], Any]] = {}
        self._spent: set[str] = set()

    # ── registration: where secrets live, and nowhere else ────────────────
    def register_executor(self, path: str, fn: Callable[[dict], Any]) -> None:
        """Bind a path to the function that performs it.

        `fn` closes over the provider secret. Registering is the ONLY way an
        irreversible action becomes runnable, so an unregistered path simply
        cannot fire — a safe default that needs no policy to enforce.
        """
        self._executors[path] = fn

    def paths(self) -> list[str]:
        return sorted(self._executors)

    # ── ticket minting ────────────────────────────────────────────────────
    def _sign(self, intent: str, path: str, fence: str, args_digest: str, exp: float) -> str:
        msg = f"{intent}|{path}|{fence}|{args_digest}|{exp}".encode()
        return hmac.new(self._key, msg, sha256).hexdigest()

    def _verify(self, t: Ticket, args: Any) -> None:
        expected = self._sign(t.intent, t.path, t.fence, t.args_digest, t.expires_at)
        if not hmac.compare_digest(expected, t.sig):
            raise InvalidTicket("ticket signature does not verify")
        if time.time() > t.expires_at:
            raise InvalidTicket("ticket expired")
        if t.sig in self._spent:
            raise InvalidTicket("ticket already spent — tickets are single-use")
        # Bind execution to the args that were actually cleared. Without this,
        # a ticket proposed for $1 could be executed for any amount — the
        # signature would still verify, because intent/path/fence never
        # encoded the amount. This is the check that closes that hole.
        if _digest(args) != t.args_digest:
            raise InvalidTicket(
                "args at execute() do not match what was proposed and cleared — refusing"
            )

    # ── the agent-facing surface ──────────────────────────────────────────
    def propose(self, path: str, args: Any, key: str | None = None,
                domain: str | None = None, budget_key: str | None = None,
                amount: float | None = None, approval_id: str | None = None) -> dict:
        """An agent asks to act. It gets a ticket, a replayed result, a no, or
        (for amounts above the auto-clear ceiling) a request to go get a
        satisfied maker-checker approval first.

        Order is deliberate: clearance (may this path run at all?) → admission
        (is this intent already taken?) → graduated approval (does this AMOUNT
        need a second human?) → budget (is there headroom?). The cheapest and
        most absolute refusals come first.
        """
        if path not in self._executors:
            raise NoSuchExecutor(f"no executor registered for path {path!r}")

        # admit() itself enforces clearance and the domain freeze
        adm = self.seal.admit(path, args, key=key, domain=domain, path=path)

        if not adm.fresh:
            if adm.cert is not None:
                return {"status": "already_done", "intent": adm.intent, "cert": adm.cert}
            return {"status": "in_flight", "intent": adm.intent}

        # GRADUATED CLEARANCE — only meaningful when the caller states an
        # amount. A path's binary CLEARED does not, on its own, authorise a
        # single amount above the auto-ceiling; that needs a second human. If
        # this branch bails, release the admission (self.seal.fail) rather
        # than leaving a claimed-but-unusable intent sitting open.
        if amount is not None:
            from .graduated import (
                AUTO, APPROVED, GraduatedClearance, GraduatedError,
                ApprovalConsumed, ApprovalNotSatisfied,
            )
            gc = GraduatedClearance(self.seal)
            # Graduated clearance only engages for a path an operator has
            # explicitly configured with set_thresholds(). Passing `amount` to
            # propose() is also how ordinary Budget reservations work, and
            # those callers never opted into maker-checker — treating every
            # unconfigured path as ALWAYS_HUMAN here would silently block
            # every existing budget-only integration the moment it named an
            # amount. tier_for()'s own "no config -> ALWAYS_HUMAN" default is
            # still correct for a caller asking it directly; it is simply not
            # this gateway's job to apply that opinion to paths nobody asked
            # it to guard.
            configured = gc.get_thresholds(path) is not None
            tier = gc.tier_for(path, amount) if configured else AUTO
            if configured and tier != AUTO:
                if approval_id is None:
                    self.seal.fail(adm.intent, adm.fence, "needs graduated approval")
                    # An agent refused permission to spend is a countable
                    # control event, not a silent branch. Without this the
                    # Range Report shows "0 blocked" for a month in which the
                    # gateway stopped every large spend an agent attempted.
                    self.seal.record_event(
                        "approval_required", path=path, intent=adm.intent,
                        detail={"amount": amount, "tier": tier},
                    )
                    return {"status": "needs_approval", "intent": adm.intent, "tier": tier}
                appr = gc.get(approval_id)
                mismatch = (appr["intent"] != adm.intent or appr["path"] != path
                           or appr["amount"] != amount)
                if mismatch:
                    self.seal.fail(adm.intent, adm.fence, "approval does not match this proposal")
                    raise GraduatedError(
                        "approval_id does not match this exact intent/path/amount"
                    )
                if appr["state"] != APPROVED:
                    self.seal.fail(adm.intent, adm.fence, f"approval is {appr['state']}")
                    raise ApprovalNotSatisfied(
                        f"approval {approval_id!r} is {appr['state']!r}, needs {appr['required']} "
                        f"distinct approvals, has {appr['approve_count']}"
                    )
                if appr["consumed_at"] is not None:
                    self.seal.fail(adm.intent, adm.fence, "approval already consumed")
                    raise ApprovalConsumed(f"approval {approval_id!r} already spent")
                gc.consume(approval_id)   # single-use, marked atomically before minting

        # budget is reserved BEFORE the ticket is issued: a ticket that cannot
        # be funded should never exist.
        reservation = None
        if budget_key is not None and amount is not None:
            from .budget import Budget, BudgetExceeded
            try:
                reservation = Budget(self.seal).reserve(budget_key, amount, intent=adm.intent)
            except BudgetExceeded:
                self.seal.fail(adm.intent, adm.fence, "budget exceeded")
                raise

        exp = time.time() + self._ttl
        args_dig = _digest(args)
        t = Ticket(adm.intent, path, adm.fence, args_dig, exp,
                   self._sign(adm.intent, path, adm.fence, args_dig, exp))
        self._pending = getattr(self, "_pending", {})
        self._pending[t.sig] = reservation
        return {"status": "cleared", "intent": adm.intent, "ticket": t.to_dict()}

    def execute(self, ticket: dict | Ticket, args: Any) -> dict:
        """Spend a ticket. The gateway — not the agent — calls the provider."""
        t = ticket if isinstance(ticket, Ticket) else Ticket(**ticket)
        self._verify(t, args)
        fn = self._executors.get(t.path)
        if fn is None:
            raise NoSuchExecutor(f"no executor registered for path {t.path!r}")

        # DURABLE single-use claim, BEFORE the provider is touched.
        #
        # `self._spent` is process memory. A restarted gateway, or a second
        # replica sharing SEAL_TICKET_KEY (which replicas MUST share to work at
        # all), has an empty set — it re-verified a spent ticket, called the
        # provider a second time, and only then failed to seal. The agent saw
        # "NotFenceHolder" and read it as "it didn't work", while the money had
        # moved twice and the chain recorded once.
        #
        # That is check-then-act across processes: the exact defect this
        # library exists to prevent, inside this library. The guard has to live
        # where both processes can see it, and it has to be one atomic step.
        with self.seal._connect(autocommit=True) as c:
            claimed = c.execute(
                "INSERT INTO seal_tickets (sig, intent, path, spent_at) "
                "VALUES (%s,%s,%s,%s) ON CONFLICT (sig) DO NOTHING",
                (t.sig, t.intent, t.path, time.time()),
            ).rowcount
        if not claimed:
            self._spent.add(t.sig)   # keep local memory consistent with the store
            raise TicketAlreadySpent(
                f"ticket for intent {t.intent} was already spent — refusing to "
                "call the provider a second time"
            )

        pending = getattr(self, "_pending", {})
        reservation = pending.pop(t.sig, None)

        try:
            result = fn(args)                      # the ONLY place the secret is used
        except Exception as e:
            if reservation is not None:
                reservation.release()              # nothing happened; give budget back
            self.seal.fail(t.intent, t.fence, f"executor failed: {e!r}")
            raise

        self._spent.add(t.sig)
        if reservation is not None:
            reservation.settle()
        cert = self.seal.seal(t.intent, t.fence, result)
        return {"status": "executed", "intent": t.intent, "result": result, "cert": cert}
