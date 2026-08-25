"""Graduated Clearance — maker-checker approval for the amounts that matter.

Clearance answers "may this PATH run unattended at all." That is binary and it
is enough for a $5 API call. It is not enough for a $50,000 payout, because no
finance org signs off on "the path is cleared" as the entire control — they
sign off on segregation of duties: the person who PROPOSES a spend is never
the same person who APPROVES it, and every approval is on the record.

Three tiers per path, by amount:

    AUTO           <= auto_ceiling        normal Clearance (earned by proof) applies
    DUAL           <= dual_ceiling        needs N distinct human approvers, maker excluded
    ALWAYS_HUMAN   >  dual_ceiling        same mechanic as DUAL — the name marks that no
                                          policy change ever routes this tier to AUTO

The property an auditor actually checks, made structural rather than advisory:

1. **The maker cannot approve their own request.** Not a UI hint — `add_vote`
   raises if `approver == maker`.
2. **One approver cannot be counted twice.** Enforced by a UNIQUE constraint in
   Postgres on (approval_id, approver), so it holds even if two votes from the
   same person land in the same instant — there is no window for an app-level
   check-then-act race to slip through, which is the exact bug class this
   whole project exists to close everywhere else.
3. **A single reject is terminal.** Real approval workflows do not average
   objections away.
4. **An approval is single-use.** Spending it against a second execution is
   exactly the ticket-replay bug Exclusive Authority already closes, applied
   to the human decision instead of the machine one.
5. **Every decided approval is appended into the SAME hash chain as certs**
   (via `Seal._append_cert`), not a side table nobody audits. `seal verify`
   covers governance decisions the same way it covers execution certs.

Honest limit: v0 signs votes with one shared governance key (`SEAL_GOV_KEY`),
which proves a vote was minted by code holding that key, not by a specific
individual. Per-approver signing keys are the natural v1 hardening; recorded
here so the gap is not quietly forgotten.
"""
from __future__ import annotations

import hmac
import os
import secrets
import time
import uuid
from dataclasses import dataclass
from hashlib import sha256
from typing import Optional

from .core import Seal, SealError

AUTO = "AUTO"
DUAL = "DUAL"
ALWAYS_HUMAN = "ALWAYS_HUMAN"

APPROVE = "approve"
REJECT = "reject"

PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"
EXPIRED = "expired"

DEFAULT_TTL_SEC = 24 * 60 * 60  # a pending approval that nobody acts on expires, not lingers


class GraduatedError(SealError):
    pass


class SelfApproval(GraduatedError):
    """The maker tried to approve their own request. This is the one rule
    maker-checker exists to enforce; it is never configurable away."""


class ApprovalNotSatisfied(GraduatedError):
    """Not enough distinct, valid approvals yet to execute this tier."""


class ApprovalConsumed(GraduatedError):
    """This approval already authorised one execution. Single-use, like a ticket."""


@dataclass(frozen=True)
class Threshold:
    path: str
    auto_ceiling: float
    dual_ceiling: float
    required_approvers: int


class GraduatedClearance:
    def __init__(self, seal: Seal, gov_key: bytes | None = None):
        self.seal = seal
        configured = gov_key or os.environ.get("SEAL_GOV_KEY", "").encode()
        # An unconfigured deployment used to get secrets.token_bytes(32) with
        # no signal at all. That key dies with the process, so votes signed by
        # one replica could never be checked by another and nothing survived a
        # restart — the signature looked like evidence and proved nothing.
        # The fallback stays (refusing here would lock an operator out of
        # their own approval queue), but it is now recorded, so verify_votes()
        # and the receipt can say plainly how much the signature is worth.
        self._ephemeral_key = not configured
        self._key = configured or secrets.token_bytes(32)

    # ── thresholds ──────────────────────────────────────────────────────
    def set_thresholds(self, path: str, auto_ceiling: float, dual_ceiling: float,
                       required_approvers: int = 2, by: str = "operator") -> Threshold:
        if auto_ceiling < 0 or dual_ceiling < auto_ceiling:
            raise ValueError("need 0 <= auto_ceiling <= dual_ceiling")
        if required_approvers < 2:
            raise ValueError("required_approvers must be >= 2 — that is the whole point")
        with self.seal._connect(autocommit=True) as c:
            c.execute(
                """
                INSERT INTO seal_thresholds (path, auto_ceiling, dual_ceiling, required_approvers, updated_at, updated_by)
                VALUES (%s,%s,%s,%s,%s,%s)
                ON CONFLICT (path) DO UPDATE SET
                  auto_ceiling=EXCLUDED.auto_ceiling, dual_ceiling=EXCLUDED.dual_ceiling,
                  required_approvers=EXCLUDED.required_approvers,
                  updated_at=EXCLUDED.updated_at, updated_by=EXCLUDED.updated_by
                """,
                (path, auto_ceiling, dual_ceiling, required_approvers, time.time(), by),
            )
        return Threshold(path, auto_ceiling, dual_ceiling, required_approvers)

    def get_thresholds(self, path: str) -> Optional[Threshold]:
        with self.seal._connect(autocommit=True) as c:
            row = c.execute(
                "SELECT auto_ceiling, dual_ceiling, required_approvers FROM seal_thresholds WHERE path=%s",
                (path,),
            ).fetchone()
        return Threshold(path, *row) if row else None

    def tier_for(self, path: str, amount: float) -> str:
        """No threshold configured for a path is the SAFEST failure, not the
        most permissive: treat it as ALWAYS_HUMAN rather than silently AUTO."""
        th = self.get_thresholds(path)
        if th is None:
            return ALWAYS_HUMAN
        if amount <= th.auto_ceiling:
            return AUTO
        if amount <= th.dual_ceiling:
            return DUAL
        return ALWAYS_HUMAN

    # ── requesting approval ─────────────────────────────────────────────
    def request(self, path: str, amount: float, maker: str, intent: str,
               ttl_sec: float = DEFAULT_TTL_SEC) -> dict:
        tier = self.tier_for(path, amount)
        if tier == AUTO:
            raise GraduatedError(f"amount {amount} on {path!r} is AUTO tier — no approval needed")
        th = self.get_thresholds(path)
        required = th.required_approvers if th else 2
        now = time.time()
        aid = uuid.uuid4().hex
        with self.seal._connect(autocommit=True) as c:
            c.execute(
                """
                INSERT INTO seal_approvals
                    (id, intent, path, amount, maker, tier, state, required, created_at, expires_at)
                VALUES (%s,%s,%s,%s,%s,%s,'pending',%s,%s,%s)
                """,
                (aid, intent, path, amount, maker, tier, required, now, now + ttl_sec),
            )
        self.seal.record_event("approval_requested", path=path, intent=intent,
                               detail={"approval_id": aid, "amount": amount, "maker": maker, "tier": tier})
        return self.get(aid)

    # ── voting ───────────────────────────────────────────────────────────
    def _sign_vote(self, approval_id: str, approver: str, decision: str, at: float) -> str:
        msg = f"{approval_id}|{approver}|{decision}|{at}".encode()
        return hmac.new(self._key, msg, sha256).hexdigest()

    def add_vote(self, approval_id: str, approver: str, decision: str) -> dict:
        """Record one vote and, if it settles the request, decide it.

        Structured so that any raise happens AFTER the transaction below has
        cleanly committed, never from inside it. `c.transaction()` rolls back
        on an exception raised within its block — so a first version of this
        method that wrote `state='expired'` and then `raise`d from inside the
        block silently discarded that very write. The write must land, and
        only then may the caller be told why the vote didn't count.
        """
        if decision not in (APPROVE, REJECT):
            raise ValueError("decision must be 'approve' or 'reject'")

        now = time.time()
        # what happened, decided while still holding the row lock; acted on
        # (raised / returned) only after the block below has committed.
        outcome: str | None = None       # None | "not_found" | "self" | "not_pending" | "expired" | "dup_vote"
        detail = ""

        with self.seal._connect(autocommit=False) as c:
            with c.transaction():
                row = c.execute(
                    "SELECT maker, state, required, expires_at, intent, path FROM seal_approvals "
                    "WHERE id=%s FOR UPDATE",
                    (approval_id,),
                ).fetchone()
                if row is None:
                    outcome = "not_found"
                else:
                    maker, state, required, expires_at, intent, path = row

                    # THE RULE. Structural, not a UI hint: the code path that
                    # would let a maker approve their own request does not exist.
                    if approver == maker:
                        outcome = "self"
                    elif state != PENDING:
                        outcome = "not_pending"; detail = state
                    elif now > expires_at:
                        c.execute(
                            "UPDATE seal_approvals SET state='expired' WHERE id=%s",
                            (approval_id,),
                        )
                        outcome = "expired"
                    else:
                        sig = self._sign_vote(approval_id, approver, decision, now)
                        try:
                            c.execute(
                                "INSERT INTO seal_approval_votes (approval_id, approver, decision, at, sig) "
                                "VALUES (%s,%s,%s,%s,%s)",
                                (approval_id, approver, decision, now, sig),
                            )
                        except Exception:
                            # UNIQUE (approval_id, approver) fired: this approver
                            # already voted. The DB enforces "one approver counts
                            # once" — not something a caller can retry past.
                            outcome = "dup_vote"
                        else:
                            if decision == REJECT:
                                self._decide(c, approval_id, intent, path, REJECTED)
                            else:
                                n = c.execute(
                                    "SELECT count(*) FROM seal_approval_votes "
                                    "WHERE approval_id=%s AND decision='approve'",
                                    (approval_id,),
                                ).fetchone()[0]
                                if n >= required:
                                    self._decide(c, approval_id, intent, path, APPROVED)
                # falling through here (no raise) lets the transaction commit
                # cleanly, whatever `outcome` ended up being.

        if outcome == "not_found":
            raise GraduatedError(f"no such approval {approval_id!r}")
        if outcome == "self":
            raise SelfApproval(f"{approver!r} is the maker of this request and cannot approve it")
        if outcome == "not_pending":
            raise GraduatedError(f"approval {approval_id!r} is already {detail}, not pending")
        if outcome == "expired":
            raise GraduatedError(f"approval {approval_id!r} expired")
        if outcome == "dup_vote":
            raise GraduatedError(
                f"{approver!r} already voted on {approval_id!r} — one approver, one vote"
            )
        return self.get(approval_id)

    def _decide(self, c, approval_id: str, intent: str, path: str, outcome: str) -> dict:
        """Finalise an approval and append the decision into the SAME chain the
        execution certs live in — governance and execution, one audit trail."""
        now = time.time()
        votes = c.execute(
            "SELECT approver, decision, at, sig FROM seal_approval_votes WHERE approval_id=%s ORDER BY at",
            (approval_id,),
        ).fetchall()
        body = {
            "intent": f"approval:{approval_id}",
            "action": "graduated_approval",
            "args_digest": approval_id,
            "result_digest": None,
            "tier": "SEALED",
            "world": "unconfirmed",
            "approval_id": approval_id,
            "underlying_intent": intent,
            "path": path,
            "outcome": outcome,
            "votes": [{"approver": a, "decision": d, "at": t, "sig": s} for a, d, t, s in votes],
            "at": now,
        }
        cert = self.seal._append_cert(c, body)
        c.execute(
            "UPDATE seal_approvals SET state=%s, decided_at=%s WHERE id=%s",
            (outcome, now, approval_id),
        )
        self.seal.record_event("approval_decided", path=path, intent=intent,
                               detail={"approval_id": approval_id, "outcome": outcome})
        return cert

    # ── status + consumption ────────────────────────────────────────────
    def get(self, approval_id: str) -> dict:
        with self.seal._connect(autocommit=True) as c:
            row = c.execute(
                "SELECT intent, path, amount, maker, tier, state, required, "
                "created_at, expires_at, decided_at, consumed_at FROM seal_approvals WHERE id=%s",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise GraduatedError(f"no such approval {approval_id!r}")
            votes = c.execute(
                "SELECT approver, decision, at FROM seal_approval_votes WHERE approval_id=%s ORDER BY at",
                (approval_id,),
            ).fetchall()
        keys = ("intent", "path", "amount", "maker", "tier", "state", "required",
                "created_at", "expires_at", "decided_at", "consumed_at")
        out = dict(zip(keys, row))
        out["id"] = approval_id
        out["votes"] = [{"approver": a, "decision": d, "at": t} for a, d, t in votes]
        out["approve_count"] = sum(1 for v in out["votes"] if v["decision"] == APPROVE)
        return out

    def verify_votes(self, approval_id: str) -> dict:
        """Recompute every vote signature and say whether it still holds.

        `_sign_vote` was previously only ever CALLED — nothing in the codebase
        read the `sig` column back, so a tampered vote row verified as
        happily as an honest one. (Tickets always did this properly in
        authority.py; approvals did not.) A signature nobody checks is
        decoration, and this is the check.

        `ephemeral_key` is reported alongside the result rather than buried:
        under a process-generated key the signatures cannot mean anything to
        another replica or after a restart, and a reader deserves to know that
        before treating a green result as proof of who voted.
        """
        with self.seal._connect(autocommit=True) as c:
            votes = c.execute(
                "SELECT approver, decision, at, sig FROM seal_approval_votes "
                "WHERE approval_id=%s ORDER BY at",
                (approval_id,),
            ).fetchall()

        checked, bad = [], []
        for approver, decision, at, sig in votes:
            expected = self._sign_vote(approval_id, approver, decision, at)
            ok = hmac.compare_digest(expected, sig or "")
            checked.append({"approver": approver, "decision": decision,
                            "at": at, "signature_ok": ok})
            if not ok:
                bad.append(approver)

        return {
            "approval_id": approval_id,
            "votes": checked,
            "ok": not bad and bool(votes),
            "unverified": bad,
            "ephemeral_key": self._ephemeral_key,
            "note": (
                "SEAL_GOV_KEY is not configured, so these signatures were made "
                "with a per-process key: they cannot be verified by another "
                "replica or after a restart, and prove nothing about WHO voted."
                if self._ephemeral_key else
                "Signatures verified against the configured governance key. "
                "v0 signs with one shared key, so this proves a vote was minted "
                "by code holding that key, not by a specific individual."
            ),
        }

    def consume(self, approval_id: str) -> None:
        """Mark an approval spent. Called once by the gateway at execute() time
        so a satisfied approval cannot authorise a second execution — the same
        single-use discipline as a ticket, applied to the human decision."""
        now = time.time()
        with self.seal._connect(autocommit=False) as c:
            with c.transaction():
                row = c.execute(
                    "SELECT state, consumed_at FROM seal_approvals WHERE id=%s FOR UPDATE",
                    (approval_id,),
                ).fetchone()
                if row is None:
                    raise GraduatedError(f"no such approval {approval_id!r}")
                state, consumed_at = row
                if state != APPROVED:
                    raise ApprovalNotSatisfied(f"approval {approval_id!r} is {state}, not approved")
                if consumed_at is not None:
                    raise ApprovalConsumed(f"approval {approval_id!r} already consumed")
                c.execute("UPDATE seal_approvals SET consumed_at=%s WHERE id=%s", (now, approval_id))
