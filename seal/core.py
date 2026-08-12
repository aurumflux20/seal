"""
Seal — settlement for irreversible agent actions, across processes.

`once` proves one process didn't run an effect twice. EffectFence proves one
MCP server didn't. Neither answers the question that actually breaks multi-agent
systems: two *different* agents, on two *different* machines, both decide to
charge order 123 at the same instant. The guard has to live in a store they
both talk to, and the winner has to be decided atomically there — not in either
process's memory.

Seal is that layer. Every irreversible action is:

  1. PROPOSED  — an intent, content-addressed by (action, args-digest).
  2. ADMITTED  — exactly one caller wins the right to run it; a durable
                 Postgres row is the single source of truth, claimed with
                 INSERT ... ON CONFLICT DO NOTHING (one row, one winner).
  3. SEALED    — on success, a certificate is written: a content-addressed
                 hash over intent + args digest + result digest + the previous
                 cert's hash. Tampering breaks the chain by arithmetic.
  4. REPLAYED  — every later caller for the same intent gets the sealed cert
                 back and is told to STAND DOWN. The effect never re-runs.

Honesty boundary, carried in the cert from v1 so v2 can't break the format:
a Seal proves an action was ADMITTED exactly once at this gateway. It does NOT
prove the world settled it — `world` is "unconfirmed" until a provider adapter
says otherwise. "We admitted this once" and "Stripe took the money" are
different claims, and Seal never conflates them.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional

import psycopg


# ── canonical hashing ─────────────────────────────────────────────────────
# JSON with sorted keys + no whitespace. Good enough for a single-language
# store; the cross-language RFC 8785 kernel is the upgrade if two languages
# ever seal into the same chain.
def _digest(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


GENESIS = "0" * 64


def intent_id(action: str, args: Any) -> str:
    """Content-addressed intent id: same action + same args → same intent.

    This is the whole ballgame. Too narrow and two genuinely different actions
    collide (one silently vanishes). Too wide and a legitimate retry looks new
    (double effect). The caller owns what goes into `args`; Seal only hashes it.
    """
    return _digest({"action": action, "args": args})


@dataclass(frozen=True)
class Admission:
    fresh: bool           # True = you won, run the effect. False = stand down.
    intent: str
    fence: str            # your claim token; only you may seal this intent
    cert: Optional[dict]  # present when fresh is False: the sealed result


SCHEMA = """
CREATE TABLE IF NOT EXISTS seal_intents (
    intent      TEXT PRIMARY KEY,
    action      TEXT NOT NULL,
    args_digest TEXT NOT NULL,
    state       TEXT NOT NULL,                 -- open | sealed | fenced | failed
    fence       TEXT NOT NULL,
    lease_until DOUBLE PRECISION NOT NULL,
    cert        JSONB,
    created_at  DOUBLE PRECISION NOT NULL,
    updated_at  DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS seal_certs (
    seq        BIGSERIAL PRIMARY KEY,
    intent     TEXT NOT NULL,
    hash       TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    body       JSONB NOT NULL,
    created_at DOUBLE PRECISION NOT NULL
);
"""


class Seal:
    def __init__(self, dsn: str, lease_sec: float = 30.0, connect_tries: int = 8):
        self.dsn = dsn
        self.lease_sec = lease_sec
        self._connect_tries = connect_tries

    def _connect(self, *, autocommit: bool):
        # Pin the client encoding to UTF-8 explicitly. A store created under a
        # C locale is SQL_ASCII, and psycopg then hands back `bytes` for every
        # TEXT column rather than `str` — args_digest and the cert body would
        # silently become unhashable/unserialisable. A settlement kernel must
        # behave the same whatever encoding the customer's Postgres was
        # initialised with, so we never leave this to chance.
        #
        # Bounded retry on the CONNECTION ONLY. A burst of simultaneous callers
        # can briefly overflow the server's accept backlog and get "connection
        # refused" — a transient blip, not a store that is down. Retrying to
        # *open a socket* is always safe: it performs no effect and repeats no
        # write. (It is emphatically NOT a retry of the irreversible action —
        # that is what admission already made exactly-once.) After the budget
        # is spent we raise, and the caller's only safe move is to stand down —
        # which is the correct fail-safe when the store is genuinely
        # unreachable. Production should put a real pool in front of this; the
        # retry just stops a backlog spike from turning a won admission into a
        # lost certificate.
        last: Exception | None = None
        delay = 0.02
        for _ in range(self._connect_tries):
            try:
                return psycopg.connect(
                    self.dsn, autocommit=autocommit, client_encoding="UTF8"
                )
            except psycopg.OperationalError as e:
                last = e
                time.sleep(delay)
                delay = min(delay * 2, 0.5)
        assert last is not None
        raise last

    def setup(self) -> None:
        with self._connect(autocommit=True) as c:
            c.execute(SCHEMA)

    # ── admission: the atomic single-winner claim ─────────────────────────
    def admit(self, action: str, args: Any) -> Admission:
        iid = intent_id(action, args)
        args_dig = _digest(args)
        fence = uuid.uuid4().hex
        now = time.time()
        lease = now + self.lease_sec

        with self._connect(autocommit=True) as c:
            # One statement decides the winner. ON CONFLICT DO NOTHING means the
            # second concurrent caller inserts nothing and RETURNING is empty —
            # there is no check-then-act window for anyone to slip through.
            row = c.execute(
                """
                INSERT INTO seal_intents
                    (intent, action, args_digest, state, fence, lease_until, created_at, updated_at)
                VALUES (%s, %s, %s, 'open', %s, %s, %s, %s)
                ON CONFLICT (intent) DO NOTHING
                RETURNING intent
                """,
                (iid, action, args_dig, fence, lease, now, now),
            ).fetchone()

            if row is not None:
                return Admission(fresh=True, intent=iid, fence=fence, cert=None)

            # Someone else holds it. Read the current state to decide the answer.
            cur = c.execute(
                "SELECT state, cert, lease_until, fence FROM seal_intents WHERE intent=%s",
                (iid,),
            ).fetchone()
            if cur is None:
                # Raced with a delete — treat as fresh-eligible on one retry.
                return self.admit(action, args)

            state, cert, lease_until, _held_fence = cur
            if state == "sealed":
                return Admission(fresh=False, intent=iid, fence="", cert=cert)
            if state == "open" and lease_until < now:
                # The holder crashed mid-effect. Reclaim atomically: only if the
                # lease is still dead at write time (another reclaimer may beat us).
                took = c.execute(
                    """
                    UPDATE seal_intents
                       SET fence=%s, lease_until=%s, updated_at=%s
                     WHERE intent=%s AND state='open' AND lease_until < %s
                    RETURNING intent
                    """,
                    (fence, now + self.lease_sec, now, iid, now),
                ).fetchone()
                if took is not None:
                    return Admission(fresh=True, intent=iid, fence=fence, cert=None)
            # Held and alive, or lost the reclaim race, or failed/fenced.
            return Admission(fresh=False, intent=iid, fence="", cert=cert)

    # ── seal: write the certificate after the effect ran ──────────────────
    def seal(self, intent: str, fence: str, result: Any) -> dict:
        now = time.time()
        with self._connect(autocommit=True) as c:
            with c.transaction():
                # Only the fence holder may seal, and only while still open.
                held = c.execute(
                    "SELECT args_digest FROM seal_intents WHERE intent=%s AND fence=%s AND state='open' FOR UPDATE",
                    (intent, fence),
                ).fetchone()
                if held is None:
                    raise PermissionError("not the fence holder, or already sealed")
                args_digest = held[0]

                prev = c.execute(
                    "SELECT hash FROM seal_certs ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                prev_hash = prev[0] if prev else GENESIS

                body = {
                    "intent": intent,
                    "args_digest": args_digest,
                    "result_digest": _digest(result),
                    "world": "unconfirmed",   # v1 never claims world settlement
                    "prev_hash": prev_hash,
                    "at": now,
                }
                cert_hash = _digest(body)
                cert = {**body, "hash": cert_hash}

                c.execute(
                    "INSERT INTO seal_certs (intent, hash, prev_hash, body, created_at) VALUES (%s,%s,%s,%s,%s)",
                    (intent, cert_hash, prev_hash, json.dumps(cert), now),
                )
                c.execute(
                    "UPDATE seal_intents SET state='sealed', cert=%s, updated_at=%s WHERE intent=%s",
                    (json.dumps(cert), now, intent),
                )
                return cert

    def fail(self, intent: str, fence: str, reason: str) -> None:
        """Release a claim so the intent can be legitimately retried later."""
        now = time.time()
        with self._connect(autocommit=True) as c:
            # Delete the open row so the same intent is fresh-eligible again.
            c.execute(
                "DELETE FROM seal_intents WHERE intent=%s AND fence=%s AND state='open'",
                (intent, fence),
            )

    # ── audit: verify the whole cert chain from the store alone ───────────
    def verify_chain(self) -> dict:
        with self._connect(autocommit=False) as c:
            rows = c.execute(
                "SELECT seq, hash, prev_hash, body FROM seal_certs ORDER BY seq ASC"
            ).fetchall()
        prev = GENESIS
        for i, (seq, h, ph, body) in enumerate(rows):
            if ph != prev:
                return {"ok": False, "at": i, "why": "chain link broken"}
            recomputed = _digest({k: body[k] for k in
                                  ("intent", "args_digest", "result_digest", "world", "prev_hash", "at")})
            if recomputed != h or body["hash"] != h:
                return {"ok": False, "at": i, "why": "cert altered since written"}
            prev = h
        return {"ok": True, "certs": len(rows)}
