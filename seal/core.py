"""
Seal — settlement for irreversible agent actions, across processes.

`once` proves one process didn't run an effect twice. EffectFence proves one
MCP server didn't. Neither answers the question that actually breaks multi-agent
systems: two *different* agents, on two *different* machines, both decide to
charge order 123 at the same instant. The guard has to live in a store they
both talk to, and the winner has to be decided atomically there — not in either
process's memory.

Seal is that layer. Every irreversible action is:

  1. PROPOSED  — an intent, identified by a caller-supplied stable key
                 (`charge:order-777`) or content-addressed from its args.
  2. ADMITTED  — exactly one caller wins the right to run it; a durable
                 Postgres row is the single source of truth, claimed with
                 INSERT ... ON CONFLICT DO NOTHING (one row, one winner).
  3. SEALED    — on success, a certificate is written: a content-addressed
                 hash over the cert body + the previous cert's hash.
                 Tampering breaks the chain by arithmetic.
  4. WITNESSED — a provider adapter re-checks the outside world and appends a
                 NEW cert upgrading the tier. The chain is append-only, so
                 witnessing never rewrites history.
  5. REPLAYED  — every later caller for the same intent gets the sealed cert
                 back and is told to STAND DOWN. The effect never re-runs.

Honesty boundary, carried in the cert from v1 so v2 can't break the format:
a SEALED cert proves an action was ADMITTED exactly once at this gateway. It
does NOT prove the world settled it — `world` stays "unconfirmed" until a
witness says otherwise. "We admitted this once" and "Stripe took the money"
are different claims, and Seal never conflates them.
"""
from __future__ import annotations

import datetime
import decimal
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
def _ascii_safe(obj):
    """Recursively replace non-ASCII characters in strings.

    A Postgres created under a C locale is SQL_ASCII, and it rejects a JSONB
    value containing non-ASCII -- INCLUDING a \\uXXXX escape, which it still
    tries to translate into the server encoding and fails with
    UntranslatableCharacter. So ensure_ascii is not enough: the characters must
    be gone from the data, not merely escaped.

    A settlement kernel must never fail to record an event because a customer
    initialised their database with a different encoding -- losing the audit
    trail is far worse than losing a typographic dash. Characters are swapped
    for a close ASCII equivalent where one exists, and dropped otherwise.
    """
    if isinstance(obj, str):
        if obj.isascii():
            return obj
        swaps = {"\u2014": "-", "\u2013": "-", "\u2018": "'", "\u2019": "'",
                 "\u201c": '"', "\u201d": '"', "\u2026": "...",
                 "\u2192": "->", "\u00a0": " "}
        out = "".join(swaps.get(ch, ch) for ch in obj)
        return out.encode("ascii", "ignore").decode("ascii")
    if isinstance(obj, dict):
        return {_ascii_safe(k): _ascii_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_ascii_safe(v) for v in obj]
    return obj


def _jsonb(obj) -> str:
    """Serialize for JSONB storage on any Postgres encoding. See _ascii_safe."""
    return json.dumps(_ascii_safe(obj), default=str, ensure_ascii=True)


class UnstableDigestInput(TypeError):
    """A value was handed to _digest() that has no stable serialisation.

    `default=str` used to swallow these. For an object with no custom __str__
    that means hashing `<Money object at 0x7f...>` — a MEMORY ADDRESS. Two
    attempts at the same logical action then produce two different intent ids,
    so content-addressed `admit()` admits both and the effect runs TWICE. The
    identical hazard applies to `result_digest`, which stops being
    content-addressed at all.

    A settlement kernel cannot hash something it cannot reproduce, so this is
    now a loud refusal at the call site instead of a silent double-charge
    later. Pass a JSON-native value, or an explicit `key=` to intent_id().
    """


# Types whose str() is stable across processes and runs. These already
# serialised via `default=str`, so keeping them preserves every digest an
# existing store has already written — the tightening is strictly additive.
_STABLE_STR_TYPES = (
    datetime.datetime, datetime.date, datetime.time,
    decimal.Decimal, uuid.UUID,
)


def _stable_default(o: Any):
    if isinstance(o, _STABLE_STR_TYPES):
        return str(o)
    raise UnstableDigestInput(
        f"{type(o).__name__} has no stable serialisation, so any hash over it "
        f"would depend on this process's memory layout. Convert it to a "
        f"JSON-native value first (or pass an explicit intent key)."
    )


def _digest(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                     default=_stable_default)
    return hashlib.sha256(raw.encode()).hexdigest()


GENESIS = "0" * 64

# Cert tiers. SEALED is the only tier v1 can assert without a witness.
TIER_SEALED = "SEALED"
TIER_WORLD_FINAL = "WORLD_FINAL"
TIER_WORLD_UNKNOWN = "WORLD_UNKNOWN"
TIER_WORLD_DIVERGED = "WORLD_DIVERGED"

# `world` is the v1 field name, kept forever so the cert format never breaks.
_TIER_TO_WORLD = {
    TIER_SEALED: "unconfirmed",
    TIER_WORLD_FINAL: "confirmed",
    TIER_WORLD_UNKNOWN: "unknown",
    TIER_WORLD_DIVERGED: "diverged",
}


class SealError(Exception):
    """Base for every refusal Seal raises."""


class NotFenceHolder(SealError, PermissionError):
    """You are not the admitted caller for this intent (or it is already sealed)."""


class PayloadConflict(SealError):
    """Same intent key, different arguments.

    This is a HARD failure on purpose. If a caller reuses `charge:order-777`
    with a different amount, one of the two is wrong, and serving either the
    cached result or a fresh execution would be a lie. Refusing loudly is the
    only safe answer — the caller must pick a new key or fix the args.
    """


class DomainFrozen(SealError):
    """The domain is frozen by the divergence circuit breaker; nothing is admitted."""


class StaleWorldRead(SealError):
    """The caller's own freshness check says the world moved since read_set was
    captured. Refused before the fence is granted — nothing was admitted, so
    nothing was acted on, on information that was already stale."""


def intent_id(action: str, args: Any, key: str | None = None) -> str:
    """Stable id for a logical action.

    Two modes, and the difference matters:

    * `key` given (RECOMMENDED for money): the intent is `action` + that key,
      e.g. charge + "order-777". Args are NOT part of the identity, so a retry
      whose amount was recomputed slightly differently is caught as a
      PayloadConflict instead of silently becoming a second charge.
    * `key` omitted: content-addressed from the args. Convenient, and safe when
      args are genuinely deterministic — but a recomputed field makes a retry
      look like a brand-new intent. Prefer an explicit key for irreversible work.
    """
    if key is not None:
        return _digest({"action": action, "key": key})
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
    domain      TEXT,
    read_set    JSONB,
    tier        TEXT,
    graph_id    TEXT,
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
CREATE TABLE IF NOT EXISTS seal_domains (
    domain    TEXT PRIMARY KEY,
    frozen    BOOLEAN NOT NULL,
    reason    TEXT,
    evidence  JSONB,
    frozen_at DOUBLE PRECISION
);
CREATE TABLE IF NOT EXISTS seal_graphs (
    graph_id   TEXT PRIMARY KEY,
    state      TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS seal_graph_children (
    graph_id        TEXT NOT NULL,
    child_key       TEXT NOT NULL,
    action          TEXT NOT NULL,
    args            JSONB NOT NULL,
    required        BOOLEAN NOT NULL,
    intent          TEXT,
    state           TEXT NOT NULL,             -- pending|sealed|failed|compensated
    compensates_key TEXT,
    PRIMARY KEY (graph_id, child_key)
);
CREATE TABLE IF NOT EXISTS seal_clearance (
    path        TEXT PRIMARY KEY,          -- the irreversible tool path, e.g. "charge"
    status      TEXT NOT NULL,             -- CLEARED | HOLD | REVOKED
    reason      TEXT,
    max_proof_age_sec DOUBLE PRECISION,    -- CLEARED expires without fresh green proof
    updated_at  DOUBLE PRECISION NOT NULL,
    updated_by  TEXT
);
CREATE TABLE IF NOT EXISTS seal_proof (
    id          BIGSERIAL PRIMARY KEY,
    path        TEXT NOT NULL,
    green       BOOLEAN NOT NULL,
    storm_n     INTEGER,
    executions  INTEGER,
    detail      JSONB,
    at          DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS seal_proof_path_at ON seal_proof (path, at DESC);
CREATE TABLE IF NOT EXISTS seal_thresholds (
    path               TEXT PRIMARY KEY,
    auto_ceiling       DOUBLE PRECISION NOT NULL,  -- <= this: normal Clearance applies
    dual_ceiling       DOUBLE PRECISION NOT NULL,  -- <= this: needs 2 distinct approvers
                                                    -- > this: ALWAYS_HUMAN, same mechanic,
                                                    -- never eligible for AUTO regardless of policy
    required_approvers INTEGER NOT NULL DEFAULT 2,
    updated_at         DOUBLE PRECISION NOT NULL,
    updated_by         TEXT
);
CREATE TABLE IF NOT EXISTS seal_approvals (
    id           TEXT PRIMARY KEY,
    intent       TEXT NOT NULL,
    path         TEXT NOT NULL,
    amount       DOUBLE PRECISION NOT NULL,
    maker        TEXT NOT NULL,
    tier         TEXT NOT NULL,             -- DUAL | ALWAYS_HUMAN
    state        TEXT NOT NULL,             -- pending | approved | rejected | expired
    required     INTEGER NOT NULL,
    created_at   DOUBLE PRECISION NOT NULL,
    expires_at   DOUBLE PRECISION NOT NULL,
    decided_at   DOUBLE PRECISION,
    consumed_at  DOUBLE PRECISION           -- set once spent by execute(); single-use
);
CREATE TABLE IF NOT EXISTS seal_approval_votes (
    id           BIGSERIAL PRIMARY KEY,
    approval_id  TEXT NOT NULL,
    approver     TEXT NOT NULL,
    decision     TEXT NOT NULL,             -- approve | reject
    at           DOUBLE PRECISION NOT NULL,
    sig          TEXT NOT NULL,
    -- The property that makes maker-checker real rather than advisory: one
    -- approver cannot be counted twice toward the required count. This is
    -- enforced by Postgres, not application logic, so it holds even if two
    -- votes from the same approver are submitted in the same instant.
    UNIQUE (approval_id, approver)
);
CREATE TABLE IF NOT EXISTS seal_events (
    id      BIGSERIAL PRIMARY KEY,
    path    TEXT,
    kind    TEXT NOT NULL,                 -- admitted|blocked|replayed|healed|diverged|revoked
    intent  TEXT,
    detail  JSONB,
    at      DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS seal_events_at ON seal_events (at DESC);

-- Single-use gateway tickets, claimed DURABLY before the provider is called.
--
-- The gateway used to guard replay with an in-process set. Two server
-- processes share no memory, so a restarted or replicated gateway would
-- re-verify a spent ticket, call the provider a SECOND time, and only then
-- fail to seal — money moved twice, chain records once. Found by driving the
-- MCP server as two separate processes; a single-process test cannot see it.
--
-- One row per ticket signature, INSERT ... ON CONFLICT DO NOTHING: one winner,
-- decided in the store, with no window between the check and the write.
CREATE TABLE IF NOT EXISTS seal_tickets (
    sig      TEXT PRIMARY KEY,
    intent   TEXT NOT NULL,
    path     TEXT NOT NULL,
    spent_at DOUBLE PRECISION NOT NULL
);

-- What propose() set aside and execute() must finish: the budget reservation
-- to settle, and the Mandate to consume.
--
-- These lived in two in-process dicts on the Gateway (`_pending`,
-- `_pending_mandate`) — the same defect seal_tickets above was created to fix,
-- left in the two fields beside it. propose() on one replica and execute() on
-- another (a load balancer, a rolling deploy, a restart) meant execute() found
-- nothing to pop: the reservation was never settled and stayed `reserved`
-- forever, so the budget filled with phantom spend until it refused real
-- charges; and the Mandate was never consumed, so the receipt for a completed
-- action still reported it ACTIVE. Not a race — the ordinary path for any
-- multi-replica gateway.
CREATE TABLE IF NOT EXISTS seal_ticket_pending (
    sig        TEXT PRIMARY KEY,
    intent     TEXT NOT NULL,
    spend_id   BIGINT,
    budget_key TEXT,
    amount     DOUBLE PRECISION,
    mandate_id TEXT,
    created_at DOUBLE PRECISION NOT NULL
);

-- Which paths are under Mandate. An operator-only table: no agent-facing tool
-- writes to it, for the same reason there is no seal_unfreeze tool — a gate
-- that could release itself is not a gate.
CREATE TABLE IF NOT EXISTS seal_mandate_paths (
    path       TEXT PRIMARY KEY,
    required   BOOLEAN NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL,
    updated_by TEXT NOT NULL
);

-- One row per Mandate: durable evidence of WHY an execution was permitted,
-- written at the moment it was permitted. `consumed_at` is claimed via
-- `UPDATE ... WHERE consumed_at IS NULL`, the same single-writer-wins idiom
-- as seal_tickets, so two processes racing the same Mandate cannot both spend it.
CREATE TABLE IF NOT EXISTS seal_mandates (
    mandate_id   TEXT PRIMARY KEY,
    intent       TEXT NOT NULL,
    path         TEXT NOT NULL,
    args_digest  TEXT NOT NULL,
    amount       DOUBLE PRECISION,
    tier         TEXT,
    approval_id  TEXT,
    approvers    JSONB,
    clearance    TEXT,
    created_at   DOUBLE PRECISION NOT NULL,
    expires_at   DOUBLE PRECISION NOT NULL,
    consumed_at  DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS seal_mandates_intent ON seal_mandates (intent);
"""

# Idempotent migrations for stores created by an earlier version.
#
# `CREATE TABLE IF NOT EXISTS` is a trap on upgrade: it silently does NOTHING
# when the table already exists, so a customer who installs a new Seal over an
# existing database keeps the old columns and every query fails at runtime.
# This was caught by running the suite against a store built by the previous
# version — exactly the upgrade path a real user takes, and exactly the path a
# from-scratch test database would have hidden.
MIGRATIONS = """
ALTER TABLE seal_intents ADD COLUMN IF NOT EXISTS domain   TEXT;
ALTER TABLE seal_intents ADD COLUMN IF NOT EXISTS read_set JSONB;
ALTER TABLE seal_intents ADD COLUMN IF NOT EXISTS tier     TEXT;
ALTER TABLE seal_intents ADD COLUMN IF NOT EXISTS graph_id TEXT;
CREATE TABLE IF NOT EXISTS seal_tickets (
    sig      TEXT PRIMARY KEY,
    intent   TEXT NOT NULL,
    path     TEXT NOT NULL,
    spent_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS seal_ticket_pending (
    sig        TEXT PRIMARY KEY,
    intent     TEXT NOT NULL,
    spend_id   BIGINT,
    budget_key TEXT,
    amount     DOUBLE PRECISION,
    mandate_id TEXT,
    created_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS seal_mandate_paths (
    path       TEXT PRIMARY KEY,
    required   BOOLEAN NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL,
    updated_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS seal_mandates (
    mandate_id   TEXT PRIMARY KEY,
    intent       TEXT NOT NULL,
    path         TEXT NOT NULL,
    args_digest  TEXT NOT NULL,
    amount       DOUBLE PRECISION,
    tier         TEXT,
    approval_id  TEXT,
    approvers    JSONB,
    clearance    TEXT,
    created_at   DOUBLE PRECISION NOT NULL,
    expires_at   DOUBLE PRECISION NOT NULL,
    consumed_at  DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS seal_mandates_intent ON seal_mandates (intent);
"""


class Seal:
    # 8 tries (~1s of backoff) was not enough: under a 1,000-caller burst the
    # accept queue stays saturated for seconds, and the caller that loses is
    # sometimes the WINNER — which sealed nothing, so the run recorded zero
    # certs. Safety held (one execution, everyone else failed safe), but a
    # settlement rail that cannot record an effect under load is not shippable.
    # 24 tries with capped backoff covers the observed saturation window.
    def __init__(self, dsn: str, lease_sec: float = 30.0, connect_tries: int = 24):
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
        # is spent we raise, and the caller's only safe move is to stand down.
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
        """Create the schema, and migrate a store made by an older version.

        Safe to run on every boot: both halves are idempotent.
        """
        with self._connect(autocommit=True) as c:
            c.execute(SCHEMA)
            c.execute(MIGRATIONS)

    # ── domain circuit breaker (B7) ───────────────────────────────────────
    def freeze_domain(self, domain: str, reason: str, evidence: Any = None) -> None:
        """Stop admitting anything in this domain. The rail stops the bleeding.

        Freezing is deliberately blunt: once the world has contradicted the
        ledger, we do not know which other intents in that domain are also
        wrong, so guessing is worse than halting.
        """
        now = time.time()
        with self._connect(autocommit=True) as c:
            c.execute(
                """
                INSERT INTO seal_domains (domain, frozen, reason, evidence, frozen_at)
                VALUES (%s, TRUE, %s, %s, %s)
                ON CONFLICT (domain) DO UPDATE
                   SET frozen=TRUE, reason=EXCLUDED.reason,
                       evidence=EXCLUDED.evidence, frozen_at=EXCLUDED.frozen_at
                """,
                (domain, reason, _jsonb(evidence), now),
            )

    def unfreeze_domain(self, domain: str) -> None:
        """Human-driven only: reconcile first, then release."""
        with self._connect(autocommit=True) as c:
            c.execute(
                "UPDATE seal_domains SET frozen=FALSE WHERE domain=%s", (domain,)
            )

    def domain_frozen(self, domain: str) -> Optional[dict]:
        with self._connect(autocommit=True) as c:
            row = c.execute(
                "SELECT reason, evidence, frozen_at FROM seal_domains WHERE domain=%s AND frozen",
                (domain,),
            ).fetchone()
        if row is None:
            return None
        return {"reason": row[0], "evidence": row[1], "frozen_at": row[2]}

    # ── admission: the atomic single-winner claim ─────────────────────────
    def admit(
        self,
        action: str,
        args: Any,
        key: str | None = None,
        domain: str | None = None,
        read_set: Any = None,
        graph_id: str | None = None,
        heal_with=None,
        path: str | None = None,
        checker=None,
        _mandate_exempt: bool = False,
        _retry: int = 0,
    ) -> Admission:
        iid = intent_id(action, args, key)
        args_dig = _digest(args)
        fence = uuid.uuid4().hex
        now = time.time()
        lease = now + self.lease_sec

        # CLEARANCE — the control plane, checked before anything else. A path
        # that is not effectively CLEARED cannot fire unattended, no matter what
        # the fence would allow. Only enforced when the caller names a path;
        # callers that don't use clearance are unaffected.
        if path is not None:
            from .clearance import Clearance
            Clearance(self).check(path)   # raises ClearanceDenied

            # MANDATE GATE. A path an operator has put `require_mandate` on
            # cannot be admitted by a bare admit() call at all — only through
            # Gateway.propose(), which mints the Mandate right after this
            # check passes. This is what makes "cannot execute without a
            # Mandate" a real refusal rather than a naming exercise: an agent
            # that fetched a raw admit() path and skipped the gateway is
            # stopped HERE, before a fence is ever granted, not detected after
            # the fact by reconcile.py (which remains the backstop for a
            # caller that bypasses Seal entirely, holding its own credential —
            # no in-process gate can reach that case; only the CFO-facing
            # sweep can).
            #
            # `_mandate_exempt` exists ONLY for Gateway.propose()'s own call
            # into admit() — the Gateway is the trusted path that is ABOUT TO
            # mint the Mandate this same check would otherwise demand already
            # exist, a chicken-and-egg the flag breaks. It is not part of the
            # MCP surface: `seal_admit` never sets it, so the direct/bypass
            # path stays blocked exactly as before.
            if not _mandate_exempt:
                from .mandate import Mandates, MandateRequired
                if Mandates(self).is_required(path):
                    raise MandateRequired(
                        f"path {path!r} requires a Seal Mandate — call "
                        "Gateway.propose()/execute(), not admit() directly"
                    )

        # PRE-COMMIT WORLD FREEZE (B1). Enforced HERE, before any fence is
        # granted — not at seal(), after the caller has already run the
        # effect. Checking after the fact could only refuse to claim success;
        # it cannot stop money moving on information that was already stale.
        # Opt-in and backward-compatible by the same rule as graduated
        # clearance: only engages when the caller supplies BOTH a read_set
        # and a checker. A read_set with no checker is still accepted and
        # stored on the cert — Seal cannot invent a freshness check for facts
        # it does not understand — but it is now honestly inert rather than
        # silently believed to be enforced.
        if read_set is not None and checker is not None:
            if not checker.fresh(read_set):
                raise StaleWorldRead(
                    "read_set is stale — the world moved since these facts "
                    "were captured; refusing to admit before anything ran"
                )
            # HONEST LIMIT: checker.fresh() calls out to the caller's world —
            # it cannot be embedded in the INSERT's WHERE clause the way the
            # domain-freeze re-check below can, because Postgres cannot ask an
            # external system a question inside one statement. A change
            # landing in the gap between this line and the INSERT is a
            # narrower residual window, not a closed one. This freeze is
            # exactly as strong as the caller's checker and the freshness of
            # its own read, same caveat class as a witness's eventually-
            # consistent provider index — printed here rather than left to be
            # discovered.

        if domain is not None:
            frozen = self.domain_frozen(domain)
            if frozen is not None:
                raise DomainFrozen(
                    f"domain {domain!r} is frozen: {frozen['reason']}"
                )

        with self._connect(autocommit=True) as c:
            # One statement decides the winner. ON CONFLICT DO NOTHING means the
            # second concurrent caller inserts nothing and RETURNING is empty —
            # there is no check-then-act window for anyone to slip through.
            # The freeze check above is a fast path with a good error message,
            # but on its own it is check-then-act: a freeze landing between the
            # check and this INSERT would let one more intent through, and the
            # whole point of the breaker is that nothing else gets through.
            # So the freeze test is repeated INSIDE the insert, where Postgres
            # evaluates it atomically with the write.
            row = c.execute(
                """
                INSERT INTO seal_intents
                    (intent, action, args_digest, state, fence, lease_until,
                     domain, read_set, tier, graph_id, created_at, updated_at)
                SELECT %s, %s, %s, 'open', %s, %s, %s, %s, NULL, %s, %s, %s
                 WHERE NOT EXISTS (
                       SELECT 1 FROM seal_domains
                        WHERE domain = %s AND frozen
                 )
                ON CONFLICT (intent) DO NOTHING
                RETURNING intent
                """,
                (
                    iid, action, args_dig, fence, lease, domain,
                    _jsonb(read_set) if read_set is not None else None,
                    graph_id, now, now,
                    domain,
                ),
            ).fetchone()

            if row is not None:
                if path is not None:
                    self.record_event("admitted", path=path, intent=iid)
                return Admission(fresh=True, intent=iid, fence=fence, cert=None)

            # Nothing inserted: either the intent already exists, or the domain
            # froze underneath us. Distinguish, so a frozen domain never gets
            # misreported as a replay.
            if domain is not None:
                frozen = self.domain_frozen(domain)
                if frozen is not None:
                    raise DomainFrozen(
                        f"domain {domain!r} is frozen: {frozen['reason']}"
                    )

            # Someone else holds it. Read the current state to decide the answer.
            cur = c.execute(
                "SELECT state, cert, lease_until, fence, args_digest FROM seal_intents WHERE intent=%s",
                (iid,),
            ).fetchone()
            if cur is None:
                # Raced with a delete (a peer's fail()) — treat as
                # fresh-eligible on one retry.
                #
                # EVERY argument is threaded through. The first version passed
                # only the first six positionally, silently dropping `path`,
                # `checker`, `heal_with` and `_mandate_exempt`: a guarded
                # admission quietly became an unguarded one. Clearance was not
                # re-checked, the caller's pre-commit freshness check was
                # skipped on a read_set that was now even staler, the
                # heal-on-reclaim probe could not run, and the `admitted`
                # event was never written — so the Range Report under-counted
                # the very admissions it exists to attest.
                #
                # `_retry` is a real counter because the old comment said "on
                # one retry" and nothing enforced it: a peer deleting the row
                # in a loop recursed until Python's stack gave out. Failing
                # closed beats a RecursionError on a money path.
                if _retry >= 1:
                    raise SealError(
                        f"intent {iid[:12]}… kept vanishing between the claim "
                        "and the read (a peer is deleting it concurrently); "
                        "refusing to admit rather than retry indefinitely"
                    )
                return self.admit(
                    action, args, key=key, domain=domain, read_set=read_set,
                    graph_id=graph_id, heal_with=heal_with, path=path,
                    checker=checker, _mandate_exempt=_mandate_exempt,
                    _retry=_retry + 1,
                )

            state, cert, lease_until, _held_fence, stored_args = cur

            # A7 — payload fingerprint. Same intent, different args, is never a
            # replay: it is two different requests wearing one name. Refuse.
            if stored_args != args_dig:
                raise PayloadConflict(
                    f"intent {iid[:12]}… was admitted with different arguments "
                    f"(stored {stored_args[:12]}…, got {args_dig[:12]}…). "
                    "Use a distinct intent key, or send the original arguments."
                )

            if state == "sealed":
                return Admission(fresh=False, intent=iid, fence="", cert=cert)
            if state == "open" and lease_until < now and heal_with is not None:
                # HEAL-ON-RECLAIM. The holder died mid-effect. Reclaiming and
                # re-running is the LAST double-fire window in the system: if the
                # dead holder already charged and crashed before sealing, the
                # reclaimer charges again. So before handing out a fresh claim,
                # ask the world whether the effect already exists. If it does,
                # we seal it as a HEAL instead of re-executing — the effect
                # happened once, we simply never recorded it.
                #
                # Only a definitive CONFIRMED_ONE heals. UNKNOWN (provider
                # unreachable / not yet indexed) must NOT heal and must NOT
                # re-execute blindly — it falls through to the normal reclaim,
                # because guessing either way here is how money gets doubled.
                from .witness import ABSENT, CONFIRMED_ONE
                probe = heal_with.look({"intent": iid, "action": action})
                if probe.state == CONFIRMED_ONE:
                    healed = self._heal(iid, probe)
                    return Admission(fresh=False, intent=iid, fence="", cert=healed)
                if probe.state != ABSENT:
                    # UNKNOWN or MULTIPLE. The comment above is the rule: do not
                    # heal AND do not re-execute. Falling through to the reclaim
                    # below would return fresh=True -- which IS re-executing,
                    # exactly what the rule forbids and what DEPLOYMENT.md rule 5
                    # ("never auto-retry the effect on UNKNOWN") prohibits. A
                    # provider that is briefly unreachable answers UNKNOWN, and
                    # that is precisely when a second charge must not happen.
                    # Stand down: the claim keeps standing for reconciliation.
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

    # ── heal: the world already has the effect; record it instead of re-running ──
    def _heal(self, intent: str, probe) -> dict:
        """Seal an intent whose effect the world confirms already happened.

        Used when a dead holder's claim is reclaimed but a world probe finds the
        effect already exists. The alternative — re-executing — would be a real
        double. A heal cert is marked so an auditor can see the effect was
        recovered from the provider rather than sealed by its executor.
        """
        now = time.time()
        with self._connect(autocommit=True) as c:
            with c.transaction():
                row = c.execute(
                    "SELECT action, args_digest FROM seal_intents WHERE intent=%s FOR UPDATE",
                    (intent,),
                ).fetchone()
                body = {
                    "intent": intent,
                    "action": row[0],
                    "args_digest": row[1],
                    "result_digest": _digest({"healed_from_world": probe.evidence}),
                    "tier": TIER_WORLD_FINAL,
                    "world": _TIER_TO_WORLD[TIER_WORLD_FINAL],
                    "healed": True,
                    "witness_state": probe.state,
                    "witness_count": probe.count,
                    "witness_evidence": probe.evidence,
                    "at": now,
                }
                cert = self._append_cert(c, body)
                c.execute(
                    "UPDATE seal_intents SET state='sealed', cert=%s, tier=%s, updated_at=%s "
                    "WHERE intent=%s",
                    (_jsonb(cert), TIER_WORLD_FINAL, now, intent),
                )
        self.record_event("healed", intent=intent, detail={"count": probe.count})
        return cert

    # ── event log — the raw material for the Range Report ─────────────────
    def record_event(self, kind: str, path: str | None = None,
                     intent: str | None = None, detail: Any = None) -> None:
        with self._connect(autocommit=True) as c:
            c.execute(
                "INSERT INTO seal_events (path, kind, intent, detail, at) VALUES (%s,%s,%s,%s,%s)",
                (path, kind, intent, _jsonb(detail) if detail is not None else None,
                 time.time()),
            )

    # ── A3 · heartbeat: extend the lease while a long effect runs ─────────
    def heartbeat(self, intent: str, fence: str) -> float:
        """Push the lease out. Only the fence holder may, and only while open.

        Without this, an effect slower than `lease_sec` gets its claim stolen
        mid-flight and a second caller runs it — the exact double we exist to
        prevent. Returns the new lease deadline.
        """
        now = time.time()
        new_lease = now + self.lease_sec
        with self._connect(autocommit=True) as c:
            row = c.execute(
                """
                UPDATE seal_intents SET lease_until=%s, updated_at=%s
                 WHERE intent=%s AND fence=%s AND state='open'
                RETURNING lease_until
                """,
                (new_lease, now, intent, fence),
            ).fetchone()
        if row is None:
            raise NotFenceHolder("not the fence holder, or no longer open")
        return row[0]

    # ── the append-only cert chain ────────────────────────────────────────
    # A hash chain is a strictly serial structure: "read the head, then append"
    # is only correct if nobody else appends in between. Without this lock, two
    # DIFFERENT intents sealing at the same instant both read the same head and
    # both write it as their prev_hash — producing a fork that fails
    # verify_chain() forever. The 1000-thread storm never caught it because only
    # ONE caller wins and seals there; the bug needs concurrent *distinct*
    # intents, which is the ordinary production shape. Caught by probing for it
    # directly. Transaction-scoped, so it releases on commit or rollback.
    _CHAIN_LOCK_KEY = 0x5EA1C8A17

    def _append_cert(self, c, body: dict) -> dict:
        """Append one cert. Hash covers the whole body + the previous hash.

        The chain is append-only by design: a witness NEVER rewrites a sealed
        cert, it appends a new one. That is what keeps "tamper-evident" true —
        if upgrading a tier meant editing history, the guarantee would be gone.

        MUST be called inside an open transaction — the advisory lock below is
        transaction-scoped and would release immediately under autocommit.
        """
        c.execute("SELECT pg_advisory_xact_lock(%s)", (self._CHAIN_LOCK_KEY,))
        prev = c.execute(
            "SELECT hash FROM seal_certs ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_hash = prev[0] if prev else GENESIS
        # NORMALISE BEFORE HASHING. _jsonb() strips non-ASCII on the way into
        # JSONB (see _ascii_safe), so hashing the raw body meant hashing bytes
        # the store would never hand back: verify_chain() recomputed from the
        # stripped row, got a different digest, and reported "cert altered
        # since written" on a chain nobody had touched. One accented character
        # anywhere in a witness's evidence -- a German decline message, a
        # customer name -- permanently marked an honest chain as tampered, and
        # because the chain is append-only by design it could never be undone.
        # Hashing the normalised body closes the gap: what we hash is exactly
        # what we store and exactly what an auditor reads back.
        body = _ascii_safe({**body, "prev_hash": prev_hash})
        cert_hash = _digest(body)
        cert = {**body, "hash": cert_hash}
        c.execute(
            "INSERT INTO seal_certs (intent, hash, prev_hash, body, created_at) "
            "VALUES (%s,%s,%s,%s,%s)",
            (body["intent"], cert_hash, prev_hash, _jsonb(cert),
             body.get("at", time.time())),
        )
        return cert

    # ── seal: write the certificate after the effect ran ──────────────────
    def seal(
        self,
        intent: str,
        fence: str,
        result: Any,
        compensates_cert: str | None = None,
        graph_id: str | None = None,
    ) -> dict:
        now = time.time()
        with self._connect(autocommit=True) as c:
            with c.transaction():
                # Only the fence holder may seal, and only while still open.
                held = c.execute(
                    "SELECT args_digest, action, read_set, graph_id FROM seal_intents "
                    "WHERE intent=%s AND fence=%s AND state='open' FOR UPDATE",
                    (intent, fence),
                ).fetchone()
                if held is None:
                    raise NotFenceHolder("not the fence holder, or already sealed")
                args_digest, action, read_set, stored_graph = held

                body = {
                    "intent": intent,
                    "action": action,
                    "args_digest": args_digest,
                    "result_digest": _digest(result),
                    "tier": TIER_SEALED,
                    "world": _TIER_TO_WORLD[TIER_SEALED],  # v1 field, never dropped
                    "read_set": read_set,
                    "compensates_cert": compensates_cert,
                    "graph_id": graph_id or stored_graph,
                    "at": now,
                }
                cert = self._append_cert(c, body)
                c.execute(
                    "UPDATE seal_intents SET state='sealed', cert=%s, tier=%s, updated_at=%s "
                    "WHERE intent=%s",
                    (_jsonb(cert), TIER_SEALED, now, intent),
                )
                return cert

    def fail(self, intent: str, fence: str, reason: str) -> None:
        """Release a claim so the intent can be legitimately retried later.

        Only safe when nothing irreversible happened. If the effect may have
        fired, do NOT call this — leave the claim and witness it instead.
        """
        with self._connect(autocommit=True) as c:
            c.execute(
                "DELETE FROM seal_intents WHERE intent=%s AND fence=%s AND state='open'",
                (intent, fence),
            )

    # ── status ────────────────────────────────────────────────────────────
    def get(self, intent: str) -> Optional[dict]:
        with self._connect(autocommit=True) as c:
            row = c.execute(
                "SELECT intent, action, state, tier, cert, domain, graph_id, created_at "
                "FROM seal_intents WHERE intent=%s",
                (intent,),
            ).fetchone()
        if row is None:
            return None
        return {
            "intent": row[0], "action": row[1], "state": row[2],
            "tier": row[3], "cert": row[4], "domain": row[5], "graph_id": row[6],
            "created_at": row[7],
        }

    def certs_for(self, intent: str) -> list[dict]:
        with self._connect(autocommit=True) as c:
            rows = c.execute(
                "SELECT body FROM seal_certs WHERE intent=%s ORDER BY seq ASC",
                (intent,),
            ).fetchall()
        return [r[0] for r in rows]

    # ── B2–B7 · world witness, cert tiers, circuit breaker ────────────────
    def witness(self, intent: str, witness, freeze_on_diverge: bool = True) -> dict:
        """Ask the outside world what really happened, and append the verdict.

        This never edits the SEALED cert — it appends a new one carrying the
        upgraded tier, so the chain stays append-only and tamper-evidence
        survives. A DIVERGED verdict trips the circuit breaker for the
        intent's domain: we now know the ledger and the world disagree, and we
        do not know what else in that domain is wrong, so the rail halts.
        """
        from .witness import ABSENT, CONFIRMED_ONE, MULTIPLE, UNKNOWN

        rec = self.get(intent)
        if rec is None:
            raise SealError(f"unknown intent {intent[:12]}…")
        if rec["state"] != "sealed":
            raise SealError(
                "only a sealed intent can be witnessed — there is nothing to "
                "confirm until the effect has been sealed"
            )

        result = witness.look(rec)
        tier = {
            CONFIRMED_ONE: TIER_WORLD_FINAL,
            MULTIPLE: TIER_WORLD_DIVERGED,
            # Sealed here but nothing there: the ledger claims an effect the
            # world denies. That is a contradiction, not an absence.
            ABSENT: TIER_WORLD_DIVERGED,
            UNKNOWN: TIER_WORLD_UNKNOWN,
        }[result.state]

        # DIVERGENCE IS STICKY. Once the world has contradicted the ledger, a
        # later witness that happens to count 1 again must NOT silently downgrade
        # the intent back to WORLD_FINAL — the contradiction is a permanent
        # incident until a human reconciles it, and provider search indexes are
        # eventually consistent, so a re-poll flapping to 1 is expected noise,
        # not an all-clear. The new observation is still appended to the chain as
        # evidence (append-only), but the intent's TIER never comes back up from
        # DIVERGED. Caught by running the demo against live Stripe, where the
        # rogue charge's search-index lag made a re-poll count 1 and un-diverge
        # the cert. The domain freeze was already sticky; the tier now matches.
        now = time.time()
        already_diverged = rec["tier"] == TIER_WORLD_DIVERGED
        effective_tier = TIER_WORLD_DIVERGED if already_diverged else tier
        with self._connect(autocommit=True) as c:
            with c.transaction():
                sealed = c.execute(
                    "SELECT cert, action, args_digest FROM seal_intents WHERE intent=%s FOR UPDATE",
                    (intent,),
                ).fetchone()
                prior_cert = sealed[0]
                body = {
                    "intent": intent,
                    "action": sealed[1],
                    "args_digest": sealed[2],
                    "tier": effective_tier,
                    "world": _TIER_TO_WORLD[effective_tier],
                    "observed_tier": tier,      # what THIS witness alone saw
                    "witness_state": result.state,
                    "witness_count": result.count,
                    "witness_evidence": result.evidence,
                    "parent_cert": prior_cert.get("hash") if prior_cert else None,
                    "at": now,
                }
                cert = self._append_cert(c, body)
                c.execute(
                    "UPDATE seal_intents SET tier=%s, updated_at=%s WHERE intent=%s",
                    (effective_tier, now, intent),
                )

        # Freeze whenever THIS observation is a divergence — even if the tier was
        # already diverged, re-freezing is harmless (idempotent) and keeps the
        # freeze reason current.
        if tier == TIER_WORLD_DIVERGED and freeze_on_diverge and rec["domain"]:
            self.freeze_domain(
                rec["domain"],
                f"witness returned {result.state} for intent {intent[:12]}…",
                evidence=result.evidence,
            )
        return cert

    # ── B8 · incident receipt ─────────────────────────────────────────────
    def incident_receipt(self, intent: str) -> dict:
        """Everything an auditor needs about one intent, in one exportable blob.

        Deliberately self-contained and self-checking: it carries the full cert
        chain for the intent plus a fresh chain verification, so the reader can
        confirm it without calling us and without trusting this process.
        """
        rec = self.get(intent)
        if rec is None:
            raise SealError(f"unknown intent {intent[:12]}…")
        certs = self.certs_for(intent)
        chain = self.verify_chain()
        domain_state = self.domain_frozen(rec["domain"]) if rec["domain"] else None
        receipt = {
            "intent": rec["intent"],
            "action": rec["action"],
            "state": rec["state"],
            "tier": rec["tier"],
            "domain": rec["domain"],
            "domain_frozen": domain_state,
            "certs": certs,
            "chain_verified": chain["ok"],
            "chain_detail": chain,
            "generated_at": time.time(),
        }
        receipt["receipt_digest"] = _digest(
            {k: v for k, v in receipt.items() if k != "generated_at"}
        )
        return receipt

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
            # Hash covers every field except the hash itself. Deriving the set
            # from the body (rather than a hardcoded tuple) means adding a cert
            # field can never silently drop it out of the tamper check.
            recomputed = _digest({k: v for k, v in body.items() if k != "hash"})
            if recomputed != h or body.get("hash") != h:
                return {"ok": False, "at": i, "why": "cert altered since written"}
            prev = h
        return {"ok": True, "certs": len(rows)}
