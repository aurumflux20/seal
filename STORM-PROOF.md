# SEAL — proof of all three layers (Aug 12 2026, v0.2.0)

**Claim tested:** across many real, independent workers sharing ONE Postgres,
an irreversible action admitted through Seal executes EXACTLY ONCE, and every
loser replays the sealed certificate instead of re-running it.

**Result — 4 consecutive runs, N=1000 concurrent live threads, packaged `seal-kernel`:**

| Run | ACTUAL_EXECUTIONS | Verdict (exit code) |
|-----|-------------------|---------------------|
| 1 | 1 | PASS (0) |
| 2 | 1 | PASS (0) |
| 3 | 1 | PASS (0) |
| 4 | 1 | PASS (0) |

Representative run (run 1):
- attempts: 1000 (all released by one `threading.Barrier` — genuine simultaneity)
- ACTUAL_EXECUTIONS: **1**
- admitted fresh: 1 (one winner sealed the cert)
- replayed cert: 964 (arrived after seal → got the cert, never re-ran)
- stood down: 18 (arrived mid-flight → safe, no cert yet, never ran)
- store unreachable: 17 (backlog spike → those callers FAILED SAFE: no store, no charge)
- post-seal wave (50): all 50 replayed, 0 re-executed
- cert chain: VERIFIED from the store alone (1 cert)

**Also green, all from a FRESH CLONE on a FRESH DATABASE, every verdict by exit code:**
- **56 tests** across three layers — wrong-fence seal rejected, double-seal
  rejected, dead-lease reclaim invalidates the zombie fence, edited/deleted/
  re-hashed certs all break the chain, same-key-different-args refused as a
  conflict, `WORLD_UNKNOWN` never collapsing to absent, a frozen domain
  refusing admission, a graph refusing FINAL while a child is unconfirmed, and
  a compensation that stays single-fire under 20 concurrent callers.
- **`demo.py`** — 11 measured checks: two agents double-click → one charge;
  divergence → domain frozen + further spend refused; checkout fails halfway →
  exactly one sealed refund, `GRAPH_COMPENSATED`, chain still verifying.
- **`seal-mcp`** — driven as a subprocess over real JSON-RPC stdio, not by
  importing its functions, so the handshake and framing are actually proven.
- **`python -m seal verify`** — chain audited from the DSN alone, exit 0.

**What is proven:** exactly-once across processes on a shared durable store, plus
a tamper-evident cert chain. The mechanism is `INSERT ... ON CONFLICT DO NOTHING`
— one row, one winner, no check-then-act window.

**SIX real bugs were caught by auditing and demoing rather than assuming, and
all six are fixed in the shipped code. Every one was found by attacking our own
work; none surfaced from a passing suite:**
1. **SQL_ASCII stores returned `bytes` for TEXT.** A Postgres initialised under a
   C locale is SQL_ASCII, and psycopg then hands back `bytes` for every TEXT
   column — args_digest and the cert body silently became unserialisable. Fixed
   by pinning `client_encoding="UTF8"` on every connection. A settlement kernel
   must behave identically whatever encoding the customer's store was built with.
2. **A backlog spike could cost the winner its certificate.** 1000 simultaneous
   raw connects briefly overflow the socket accept queue; the first run lost the
   winner's `seal()` connection and wrote 0 certs (777 unreachable). Fixed with a
   bounded retry on **connection establishment only** — never on the effect,
   which admission already made exactly-once. Unreachable dropped 777 → 17 and
   the SAFETY property held throughout: an unreachable store is always fail-safe,
   never a double-charge.

3. **The cert chain forked under concurrent seals.** Two DIFFERENT intents
   sealing at the same instant both read the same chain head and both wrote it
   as `prev_hash` — a fork that fails verification permanently, voiding the
   tamper-evidence guarantee in the ordinary production shape. **The
   1,000-thread storm could never catch this**: only one caller wins and seals
   there. Found by probing for it directly. Fixed with a transaction-scoped
   advisory lock around read-head-then-append.
4. **The divergence circuit breaker was raceable.** The freeze was checked
   before the INSERT, so a freeze landing in between let one more irreversible
   action through — in the very mechanism whose job is to stop exactly that.
   The freeze test now runs inside the INSERT, evaluated atomically with the
   write.
5. **Upgrading silently did nothing.** `CREATE TABLE IF NOT EXISTS` is a no-op
   on an existing table, so a customer installing a new Seal over an existing
   database kept the old columns and hit runtime errors. Fixed with idempotent
   migrations, then proven by building a real v0.1.0-schema store and upgrading
   it — the path a user actually takes, and the one a from-scratch test
   database hides.
6. **A retried compensation got stuck non-terminal.** Re-calling `compensate()`
   set the graph to `COMPENSATING`, then returned early on the already-done
   path and never finalised — leaving a retried refund permanently mid-flight.
   Idempotent has to mean the STATE repeats, not just the side effect. **Found
   by the end-to-end demo, which the unit tests had missed** — they asserted
   the refund ran once and stopped there.
7. **The gateway double-charged across processes — our own bug, our own thesis.**
   `Gateway.execute()` guarded ticket replay with `self._spent`, an in-process
   Python set. A restarted gateway — or a second replica sharing
   `SEAL_TICKET_KEY`, which replicas *must* share to function at all — starts
   with an empty set. It re-verified an already-spent ticket, **called the
   provider a second time, and only then failed to seal.** The caller received
   `NotFenceHolder` and would reasonably read it as "it didn't work", while the
   money had moved twice and the certificate chain recorded once.

   Counted, not inferred — the executor appends to a file, so the claim is a
   counter rather than an opinion:

   ```
   before:  ['charge:7700', 'charge:7700']
   after:   ['charge:7700']
   ```

   This is check-then-act across a process boundary: precisely the defect this
   library exists to prevent, living inside this library. **No single-process
   test can see it** — it only appears when you drive the MCP server as two
   separate processes, which is how agent teams actually deploy. Fixed with the
   kernel's own idiom: a `seal_tickets` row claimed via
   `INSERT ... ON CONFLICT DO NOTHING` *before* the executor is called. Losing
   that race now raises `TicketAlreadySpent` and the provider is never touched.

   Worth stating plainly, since it is the exact failure we sell against: an
   audit log that says one charge does not prove the provider only took one.

**Honest limits (measured, not hidden):**
1. Raw one-connection-per-call still isn't how you'd run this in production — put
   a real pool in front of it. The retry stops a transient blip from losing a
   cert; it does not make 1000 raw connections a good idea.
2. Cert says `world: "unconfirmed"` — Seal proves ADMISSION, not world
   settlement. The provider-adapter layer (Slice 2) turns that field on; the
   schema already carries it so the format never breaks.

**Reproduce:**
```bash
pip install -e . && export SEAL_DSN="host=... dbname=seal"
python -m pytest tests/ -q      # 13 attack tests
python storm.py --n 1000        # exit 0 == exactly-once held
python -m seal verify           # audit the cert chain, DSN only
```

**Files:** `seal/core.py` (kernel), `seal/cli.py` (`seal verify`), `storm.py`
(the proof), `tests/test_seal.py` (the attack suite).
