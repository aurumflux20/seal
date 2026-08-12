# SEAL v1 — exactly-once proof (re-run Aug 12 2026, packaged build)

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

**Also green:** the 13-test attack suite (`tests/test_seal.py`) — wrong-fence seal
rejected, double-seal rejected, dead-lease reclaim invalidates the zombie fence,
edited/deleted/re-hashed certs all break the chain, cert never claims world
settlement. Verified from a **fresh clone + fresh venv**, outside the dev tree.

**What is proven:** exactly-once across processes on a shared durable store, plus
a tamper-evident cert chain. The mechanism is `INSERT ... ON CONFLICT DO NOTHING`
— one row, one winner, no check-then-act window.

**Two robustness fixes were caught by this re-run and are in the shipped code:**
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
