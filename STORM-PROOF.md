# SEAL v1 — 48h exit criterion: PASSED (Aug 12 2026)

**Claim tested:** across many real, independent workers sharing ONE Postgres,
an irreversible action admitted through Seal executes EXACTLY ONCE.

**Result — 4 consecutive runs, N=1000 concurrent live threads:**

| Run | ACTUAL_EXECUTIONS | Verdict |
|-----|-------------------|---------|
| 1 | 1 | PASS |
| 2 | 1 | PASS |
| 3 | 1 | PASS |
| 4 | 1 | PASS |

Representative run:
- attempts: 1000 (all released by one barrier — genuine simultaneity)
- ACTUAL_EXECUTIONS: **1**
- admitted fresh: 1 (one winner)
- replayed cert: ~806 (arrived after seal → got the cert, never re-ran)
- stood down: ~38 (arrived mid-flight → safe, no cert yet, never ran)
- store unreachable: ~155 (1000 raw connections briefly overwhelmed the socket
  → those callers FAILED SAFE: no store, no charge)
- post-seal wave (50): all 50 replayed, 0 re-executed
- cert chain: VERIFIED from the store alone

**What is proven:** exactly-once across processes on a shared durable store, plus
a tamper-evident cert chain. The mechanism is `INSERT ... ON CONFLICT DO NOTHING`
— one row, one winner, no check-then-act window.

**Honest limits (measured, not hidden):**
1. The 155 "unreachable" show the naive one-connection-per-call model doesn't
   scale to 1000 raw simultaneous connections — production needs a connection
   pool. The SAFETY property held anyway: unreachable = fail-safe, never a
   double-charge. This is an implementation detail, not a correctness gap.
2. Cert says `world: "unconfirmed"` — Seal proves ADMISSION, not world
   settlement. v2 (provider adapters) turns that field on; the schema already
   carries it so the format never breaks.

**Files:** seal.py (core), storm.py (the proof). Postgres 17, psycopg 3.
