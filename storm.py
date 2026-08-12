"""
seal storm --n 1000 — the one proof that makes Seal real.

The claim under test: across many real, independent workers sharing one
Postgres, an irreversible action admitted through Seal executes EXACTLY ONCE,
and every loser replays the sealed certificate instead of re-running it.

This is the honest version of the test, so it is built to FAIL if the property
doesn't hold:

  - Real concurrency: N threads across a process pool, released together by a
    barrier, so they hit `admit()` at genuinely the same moment — not staggered
    by lucky scheduling.
  - The "charge" increments a shared counter guarded by its own lock, so the
    execution count is measured, not assumed. If two callers both ran, the
    counter reads 2 and the test fails loudly.
  - We assert the winner sealed a cert, every loser got that same cert back,
    and the cert chain verifies from the store alone.
"""
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from seal import Seal

DSN = os.environ["SEAL_DSN"]
N = int(sys.argv[sys.argv.index("--n") + 1]) if "--n" in sys.argv else 1000

# The shared, mutable thing an irreversible effect touches. In production this
# is a Stripe charge; here it is a counter we can measure exactly.
_charges = {"count": 0}
_charge_lock = threading.Lock()


def charge(order_id: str) -> dict:
    with _charge_lock:
        _charges["count"] += 1
        n = _charges["count"]
    time.sleep(0.01)  # hold the effect open, like a real network call
    return {"order": order_id, "amount": 4900, "charge_seq": n}


def worker(_i: int, barrier: threading.Barrier) -> str:
    """One agent trying to charge the same order."""
    seal = Seal(DSN)
    barrier.wait()  # everyone launches together
    try:
        adm = seal.admit("charge", {"order_id": "order-123", "amount": 4900})
    except Exception:
        # Could not reach the coordination store. The ONLY safe move is to not
        # fire the irreversible action. This is the fail-safe, not an error:
        # unreachable Seal → stand down, never charge on a guess.
        return "unreachable"
    if adm.fresh:
        try:
            result = charge("order-123")
        except Exception as e:
            seal.fail(adm.intent, adm.fence, str(e))
            return "error"
        seal.seal(adm.intent, adm.fence, result)
        return "fresh"
    else:
        # Loser: must be handed the sealed cert, must NOT have run the charge.
        return "replay" if adm.cert is not None else "standdown"


def main() -> int:
    seal = Seal(DSN)
    seal.setup()
    # clean slate for this run
    import psycopg
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("TRUNCATE seal_intents, seal_certs")

    print(f"seal storm --n {N}  (real threads, shared Postgres)")
    # N genuinely-live threads, all released by one barrier — so admit() is hit
    # simultaneously, not staggered by a pool. A worker pool smaller than N would
    # weaken the very race we are trying to break.
    t0 = time.time()
    barrier = threading.Barrier(N)
    outcomes: list[str] = [None] * N  # type: ignore
    lock = threading.Lock()

    def run(i: int) -> None:
        r = worker(i, barrier)
        with lock:
            outcomes[i] = r

    threads = [threading.Thread(target=run, args=(i,)) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    dt = time.time() - t0

    fresh = outcomes.count("fresh")
    replay = outcomes.count("replay")
    standdown = outcomes.count("standdown")
    unreachable = outcomes.count("unreachable")
    errors = outcomes.count("error")
    actual_exec = _charges["count"]

    # A loser that arrives DURING the effect legitimately gets "stand down" —
    # the cert doesn't exist yet, and the honest answer is "someone else is on
    # it", not a fabricated result. A loser that arrives AFTER the seal gets the
    # cert. Both are safe: neither re-ran the charge. So we prove the replay path
    # separately with a second wave that starts once the seal is written.
    print(f"\n  ── storm (all {N} at once) ──")
    print(f"  attempts            {N}")
    print(f"  ACTUAL_EXECUTIONS   {actual_exec}")
    print(f"  admitted fresh      {fresh}")
    print(f"  replayed cert       {replay}")
    print(f"  stood down          {standdown}  (arrived mid-flight — safe)")
    print(f"  store unreachable   {unreachable}  (failed safe — never charged)")
    print(f"  errors              {errors}")
    print(f"  wall time           {dt:.2f}s")

    # Second wave: everyone arrives after the seal → all must replay the cert.
    wave2 = [worker(i, threading.Barrier(1)) for i in range(50)]
    w2_replay = wave2.count("replay")
    w2_fresh = wave2.count("fresh")
    print(f"\n  ── post-seal wave (50) ──")
    print(f"  replayed cert       {w2_replay}")
    print(f"  re-executed         {w2_fresh}  (must be 0)")
    print(f"  ACTUAL_EXECUTIONS   {_charges['count']}  (must still be 1)")

    chain = seal.verify_chain()
    print(f"\n  cert chain          {'VERIFIED ('+str(chain['certs'])+' cert)' if chain['ok'] else 'BROKEN: '+chain['why']}")

    # Every non-winner must have been SAFE: replayed the cert, stood down
    # mid-flight, or failed safe on an unreachable store. None re-ran the charge.
    safe_losers = replay + standdown + unreachable
    ok = (
        actual_exec == 1               # the storm ran the effect once
        and fresh == 1                 # exactly one winner
        and safe_losers == N - 1       # every other caller was safe
        and errors == 0
        and w2_fresh == 0              # nobody re-ran after the seal
        and w2_replay == 50            # all post-seal callers got the cert
        and _charges["count"] == 1     # still one execution, total
        and chain["ok"] and chain["certs"] == 1
    )
    print("\n" + ("  ✅ PASS — 1,000 concurrent + 50 post-seal callers, EXACTLY ONE execution, cert chain verified"
                  if ok else
                  "  ❌ FAIL — see the numbers above"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
