"""The Agent Side-Effect Range Safety Test — run this against YOUR server.

A public, standalone benchmark for one question: when N agents (or one agent
retrying) fire the same logical irreversible action at the same instant, does
your guard let more than one through?

No Seal import required. This file has zero dependencies on this repo — copy
it, point `TARGET` at your own write-bearing tool, and run it. If it fails,
you've found a real gap, not a hypothetical one, because the harness measures
the actual side effect rather than trusting your code to tell the truth about
itself.

    python range_safety_test.py

Three ways a naive version of this test lies to you, each fixed here on
purpose (learned by getting them wrong first, then fixing them, on our own
kernel — see the accompanying write-up for the full story):

1. A THREAD POOL IS NOT CONCURRENCY. A pool with fewer workers than tasks
   staggers them, so the race you're trying to force never actually happens
   and a pass proves scheduling luck. Fix: N real OS threads, all parked on a
   `threading.Barrier`, released together.

2. "NO EXCEPTIONS" IS NOT "NO DOUBLE." A double execution is not an error —
   it's two successes. Fix: the guarded action increments a real counter
   behind its own lock; the verdict is `ACTUAL_EXECUTIONS == 1`, not the
   absence of a traceback.

3. THE LOSERS AREN'T ONE OUTCOME. A caller that lost the race can safely
   replay a result, safely stand down mid-flight, or safely fail closed if
   your coordination store was unreachable — all three are fine. Silently
   swallowing a caller into "must have worked somehow" is not. Fix: every
   outcome is bucketed and accounted for; anything unaccounted for is a bug
   in the test, not a pass.

HONEST LIMIT: this tests ONE intent under contention. It says nothing about
many different intents settling at once, and nothing about whether the
outside world (Stripe, your bank, whatever) agrees with your local ledger
after the fact — that's a different, harder property (see: world confirmation
/ WORLD_FINAL in the parent project) and this benchmark does not claim it.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class RangeSafetyResult:
    n: int
    actual_executions: int
    outcomes: dict[str, int] = field(default_factory=dict)
    unaccounted: int = 0
    wall_time_sec: float = 0.0

    @property
    def passed(self) -> bool:
        return self.actual_executions == 1 and self.unaccounted == 0

    def report(self) -> str:
        lines = [
            f"  attempts             {self.n}",
            f"  ACTUAL_EXECUTIONS    {self.actual_executions}   {'✅' if self.actual_executions == 1 else '❌ SHOULD BE 1'}",
        ]
        for k, v in sorted(self.outcomes.items()):
            lines.append(f"  {k:<20} {v}")
        if self.unaccounted:
            lines.append(f"  UNACCOUNTED          {self.unaccounted}   ❌ test bug or a swallowed outcome")
        lines.append(f"  wall time            {self.wall_time_sec:.2f}s")
        lines.append("")
        lines.append("  ✅ PASS — exactly one execution under real concurrency" if self.passed
                     else "  ❌ FAIL — this write path can double-fire")
        return "\n".join(lines)


def storm(
    n: int,
    attempt: Callable[[int], str],
    valid_outcomes: set[str] = frozenset({"executed", "replayed", "stood_down", "unreachable"}),
) -> RangeSafetyResult:
    """Run `attempt(i)` from N real, simultaneously-released threads.

    `attempt(i)` is YOUR code: call your write-bearing tool the way an agent
    would, and return one of the strings in `valid_outcomes` describing what
    genuinely happened for that caller. The harness does not trust your
    return value alone — pair it with a real effect counter inside whatever
    `attempt` calls, and check that counter separately (see `__main__` below
    for the pattern).

    Real threads, not a pool: a `ThreadPoolExecutor` sized below `n` would
    stagger the calls and hide the exact race this exists to force.
    """
    barrier = threading.Barrier(n)
    outcomes: list[str | None] = [None] * n
    lock = threading.Lock()

    def run(i: int) -> None:
        barrier.wait()
        try:
            r = attempt(i)
        except Exception as e:
            r = f"error:{type(e).__name__}"
        with lock:
            outcomes[i] = r

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    t0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    dt = time.time() - t0

    counts: dict[str, int] = {}
    unaccounted = 0
    for o in outcomes:
        if o is None:
            unaccounted += 1
            continue
        counts[o] = counts.get(o, 0) + 1
        if o not in valid_outcomes and not o.startswith("error:"):
            unaccounted += 1

    return RangeSafetyResult(n=n, actual_executions=-1, outcomes=counts,
                             unaccounted=unaccounted, wall_time_sec=dt)


# ── self-demonstration: prove the harness distinguishes safe from unsafe ────
if __name__ == "__main__":
    import sys

    N = int(sys.argv[sys.argv.index("--n") + 1]) if "--n" in sys.argv else 200

    print("=" * 66)
    print("  AGENT SIDE-EFFECT RANGE SAFETY TEST — self-demonstration")
    print("  (proving the harness actually catches an unsafe pattern,")
    print("   not just asserting a safe one)")
    print("=" * 66)

    # ── Target A: the naive, unsynchronized "guard" everyone writes first ──
    print(f"\n── Target A: naive in-memory guard (the bug this test exists to find) ──")
    _seen_a: set = set()
    _charges_a = {"n": 0}
    _lock_a = threading.Lock()

    def naive_attempt(i: int) -> str:
        order_id = "order-777"
        # THE BUG: check, then a real gap (simulated I/O), then record.
        if order_id in _seen_a:
            return "replayed"
        time.sleep(0.01)                    # the network round-trip that opens the window
        with _lock_a:
            _charges_a["n"] += 1
        _seen_a.add(order_id)               # recorded AFTER the effect, too late
        return "executed"

    res_a = storm(N, naive_attempt)
    res_a.actual_executions = _charges_a["n"]
    print(res_a.report())
    assert not res_a.passed, "the naive target should FAIL — if it didn't, this harness is broken"
    print("  (confirmed: harness correctly caught the double-fire — it is not a rubber stamp)")

    # ── Target B: a real atomic guard (what passing actually looks like) ───
    print(f"\n── Target B: atomic guard via a DB-style unique claim ──")
    _claimed_b: dict = {}
    _charges_b = {"n": 0}
    _lock_b = threading.Lock()

    def safe_attempt(i: int) -> str:
        order_id = "order-777"
        with _lock_b:                       # the check AND the claim, atomic together
            if order_id in _claimed_b:
                return "replayed"
            _claimed_b[order_id] = True
        time.sleep(0.01)
        with _lock_b:
            _charges_b["n"] += 1
        return "executed"

    res_b = storm(N, safe_attempt)
    res_b.actual_executions = _charges_b["n"]
    print(res_b.report())
    assert res_b.passed, "the atomic target should PASS"

    print("\n" + "=" * 66)
    print("  Both assertions held: this harness FAILS an unsafe guard and")
    print("  PASSES an atomic one. Copy this file, replace `attempt()` with")
    print("  a real call to your own write-bearing tool, and run it for real.")
    print("=" * 66)
