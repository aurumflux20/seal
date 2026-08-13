# The Agent Side-Effect Range Safety Test

**Run this against your own MCP server. It's designed to fail servers that
deserve to fail it — including, until we fixed it, an early version of ours.**

## The one question it answers

When N agents (or one agent retrying) fire the same logical irreversible
action — a charge, a payout, a send — at the same instant, does your guard
let more than one through?

```bash
python range_safety_test.py --n 1000
```

No dependency on this repo. Copy `range_safety_test.py` alone, replace the
`attempt()` function with a real call to your own write-bearing tool, and run
it. If it fails, you have found a genuine gap — the harness measures the
actual side effect, it does not trust your code's own account of itself.

## What "passing" actually means

`ACTUAL_EXECUTIONS == 1`. Not "no exceptions were thrown" — a double charge is
not an error, it is two successes, and a test that only checks for exceptions
will tell you your unsafe code is fine. The harness wraps the guarded action
in a real counter behind its own lock and asserts on that counter, not on
whether anything crashed.

## Why the harness itself is worth reading before you trust it

We built the wrong version of this test three times before this one, each
time believing it proved something it didn't:

1. **A thread pool is not concurrency.** A pool with fewer workers than tasks
   staggers the calls — worker 1 finishes before worker 40 starts, so the race
   you're claiming to test never actually happens, and a pass just proves
   scheduling got lucky. This harness uses real OS threads, all parked on a
   `threading.Barrier`, released together. If your own test harness can't
   produce genuine simultaneity, a green result from it means nothing.

2. **"No exceptions" is not "no double."** See above. Measure the effect.

3. **The losers are not one outcome.** A caller that lost the race can
   legitimately replay a cached result, legitimately stand down mid-flight
   because someone else is still working, or legitimately fail closed because
   the coordination store was briefly unreachable. All three are *safe*.
   Silently letting an outcome go unaccounted for — swallowing an exception,
   ignoring a thread that never reported back — is how a real bug hides behind
   a passing test. This harness buckets every outcome and flags anything that
   doesn't land in a known bucket as `UNACCOUNTED`, which fails the run.

## Proof the harness itself isn't a rubber stamp

Run the file with no arguments and it demonstrates itself against two
synthetic targets before you ever point it at your own code:

- **Target A**, a naive in-memory guard with a real check-then-act window —
  the harness correctly **fails** it. At `n=1000` on this machine it measured
  **58 actual executions**, not the full 1,000 and not a clean round number —
  which is the honest, slightly unsettling shape of a real race: how many
  callers actually land inside the window varies run to run. That's real
  nondeterminism, not a canned result.
- **Target B**, the same shape guarded by an atomic claim (a single lock
  covering check-and-record together) — the harness correctly **passes** it:
  exactly 1 execution, 999 replays, every one of the thousand accounted for.

Both assertions are `assert` statements in the file itself — if either target
produced the wrong verdict, the script would crash with an `AssertionError`
rather than print a false "pass." A benchmark that can't fail is not a
benchmark.

## Honest limits — what this does NOT prove

- **One intent under contention.** It says nothing about many *different*
  intents settling concurrently — that needs its own storm, not this one.
- **Nothing about the outside world.** Passing this proves your gateway admits
  the action once. It says nothing about whether the provider (Stripe, your
  bank, whatever actually moves the money) agrees with your local ledger
  afterward — a timeout can still leave you not knowing whether the effect
  really landed. That's a different, harder property. If you're curious what
  that layer looks like once you've closed the local race, see the `seal`
  project this file ships alongside: exactly-once admission plus **world
  confirmation measured against a live payment provider**, not mocked.
- **This is a local property test, not a security audit.** Passing it does
  not mean your system is safe from a compromised credential, a malicious
  insider, or any threat model other than "two honest callers raced."

## We ran it on ourselves first

The kernel this harness ships alongside passes it at `n=1000`, four
consecutive runs, verified from a fresh clone: see
[`STORM-PROOF.md`](../STORM-PROOF.md). We do not ask anyone to run a test
we haven't already failed and fixed ourselves — [`STORM-PROOF.md`](../STORM-PROOF.md)
also lists the six real bugs that surfaced from doing exactly that.
