"""Pre-commit World Freeze — B1 in the locked spec, and the one line of the
20x feature map that was in the schema and not in the code.

`admit()` has always accepted `read_set` — the world facts a decision depends
on ("cart total was $50", "inventory had 3 units") — and stored it on the
cert. Nothing ever checked it. A caller who believed they had staleness
protection had none: `read_set` was write-only.

That is the same defect shape as the ticket-replay bug found earlier tonight —
a guard present in the plumbing, never enforced in the store — just one layer
up, in the decision to admit rather than the decision to execute.

The fix follows the same idiom as `witness.py`: a small Protocol the caller
implements against THEIR world, injected at the call site, never owned by
Seal. Seal does not know what a "cart total" is; it only knows how to refuse
to grant a fence when the caller's own check says the facts it is about to act
on have already moved.

Enforcement point is deliberate: BEFORE the fence is granted, inside admit(),
not at seal() after the effect has already run. Checking after the effect ran
can only refuse to claim success — it cannot stop money from moving on stale
information, which is the actual thing "pre-commit" freeze exists to prevent.
"""
from __future__ import annotations

from typing import Any, Callable, Protocol


class Checker(Protocol):
    """Anything that can say whether a read-set is still true right now."""

    def fresh(self, read_set: Any) -> bool:
        ...


class CallableChecker:
    """Wrap a plain function as a Checker. Handy for tests and one-offs."""

    def __init__(self, fn: Callable[[Any], bool]):
        self._fn = fn

    def fresh(self, read_set: Any) -> bool:
        return self._fn(read_set)
