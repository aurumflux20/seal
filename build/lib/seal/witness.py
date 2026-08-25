"""World witnesses — the part where software stops believing only itself.

A SEALED cert says "this gateway admitted the action exactly once." That is a
claim about *us*. A witness asks the provider — Stripe, the mail API, the
chain — "how many of these actually exist on your side?" and the answer is
allowed to disagree with us.

The four answers, and why the middle one is the whole ballgame:

    CONFIRMED_ONE  exactly one matching effect exists      → WORLD_FINAL
    MULTIPLE       more than one exists                    → WORLD_DIVERGED
    ABSENT         provider says definitively: none exist  → WORLD_DIVERGED
    UNKNOWN        we could not find out                   → WORLD_UNKNOWN

`UNKNOWN` must NEVER collapse into `ABSENT`. A timeout, a 500, a rate-limit,
a network reset — none of those mean "it didn't happen." Treating them as
"absent" and re-running is precisely the double-charge bug this product
exists to stop, and it is the single most common mistake in every retry
client we have audited. Only an explicit, authoritative "no such object"
(a 404 on a direct lookup, or an empty result from a query the provider
answered successfully) is ABSENT.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

CONFIRMED_ONE = "confirmed_one"
MULTIPLE = "multiple"
ABSENT = "absent"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class WitnessResult:
    state: str                              # one of the four constants above
    count: int | None = None                # matching effects, when countable
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.state not in (CONFIRMED_ONE, MULTIPLE, ABSENT, UNKNOWN):
            raise ValueError(f"unknown witness state {self.state!r}")


class Witness(Protocol):
    """Anything that can look up an effect in the outside world."""

    def look(self, record: dict) -> WitnessResult:
        ...


class CallableWitness:
    """Wrap a plain function as a Witness. Handy for tests and one-offs."""

    def __init__(self, fn: Callable[[dict], WitnessResult]):
        self._fn = fn

    def look(self, record: dict) -> WitnessResult:
        return self._fn(record)


class StripeWitness:
    """Ask Stripe how many charges carry this intent id.

    We tag every PaymentIntent with `metadata[seal_intent] = <intent>` at
    creation time, then count what Stripe reports back. One is settled; two is
    a divergence we must not paper over; a failed lookup is UNKNOWN.

    `transport` is injected so this class is testable without a network or a
    live key: it takes (path, params) and returns the decoded JSON body, or
    raises to signal "could not find out".

    HONESTY: the request shape below is implemented against Stripe's documented
    search API but has NOT been measured against live Stripe. Per our provider
    atlas rule, that makes it DOCUMENTED, not MEASURED — do not present it as a
    verified integration until it has run against a real test-mode account.
    """

    def __init__(self, transport: Callable[[str, dict], Any], *, metadata_key: str = "seal_intent"):
        self._transport = transport
        self._metadata_key = metadata_key

    def look(self, record: dict) -> WitnessResult:
        intent = record["intent"]
        query = f"metadata['{self._metadata_key}']:'{intent}'"
        try:
            body = self._transport("/v1/payment_intents/search", {"query": query})
        except Exception as e:
            # Could not find out. NOT "absent" — see the module docstring.
            return WitnessResult(UNKNOWN, evidence={"error": repr(e)})

        data = body.get("data")
        if data is None:
            # A well-formed provider reply we cannot interpret is still
            # "we don't know", never "nothing there".
            return WitnessResult(UNKNOWN, evidence={"unparsed": body})

        # Only count effects that actually moved money. A canceled or failed
        # PaymentIntent exists as an object but settled nothing, and counting
        # it would manufacture a divergence that did not happen.
        settled = [d for d in data if d.get("status") in ("succeeded", "processing")]
        n = len(settled)
        ev = {"matched": n, "ids": [d.get("id") for d in settled][:10]}
        if n == 1:
            return WitnessResult(CONFIRMED_ONE, count=1, evidence=ev)
        if n > 1:
            return WitnessResult(MULTIPLE, count=n, evidence=ev)
        return WitnessResult(ABSENT, count=0, evidence=ev)
