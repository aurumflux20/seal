"""Out-of-band spend detection — find money that moved WITHOUT the gateway.

The honest limit we have always printed is: *Seal cannot stop a process that
holds the credential and bypasses the gateway.* That stays true. This module
changes what happens next — bypass is now **detectable**, and detectable fast.

The witness answers one question: "provider, does THIS intent exist?" That only
ever sees effects we already know about. It is blind by construction to the
dangerous case — a charge the provider made that we never admitted at all.

This is the inverse sweep. Enumerate what the provider actually did in a window,
and subtract what we admitted. Anything left is spend that did not come through
the gateway:

    provider effects in window  −  effects carrying our intent tag  =  out-of-band

Why it matters commercially as well as technically: "we prevent double-charges
on the path you route through us" is a smaller promise than "we prevent them on
that path AND tell you when something moved money outside it." The second is the
one a CFO actually wants, because the failure they fear is the one nobody
reported.

What this does NOT claim, stated here rather than left to be discovered:

* It is **detection, not prevention.** By the time a sweep sees it, the money
  moved. The value is the clock: minutes instead of the next statement.
* It can only see what the provider will enumerate. A provider with no list
  endpoint, or a window the API won't serve, is `UNKNOWN` — and `UNKNOWN` is
  never reported as "clean". Same rule as the witness.
* An effect legitimately created before Seal was installed is out-of-band by
  this definition. Set `since` accordingly, or tag legacy effects.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Protocol

from .core import Seal

# Verdicts for a sweep as a whole.
CLEAN = "clean"                # provider answered, everything matched a cert
OUT_OF_BAND = "out_of_band"    # provider answered, effects exist we never admitted
UNKNOWN = "unknown"            # we could not enumerate — NOT the same as clean


@dataclass(frozen=True)
class ProviderEffect:
    """One thing the provider says it actually did.

    `intent_tag` is our marker if present (Stripe: metadata['seal_intent']).
    Absent/None means the provider has no record that this came from us, which
    is exactly the signal this module exists to surface.
    """
    id: str
    amount: float | None = None
    created_at: float | None = None
    intent_tag: str | None = None
    raw: dict = field(default_factory=dict)


class ProviderLister(Protocol):
    """Enumerates effects the provider performed in a window.

    Must RAISE if it cannot enumerate. Returning an empty list has to mean
    "the provider answered and there were none" — never "the call failed".
    Collapsing those two is the same mistake as treating UNKNOWN as ABSENT,
    and here it would report a breach as a clean bill of health.
    """

    def list_effects(self, since: float, until: float) -> Iterable[ProviderEffect]:
        ...


class CallableLister:
    """Wrap a plain function as a ProviderLister (tests, one-offs)."""

    def __init__(self, fn: Callable[[float, float], Iterable[ProviderEffect]]):
        self._fn = fn

    def list_effects(self, since: float, until: float) -> Iterable[ProviderEffect]:
        return self._fn(since, until)


class StripeLister:
    """List Stripe PaymentIntents in a window, tagged or not.

    HONESTY: implemented against Stripe's documented list API, NOT measured
    against a live account. Per the provider-atlas rule that makes it
    DOCUMENTED, not MEASURED — do not present it as verified until it has run
    against a real test-mode key.
    """

    def __init__(self, transport: Callable[[str, dict], Any], *,
                 metadata_key: str = "seal_intent"):
        self._transport = transport
        self._metadata_key = metadata_key

    def list_effects(self, since: float, until: float) -> Iterable[ProviderEffect]:
        # Deliberately no try/except: a failure must propagate so the sweep
        # reports UNKNOWN rather than an empty (= "clean") result.
        out: list[ProviderEffect] = []
        params = {"created[gte]": int(since), "created[lte]": int(until), "limit": 100}
        body = self._transport("/v1/payment_intents", params)
        for d in (body.get("data") or []):
            if d.get("status") not in ("succeeded", "processing"):
                continue          # existed but settled nothing — not spend
            out.append(ProviderEffect(
                id=d.get("id", ""),
                amount=d.get("amount"),
                created_at=d.get("created"),
                intent_tag=(d.get("metadata") or {}).get(self._metadata_key),
                raw={"status": d.get("status")},
            ))
        return out


class Reconciler:
    """Sweep the provider for spend that never passed through the gateway."""

    def __init__(self, seal: Seal):
        self.seal = seal

    def _known_intents(self, since: float, until: float) -> set[str]:
        """Every intent this gateway admitted in the window.

        Deliberately reads seal_intents, not seal_certs: an intent that was
        admitted and executed but whose seal was lost (the accept-backlog
        failure mode in STORM-PROOF #2) is still OURS. Matching only against
        sealed certs would report our own successful charge as a breach.
        """
        with self.seal._connect(autocommit=True) as c:
            rows = c.execute(
                "SELECT intent FROM seal_intents WHERE created_at >= %s AND created_at <= %s",
                (since - 3600, until + 3600),   # generous edges: clock skew is not a breach
            ).fetchall()
        return {r[0] for r in rows}

    def sweep(self, lister: ProviderLister, *, since: float, until: float | None = None,
              freeze_domain: str | None = None) -> dict:
        """Compare provider reality against what we admitted.

        `freeze_domain` — if given and out-of-band spend is found, that domain
        is frozen so the gateway stops admitting further spend on it. Detection
        without a lever is just a nicer way to find out later.
        """
        until = time.time() if until is None else until

        try:
            effects = list(lister.list_effects(since, until))
        except Exception as e:
            # Could not enumerate. Report UNKNOWN loudly. Never "clean".
            self.seal.record_event("reconcile_unknown", detail={"error": repr(e)})
            return {
                "verdict": UNKNOWN,
                "reason": "provider could not be enumerated — this is NOT a clean result",
                "error": repr(e),
                "since": since, "until": until,
            }

        known = self._known_intents(since, until)
        matched, unknown_tag, untagged = [], [], []
        for e in effects:
            if e.intent_tag and e.intent_tag in known:
                matched.append(e)
            elif e.intent_tag:
                # Carries a seal tag we have no record of — a different Seal
                # store, a forged tag, or our own data loss. Suspicious either way.
                unknown_tag.append(e)
            else:
                untagged.append(e)

        rogue = untagged + unknown_tag
        verdict = OUT_OF_BAND if rogue else CLEAN

        report = {
            "verdict": verdict,
            "since": since, "until": until,
            "provider_effects": len(effects),
            "matched_our_certs": len(matched),
            "out_of_band": len(rogue),
            "out_of_band_ids": [e.id for e in rogue][:20],
            "out_of_band_amount": sum(e.amount or 0 for e in rogue),
            "untagged": len(untagged),
            "tagged_but_unknown_to_us": len(unknown_tag),
            "note": (
                "out_of_band means the provider performed spend this gateway "
                "never admitted. Detection, not prevention — the money already "
                "moved. UNKNOWN is never reported as clean."
            ),
        }

        if rogue:
            self.seal.record_event(
                "out_of_band_spend",
                detail={"count": len(rogue), "amount": report["out_of_band_amount"],
                        "ids": report["out_of_band_ids"], "domain": freeze_domain},
            )
            if freeze_domain:
                self.seal.freeze_domain(
                    freeze_domain,
                    reason=f"out-of-band spend detected: {len(rogue)} effect(s) "
                           f"the gateway never admitted",
                )
                report["domain_frozen"] = freeze_domain
        else:
            self.seal.record_event("reconcile_clean", detail={"effects": len(effects)})

        return report
