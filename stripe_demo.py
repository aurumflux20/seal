"""Seal + Stripe test-mode demo — the closing asset.

Two agents fire the SAME charge at the same instant. Seal admits exactly one.
One real Stripe test-mode PaymentIntent is created. Then the witness asks
Stripe itself — "how many charges carry this intent?" — and Stripe answers ONE,
upgrading the cert to WORLD_FINAL.

Then a rogue charge is created OUTSIDE the gateway (the thing Seal can't stop
on its own), the witness runs again, Stripe now answers TWO, the cert becomes
WORLD_DIVERGED, and the domain freezes.

Everything here is measured against a live Stripe test account. livemode=False,
no real money. Run:  SEAL_DSN=... python stripe_demo.py
"""
from __future__ import annotations

import os
import threading
import time
import urllib.parse
import urllib.request

from seal import Seal
from seal.core import TIER_WORLD_FINAL, TIER_WORLD_DIVERGED
from seal.witness import StripeWitness, CONFIRMED_ONE

DSN = os.environ["SEAL_DSN"]
KEY = os.environ.get("STRIPE_TEST_KEY") or _read_key()  # noqa: F821 (defined below)


def _read_key() -> str:
    with open(os.path.expanduser("~/.seal-stripe-key")) as f:
        for line in f:
            if line.startswith("STRIPE_TEST_KEY="):
                return line.split("=", 1)[1].strip()
    raise SystemExit("no STRIPE_TEST_KEY")


KEY = os.environ.get("STRIPE_TEST_KEY") or _read_key()
API = "https://api.stripe.com"


# ── real Stripe transport ──────────────────────────────────────────────────
def _auth_header():
    import base64
    tok = base64.b64encode(f"{KEY}:".encode()).decode()
    return {"Authorization": f"Basic {tok}"}


def stripe_search(path: str, params: dict):
    """GET transport for the witness — Stripe search API. Raises on failure
    so the witness maps it to UNKNOWN, never a fabricated ABSENT."""
    url = f"{API}{path}?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=_auth_header())
    with urllib.request.urlopen(req, timeout=20) as r:
        import json
        return json.load(r)


def stripe_create_charge(intent: str, amount: int = 4900) -> str:
    """Create a REAL test-mode PaymentIntent, confirmed with a test card,
    tagged with the seal intent. Returns the PI id."""
    body = {
        "amount": str(amount),
        "currency": "usd",
        "payment_method": "pm_card_visa",
        "confirm": "true",
        "metadata[seal_intent]": intent,
        "automatic_payment_methods[enabled]": "true",
        "automatic_payment_methods[allow_redirects]": "never",
    }
    data = urllib.parse.urlencode(body).encode()
    req = urllib.request.Request(
        f"{API}/v1/payment_intents", data=data,
        headers={**_auth_header(), "Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=25) as r:
        import json
        pi = json.load(r)
    return pi["id"]


# ── the measured effect ────────────────────────────────────────────────────
_charges = {"n": 0}
_lock = threading.Lock()
_pi_ids: list[str] = []


def charge(intent: str) -> dict:
    with _lock:
        _charges["n"] += 1
    pi_id = stripe_create_charge(intent)
    _pi_ids.append(pi_id)
    return {"stripe_payment_intent": pi_id, "amount": 4900}


def poll_until_definite(seal: Seal, intent: str, want_count: int, tries: int = 40, gap: float = 2.0):
    """Stripe search is eventually consistent — a fresh PaymentIntent can take
    30-60s to appear in the search index. An empty result for an object we KNOW
    we just created is 'not indexed yet' (UNKNOWN), NOT authoritative absence.

    So we poll the RAW witness look() until Stripe reports the count we're
    waiting for, and only THEN record it as a cert. This is the honest way to
    witness against an eventually-consistent provider: never freeze the rail on
    a transient empty read. Learned from running against live Stripe test mode.
    """
    from seal.witness import CONFIRMED_ONE, MULTIPLE, CallableWitness
    w = StripeWitness(stripe_search)
    rec = seal.get(intent)
    last = None
    for _ in range(tries):
        last = w.look(rec)
        n = last.count or 0
        if last.state in (CONFIRMED_ONE, MULTIPLE) and n >= want_count:
            break
        time.sleep(gap)
    # record the settled observation exactly once
    seal.witness(intent, CallableWitness(lambda r: last))
    return seal.certs_for(intent)[-1]


def main() -> int:
    seal = Seal(DSN)
    seal.setup()
    import psycopg
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        c.execute("TRUNCATE seal_intents, seal_certs, seal_domains, "
                  "seal_graphs, seal_graph_children RESTART IDENTITY")

    print("=" * 66)
    print("  SEAL × STRIPE (test mode, livemode=False) — closing demo")
    print("=" * 66)

    # Unique per run so Stripe's search index (which persists across runs, keyed
    # on the deterministic seal_intent metadata) only ever sees THIS run's
    # charges. In production the intent is naturally unique per real order; the
    # demo just needs a fresh order id each time it is run.
    import uuid
    KEYSTR = f"checkout:order-{uuid.uuid4().hex[:10]}"
    DOMAIN = f"customer:{uuid.uuid4().hex[:8]}"

    # ── Demo 1: two agents double-click → ONE real charge ──────────────────
    print("\n── 1. Two agents fire the same charge at the same instant ──")
    barrier = threading.Barrier(2)
    intents = {}

    def agent(name):
        s = Seal(DSN)
        barrier.wait()
        adm = s.admit("charge", {"amount": 4900}, key=KEYSTR, domain=DOMAIN)
        if adm.fresh:
            result = charge(adm.intent)
            s.seal(adm.intent, adm.fence, result)
            intents["id"] = adm.intent
            print(f"     {name}: CHARGED — Stripe PI {result['stripe_payment_intent']}")
        else:
            intents["id"] = adm.intent
            print(f"     {name}: stood down (someone else won)")

    ts = [threading.Thread(target=agent, args=(n,)) for n in ("agent-A", "agent-B")]
    for t in ts: t.start()
    for t in ts: t.join()

    intent = intents["id"]
    ok = _charges["n"] == 1
    print(f"\n     ACTUAL Stripe charges created: {_charges['n']}   {'✅' if ok else '❌ DOUBLE CHARGE'}")

    # ── Demo 2: ask Stripe itself ──────────────────────────────────────────
    print("\n── 2. Ask Stripe: how many charges carry this intent? ──")
    print("     (Stripe search is eventually consistent — polling...)")
    last = poll_until_definite(seal, intent, want_count=1)
    print(f"     Stripe witness: {last.get('witness_state')} "
          f"(count={last.get('witness_count')})  →  cert tier {last.get('tier')}")
    final_ok = seal.get(intent)["tier"] == TIER_WORLD_FINAL

    # ── Demo 3: a rogue charge OUTSIDE the gateway → DIVERGED + freeze ─────
    print("\n── 3. A rogue process charges again, bypassing Seal ──")
    rogue_pi = stripe_create_charge(intent)  # same intent tag, no admission
    _pi_ids.append(rogue_pi)
    print(f"     rogue Stripe PI created outside the gate: {rogue_pi}")
    print("     (polling Stripe until its index shows the second charge...)")
    last = poll_until_definite(seal, intent, want_count=2)
    certs = seal.certs_for(intent)
    frozen = seal.domain_frozen(DOMAIN)
    print(f"     Stripe witness: {certs[-1].get('witness_state')} "
          f"(count={certs[-1].get('witness_count')})  →  cert tier {certs[-1].get('tier')}")
    print(f"     domain {DOMAIN} frozen: {frozen is not None}")

    try:
        seal.admit("charge", {"amount": 100}, key="order-778", domain=DOMAIN)
        refused = False
    except Exception:
        refused = True
    print(f"     further spend on {DOMAIN}: {'REFUSED (rail stopped)' if refused else 'ADMITTED ❌'}")

    # ── verdict ────────────────────────────────────────────────────────────
    chain = seal.verify_chain()
    all_ok = (ok and final_ok
              and seal.get(intent)["tier"] == TIER_WORLD_DIVERGED
              and frozen is not None and refused and chain["ok"])
    print("\n" + "=" * 66)
    print("  ✅ DEMO PASSED — one charge, Stripe-confirmed WORLD_FINAL,"
          if all_ok else "  ❌ DEMO FAILED — see above")
    if all_ok:
        print("     then a real divergence caught by Stripe and the rail frozen.")
    print(f"     cert chain: {'VERIFIED' if chain['ok'] else 'BROKEN'} "
          f"({chain.get('certs')} certs)")
    print(f"     Stripe PaymentIntents created this run: {_pi_ids}")
    print("=" * 66)
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
