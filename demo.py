"""Seal end-to-end demo — the three claims, run in front of you.

    SEAL_DSN=... python demo.py

Demo A  two agents double-click            → exactly ONE charge
Demo B  the world is asked, and disagrees  → WORLD_DIVERGED, domain frozen
Demo C  a checkout fails halfway           → sealed refund, GRAPH_COMPENSATED
Demo D  spend that bypassed the gateway    → OUT_OF_BAND, domain frozen

Every number printed is measured, not asserted: the "charge" and "refund"
functions increment real counters, so if the property broke, the demo says so
and exits nonzero.
"""
from __future__ import annotations

import os
import sys
import time
import threading

import psycopg

from seal import Seal
from seal.core import TIER_WORLD_FINAL
from seal.graph import GRAPH_COMPENSATED, GRAPH_FINAL, EffectGraph
from seal.witness import CONFIRMED_ONE, MULTIPLE, CallableWitness, WitnessResult
from seal.reconcile import CLEAN, OUT_OF_BAND, CallableLister, ProviderEffect, Reconciler

DSN = os.environ["SEAL_DSN"]
ok = True


def head(n, t):
    print(f"\n{'━'*66}\n  DEMO {n} · {t}\n{'━'*66}")


def check(label, got, want):
    global ok
    good = got == want
    ok = ok and good
    print(f"  {'✅' if good else '❌'} {label}: {got}" + ("" if good else f"  (expected {want})"))


def reset(s):
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        c.execute("TRUNCATE seal_intents, seal_certs, seal_domains, "
                  "seal_graphs, seal_graph_children RESTART IDENTITY")


def _w(state, **kw):
    return CallableWitness(lambda rec: WitnessResult(state, **kw))


seal = Seal(DSN)
seal.setup()
reset(seal)

# ── A · two agents, one charge ────────────────────────────────────────────
head("A", "Two agents double-click the same order")
charges = {"n": 0}
lock = threading.Lock()


def stripe_charge():
    with lock:
        charges["n"] += 1
    return {"amount": 4900, "currency": "usd"}


def agent(name, barrier, out):
    s = Seal(DSN)
    barrier.wait()
    adm = s.admit("charge", {"amount": 4900}, key="order-777", domain="customer:42")
    if adm.fresh:
        s.seal(adm.intent, adm.fence, stripe_charge())
        out[name] = "charged"
    else:
        out[name] = "replayed the receipt" if adm.cert else "stood down"


b, out = threading.Barrier(2), {}
ts = [threading.Thread(target=agent, args=(n, b, out)) for n in ("agent-A", "agent-B")]
[t.start() for t in ts]
[t.join() for t in ts]
for k, v in sorted(out.items()):
    print(f"     {k}: {v}")
check("real charges executed", charges["n"], 1)

intent = seal.admit("charge", {"amount": 4900}, key="order-777", domain="customer:42").intent

# ── B · ask the world ─────────────────────────────────────────────────────
head("B", "Ask the provider what really happened")
seal.witness(intent, _w(CONFIRMED_ONE, count=1))
check("cert tier after a clean witness", seal.get(intent)["tier"], TIER_WORLD_FINAL)

print("\n  ...now a rogue process charges again outside the gateway:")
seal.witness(intent, _w(MULTIPLE, count=2))
check("cert tier after divergence", seal.get(intent)["tier"], "WORLD_DIVERGED")
check("domain frozen", seal.domain_frozen("customer:42") is not None, True)

try:
    seal.admit("charge", {"amount": 100}, key="order-778", domain="customer:42")
    check("further spend on that customer", "ADMITTED", "REFUSED")
except Exception as e:
    check("further spend on that customer", f"REFUSED ({type(e).__name__})",
          "REFUSED (DomainFrozen)")

r = seal.incident_receipt(intent)
print(f"     incident receipt: {len(r['certs'])} certs, "
      f"chain_verified={r['chain_verified']}, digest={r['receipt_digest'][:16]}…")

# ── C · a checkout that fails halfway ─────────────────────────────────────
head("C", "Checkout fails after the money moved")
reset(seal)
g = EffectGraph(seal)
g.create("checkout:1001", [
    {"key": "charge", "action": "charge", "args": {"amount": 4900}, "required": True},
    {"key": "fulfill", "action": "fulfill", "args": {"sku": "ABC"}, "required": True},
])

a = g.admit_child("checkout:1001", "charge")
g.commit_child("checkout:1001", "charge", a.intent, a.fence, stripe_charge())
g.seal.witness(a.intent, _w(CONFIRMED_ONE, count=1))
print("     charge: WORLD_FINAL (money really moved)")

f = g.admit_child("checkout:1001", "fulfill")
g.fail_child("checkout:1001", "fulfill", f.intent, f.fence, "warehouse API down")
print("     fulfill: FAILED (warehouse down)")
check("graph is NOT final", g.evaluate("checkout:1001")["state"] != GRAPH_FINAL, True)

refunds = {"n": 0}


def stripe_refund():
    refunds["n"] += 1
    return {"refunded": 4900}


print("\n  ...the caller retries the compensation 5 times (agents do this):")
for _ in range(5):
    cert = g.compensate("checkout:1001", "refund", "charge", "refund",
                        {"amount": 4900}, stripe_refund)
check("real refunds executed", refunds["n"], 1)
check("graph state", g.get("checkout:1001")["state"], GRAPH_COMPENSATED)
check("refund cert links to the charge it reverses", bool(cert["compensates_cert"]), True)
check("whole chain still verifies", seal.verify_chain()["ok"], True)

# ── D · spend that never passed through the gateway ───────────────────
head("D", "A charge that bypassed the gateway entirely")
reset(seal)
t0 = time.time() - 60

# One legitimate charge, admitted and sealed the normal way.
adm = seal.admit("charge", {"amount": 4900}, key="order-2001", domain="charge")
seal.seal(adm.intent, adm.fence, {"charged": 4900})
print("     1 charge admitted + sealed through the gateway (the honest one)")

# The provider's ledger holds THREE charges. Two never passed through us:
# a leaked API key firing directly, and a tag from a store we don't know.
def provider_ledger(since, until):
    return [
        ProviderEffect(id="pi_legit", amount=4900, intent_tag=adm.intent),
        ProviderEffect(id="pi_rogue_key", amount=25000, intent_tag=None),
        ProviderEffect(id="pi_forged", amount=9900, intent_tag="intent-we-never-issued"),
    ]

print("     provider ledger actually shows 3 charges\n")
rep = Reconciler(seal).sweep(CallableLister(provider_ledger), since=t0,
                             freeze_domain="charge")

check("verdict", rep["verdict"], OUT_OF_BAND)
check("charges we authorised", rep["matched_our_certs"], 1)
check("spend that bypassed the gateway", rep["out_of_band"], 2)
check("unauthorised amount caught (cents)", rep["out_of_band_amount"], 34900)
check("domain frozen on detection", rep.get("domain_frozen"), "charge")
print(f"     caught: {rep['out_of_band_ids']}")

# A provider we cannot enumerate must never be reported as clean.
def provider_down(since, until):
    raise RuntimeError("stripe API unreachable")

down = Reconciler(seal).sweep(CallableLister(provider_down), since=t0)
check("provider unreachable is NOT reported clean", down["verdict"] != CLEAN, True)
print(f"     verdict when the provider is down: {down['verdict']}")


print(f"\n{'━'*66}")
print("  ✅ ALL DEMOS PASSED" if ok else "  ❌ A DEMO FAILED — see above")
print(f"{'━'*66}\n")
sys.exit(0 if ok else 1)
