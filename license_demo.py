"""Earned autonomy, watched live.

    SEAL_DSN=... python license_demo.py

Every other guard in this space gives you a cap a human sets once. This shows
the opposite: an agent that starts with no authority, earns unattended spend by
proving itself, and loses all of it the instant money moves behind the gateway.

Every number printed is measured from the ledger, not asserted.
"""
from __future__ import annotations

import os
import sys
import time

import psycopg

from seal import Seal
from seal.license import LicenceEngine
from seal.reconcile import CallableLister, ProviderEffect, Reconciler
from seal.witness import CONFIRMED_ONE, CallableWitness, WitnessResult

DSN = os.environ["SEAL_DSN"]
PATH = "charge"
ok = True
seq = iter(range(10_000))


def check(label, got, want):
    global ok
    good = got == want
    ok = ok and good
    print(f"  {'✅' if good else '❌'} {label}: {got}" + ("" if good else f"  (expected {want})"))


def show(eng, note):
    lic = eng.evaluate(PATH)
    bar = "█" * (int(lic.level[1]) * 4) + "·" * ((5 - int(lic.level[1])) * 4)
    state = "SUSPENDED" if lic.suspended else ("unattended" if lic.unattended else "human required")
    print(f"  {bar}  {lic.level} {lic.name:<11} {lic.proven:>4} proven · "
          f"{lic.confirmed_ratio:>4.0%} confirmed   [{state}]")
    if note:
        print(f"       {note}")
    return lic


def settle(seal, n):
    for _ in range(n):
        i = next(seq)
        a = seal.admit("charge", {"amount": 100 + i}, key=f"lic-{i}", domain=PATH)
        seal.seal(a.intent, a.fence, {"charged": 100 + i})
        seal.witness(a.intent, CallableWitness(
            lambda intent: WitnessResult(CONFIRMED_ONE, count=1, evidence="provider ok")))


seal = Seal(DSN)
seal.setup()
with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
    c.execute("TRUNCATE seal_intents, seal_certs, seal_domains, seal_graphs, "
              "seal_graph_children, seal_clearance, seal_proof, seal_events, "
              "seal_thresholds, seal_approvals, seal_approval_votes, seal_tickets "
              "RESTART IDENTITY")

eng = LicenceEngine(seal)

print(f"\n{'━'*72}\n  AN AGENT EARNS ITS LICENCE TO SPEND — then loses it\n{'━'*72}\n")

show(eng, "day one: no record, so no authority. every charge needs a human.")
check("fresh agent may act unattended", eng.evaluate(PATH).unattended, False)

print()
settle(seal, 1);   show(eng, "first settlement the provider confirmed.")
settle(seal, 9);   show(eng, "ten clean, confirmed settlements.")
settle(seal, 40);  show(eng, "fifty — but volume alone is not trust.")

lic = eng.evaluate(PATH)
check("50 confirmed settlements is enough on its own", lic.unattended, False)
print(f"       still needs: {lic.needs[0] if lic.needs else '—'}")

print("\n  ...the gateway sweeps the provider: did anything move behind our back?")
Reconciler(seal).sweep(CallableLister(lambda a, b: []), since=time.time() - 3600)
lic = show(eng, "clean sweep. the human stops clicking Approve.")
check("licence now grants unattended spend", lic.unattended, True)
check("level earned", lic.level, "L3")

print(f"\n{'─'*72}")
print("  Now a charge appears on the provider that this gateway never admitted")
print("  (a leaked key, a rogue script — the money already moved).")
print(f"{'─'*72}\n")

Reconciler(seal).sweep(
    CallableLister(lambda a, b: [ProviderEffect(id="pi_rogue", amount=25000)]),
    since=time.time() - 3600, freeze_domain=PATH,
)

lic = show(eng, "one breach. fifty clean settlements do not outweigh it.")
check("licence suspended", lic.suspended, True)
check("unattended authority revoked", lic.unattended, False)
print(f"       {lic.suspended_reason}")

print("\n  ...and good behaviour afterwards does not wash it off:")
Reconciler(seal).sweep(CallableLister(lambda a, b: []), since=time.time() - 3600)
check("still suspended after a clean sweep", eng.evaluate(PATH).suspended, True)

print(f"\n{'━'*72}")
print("  ✅ DEMO PASSED — autonomy earned by evidence, revoked by evidence"
      if ok else "  ❌ DEMO FAILED — see above")
print(f"{'━'*72}\n")
sys.exit(0 if ok else 1)
