"""Approval demo — how an agent gets to spend money without a human clicking
every time, and without anyone losing control.

The problem this is for: your agents can do the work, but a person still
approves every purchase order, every payout, every invoice. Not because the
agent is bad at the job — because nobody can prove to Finance and Security
that it is safe to let it finish. So the automation stops one step early,
forever.

This demo shows the middle ground that unblocks that:

    small amounts   -> the agent just does it
    medium amounts  -> two different people must approve
    large amounts   -> always a person, no exceptions

...plus the rules that make Finance actually sign off on it:

    * the person who REQUESTS a spend can never be one of its approvers
    * the same person cannot approve twice to make up the numbers
    * one rejection stops it, no matter how many approvals came before
    * every decision is written into a tamper-evident log

Run:  SEAL_DSN="host=... dbname=..." python approval_demo.py
No payment provider needed. Nothing real is charged.
"""
from __future__ import annotations

import os
import sys
import threading

DSN = os.environ.get("SEAL_DSN")
if not DSN:
    sys.exit('SEAL_DSN not set.  export SEAL_DSN="host=... dbname=..."')

import psycopg

from seal import Seal
from seal.authority import Gateway
from seal.clearance import CLEARED, Clearance
from seal.graduated import (
    ALWAYS_HUMAN, APPROVE, APPROVED, AUTO, DUAL, REJECT,
    GraduatedClearance, SelfApproval,
)

W = 70
ok = True


def head(t):
    print("\n" + "─" * W)
    print(f"  {t}")
    print("─" * W)


def check(label, got, want):
    global ok
    good = got == want
    ok = ok and good
    mark = "✅" if good else "❌"
    print(f"  {mark} {label}")
    if not good:
        print(f"       got {got!r}, expected {want!r}")


def main() -> int:
    seal = Seal(DSN)
    seal.setup()
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        c.execute("TRUNCATE seal_intents, seal_certs, seal_domains, seal_graphs, "
                  "seal_graph_children, seal_clearance, seal_proof, seal_events, "
                  "seal_thresholds, seal_approvals, seal_approval_votes "
                  "RESTART IDENTITY")

    gc = GraduatedClearance(seal)
    cl = Clearance(seal)

    print("=" * W)
    print("  LETTING AN AGENT SPEND MONEY — SAFELY")
    print("=" * W)

    # ── the policy a finance team would actually write ────────────────────
    head("THE POLICY (set once, by your finance/ops team)")
    gc.set_thresholds("purchase_order", auto_ceiling=500,
                      dual_ceiling=50_000, required_approvers=2)
    cl.set_policy("purchase_order", CLEARED)
    cl.record_proof("purchase_order", green=True, storm_n=1000, executions=1)

    print("  Purchase orders:")
    print("    up to    $500     the agent proceeds on its own")
    print("    $500 to  $50,000  two different people must approve")
    print("    above    $50,000  always a person, never automatic")

    gw = Gateway(seal)
    issued = []
    gw.register_executor("purchase_order",
                         lambda a: issued.append(a) or {"po": f"PO-{len(issued):04d}",
                                                        "amount": a["amount"]})

    # ── 1. small: the agent just does it ──────────────────────────────────
    head("1.  Agent orders $200 of office supplies")
    prop = gw.propose("purchase_order", {"amount": 200}, key="po-supplies", amount=200)
    print(f"     tier: {gc.tier_for('purchase_order', 200)}  →  no human needed")
    res = gw.execute(prop["ticket"], {"amount": 200})
    print(f"     PO issued automatically: {res['result']['po']}")
    check("small purchase completed with no human in the loop",
          res["status"], "executed")

    # ── 2. medium: needs two humans ───────────────────────────────────────
    head("2.  Agent requests $12,000 for a supplier invoice")
    first = gw.propose("purchase_order", {"amount": 12_000}, key="po-supplier", amount=12_000)
    print(f"     tier: {first.get('tier')}  →  the agent is NOT allowed to just do this")
    check("agent alone is refused, and told why", first["status"], "needs_approval")

    req = gc.request("purchase_order", 12_000, maker="agent:procurement",
                     intent=first["intent"])
    print(f"     approval request opened, needs {req['required']} different people")

    # ── 3. the rule finance cares about most ──────────────────────────────
    head("3.  The requester tries to approve their own request")
    try:
        gc.add_vote(req["id"], "agent:procurement", APPROVE)
        check("self-approval was blocked", "ALLOWED", "BLOCKED")
    except SelfApproval:
        print("     refused — whoever asks for the money can never approve it")
        check("self-approval was blocked", "BLOCKED", "BLOCKED")

    # ── 4. one person cannot approve twice ────────────────────────────────
    head("4.  One approver tries to count twice")
    gc.add_vote(req["id"], "dana@finance", APPROVE)
    print("     dana@finance approves           (1 of 2)")
    try:
        gc.add_vote(req["id"], "dana@finance", APPROVE)
        check("duplicate approval was blocked", "ALLOWED", "BLOCKED")
    except Exception:
        print("     dana tries again              refused — one person, one vote")
        check("duplicate approval was blocked", "BLOCKED", "BLOCKED")
    print(f"     still waiting: {gc.get(req['id'])['state']}")

    # ── 5. a second, different person approves ────────────────────────────
    head("5.  A second person approves")
    out = gc.add_vote(req["id"], "sam@ops", APPROVE)
    print("     sam@ops approves                (2 of 2)")
    check("request is now approved", out["state"], APPROVED)

    prop2 = gw.propose("purchase_order", {"amount": 12_000}, key="po-supplier",
                       amount=12_000, approval_id=req["id"])
    res2 = gw.execute(prop2["ticket"], {"amount": 12_000})
    print(f"     PO issued: {res2['result']['po']}")
    check("payment went through only after two approvals", res2["status"], "executed")

    # ── 6. rejection wins ─────────────────────────────────────────────────
    head("6.  A different request gets one approval, then one rejection")
    third = gw.propose("purchase_order", {"amount": 8_000}, key="po-rejected", amount=8_000)
    req2 = gc.request("purchase_order", 8_000, maker="agent:procurement",
                      intent=third["intent"])
    gc.add_vote(req2["id"], "dana@finance", APPROVE)
    print("     dana@finance approves")
    out2 = gc.add_vote(req2["id"], "sam@ops", REJECT)
    print("     sam@ops rejects                 one 'no' ends it")
    check("one rejection stops the spend", out2["state"], "rejected")

    # ── 7. big money is never automatic ───────────────────────────────────
    head("7.  Agent requests $250,000")
    tier = gc.tier_for("purchase_order", 250_000)
    print(f"     tier: {tier}  →  no policy setting can make this automatic")
    check("large spend always requires a person", tier, ALWAYS_HUMAN)

    # ── 8. the audit trail ────────────────────────────────────────────────
    head("8.  What your auditor sees")
    chain = seal.verify_chain()
    report = cl.range_report()
    ap = report["approvals"]
    approved = ap.get("approved", {"count": 0, "amount": 0})
    rejected = ap.get("rejected", {"count": 0, "amount": 0})
    print(f"     every decision recorded, tamper-evident:  {'VERIFIED' if chain['ok'] else 'BROKEN'}")
    print(f"     certificates in the log:                  {chain['certs']}")
    print(f"     times an agent was stopped and made to ask: "
          f"{report['events'].get('approval_required', 0)}")
    print(f"     spend approved by two people:             "
          f"${approved['amount']:,.0f}  ({approved['count']} request(s))")
    print(f"     spend a human stopped:                    "
          f"${rejected['amount']:,.0f}  ({rejected['count']} request(s))")
    print("     each one shows who asked, who approved, who refused, and when")
    check("audit log is complete and tamper-evident", chain["ok"], True)
    check("the report counts money, not just events",
          (approved["amount"], rejected["amount"]), (12_000.0, 8_000.0))
    check("agent refusals are counted, not silent",
          report["events"].get("approval_required", 0), 2)

    # ── 9. the kill switch ────────────────────────────────────────────────
    head("9.  Something looks wrong — stop everything")
    cl.revoke("purchase_order", reason="finance review", by="ciso@company")
    from seal.clearance import ClearanceDenied
    try:
        gw.propose("purchase_order", {"amount": 100}, key="po-after-stop", amount=100)
        check("everything stopped", "STILL RUNNING", "STOPPED")
    except ClearanceDenied:
        print("     one switch. even the $100 automatic purchases stop.")
        print("     an agent cannot turn this back on — only a person can.")
        check("everything stopped", "STOPPED", "STOPPED")

    print("\n" + "=" * W)
    if ok:
        print("  ✅ ALL CHECKS PASSED")
        print()
        print("  The agent handled the small purchase by itself.")
        print("  The $12,000 one waited for two different people.")
        print("  Nobody could approve their own request, or vote twice.")
        print("  One 'no' stopped a payment. Big money always needs a person.")
        print("  Everything is in a log that cannot be quietly edited.")
        print(f"  Real purchases made: {len(issued)}")
    else:
        print("  ❌ SOMETHING FAILED — see above")
    print("=" * W)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
