"""Executor module used by the seal-mcp gateway-mode tests.

Stands in for the operator's real module — the one that would hold the Stripe
key. It records every actual "provider call" to a file so the test can count
real executions the same way storm.py does: with a counter that cannot lie.
"""
from __future__ import annotations

import os


def _record(path: str, amount) -> None:
    log = os.environ.get("SEAL_TEST_CALLS")
    if log:
        with open(log, "a", encoding="utf-8") as fh:
            fh.write(f"{path}:{amount}\n")


def register(gw) -> None:
    def charge(args: dict):
        _record("charge", args.get("amount"))
        return {"provider_id": "pi_test_123", "amount": args.get("amount")}

    def payout(args: dict):
        _record("payout", args.get("amount"))
        return {"provider_id": "po_test_456", "amount": args.get("amount")}

    gw.register_executor("charge", charge)
    gw.register_executor("payout", payout)
