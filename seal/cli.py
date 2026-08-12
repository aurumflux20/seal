"""`python -m seal verify` — audit the cert chain from the store alone.

The point of the exercise: an auditor needs the Postgres DSN and nothing else.
No network, no vendor, no trust in the process that wrote the certs. Editing,
deleting or reordering any cert breaks every hash after it, and this command
says so with a nonzero exit code.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .core import Seal


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="seal")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="verify the cert chain from the store alone")
    v.add_argument(
        "--dsn",
        default=os.environ.get("SEAL_DSN"),
        help="Postgres DSN (or set SEAL_DSN)",
    )
    v.add_argument("--json", action="store_true", help="machine-readable output")

    args = p.parse_args(argv)

    if args.cmd == "verify":
        if not args.dsn:
            print("seal verify: no DSN (pass --dsn or set SEAL_DSN)", file=sys.stderr)
            return 2
        report = Seal(args.dsn).verify_chain()
        if args.json:
            print(json.dumps(report, sort_keys=True))
        elif report["ok"]:
            print(f"chain VERIFIED — {report['certs']} cert(s), every link intact")
        else:
            print(f"chain BROKEN at cert #{report['at']}: {report['why']}")
        return 0 if report["ok"] else 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
