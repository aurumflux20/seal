"""`python -m seal` — the audit surface.

    verify          audit the whole cert chain. Needs the Postgres DSN and
                    nothing else — no network, no vendor, no trust in the
                    process that wrote the certs.
    export          one intent's evidence as a portable receipt (JSON on
                    stdout). Needs the DSN.
    verify-receipt  check a receipt file. Needs NO database at all — this is
                    the command the OTHER side of a dispute runs. Pass
                    --pubkey (the gateway's Ed25519 public key, hex, obtained
                    out of band) to verify authorship, not just consistency.
    keygen          mint an Ed25519 signing keypair for SEAL_SIGNING_KEY.

Editing, deleting or reordering any cert breaks every hash after it, and every
command here says so with a nonzero exit code.
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

    e = sub.add_parser("export", help="export one intent's portable receipt")
    e.add_argument("--intent", required=True, help="the intent id to export")
    e.add_argument("--dsn", default=os.environ.get("SEAL_DSN"),
                   help="Postgres DSN (or set SEAL_DSN)")

    vr = sub.add_parser(
        "verify-receipt",
        help="verify a receipt file — no database needed",
    )
    vr.add_argument("file", help="receipt JSON file (- for stdin)")
    vr.add_argument("--pubkey", default=None,
                    help="pinned Ed25519 public key (hex). Without it the "
                         "verdict is consistency only, never authorship")
    vr.add_argument("--json", action="store_true", help="machine-readable output")

    sub.add_parser("keygen", help="mint an Ed25519 signing keypair")

    ob = sub.add_parser(
        "obligations",
        help="sweep declared duties for silence — exit 1 on any open breach",
    )
    ob.add_argument("--dsn", default=os.environ.get("SEAL_DSN"),
                    help="Postgres DSN (or set SEAL_DSN)")
    ob.add_argument("--json", action="store_true", help="machine-readable output")

    args = p.parse_args(argv)

    if args.cmd == "verify":
        if not args.dsn:
            print("seal verify: no DSN (pass --dsn or set SEAL_DSN)", file=sys.stderr)
            return 2
        report = Seal(args.dsn).verify_chain()
        if args.json:
            print(json.dumps(report, sort_keys=True))
        elif report["ok"]:
            signed = report.get("signed", 0)
            extra = f", {signed} signed" if signed else ""
            print(f"chain VERIFIED — {report['certs']} cert(s), every link intact{extra}")
        else:
            print(f"chain BROKEN at cert #{report['at']}: {report['why']}")
        return 0 if report["ok"] else 1

    if args.cmd == "export":
        if not args.dsn:
            print("seal export: no DSN (pass --dsn or set SEAL_DSN)", file=sys.stderr)
            return 2
        from .portable import export_receipt
        print(json.dumps(export_receipt(Seal(args.dsn), args.intent), sort_keys=True))
        return 0

    if args.cmd == "verify-receipt":
        from .portable import verify_receipt
        raw = sys.stdin.read() if args.file == "-" else open(args.file).read()
        report = verify_receipt(json.loads(raw), public_key_hex=args.pubkey)
        if args.json:
            print(json.dumps(report, sort_keys=True))
        else:
            if report["ok"]:
                print(f"receipt VERIFIED — {report['certs']} cert(s), "
                      f"{report['signed']} signed")
            else:
                print("receipt FAILED:")
                for prob in report["problems"]:
                    print(f"  - {prob}")
            print(f"  {report['note']}")
        return 0 if report["ok"] else 1

    if args.cmd == "obligations":
        if not args.dsn:
            print("seal obligations: no DSN (pass --dsn or set SEAL_DSN)",
                  file=sys.stderr)
            return 2
        from .obligation import Obligations
        obs = Obligations(Seal(args.dsn))
        obs.setup()
        report = obs.sweep()
        if args.json:
            print(json.dumps(report, sort_keys=True))
        else:
            print(f"duties {report['verdict'].upper()} — "
                  f"{report['duties_checked']} checked, "
                  f"{report['open_breaches']} open breach(es)")
            for item in report["items"]:
                if item["status"] != "satisfied":
                    print(f"  - [{item['status']}] {item['action']} "
                          f"({item.get('key') or 'window ' + str(item.get('window'))})")
        # Cron-friendly: silence that should have been work is a red exit.
        return 0 if report["verdict"] == "met" else 1

    if args.cmd == "keygen":
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except ImportError:
            print("seal keygen: pip install 'seal-kernel[signing]' first",
                  file=sys.stderr)
            return 2
        key = Ed25519PrivateKey.generate()
        seed = key.private_bytes_raw().hex()
        pub = key.public_key().public_bytes_raw().hex()
        print(f"SEAL_SIGNING_KEY={seed}")
        print(f"public key       ={pub}")
        print("Keep the first line SECRET (gateway env only). Publish the "
              "second to anyone who must verify your receipts.")
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
