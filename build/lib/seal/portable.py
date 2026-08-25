"""Portable receipts — evidence that survives leaving the building.

The dispute that matters spans three parties: the user who authorised an
agent, the operator who ran it, and the merchant who got paid. Each holds a
database the other two cannot read and would not trust if they could. Seal's
store answers "did this run exactly once, and did the world confirm it?" — but
until now only to someone holding the Postgres DSN, which is to say, only to
the party being asked to prove its own innocence.

A portable receipt is that answer as a file:

    * every cert re-verifiable from its RFC 8785 canonical bytes — any
      language, no Seal, no database;
    * every signature checkable against a PINNED public key the relying party
      obtained out of band, which is what makes it evidence rather than a
      self-signed note;
    * the Mandate included, so "was this within the limits of the task?" is
      answered in the same file as "did it happen once?".

What a verified receipt PROVES: these certs were produced by the holder of the
pinned key and have not been altered since; their tiers say what the world
confirmed. What it does NOT prove: completeness. A single-intent receipt
cannot show that no OTHER certs exist — omission is invisible to it. The full
chain sweep (`seal verify`, with the store) remains the completeness check;
the receipt is the portability check. Both are stated on the verdict so a
relying party never mistakes one for the other.
"""
from __future__ import annotations

import time
from typing import Any, Optional

from .canonical import jcs_digest
from .core import Seal, SealError, _digest

RECEIPT_FORMAT = "seal-receipt/1"


def export_receipt(seal: Seal, intent: str) -> dict:
    """Everything a third party needs about one intent, in one file.

    Refuses an intent with no certs: an open claim has nothing provable about
    it yet, and exporting a receipt that says "pending" invites reading it as
    "fine".
    """
    rec = seal.get(intent)
    if rec is None:
        raise SealError(f"unknown intent {intent[:12]}…")
    certs = seal.certs_for(intent)
    if not certs:
        raise SealError(
            f"intent {intent[:12]}… has no certs yet — there is nothing "
            "provable to export; settle() it first"
        )
    from .mandate import Mandates
    mandate = Mandates(seal).for_intent(intent)
    return {
        "format": RECEIPT_FORMAT,
        "intent": {
            "intent": rec["intent"],
            "action": rec["action"],
            "state": rec["state"],
            "tier": rec["tier"],
            "domain": rec["domain"],
        },
        "certs": certs,
        "mandate": mandate,
        "generated_at": time.time(),
    }


def verify_receipt(bundle: dict, public_key_hex: Optional[str] = None) -> dict:
    """Check a receipt with no database and no trust in who handed it over.

    `public_key_hex` is the RELYING PARTY'S pinned copy of the gateway's
    public key (raw Ed25519, hex), obtained out of band. With it, a passing
    verdict means: produced by the key holder, unaltered since. Without it,
    the verdict can only attest internal consistency — the hashes hold and
    any embedded signatures agree with the keys the receipt itself names,
    which an attacker who re-signed everything could also arrange. The
    verdict says which of the two it is; never let a UI collapse them.
    """
    problems: list[str] = []
    if not isinstance(bundle, dict) or bundle.get("format") != RECEIPT_FORMAT:
        return {"ok": False, "problems": [f"not a {RECEIPT_FORMAT} bundle"]}

    certs = bundle.get("certs") or []
    if not certs:
        problems.append("bundle contains no certs")

    signed = 0
    hashes_seen: set[str] = set()
    for i, cert in enumerate(certs):
        # 1 · the hash must be recomputable from the body alone.
        if cert.get("cv") == 2:
            recomputed = jcs_digest(
                {k: v for k, v in cert.items() if k not in ("hash", "sig")}
            )
        else:
            recomputed = _digest({k: v for k, v in cert.items() if k != "hash"})
        if recomputed != cert.get("hash"):
            problems.append(f"cert {i}: body does not match its hash")
            continue
        hashes_seen.add(cert["hash"])

        # 2 · a witness cert must point at a cert this receipt contains.
        parent = cert.get("parent_cert")
        if parent is not None and parent not in hashes_seen:
            problems.append(
                f"cert {i}: parent_cert {parent[:12]}… is not an earlier cert "
                "in this receipt"
            )

        # 3 · signatures — against the pinned key when one is given.
        sig, signer = cert.get("sig"), cert.get("signer")
        if public_key_hex is not None:
            if sig is None:
                problems.append(
                    f"cert {i}: unsigned, but a public key was pinned — an "
                    "unsigned cert proves nothing to a third party"
                )
                continue
            if signer != public_key_hex:
                problems.append(
                    f"cert {i}: signed by {str(signer)[:16]}…, not the pinned key"
                )
                continue
        if sig is not None:
            key_hex = public_key_hex or signer
            err = _check_sig(key_hex, cert["hash"], sig)
            if err:
                problems.append(f"cert {i}: {err}")
            else:
                signed += 1

    ok = not problems
    return {
        "ok": ok,
        "certs": len(certs),
        "signed": signed,
        "pinned_key": public_key_hex is not None,
        "problems": problems,
        "note": (
            "Verified against a pinned key: these certs were produced by its "
            "holder and are unaltered since. This receipt cannot prove "
            "completeness — whether OTHER certs exist takes the full chain "
            "check against the store."
            if ok and public_key_hex is not None else
            "Internally consistent only: hashes hold, but no key was pinned, "
            "so authorship is NOT established. Obtain the gateway's public "
            "key out of band and pass it to make this evidence."
            if ok else
            "Verification FAILED — treat this receipt as no evidence at all."
        ),
    }


def _check_sig(public_key_hex: str, cert_hash: str, sig_hex: str) -> str | None:
    """None if the signature verifies; a human-readable problem otherwise."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError:
        return ("cannot verify signature — the 'cryptography' package is not "
                "installed (pip install 'seal-kernel[signing]')")
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        key.verify(bytes.fromhex(sig_hex), bytes.fromhex(cert_hash))
        return None
    except InvalidSignature:
        return "signature does not verify"
    except Exception as e:
        return f"malformed key or signature: {e!r}"
