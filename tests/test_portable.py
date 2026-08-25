"""Portable receipts — evidence that a third party can check without our code,
our database, or our goodwill.

The verifier under test is the one the OTHER side of a dispute runs, so these
tests attack it the way a counterparty would be attacked: altered bodies,
re-signed certs, wrong keys, forged parents.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid

import psycopg
import pytest

from seal import Seal
from seal.portable import export_receipt, verify_receipt
from seal.witness import CONFIRMED_ONE, CallableWitness, WitnessResult

DSN = os.environ.get("SEAL_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="SEAL_DSN not set")

cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

# A fixed test keypair — the hex-seed form SEAL_SIGNING_KEY accepts.
_PRIV = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
SEED_HEX = bytes(range(32)).hex()
PUB_HEX = _PRIV.public_key().public_bytes_raw().hex()


def _wipe():
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        for t in ("seal_certs", "seal_intents", "seal_mandates", "seal_events"):
            c.execute(f"TRUNCATE {t} RESTART IDENTITY")


@pytest.fixture()
def s():
    seal = Seal(DSN, signing_key=SEED_HEX)
    seal.setup()
    _wipe()
    return seal


def _sealed_intent(s, witnessed=False):
    a = s.admit("charge", {"amt": 100}, key=f"o-{uuid.uuid4().hex[:8]}")
    s.seal(a.intent, a.fence, {"ok": True})
    if witnessed:
        s.witness(a.intent, CallableWitness(
            lambda rec: WitnessResult(CONFIRMED_ONE, count=1,
                                      evidence={"ids": ["pi_1"]})))
    return a.intent


# ── signing at the store ──────────────────────────────────────────────────
def test_configured_key_signs_every_cert(s):
    _sealed_intent(s, witnessed=True)
    report = s.verify_chain()
    assert report["ok"] and report["certs"] == 2 and report["signed"] == 2
    assert s.signer_public_key == PUB_HEX


def test_unsigned_store_still_verifies(s):
    plain = Seal(DSN)                       # no key: chain-only, as before
    intent = _sealed_intent(plain)
    report = plain.verify_chain()
    assert report["ok"] and report["signed"] == 0
    bundle = export_receipt(plain, intent)
    v = verify_receipt(bundle)
    assert v["ok"] and v["signed"] == 0 and not v["pinned_key"]
    assert "authorship is NOT established" in v["note"]


def test_misconfigured_signing_key_fails_loudly():
    broken = Seal(DSN, signing_key="not-hex-not-a-file")
    broken.setup()
    a = broken.admit("charge", {"amt": 1}, key=f"o-{uuid.uuid4().hex[:8]}")
    with pytest.raises(Exception, match="SEAL_SIGNING_KEY"):
        broken.seal(a.intent, a.fence, {"ok": True})


# ── the receipt round trip ────────────────────────────────────────────────
def test_receipt_verifies_offline_against_the_pinned_key(s):
    intent = _sealed_intent(s, witnessed=True)
    bundle = export_receipt(s, intent)
    # the file survives serialization — that IS the medium
    bundle = json.loads(json.dumps(bundle))
    v = verify_receipt(bundle, public_key_hex=PUB_HEX)
    assert v["ok"] and v["certs"] == 2 and v["signed"] == 2 and v["pinned_key"]


def test_receipt_verification_needs_no_database():
    """Run the verifier in a subprocess with no SEAL_DSN at all — the exact
    posture of a merchant or auditor who was only handed the file."""
    s = Seal(DSN, signing_key=SEED_HEX)
    s.setup()
    _wipe()
    intent = _sealed_intent(s)
    bundle = export_receipt(s, intent)

    env = {k: v for k, v in os.environ.items() if k != "SEAL_DSN"}
    proc = subprocess.run(
        [sys.executable, "-m", "seal", "verify-receipt", "-",
         "--pubkey", PUB_HEX, "--json"],
        input=json.dumps(bundle), capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["ok"] is True


def test_tampered_cert_body_fails(s):
    intent = _sealed_intent(s)
    bundle = export_receipt(s, intent)
    bundle["certs"][0]["result_digest"] = "0" * 64
    v = verify_receipt(bundle, public_key_hex=PUB_HEX)
    assert not v["ok"]
    assert any("does not match its hash" in p for p in v["problems"])


def test_resigned_cert_fails_against_the_pinned_key(s):
    """The attack self-consistency cannot catch: rewrite the body, recompute
    the hash, re-sign with YOUR key. Only the pin stops it."""
    from seal.canonical import jcs_digest

    intent = _sealed_intent(s)
    bundle = export_receipt(s, intent)
    forger = Ed25519PrivateKey.generate()
    cert = dict(bundle["certs"][0])
    cert["result_digest"] = "0" * 64
    cert["signer"] = forger.public_key().public_bytes_raw().hex()
    body = {k: v for k, v in cert.items() if k not in ("hash", "sig")}
    cert["hash"] = jcs_digest(body)
    cert["sig"] = forger.sign(bytes.fromhex(cert["hash"])).hex()
    bundle["certs"][0] = cert

    # internally consistent — the forgery is competent
    assert verify_receipt(bundle)["ok"] is True
    # but the pin names the one key that counts
    v = verify_receipt(bundle, public_key_hex=PUB_HEX)
    assert not v["ok"]
    assert any("not the pinned key" in p for p in v["problems"])


def test_unsigned_cert_fails_when_a_key_is_pinned(s):
    plain = Seal(DSN)
    intent = _sealed_intent(plain)
    bundle = export_receipt(plain, intent)
    v = verify_receipt(bundle, public_key_hex=PUB_HEX)
    assert not v["ok"]
    assert any("unsigned" in p for p in v["problems"])


def test_witness_cert_must_parent_a_cert_in_the_receipt(s):
    intent = _sealed_intent(s, witnessed=True)
    bundle = export_receipt(s, intent)
    bundle["certs"][1]["parent_cert"] = "f" * 64
    # forged parent also breaks the hash; check the dedicated path by fixing it up
    from seal.canonical import jcs_digest
    cert = bundle["certs"][1]
    body = {k: v for k, v in cert.items() if k not in ("hash", "sig")}
    cert["hash"] = jcs_digest(body)
    cert["sig"] = _PRIV.sign(bytes.fromhex(cert["hash"])).hex()
    v = verify_receipt(bundle, public_key_hex=PUB_HEX)
    assert not v["ok"]
    assert any("parent_cert" in p for p in v["problems"])


def test_receipt_includes_the_mandate_when_one_exists(s):
    from seal.mandate import Mandates

    a = s.admit("charge", {"amt": 100}, key=f"o-{uuid.uuid4().hex[:8]}")
    Mandates(s).mint(intent=a.intent, path="charge", args_digest="d" * 64,
                     amount=100.0, clearance="CLEARED")
    s.seal(a.intent, a.fence, {"ok": True})
    bundle = export_receipt(s, a.intent)
    assert bundle["mandate"] is not None
    assert bundle["mandate"]["intent"] == a.intent


def test_open_intent_has_nothing_to_export(s):
    a = s.admit("charge", {"amt": 1}, key=f"o-{uuid.uuid4().hex[:8]}")
    with pytest.raises(Exception, match="no certs"):
        export_receipt(s, a.intent)


# ── upgrade path: v1 certs keep verifying next to v2 ──────────────────────
def test_legacy_v1_cert_still_verifies_in_a_mixed_chain(s):
    from seal.core import GENESIS, _digest, _jsonb

    # Hand-write a v1 cert (the pre-upgrade format) at the chain head…
    body = {"intent": "legacy", "action": "charge", "args_digest": "a" * 64,
            "result_digest": "b" * 64, "tier": "SEALED",
            "world": "unconfirmed", "prev_hash": GENESIS, "at": 1.0}
    h = _digest(body)
    cert = {**body, "hash": h}
    with psycopg.connect(DSN, autocommit=True) as c:
        c.execute("INSERT INTO seal_certs (intent, hash, prev_hash, body, created_at) "
                  "VALUES (%s,%s,%s,%s,%s)", ("legacy", h, GENESIS, _jsonb(cert), 1.0))
    # …then seal a v2 cert on top of it.
    _sealed_intent(s)
    report = s.verify_chain()
    assert report["ok"] and report["certs"] == 2 and report["signed"] == 1
