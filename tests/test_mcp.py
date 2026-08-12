"""seal-mcp — driven the way a host drives it: JSON-RPC over stdio.

Deliberately a SUBPROCESS test. Importing the server and calling its methods
would prove the functions work; it would not prove the process speaks the
protocol, flushes stdout, or survives a handshake — which is all a host
actually cares about.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import psycopg
import pytest

DSN = os.environ.get("SEAL_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="SEAL_DSN not set")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def drive(messages: list[dict]) -> list[dict]:
    """Send messages to a fresh seal-mcp process, return its responses."""
    payload = "\n".join(json.dumps(m) for m in messages) + "\n"
    proc = subprocess.run(
        [sys.executable, "-m", "seal.mcp_server"],
        input=payload, capture_output=True, text=True, cwd=ROOT,
        env={**os.environ, "SEAL_DSN": DSN}, timeout=90,
    )
    assert proc.returncode == 0, f"server exited {proc.returncode}: {proc.stderr}"
    return [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]


def payload(resp: dict):
    return json.loads(resp["result"]["content"][0]["text"])


def _reset():
    from seal import Seal
    s = Seal(DSN)
    s.setup()
    with psycopg.connect(DSN, autocommit=True, client_encoding="UTF8") as c:
        c.execute("TRUNCATE seal_intents, seal_certs, seal_domains, "
                  "seal_graphs, seal_graph_children RESTART IDENTITY")


INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}


def test_handshake_and_tool_list():
    out = drive([INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}])
    assert out[0]["result"]["serverInfo"]["name"] == "seal-mcp"
    names = {t["name"] for t in out[1]["result"]["tools"]}
    assert {"seal_admit", "seal_commit", "seal_abort", "seal_heartbeat",
            "seal_get", "seal_verify", "seal_incident_receipt"} <= names
    # the breaker must not be releasable by the agent it is protecting against
    assert "seal_unfreeze" not in names


def test_admit_then_replay_over_the_wire():
    _reset()
    call = lambda i, n, a: {"jsonrpc": "2.0", "id": i, "method": "tools/call",
                            "params": {"name": n, "arguments": a}}
    out = drive([
        INIT,
        call(2, "seal_admit", {"action": "charge", "args": {"amount": 4900}, "key": "o-1"}),
    ])
    first = payload(out[1])
    assert first["fresh"] is True and first["fence"]

    out2 = drive([
        INIT,
        call(2, "seal_commit", {"intent": first["intent"], "fence": first["fence"],
                                "result": {"ok": True}}),
        call(3, "seal_admit", {"action": "charge", "args": {"amount": 4900}, "key": "o-1"}),
        call(4, "seal_verify", {}),
    ])
    cert = payload(out2[1])
    replay = payload(out2[2])
    assert cert["tier"] == "SEALED"
    assert replay["fresh"] is False
    assert replay["cert"]["hash"] == cert["hash"]
    assert "do NOT re-run" in replay["next"]
    assert payload(out2[3])["ok"] is True


def test_payload_conflict_surfaces_as_tool_error():
    _reset()
    call = lambda i, a: {"jsonrpc": "2.0", "id": i, "method": "tools/call",
                         "params": {"name": "seal_admit", "arguments": a}}
    out = drive([
        INIT,
        call(2, {"action": "charge", "args": {"amount": 4900}, "key": "o-2"}),
        call(3, {"action": "charge", "args": {"amount": 5100}, "key": "o-2"}),
    ])
    assert out[2]["result"].get("isError") is True
    assert payload(out[2])["refused"] == "PayloadConflict"


def test_unknown_method_returns_jsonrpc_error():
    out = drive([INIT, {"jsonrpc": "2.0", "id": 9, "method": "nope/nope"}])
    assert out[1]["error"]["code"] == -32601


def test_notifications_get_no_response():
    out = drive([INIT, {"jsonrpc": "2.0", "method": "notifications/initialized"}])
    assert len(out) == 1  # only the initialize reply
