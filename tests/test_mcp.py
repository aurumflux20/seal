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


# ── gateway mode ─────────────────────────────────────────────────────────
# The reason this exists: the admission-only surface above requires the CALLER
# to hold the provider credential. For an agent that is exactly the thing we
# tell people not to do. These tests pin the credential-safe path.

def drive_gw(messages: list[dict], calls_file: str, executors="tests._gateway_executors"):
    """Drive a seal-mcp process running in GATEWAY mode."""
    payload_s = "\n".join(json.dumps(m) for m in messages) + "\n"
    env = {**os.environ, "SEAL_DSN": DSN, "SEAL_EXECUTORS": executors,
           "SEAL_TEST_CALLS": calls_file, "SEAL_TICKET_KEY": "fixed-test-ticket-key"}
    proc = subprocess.run(
        [sys.executable, "-m", "seal.mcp_server"],
        input=payload_s, capture_output=True, text=True, cwd=ROOT,
        env=env, timeout=90,
    )
    assert proc.returncode == 0, f"server exited {proc.returncode}: {proc.stderr}"
    return [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]


def _clear(path: str):
    """Operator grants the path permission to run at all."""
    from seal import Seal
    from seal.clearance import CLEARED, Clearance
    cl = Clearance(Seal(DSN))
    cl.set_policy(path, CLEARED)
    cl.record_proof(path, green=True, storm_n=1000, executions=1)


def _provider_calls(f: str) -> list[str]:
    if not os.path.exists(f):
        return []
    with open(f, encoding="utf-8") as fh:
        return [l.strip() for l in fh if l.strip()]


CALL = lambda i, n, a: {"jsonrpc": "2.0", "id": i, "method": "tools/call",
                        "params": {"name": n, "arguments": a}}


def test_gateway_tools_are_hidden_when_no_executors_configured():
    """Advertising seal_propose with nothing behind it would invite an agent to
    call it, fail, and fall back to holding the credential itself."""
    out = drive([INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}])
    names = {t["name"] for t in out[1]["result"]["tools"]}
    assert "seal_propose" not in names
    assert "seal_execute" not in names


def test_gateway_tools_appear_when_executors_are_configured(tmp_path):
    f = str(tmp_path / "calls.txt")
    out = drive_gw([INIT, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}], f)
    names = {t["name"] for t in out[1]["result"]["tools"]}
    assert {"seal_propose", "seal_execute", "seal_paths"} <= names
    # no tool may hand the agent a way to grant itself permission
    assert not {"seal_register_executor", "seal_set_policy", "seal_unfreeze"} & names


def test_propose_then_execute_calls_the_provider_exactly_once(tmp_path):
    _reset(); _clear("charge")
    f = str(tmp_path / "calls.txt")
    out = drive_gw([
        INIT,
        CALL(2, "seal_propose", {"path": "charge", "args": {"amount": 4900}, "key": "g-1"}),
    ], f)
    prop = payload(out[1])
    assert prop["status"] == "cleared"
    assert "ticket" in prop
    # proposing alone must NOT have touched the provider
    assert _provider_calls(f) == []

    out2 = drive_gw([
        INIT,
        CALL(2, "seal_execute", {"ticket": prop["ticket"], "args": {"amount": 4900}}),
    ], f)
    res = payload(out2[1])
    assert res["status"] == "executed"
    assert res["result"]["provider_id"] == "pi_test_123"
    assert _provider_calls(f) == ["charge:4900"]


def test_agent_cannot_raise_the_amount_after_the_ticket_was_issued(tmp_path):
    """The whole point of a ticket. Propose $1, try to execute $999,999."""
    _reset(); _clear("charge")
    f = str(tmp_path / "calls.txt")
    out = drive_gw([
        INIT,
        CALL(2, "seal_propose", {"path": "charge", "args": {"amount": 1}, "key": "g-swap"}),
    ], f)
    prop = payload(out[1])

    out2 = drive_gw([
        INIT,
        CALL(2, "seal_execute", {"ticket": prop["ticket"], "args": {"amount": 999_999}}),
    ], f)
    refusal = payload(out2[1])
    assert out2[1]["result"]["isError"] is True
    assert refusal["refused"] == "InvalidTicket"
    assert refusal["retryable"] is False
    # and the provider was never called with the swapped amount
    assert _provider_calls(f) == []


def test_forged_ticket_is_refused(tmp_path):
    _reset(); _clear("charge")
    f = str(tmp_path / "calls.txt")
    out = drive_gw([
        INIT,
        CALL(2, "seal_propose", {"path": "charge", "args": {"amount": 500}, "key": "g-forge"}),
    ], f)
    t = dict(payload(out[1])["ticket"])
    t["sig"] = "0" * 64                      # agent invents a signature

    out2 = drive_gw([INIT, CALL(2, "seal_execute", {"ticket": t, "args": {"amount": 500}})], f)
    assert out2[1]["result"]["isError"] is True
    assert payload(out2[1])["refused"] == "InvalidTicket"
    assert _provider_calls(f) == []


def test_seal_paths_lists_only_registered_paths(tmp_path):
    _reset(); _clear("charge")
    f = str(tmp_path / "calls.txt")
    out = drive_gw([INIT, CALL(2, "seal_paths", {})], f)
    got = payload(out[1])
    assert {p["path"] for p in got["paths"]} == {"charge", "payout"}


def test_admit_tells_the_agent_to_prefer_the_gateway(tmp_path):
    """An agent reaching for admission on a path the gateway can run should be
    told there is a way that does not require it to hold the credential."""
    _reset(); _clear("charge")
    f = str(tmp_path / "calls.txt")
    out = drive_gw([
        INIT,
        CALL(2, "seal_admit", {"action": "charge", "args": {"amount": 100}, "key": "g-hint"}),
    ], f)
    assert "seal_propose" in payload(out[1])["prefer"]


def test_propose_without_a_gateway_is_an_error_not_a_silent_fallback():
    out = drive([INIT, CALL(2, "seal_propose", {"path": "charge", "args": {}})])
    assert out[1]["result"]["isError"] is True


def test_broken_executor_module_stops_the_server(tmp_path):
    """Starting quietly in the weaker mode is how an operator ends up believing
    agents never touch the credential while they quietly do."""
    proc = subprocess.run(
        [sys.executable, "-m", "seal.mcp_server"],
        input=json.dumps(INIT) + "\n", capture_output=True, text=True, cwd=ROOT,
        env={**os.environ, "SEAL_DSN": DSN, "SEAL_EXECUTORS": "tests.does_not_exist"},
        timeout=90,
    )
    assert proc.returncode == 2
    assert "failed to load SEAL_EXECUTORS" in proc.stderr


def test_the_same_ticket_cannot_be_spent_twice_across_processes(tmp_path):
    """A ticket is single-use. The gateway's spent-set is in-memory, so two
    server processes (restart, or two replicas) share nothing — the guarantee
    has to come from admission in Postgres, not from process memory.

    If this ever fails, the MCP path can double-charge and the product claim
    is false for exactly the deployment shape agent teams actually run.
    """
    _reset(); _clear("charge")
    f = str(tmp_path / "calls.txt")
    out = drive_gw([
        INIT,
        CALL(2, "seal_propose", {"path": "charge", "args": {"amount": 7700}, "key": "g-replay"}),
    ], f)
    ticket = payload(out[1])["ticket"]

    # process B spends it
    b = drive_gw([INIT, CALL(2, "seal_execute", {"ticket": ticket, "args": {"amount": 7700}})], f)
    assert payload(b[1])["status"] == "executed"

    # process C — brand new memory — replays the very same ticket
    c = drive_gw([INIT, CALL(2, "seal_execute", {"ticket": ticket, "args": {"amount": 7700}})], f)
    second = payload(c[1])

    calls = _provider_calls(f)
    assert calls == ["charge:7700"], (
        f"provider was called {len(calls)} times across processes: {calls}"
    )
    assert c[1]["result"].get("isError") or second.get("status") in ("already_done", "replayed"), (
        f"second spend was not refused or replayed: {second}"
    )
