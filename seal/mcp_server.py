"""seal-mcp — the Seal gateway as an MCP server, over stdio.

Zero dependencies beyond the kernel: this speaks JSON-RPC 2.0 by hand rather
than pulling in an SDK, exactly like our other servers. An agent host connects
it as a tool server and every irreversible action the agent wants to take goes
through admission first.

Design notes that matter:

* `seal_admit` returns a machine-readable verdict, not prose. The agent needs
  to branch on fresh/replay/stand-down, so the payload is JSON in the text
  content — the convention MCP hosts actually parse.
* Refusals (PayloadConflict, DomainFrozen) come back as isError=true with the
  reason. They are the product working, not the product failing.
* There is deliberately NO seal_unfreeze tool. Unfreezing after a divergence
  is a human decision made after reconciliation; handing it to the same agent
  that may be causing the divergence would defeat the breaker.

Run:  SEAL_DSN=... python -m seal.mcp_server
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

from .core import DomainFrozen, PayloadConflict, Seal, SealError

PROTOCOL_VERSION = "2024-11-05"


def _tool(name: str, desc: str, props: dict, required: list[str]) -> dict:
    return {
        "name": name,
        "description": desc,
        "inputSchema": {
            "type": "object",
            "properties": props,
            "required": required,
        },
    }


TOOLS = [
    _tool(
        "seal_admit",
        "Claim the right to run an irreversible action exactly once. "
        "Returns fresh=true with a fence (you won — run the effect, then call "
        "seal_commit), or fresh=false with the sealed cert (already done — use "
        "that result, do NOT re-run), or fresh=false with no cert (someone "
        "else is mid-flight — stand down and retry later). "
        "Always pass a stable `key` (e.g. 'order-777') for money-class "
        "actions: retrying with the same key but different args is refused as "
        "a conflict instead of becoming a second charge.",
        {
            "action": {"type": "string", "description": "What kind of effect, e.g. 'charge'."},
            "args": {"type": "object", "description": "The effect's arguments."},
            "key": {"type": "string", "description": "Stable id for this logical action. Strongly recommended."},
            "domain": {"type": "string", "description": "Blast-radius scope, e.g. 'customer:42'. Frozen domains refuse admission."},
        },
        ["action", "args"],
    ),
    _tool(
        "seal_commit",
        "Seal a successful effect: writes the tamper-evident certificate. Only "
        "the fence holder may commit, and only once.",
        {
            "intent": {"type": "string"},
            "fence": {"type": "string"},
            "result": {"type": "object", "description": "The effect's result, digested into the cert."},
        },
        ["intent", "fence", "result"],
    ),
    _tool(
        "seal_abort",
        "Release a claim after a failure where NOTHING irreversible happened, "
        "so a later retry is legitimate. If the effect may have fired (e.g. a "
        "timeout), do NOT abort — leave the claim and let a witness decide.",
        {
            "intent": {"type": "string"},
            "fence": {"type": "string"},
            "reason": {"type": "string"},
        },
        ["intent", "fence", "reason"],
    ),
    _tool(
        "seal_heartbeat",
        "Extend the lease while a slow effect is still running, so the claim "
        "is not reclaimed mid-flight.",
        {"intent": {"type": "string"}, "fence": {"type": "string"}},
        ["intent", "fence"],
    ),
    _tool(
        "seal_get",
        "Status of an intent: state, tier, cert.",
        {"intent": {"type": "string"}},
        ["intent"],
    ),
    _tool(
        "seal_verify",
        "Verify the entire certificate chain from the store alone. Returns "
        "ok=false with the position if any cert was edited, deleted or reordered.",
        {},
        [],
    ),
    _tool(
        "seal_incident_receipt",
        "Self-checking export for one intent: full cert chain, tier, domain "
        "freeze state, chain verification. What you hand an auditor.",
        {"intent": {"type": "string"}},
        ["intent"],
    ),
]


class Server:
    def __init__(self, seal: Seal):
        self.seal = seal

    # ── tool dispatch ─────────────────────────────────────────────────────
    def call(self, name: str, args: dict) -> Any:
        if name == "seal_admit":
            adm = self.seal.admit(
                args["action"], args["args"],
                key=args.get("key"), domain=args.get("domain"),
            )
            return {
                "fresh": adm.fresh,
                "intent": adm.intent,
                "fence": adm.fence if adm.fresh else None,
                "cert": adm.cert,
                "next": (
                    "run the effect, then seal_commit"
                    if adm.fresh
                    else ("already done — use cert.result, do NOT re-run"
                          if adm.cert else "in flight elsewhere — stand down")
                ),
            }
        if name == "seal_commit":
            return self.seal.seal(args["intent"], args["fence"], args["result"])
        if name == "seal_abort":
            self.seal.fail(args["intent"], args["fence"], args["reason"])
            return {"released": True}
        if name == "seal_heartbeat":
            new_lease = self.seal.heartbeat(args["intent"], args["fence"])
            return {"lease_until": new_lease}
        if name == "seal_get":
            return self.seal.get(args["intent"]) or {"error": "unknown intent"}
        if name == "seal_verify":
            return self.seal.verify_chain()
        if name == "seal_incident_receipt":
            return self.seal.incident_receipt(args["intent"])
        raise SealError(f"unknown tool {name!r}")

    # ── JSON-RPC plumbing ─────────────────────────────────────────────────
    def handle(self, msg: dict) -> dict | None:
        mid = msg.get("id")
        method = msg.get("method", "")

        if method == "initialize":
            return self._ok(mid, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "seal-mcp", "version": "0.2.0"},
            })
        if method.startswith("notifications/"):
            return None  # notifications get no response
        if method == "tools/list":
            return self._ok(mid, {"tools": TOOLS})
        if method == "tools/call":
            name = msg["params"]["name"]
            args = msg["params"].get("arguments", {})
            try:
                result = self.call(name, args)
                return self._ok(mid, {
                    "content": [{"type": "text", "text": json.dumps(result, default=str)}]
                })
            except (PayloadConflict, DomainFrozen) as e:
                # The gate refusing is the product working. Surface it as a
                # tool-level error the agent can read and adapt to.
                return self._ok(mid, {
                    "isError": True,
                    "content": [{"type": "text", "text": json.dumps(
                        {"refused": type(e).__name__, "reason": str(e)}
                    )}],
                })
            except Exception as e:
                return self._ok(mid, {
                    "isError": True,
                    "content": [{"type": "text", "text": json.dumps(
                        {"error": type(e).__name__, "reason": str(e)}
                    )}],
                })
        if mid is not None:
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32601, "message": f"method not found: {method}"}}
        return None

    @staticmethod
    def _ok(mid, result) -> dict:
        return {"jsonrpc": "2.0", "id": mid, "result": result}


def main() -> int:
    dsn = os.environ.get("SEAL_DSN")
    if not dsn:
        print("seal-mcp: SEAL_DSN not set", file=sys.stderr)
        return 2
    seal = Seal(dsn)
    seal.setup()
    server = Server(seal)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = server.handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
