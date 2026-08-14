"""seal-mcp — the Seal gateway as an MCP server, over stdio.

Zero dependencies beyond the kernel: this speaks JSON-RPC 2.0 by hand rather
than pulling in an SDK, exactly like our other servers. An agent host connects
it as a tool server and every irreversible action the agent wants to take goes
through admission first.

TWO MODES, and the difference is who holds the provider credential:

* **Gateway mode** (`seal_propose` / `seal_execute`) — set `SEAL_EXECUTORS` and
  the gateway itself calls the provider. The agent receives a single-use ticket
  bound to the exact arguments it proposed, never a key. An agent that is
  confused, or that read something hostile on the internet, cannot call the
  provider: it does not have the credential and cannot change the amount on a
  ticket it already holds.

* **Admission-only mode** (`seal_admit` / `seal_commit`) — the caller runs the
  effect itself and Seal only guarantees it is admitted once. This is correct
  when *your own code* runs the effect, and wrong when an agent does, because
  the agent must then hold the credential.

Admission-only was the original surface here, and it quietly undercut the whole
Exclusive Authority story: our own integration handed the agent the key. Both
modes remain, because admission-only is legitimate for the own-code case, but
gateway mode is the default whenever executors are configured, and `seal_admit`
says so at runtime.

Design notes that matter:

* Tools return machine-readable verdicts, not prose. The agent needs to branch
  on cleared/replay/needs-approval/stand-down, so the payload is JSON in the
  text content — the convention MCP hosts actually parse.
* Refusals (PayloadConflict, DomainFrozen, ClearanceDenied, InvalidTicket)
  come back as isError=true with the reason. They are the product working, not
  the product failing.
* There is deliberately NO seal_unfreeze tool, and no tool that registers an
  executor or sets clearance policy. Unfreezing after a divergence, and
  granting a path permission to run at all, are human decisions made after
  reconciliation. Handing either to the agent would defeat the control.

Run:  SEAL_DSN=... python -m seal.mcp_server
      SEAL_DSN=... SEAL_EXECUTORS=myapp.seal_executors python -m seal.mcp_server

`SEAL_EXECUTORS` names an importable module exposing `register(gateway)`:

    def register(gw):
        import stripe
        stripe.api_key = os.environ["STRIPE_SECRET_KEY"]   # stays in THIS process
        gw.register_executor("charge", lambda a: stripe.PaymentIntent.create(**a))

Set `SEAL_TICKET_KEY` to keep tickets valid across restarts. Without it a fresh
random key is generated per process, so tickets minted before a restart are
refused afterwards — fail-closed, which is the safe default.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
from typing import Any

from .core import DomainFrozen, PayloadConflict, Seal, SealError

PROTOCOL_VERSION = "2024-11-05"


def _refusal_types() -> tuple[type[BaseException], ...]:
    """Every way the control can legitimately say NO.

    Imported lazily and defensively: a refusal class that fails to import must
    not take the whole server down, but it also must not silently become an
    "unexpected error" — so anything missing is simply absent from the tuple
    and still surfaces as an error, just without the refused/retryable shape.
    """
    types: list[type[BaseException]] = [PayloadConflict, DomainFrozen]
    for mod, names in (
        (".clearance", ("ClearanceDenied",)),
        (".authority", ("InvalidTicket", "TicketExpired", "TicketAlreadySpent", "NoSuchExecutor")),
        (".graduated", ("GraduatedError", "SelfApproval", "ApprovalNotSatisfied", "ApprovalConsumed")),
        (".budget", ("BudgetExceeded",)),
    ):
        try:
            m = importlib.import_module(mod, __package__)
        except Exception:
            continue
        for n in names:
            t = getattr(m, n, None)
            if isinstance(t, type) and issubclass(t, BaseException):
                types.append(t)
    return tuple(types)


_REFUSALS = _refusal_types()


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


GATEWAY_TOOLS = [
    _tool(
        "seal_propose",
        "Ask permission to perform an irreversible action. The gateway — not "
        "you — will call the provider, so you never handle the credential.\n\n"
        "Returns one of:\n"
        "  status=cleared        -> a single-use ticket. Call seal_execute with "
        "it and the SAME args you proposed.\n"
        "  status=already_done   -> this exact action already ran. Use cert."
        "result. Do NOT retry.\n"
        "  status=in_flight      -> another caller holds the claim. Stand down "
        "and retry later.\n"
        "  status=needs_approval -> the amount is above the auto-clear ceiling "
        "and needs human approvers. You cannot approve it yourself; report the "
        "returned intent to your operator.\n\n"
        "Always pass a stable `key` (e.g. 'invoice-777') for money-class "
        "actions: retrying with the same key but different args is refused as "
        "a conflict rather than becoming a second payment.",
        {
            "path": {"type": "string", "description": "Registered executor path, e.g. 'charge'. Use seal_paths to list."},
            "args": {"type": "object", "description": "Exact arguments for the effect. The ticket is bound to these."},
            "key": {"type": "string", "description": "Stable id for this logical action. Strongly recommended."},
            "domain": {"type": "string", "description": "Blast-radius scope, e.g. 'customer:42'. Frozen domains refuse."},
            "amount": {"type": "number", "description": "Amount at risk. Drives approval tiers and budget."},
            "budget_key": {"type": "string", "description": "Budget bucket to reserve against, if any."},
            "approval_id": {"type": "string", "description": "A satisfied maker-checker approval, when one was required."},
        },
        ["path", "args"],
    ),
    _tool(
        "seal_execute",
        "Spend a ticket from seal_propose. The GATEWAY calls the provider and "
        "seals the certificate. Pass the ticket exactly as received, and the "
        "same args you proposed — a ticket is cryptographically bound to its "
        "arguments, so changing the amount after approval is refused.",
        {
            "ticket": {"type": "object", "description": "The ticket object returned by seal_propose."},
            "args": {"type": "object", "description": "Must match the args given to seal_propose."},
        },
        ["ticket", "args"],
    ),
    _tool(
        "seal_paths",
        "List the action paths this gateway can execute, and whether each is "
        "currently cleared to run. Call this first to discover what is allowed.",
        {},
        [],
    ),
]

TOOLS = [
    _tool(
        "seal_admit",
        "ADMISSION ONLY — prefer seal_propose when it is available, because "
        "this tool requires YOU to hold the provider credential and call the "
        "provider yourself. Use it only when your own code owns the effect.\n\n"
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


def load_gateway(seal: Seal, module_name: str | None = None):
    """Build a Gateway from an operator-provided executor module.

    The module is imported INTO THIS PROCESS and hands the gateway closures
    that hold the provider secrets. That is the whole point: the secret lives
    here, in the operator's server, and never crosses to the agent.

    Returns None when no module is configured — the server then runs in
    admission-only mode and says so.
    """
    module_name = module_name if module_name is not None else os.environ.get("SEAL_EXECUTORS")
    if not module_name:
        return None
    from .authority import Gateway
    mod = importlib.import_module(module_name)
    register = getattr(mod, "register", None)
    if register is None:
        raise SealError(
            f"SEAL_EXECUTORS module {module_name!r} has no register(gateway) function"
        )
    gw = Gateway(seal)
    register(gw)
    if not gw._executors:
        raise SealError(
            f"{module_name}.register(gateway) registered no executors — "
            "refusing to start in a state that looks like gateway mode but isn't"
        )
    return gw


class Server:
    def __init__(self, seal: Seal, gateway=None):
        self.seal = seal
        self.gateway = gateway

    @property
    def tools(self) -> list[dict]:
        """Gateway tools are advertised only when they can actually work.

        Listing seal_propose with no executors registered would invite an agent
        to call it and get nothing but errors — worse, it might then fall back
        to holding the credential itself, which is the exact outcome this
        server exists to prevent.
        """
        return (GATEWAY_TOOLS + TOOLS) if self.gateway is not None else list(TOOLS)

    # ── tool dispatch ─────────────────────────────────────────────────────
    def call(self, name: str, args: dict) -> Any:
        if name in ("seal_propose", "seal_execute", "seal_paths"):
            if self.gateway is None:
                raise SealError(
                    "this server runs in admission-only mode — no executors are "
                    "registered. Set SEAL_EXECUTORS to enable gateway mode."
                )

        if name == "seal_paths":
            from .clearance import Clearance
            cl = Clearance(self.seal)
            return {
                "paths": [
                    {"path": p, "clearance": cl.status(p)["effective"]}
                    for p in sorted(self.gateway._executors)
                ],
                "note": "propose against these paths; the gateway holds the credentials",
            }

        if name == "seal_propose":
            out = self.gateway.propose(
                args["path"], args["args"],
                key=args.get("key"), domain=args.get("domain"),
                amount=args.get("amount"), budget_key=args.get("budget_key"),
                approval_id=args.get("approval_id"),
            )
            hint = {
                "cleared": "call seal_execute with this ticket and the SAME args",
                "already_done": "already ran — use cert.result, do NOT retry",
                "in_flight": "another caller holds the claim — stand down and retry later",
                "needs_approval": (
                    "above the auto-clear ceiling — a human must approve. "
                    "You cannot approve your own request; report this intent to your operator."
                ),
            }.get(out.get("status"), "")
            return {**out, "next": hint}

        if name == "seal_execute":
            return self.gateway.execute(args["ticket"], args["args"])

        if name == "seal_admit":
            adm = self.seal.admit(
                args["action"], args["args"],
                key=args.get("key"), domain=args.get("domain"),
            )
            out = {
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
            # If a gateway IS configured, say so here rather than letting an
            # agent walk off holding a credential it never needed to hold.
            if self.gateway is not None and args["action"] in self.gateway._executors:
                out["prefer"] = (
                    f"path {args['action']!r} has a registered executor — use "
                    "seal_propose/seal_execute instead so the gateway calls the "
                    "provider and you never handle the credential"
                )
            return out
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
            return self._ok(mid, {"tools": self.tools})
        if method == "tools/call":
            name = msg["params"]["name"]
            args = msg["params"].get("arguments", {})
            try:
                result = self.call(name, args)
                return self._ok(mid, {
                    "content": [{"type": "text", "text": json.dumps(result, default=str)}]
                })
            except _REFUSALS as e:
                # The gate refusing is the product working. Surface it as a
                # tool-level error the agent can read and adapt to — distinct
                # from an unexpected fault, so an agent can tell "you may not"
                # from "something broke". Never retry a refusal blindly.
                return self._ok(mid, {
                    "isError": True,
                    "content": [{"type": "text", "text": json.dumps(
                        {"refused": type(e).__name__, "reason": str(e),
                         "retryable": False}
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

    # A misconfigured executor module must stop the server, not silently
    # downgrade it to admission-only. Starting quietly in the weaker mode is
    # how an operator ends up believing agents never touch the credential
    # while they quietly do.
    try:
        gateway = load_gateway(seal)
    except Exception as e:
        print(f"seal-mcp: failed to load SEAL_EXECUTORS: {type(e).__name__}: {e}",
              file=sys.stderr)
        return 2

    if gateway is not None:
        print(f"seal-mcp: gateway mode — {len(gateway._executors)} path(s): "
              f"{', '.join(sorted(gateway._executors))}", file=sys.stderr)
    else:
        print("seal-mcp: admission-only mode — callers run effects themselves "
              "and must hold their own credentials. Set SEAL_EXECUTORS for "
              "gateway mode.", file=sys.stderr)

    server = Server(seal, gateway)
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
