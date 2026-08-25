"""Effect graphs and compensating seals — the Apex layer.

Agents do not do one side effect. They do chains:

    charge → fulfill → email → update CRM

and chains fail halfway. Today that is hand-rolled sagas, outbox tables, and
human cleanup. The three rules that make a graph honest:

1. A root is only GRAPH_FINAL when every REQUIRED child reached WORLD_FINAL.
   Not "sealed" — WORLD_FINAL. A root that says "done" while a child is merely
   admitted is the "paid but never fulfilled" lie, told by software.
2. A compensation is a FIRST-CLASS sealed intent, admitted exactly once like
   anything else, and linked to what it reverses via `compensates_cert`.
   An undo that double-fires is as dangerous as a double charge — refunding
   twice is just a double in the other direction, and nobody guards it.
3. The graph never invents what compensates what. The caller declares it.
   Deciding that a failed shipment means "refund" rather than "retry" or
   "partial credit" is a business judgement, and a settlement rail that
   guesses at business judgement is a settlement rail that is wrong.

Scope discipline: this DAG is deliberately dumb — a static root plus declared
children, no dynamic scheduling, no workflow language. Our claim is the
COMBINATION (graph + world-finality + tamper-evident certs), never the DAG
engine itself. The moment this file grows a scheduler, we are rebuilding
Temporal with worse tooling.
"""
from __future__ import annotations

import json
import time
from typing import Any, Optional

from .core import (
    TIER_WORLD_FINAL,
    Seal,
    SealError,
)

GRAPH_OPEN = "GRAPH_OPEN"
GRAPH_EXECUTING = "GRAPH_EXECUTING"
GRAPH_FINAL = "GRAPH_FINAL"
GRAPH_COMPENSATING = "GRAPH_COMPENSATING"
GRAPH_COMPENSATED = "GRAPH_COMPENSATED"
GRAPH_DIVERGED = "GRAPH_DIVERGED"


class GraphError(SealError):
    """Refusals specific to graph rules."""


class EffectGraph:
    def __init__(self, seal: Seal):
        self.seal = seal

    # ── C1 · define the DAG ───────────────────────────────────────────────
    def create(self, graph_id: str, children: list[dict]) -> dict:
        """Declare a graph. `children` is a list of:

            {"key": "charge", "action": "charge", "args": {...}, "required": True}

        Idempotent: re-creating an existing graph returns it untouched rather
        than clobbering children that may already have sealed. A graph builder
        that resets state on a retry would be its own double-execution bug.
        """
        now = time.time()
        with self.seal._connect(autocommit=True) as c:
            with c.transaction():
                existed = c.execute(
                    "SELECT graph_id FROM seal_graphs WHERE graph_id=%s FOR UPDATE",
                    (graph_id,),
                ).fetchone()
                if existed is None:
                    c.execute(
                        "INSERT INTO seal_graphs (graph_id, state, created_at, updated_at) "
                        "VALUES (%s,%s,%s,%s)",
                        (graph_id, GRAPH_OPEN, now, now),
                    )
                    for ch in children:
                        c.execute(
                            "INSERT INTO seal_graph_children "
                            "(graph_id, child_key, action, args, required, state) "
                            "VALUES (%s,%s,%s,%s,%s,'pending')",
                            (
                                graph_id, ch["key"], ch["action"],
                                json.dumps(ch.get("args", {}), default=str),
                                bool(ch.get("required", True)),
                            ),
                        )
        return self.get(graph_id)

    # ── run one child through admission + seal ────────────────────────────
    def admit_child(self, graph_id: str, child_key: str, domain: str | None = None):
        ch = self._child(graph_id, child_key)
        if ch is None:
            raise GraphError(f"no child {child_key!r} in graph {graph_id!r}")
        # The child's intent key is scoped to the graph, so the same action in
        # two different graphs is two different intents — while a retry of THIS
        # child is the same intent, which is the point.
        return self.seal.admit(
            ch["action"],
            ch["args"],
            key=f"{graph_id}:{child_key}",
            domain=domain,
            graph_id=graph_id,
        )

    def commit_child(
        self,
        graph_id: str,
        child_key: str,
        intent: str,
        fence: str,
        result: Any,
        compensates_cert: str | None = None,
    ) -> dict:
        cert = self.seal.seal(
            intent, fence, result,
            compensates_cert=compensates_cert, graph_id=graph_id,
        )
        with self.seal._connect(autocommit=True) as c:
            c.execute(
                "UPDATE seal_graph_children SET state='sealed', intent=%s "
                "WHERE graph_id=%s AND child_key=%s",
                (intent, graph_id, child_key),
            )
            c.execute(
                "UPDATE seal_graphs SET state=%s, updated_at=%s "
                "WHERE graph_id=%s AND state=%s",
                (GRAPH_EXECUTING, time.time(), graph_id, GRAPH_OPEN),
            )
        return cert

    def fail_child(self, graph_id: str, child_key: str, intent: str, fence: str, reason: str) -> None:
        self.seal.fail(intent, fence, reason)
        with self.seal._connect(autocommit=True) as c:
            c.execute(
                "UPDATE seal_graph_children SET state='failed' "
                "WHERE graph_id=%s AND child_key=%s",
                (graph_id, child_key),
            )

    # ── C2 · the GRAPH_FINAL rule ─────────────────────────────────────────
    def evaluate(self, graph_id: str) -> dict:
        """Recompute the root state from its children. The rule is strict:
        every REQUIRED child must be WORLD_FINAL — sealed is not enough."""
        g = self.get(graph_id)
        if g is None:
            raise GraphError(f"unknown graph {graph_id!r}")

        required = [c for c in g["children"] if c["required"]]
        tiers = {}
        for ch in required:
            if ch["intent"]:
                rec = self.seal.get(ch["intent"])
                tiers[ch["child_key"]] = rec["tier"] if rec else None
            else:
                tiers[ch["child_key"]] = None

        state = g["state"]
        if state in (GRAPH_COMPENSATED, GRAPH_COMPENSATING):
            pass  # compensation flow owns the state; evaluate() does not override
        elif any(t == "WORLD_DIVERGED" for t in tiers.values()):
            state = GRAPH_DIVERGED
        elif any(c["state"] == "failed" for c in required):
            state = GRAPH_EXECUTING  # a failed required child blocks FINAL
        elif required and all(t == TIER_WORLD_FINAL for t in tiers.values()):
            state = GRAPH_FINAL
        else:
            state = GRAPH_EXECUTING

        if state != g["state"]:
            with self.seal._connect(autocommit=True) as c:
                c.execute(
                    "UPDATE seal_graphs SET state=%s, updated_at=%s WHERE graph_id=%s",
                    (state, time.time(), graph_id),
                )
        out = self.get(graph_id)
        out["required_tiers"] = tiers
        return out

    # ── C3/C4 · compensating seals ────────────────────────────────────────
    def compensate(
        self,
        graph_id: str,
        child_key: str,
        compensates_key: str,
        action: str,
        args: Any,
        executor,
        domain: str | None = None,
    ) -> dict:
        """Run a compensation as a first-class sealed intent.

        `executor()` performs the real reversal (the refund call). It runs at
        most once, because the compensation goes through the same admission
        gate as any other irreversible action — which is the entire point:
        a refund that fires twice is a double, pointing the other way.

        Returns the compensation cert, linked to the cert it reverses.
        """
        forward = self._child(graph_id, compensates_key)
        if forward is None:
            raise GraphError(f"no child {compensates_key!r} to compensate")
        if not forward["intent"]:
            raise GraphError(
                f"child {compensates_key!r} never sealed — there is nothing to reverse"
            )
        forward_rec = self.seal.get(forward["intent"])
        forward_cert_hash = (forward_rec.get("cert") or {}).get("hash")

        with self.seal._connect(autocommit=True) as c:
            c.execute(
                "INSERT INTO seal_graph_children "
                "(graph_id, child_key, action, args, required, state, compensates_key) "
                "VALUES (%s,%s,%s,%s,FALSE,'pending',%s) "
                "ON CONFLICT (graph_id, child_key) DO NOTHING",
                (graph_id, child_key, action, json.dumps(args, default=str), compensates_key),
            )
            c.execute(
                "UPDATE seal_graphs SET state=%s, updated_at=%s WHERE graph_id=%s",
                (GRAPH_COMPENSATING, time.time(), graph_id),
            )

        adm = self.seal.admit(
            action, args, key=f"{graph_id}:{child_key}", domain=domain, graph_id=graph_id
        )
        if not adm.fresh:
            # Already compensated. Hand back the existing cert — never re-refund.
            # The bookkeeping still has to be finalised: this call set the graph
            # to COMPENSATING on the way in, so returning here without settling
            # it would leave a retried compensation stuck in a non-terminal
            # state forever. Idempotent means the STATE repeats too, not just
            # the side effect. (Found by the end-to-end demo, not the unit
            # tests, which only asserted the refund ran once.)
            if adm.cert is not None:
                self._finalise_compensation(graph_id, child_key, compensates_key, adm.intent)
            return adm.cert

        result = executor()
        cert = self.seal.seal(
            adm.intent, adm.fence, result,
            compensates_cert=forward_cert_hash, graph_id=graph_id,
        )
        self._finalise_compensation(graph_id, child_key, compensates_key, adm.intent)
        return cert

    def _finalise_compensation(
        self, graph_id: str, child_key: str, compensates_key: str, intent: str
    ) -> None:
        with self.seal._connect(autocommit=True) as c:
            c.execute(
                "UPDATE seal_graph_children SET state='sealed', intent=%s "
                "WHERE graph_id=%s AND child_key=%s",
                (intent, graph_id, child_key),
            )
            c.execute(
                "UPDATE seal_graph_children SET state='compensated' "
                "WHERE graph_id=%s AND child_key=%s",
                (graph_id, compensates_key),
            )
            c.execute(
                "UPDATE seal_graphs SET state=%s, updated_at=%s WHERE graph_id=%s",
                (GRAPH_COMPENSATED, time.time(), graph_id),
            )

    # ── read ──────────────────────────────────────────────────────────────
    def _child(self, graph_id: str, child_key: str) -> Optional[dict]:
        with self.seal._connect(autocommit=True) as c:
            row = c.execute(
                "SELECT child_key, action, args, required, intent, state, compensates_key "
                "FROM seal_graph_children WHERE graph_id=%s AND child_key=%s",
                (graph_id, child_key),
            ).fetchone()
        if row is None:
            return None
        return {
            "child_key": row[0], "action": row[1], "args": row[2],
            "required": row[3], "intent": row[4], "state": row[5],
            "compensates_key": row[6],
        }

    def get(self, graph_id: str) -> Optional[dict]:
        with self.seal._connect(autocommit=True) as c:
            g = c.execute(
                "SELECT graph_id, state FROM seal_graphs WHERE graph_id=%s", (graph_id,)
            ).fetchone()
            if g is None:
                return None
            rows = c.execute(
                "SELECT child_key, action, args, required, intent, state, compensates_key "
                "FROM seal_graph_children WHERE graph_id=%s ORDER BY child_key",
                (graph_id,),
            ).fetchall()
        return {
            "graph_id": g[0],
            "state": g[1],
            "children": [
                {
                    "child_key": r[0], "action": r[1], "args": r[2], "required": r[3],
                    "intent": r[4], "state": r[5], "compensates_key": r[6],
                }
                for r in rows
            ],
        }
