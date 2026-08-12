# Deploying Seal — exclusive authority

Every guarantee on this page has one precondition, and it is not a technical
one. It is where you keep your keys.

## The asterisk

Seal can prove that *it* admitted an action once. It cannot stop a process that
holds your Stripe secret key and calls Stripe directly. If your agents hold raw
write credentials, every Seal guarantee silently carries "…unless something
bypassed the gateway" — and a guarantee with an invisible asterisk is worse
than no guarantee, because people plan around it.

**Exclusive authority** is how you delete the asterisk:

> Write credentials for irreversible tools live **only** inside the Seal
> gateway process. Agents hold Seal tickets, never provider keys.

With that in place, bypass stops being an accident somebody has on a Tuesday and
becomes a deliberate act that requires taking a credential it has no reason to
have.

## What that looks like

```
  agent (no secrets)                    seal gateway (holds STRIPE_SECRET_KEY)
        │                                          │
        │  seal_admit charge:order-777             │
        ├─────────────────────────────────────────▶│  one row, one winner
        │  ◀── fresh=true, fence=…                 │
        │                                          │
        │  "please charge" (ticket, not a key)     │
        ├─────────────────────────────────────────▶│──▶ Stripe
        │  ◀── result                              │
        │  seal_commit                             │
        ├─────────────────────────────────────────▶│  cert written
```

Checklist:

1. **One place holds the keys.** Provider secrets are injected into the gateway
   only. Not in agent env, not in the prompt, not in a `.env` an agent can read.
2. **Agents get tickets.** An agent can ask the gateway to act; it cannot act.
3. **Tag every effect with its intent.** Witnesses need to find the effect later
   — e.g. Stripe `metadata[seal_intent] = <intent>`. Untagged effects cannot be
   witnessed, so they can never reach `WORLD_FINAL`.
4. **Pick a domain per blast radius.** `customer:42`, `mailbox:ops@…`. When a
   divergence freezes a domain, the freeze is only as useful as the scope is
   meaningful.
5. **Alarm on `WORLD_UNKNOWN`.** It is not a failure — it means we could not
   find out, and a human should. Never auto-retry the effect on UNKNOWN.
6. **Nobody unfreezes from an agent.** There is deliberately no `seal_unfreeze`
   MCP tool: releasing a breaker is a human act after reconciliation, and the
   agent that may be causing the divergence must not be able to clear it.

## Honest limits

- **Offline rogues.** A process with its own credentials that never touches the
  gateway is outside the boundary. Exclusive authority is what makes this rare
  and deliberate; nothing in software makes it impossible.
- **Witness coverage.** A cert reaches `WORLD_FINAL` only for tools with a
  witness adapter. Everything else stops at `SEALED`, which is an honest claim
  about admission and nothing more.
- **The Stripe adapter is DOCUMENTED, not MEASURED.** Its request shape follows
  Stripe's published search API and is covered by tests with an injected
  transport, but it has not yet run against a live test-mode account. Do not
  present it as a verified integration until it has.

## Cross-org clearing (design note — not built)

The natural extension: two organisations share one root intent under a neutral
Seal, so neither side's agents can double-settle a joint action, and both verify
the same cert graph.

The hooks that make it possible already exist — intents are content-addressed,
certs are portable and verifiable with nothing but the store, and graphs link
children by cert hash. What does not exist is multi-tenancy, dual-control
admission, or any trust model between orgs.

Recorded here so the design stays coherent. **It is not on the build path and
should not be sold.** The closest working metaphors are card networks and
escrow — none of them for multi-agent tool graphs.
