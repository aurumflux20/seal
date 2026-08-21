# Commercial support

## Retry Safety Review — $1,200, refunded in full if we find nothing

We read one money path in your codebase — the tool, SDK or service that
actually moves funds — and hunt one specific class of defect: **what happens
when a payment fails ambiguously.**

Not "is there an idempotency key." Most competent teams have that. The seam
that survives good engineering is the timeout *after* the money may already
have moved: the aborted request that settled anyway, the retry that mints a
fresh nonce, the reservation released on a failure that wasn't a failure, the
`unknown` outcome quietly recorded as `absent`.

**You get:** a written report, each finding tied to your own file and line
numbers, with a reproduction where one is possible and a recommended fix.
Written only — no calls, no meetings.

**You pay $1,200 up front at checkout. If we find no real defect, we refund it
in full** — and you keep the report saying so, which is worth having on its
own.

**Turnaround:** five working days from access.

### Why us for this specific thing

This is the defect class we hunt full-time, in public, on other people's code:

- [`hpp-io/x402-mcp-bridge`](https://github.com/hpp-io/x402-mcp-bridge/issues/10)
  — reported a check-then-act race in a wallet spend cap; they shipped the fix
  in v0.1.14, then a second fix (v0.1.15) after a follow-up finding.
- [`TocharianOU/mcp-server-kibana`](https://github.com/TocharianOU/mcp-server-kibana/pull/12)
  — two retry-safety PRs merged.
- Further findings filed publicly against agent-payment clients and wallets;
  the full trail is our GitHub history, including the ones where we were wrong
  and said so.

We also ship the reference implementation — this repository — so the report
comes from people who had to solve the same problem under a storm harness, not
from a checklist.

### The larger engagement, if the review finds something structural

**Write-Authority Mission — $12,000 fixed.** We install the full gateway on one
money path: exactly-once admission across processes, provider confirmation,
out-of-band sweeps for spend that never passed the gateway, and the earned
autonomy levels in [`docs/AUTONOMY-LEVELS.md`](docs/AUTONOMY-LEVELS.md) — the
point being that your humans stop approving payments a proven path has earned
the right to make alone. Same risk reversal: no demonstrable gap on a path you
actually run, no invoice.

**Range Retain — $2,000/month** afterwards: quarterly re-storm, incident
channel, monthly range report.

### How to start

**[Book a review — $1,200](https://buy.stripe.com/28E7sL91C9naapQbBVdIA0l)** · after checkout, reply to the receipt with
the repository or service and which money path matters most. Work starts the
same day.

Prefer to talk first? Email **hello@aurumflux.co**, or open an issue on this
repository titled `review request`. A reply comes in writing, usually the same
day. If we don't think we can find anything, we say so before you pay.

We will say no if we don't think we can find anything — a review that bills you
for a clean bill of health is a bad trade for both of us.
