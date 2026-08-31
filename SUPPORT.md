# Assurance for agents that move money

When your AI agents can spend, refund, or settle on their own, someone has to be
able to say — to a board, an auditor, an insurer, or just to themselves — *"we
have verified these agents cannot double-charge a customer or lose track of a
payment."* That sentence is hard to say honestly, because the failure doesn't
happen on a bug you'd catch in review. It happens on a dropped connection: a
payment settles, the response is lost, the agent retries, and the money moves
twice. Every log on your side reads *one clean payment after one transient error.*

We verify that it can't — and give you the evidence to prove it.

## Why us specifically

We co-authored the **MCP retry-safety proposal** — the draft standard for exactly
this failure class ([SEP working draft](https://github.com/YoadElkayam/mcp-fuse/tree/main/sep),
[discussion](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/3188)) —
and our [conformance battery](https://github.com/aurumflux20/hostile-facilitator)
is the suite that tests against it. Section 4.3, the rule that closes the replay
gate — *"could not determine" is terminal, never "absent"* — is our doctrine,
now spec text. When we attest that a money path is safe, the attestation is
measured against the standard we wrote.

Public track record: two payment projects shipped fixes from our findings in the
last two weeks (one a company doing 1M+ paid API calls/month), and two more orgs
before that. The trail is our GitHub history — including the times we were wrong
and said so.

## The engagement

**Money-Path Assurance — fixed scope, $9,000.** We take one production money path
— the tool, SDK, or service where your agents actually move funds — and:

1. **Read it** for the ambiguous-failure defect class: the settle that times out
   after it landed, the retry that mints a fresh authorization, the reservation
   released on a failure that wasn't one, the "unknown" quietly recorded as "fine."
2. **Test it** with our conformance battery — the same one in the standard —
   driving your client through every ambiguous outcome and counting how many times
   it *actually* paid for one request.
3. **Give you the attestation:** a written report tied to your own file and line
   numbers, the conformance results, and a plain-language statement of what is and
   isn't safe on that path — the document you hand to whoever needs to trust it.

Ten working days. Written only, no calls unless you want one. **If we find no real
defect, there is no invoice** — and you keep the clean attestation, which is worth
having on its own.

**Continuous Assurance — $2,000/month**, after the first engagement: your money
paths re-tested against the standard each quarter (and each time the standard
changes), a fresh attestation, and an incident channel.

## The self-serve door, still open

Not ready for an engagement? The tools are free and the check is one command:

- [`hostile-facilitator`](https://github.com/aurumflux20/hostile-facilitator) —
  point it at your client, find out in 60 seconds if it double-pays, add the
  GitHub Action so a PR can never reintroduce it.
- [Seal](https://github.com/aurumflux20/seal) — the reference implementation of
  the fix, storm-proven exactly-once with world-confirmation.

## How to start

Email **hello@aurumflux.co** with the repository or service and which money path
matters most, or open an issue on this repo titled `assurance request`. A reply
comes in writing, usually the same day. If we don't think we can find anything,
we say so before you pay.
