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

Public track record: six payment paths fixed from our findings, three of them
this week — fastest 4.3 hours from report to release, one reproduced on a mainnet
fork before the fix. Every row and its proof is on the
[Retry-Safety Index](https://aurumflux.co/retry-safety/). The trail is our GitHub
history — including the times we were wrong and said so.

## What every finding in the report says

A double-charge is never reported as just "found." Each one is tied to a line, and
each one carries a verdict on **whose defect it is**, because that is the question
your board, your auditor, and your customer will ask next:

| Verdict | What it means | What follows |
|---|---|---|
| **Licensed-path defect** | Your money path itself turned an unknown outcome into a second payment — the settle that timed out after it landed, the retry that signed a fresh authorization, the guard that released on an error that wasn't one. | This is the finding. Fix attached, test attached, and it goes on the Index with credit when you ship. |
| **Credential outside the path** | The extra charge was made by something holding the provider secret directly, bypassing every guard you built. Your guards held; the key didn't stay where the guards are. | Not a defect in the path. The report says so plainly, names the shape of the leak, and points at exclusive-authority — the pattern where agents hold single-use tickets and never the key. |
| **Undetermined — held** | We could not establish from the code, the tests, or a reproduction whether the second record is possible. | It is reported as *undetermined*, never as *safe*, and never as *found*. Nothing on this path gets a clean verdict until it resolves. That is the same rule the standard's §4.3 imposes on the code — we hold ourselves to it in the report. |

Where we can reproduce, the report states the number: one purchase, how much was
collected, how much was owed. Where we cannot, it says *code read* and states its
own ceiling. A line that mixes the two is a line you should not trust — from us
or anyone.

**[What a review returns →](docs/REVIEW-DELIVERABLE.md)** — the deliverable
specified in full, with a real finding, real battery output, and the table above
filled in. Read it before you pay, and check the report you get against it.

> **Public register:** the [Retry-Safety Index](https://aurumflux.co/retry-safety/) lists which agent-payment implementations pay once when the answer is lost — verified safe, found & fixed (with time-to-fix), and how to get verified. Every row links to its proof.

## Two ways in

**1 · Retry-Safety Review — $1,200, one click, refunded in full if we find nothing.**
The fastest way to find out whether you have this problem at all. We read one money
path for the ambiguous-failure defect — the settle that times out after it landed,
the retry that mints a fresh nonce, the reservation released on a failure that
wasn't one — and send a written report tied to your own file and line numbers. Five
working days, written only. [Book it](https://buy.stripe.com/28E7sL91C9naapQbBVdIA0l);
if we find nothing you pay nothing and keep the report saying your guards hold.

**2 · Money-Path Assurance — $9,000.** The same reading, taken all the way to an
attestation you can hand a board, auditor, or insurer — with a conformance run
against the draft retry-safety standard we co-authored (an unadopted MCP proposal,
SEP working draft). Detailed just below.

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
