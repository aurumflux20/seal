# What a Retry-Safety Review returns

The deliverable is three things. Always these three, in this order, whether the
path is broken or clean. If a report ever comes back as narrative without them,
it is not finished.

This page is the specification of the artifact, written so you can check the
report you receive against it — and so you can see, before paying anything,
exactly what lands in your inbox.

---

## 1 · The line

Every finding names a file and a line number in **your** repository, the
mechanism in your own control flow, and why each guard you already built does
not cover it. Not a category. Not a lint rule. A line.

A real one, from a review of a self-hosted EVM facilitator (open finding —
unnamed here until they ship, per the disclosure rule below):

> Inside the settlement queue: `writeContract(transferFrom)` at line 548 — money
> moves here — then `waitForTransactionReceipt` at 576, then
> `nonceTracker.markSettled(…)` at 600. Step 600 is the only place the
> settlement is recorded, and it runs only if 576 resolves. When 576 throws,
> control reaches the catch at 616, where `partialTxHash = error?.permitHash || ''`
> — and `permitHash` is attached only inside the `transferFrom` catch at 569, so
> a receipt failure thrown after that block leaves it `''`. Neither hash reaches
> the response. `transferHash` was a local inside the closure and is gone.
>
> **Why the existing guards do not cover it.** The nonce tracker is keyed on
> completion, not on broadcast — the window between 548 and 600 is exactly where
> it is empty. The serialized queue prevents facilitator-side nonce collisions
> and has no opinion about what the client does after a `success:false`.
> `categorizeSettleError` already knows `receipt_timeout` is distinct from a
> revert, then reports both with no hash.

If the path is clean, section 1 says so in the same specificity: which paths were
read, which ambiguous outcomes each one distinguishes, and the line where it does
it. **A clean pass is a deliverable, not a refund note** — it is the document you
hand to whoever asked whether your agents can double-charge.

## 2 · The count

Battery output, from `hostile-facilitator` driven against your client. Seven
ambiguous outcomes, and for each one the number of **settlements actually
counted at the facilitator** — never response-body equality.

This distinction is the whole instrument. Twelve identical responses are not
twelve safe calls; twelve identical charges are twelve charges. A harness that
cannot tell those apart is a lying test, and it is how this defect class survived
in production code for years.

Real output, the tool's own self-test — a known-broken client and a known-correct
one, run as a mutation control:

```
  hostile-facilitator — naive client (known-broken): 3/7 safe
    [FAIL] accept_then_timeout    3 distinct settlements for one purchase — DOUBLE PAY
    [FAIL] 5xx_after_settle       3 distinct settlements for one purchase — DOUBLE PAY
    [FAIL] double_402             3 distinct settlements for one purchase — DOUBLE PAY
    [PASS] slow_answer            exactly one settlement
    [FAIL] reconcile_unavailable  3 settlements — retried after the reconciliation read failed,
                                  treating 'could not determine' as 'absent'
    [PASS] declared_safe          exactly one settlement
    [PASS] clean                  exactly one settlement

  hostile-facilitator — safe client (known-correct): 7/7 safe
    [PASS] reconcile_unavailable  held on an unresolvable outcome
                                  (correct: 'could not determine' is terminal)
    …

instrument valid: True
```

`instrument valid: True` is the line that matters most. It reports that the
broken client actually failed — i.e. that the instrument is capable of returning
a non-zero. **A battery that cannot fail cannot pass.** Any report claiming a
clean run without that control is asserting nothing, and you should reject it.

Where a live reproduction is possible we run one and state the money: one
purchase, the amount collected, the amount owed. Where it is not, the report says
**code read** and states its own ceiling in the same paragraph as the claim. A
line that blends the two is a line you should not trust — from us or anyone.

## 3 · The who-pays table

For each finding, one of three verdicts. This is the question your board, your
auditor and your customer ask immediately after "was one found."

| Verdict | What it means | What follows |
|---|---|---|
| **Licensed-path defect** | Your money path itself turned an unknown outcome into a second payment — the settle that timed out after it landed, the retry that signed a fresh authorization, the guard that released on an error that wasn't one. | This is the finding. Fix and test attached. Goes on the public Index with credit when you ship. |
| **Credential outside the path** | The extra charge came from something holding the provider secret directly, bypassing every guard you built. Your guards held; the key didn't stay where the guards are. | Not a defect in the path. Named as the shape of leak it is, and pointed at exclusive authority — agents hold single-use tickets, never the key. |
| **Undetermined — held** | We could not establish, from the code or a reproduction, whether the second record is possible. | Reported as *undetermined*. Never as safe. Never as found. Nothing on this path earns a clean verdict until it resolves. |

The third row is the one that makes the other two worth anything. "Could not
determine" is terminal — it is never "did not happen." That rule is what the
whole review is measured against, it is §4.3 of the retry-safety proposal we
co-authored, and we hold the report to it exactly as we ask your code to be held
to it.

---

## Disclosure

A finding is yours first. Nothing is published while it is open — the public
[Retry-Safety Index](https://aurumflux.co/retry-safety/) counts open findings and
names nobody, which is why the worked example above has no company attached to
it. When you ship a fix, the row goes up **with credit and your time-to-fix as
the headline**, because shipping a fix in hours is the thing worth recording.
That is the only place your name appears, and only after you have fixed it.

If you would rather never appear at all, say so and you won't.

## Scope and price

One money path — the tool, SDK, or service where your agents actually move
funds. Five working days, written only, no calls unless you want one. **$1,200,
refunded in full if the path is clean** — and you keep the clean report.

Details and how to start: [SUPPORT.md](../SUPPORT.md).
