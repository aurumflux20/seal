# Autonomy Levels for agents that spend money (L0–L5)

*A proposed common vocabulary. Version 0.1 — open to correction, and written to
be argued with.*

Self-driving cars got a shared ruler in 2014. Before SAE J3016 every carmaker
had its own word for how much the car did — "autopilot", "co-pilot",
"assisted" — and no buyer could compare two of them. After it, "Level 3" meant
one thing to everyone, and the marketing had to meet the definition.

Agents that move money are in the "before" period right now. Vendors say
*autonomous*, *supervised*, *human-in-the-loop*, *guardrailed* — and none of
those words carry a testable meaning. A buyer asking "can I let this thing pay
invoices on its own?" gets an adjective back.

This document proposes the ruler. Six levels, each defined by **what the system
must prove**, not by what it claims.

---

## The levels

| | Level | The human's role | What it means |
|---|---|---|---|
| **L0** | OBSERVED | Approves everything | The agent proposes; a human executes every money action. The agent may hold no spend credential. |
| **L1** | SUPERVISED | Approves every money action | The agent may execute non-money actions unattended. Every irreversible payment still needs a person. |
| **L2** | ASSISTED | Approves above a floor | Small, bounded spend runs unattended on paths with a clean record. Anything larger escalates. |
| **L3** | DELEGATED | Approves exceptions only | The human stops clicking. Unattended spend up to an earned ceiling, on paths that have proven themselves. **This is where the labour actually disappears.** |
| **L4** | TRUSTED | Reviews after the fact | Broad unattended authority. The human reads reports, not requests. |
| **L5** | AUTONOMOUS | Sets policy | Full unattended money authority on the path, bounded only by the operator's own ceiling. |

The interesting boundary is **L2 → L3**. Below it a human is still in the loop
for anything that matters, so the headcount cost is unchanged. Above it the
approval queue goes away. Every vendor selling "autonomy" should have to say
which side of that line their product actually puts you on.

---

## The five criteria

A level is a claim about evidence. To assert one, a system should be able to
answer all five — with artefacts, not assurances.

**1. Identity — whose record is this?**
A level attaches to a *path* (a specific money action on a specific rail), not
to a vendor or a model. "Our agent is L3" is meaningless; "refunds on Stripe are
L3, payouts are L1" is a claim you can check.

**2. Evidence — what has it actually proven?**
Count of irreversible effects the system executed *and* can still produce a
tamper-evident record for. Self-reported success does not count. Neither does a
log the operator could have edited.

**3. World confirmation — did the provider agree?**
The share of those effects the *provider's own ledger* confirms happened exactly
once. A local "success" is a claim; the provider agreeing is evidence. An
ambiguous timeout must be recorded as *unknown* and never silently as *fine* —
that collapse is the single most common way a duplicate charge hides.

**4. Out-of-band coverage — could money move without the system seeing it?**
Whether the system has swept the provider for effects that never passed through
it. Prevention answers "did I dedupe?"; only reconciliation answers "did anything
move behind my back?" **No system should claim L3 or above without this**, since
a gate that cannot see around itself cannot know its record is complete.

**5. Revocation — how fast does the level fall?**
The test that separates a real level from a badge. A level must be computed
continuously and drop on evidence of breach — not on a quarterly review. Slow to
earn, instant to lose.

---

## What a level is not

- **Not a safety proof.** L4 says "this path has behaved", never "this path
  cannot misbehave". Levels are earned track record, and track records are
  descriptions of the past.
- **Not transferable.** A record on one rail says nothing about another.
  Autonomy earned on $50 refunds is not autonomy over $50,000 wires.
- **Not a substitute for a ceiling.** A level decides how much room a path has
  *inside* the operator's limits. It never raises the limit itself.
- **Not vendor-scoped.** Two deployments of the same product will sit at
  different levels, because they have different records. That is the point.

---

## Why propose this at all

We build one implementation of it ([Seal](https://github.com/aurumflux20/seal)
computes these levels from its own ledger and suspends on out-of-band spend), so
this is not a neutral document and we would rather say so than pretend.

But the vocabulary is worth more shared than owned. Today a buyer cannot compare
two agent-payment products, and every vendor grades its own homework — including
us. A ruler that anyone can apply, to anyone's system, is better for the buyer
than six brochures.

If you think a level is drawn in the wrong place, or a criterion is missing, the
useful reply is a concrete one: which path, which evidence, what should have
been required instead. Corrections that make this harder to satisfy are the most
welcome kind.

*Apache-2.0 — this document is free to copy, quote, adapt, or implement, with or
without attribution, including by competitors.*
