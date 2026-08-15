# seal

**Exactly-once admission for irreversible agent actions, across processes.**

> Not an engineer? Read [docs/PLAIN-ENGLISH.md](docs/PLAIN-ENGLISH.md) instead —
> the same thing with no jargon, including what we can't do.

Two different agents, on two different machines, both decide to charge order 123
at the same instant. In-process idempotency can't help — the guard has to live in
a store both agents talk to, and the winner has to be decided *atomically there*.

Seal is that layer. One Postgres, one row per intent, one winner:

```
INSERT ... ON CONFLICT DO NOTHING     -- one row, one winner, no check-then-act window
```

Every admitted action ends in a **certificate**: a content-addressed hash over
intent + args digest + result digest + the previous cert's hash. Editing,
deleting or reordering any cert breaks every hash after it — and anyone with the
DSN can check, with no network and no trust in us:

```bash
SEAL_DSN="..." python3 -m seal verify
# chain VERIFIED — 41 cert(s), every link intact   (exit 0; broken chain → exit 1)
```

## The proof

The claim is tested the hostile way: **1,000 real threads released by one
barrier against one shared Postgres**, where the "charge" increments a measured
counter — if two callers run, the counter says 2 and the test fails loudly.

Result, four consecutive runs: **ACTUAL_EXECUTIONS = 1.** Every loser either
replayed the sealed cert, stood down mid-flight, or failed safe when the store
was unreachable. A 50-caller post-seal wave: all replayed, none re-ran. Full
numbers, including the honest limits: [STORM-PROOF.md](STORM-PROOF.md).

Run it yourself:

```bash
# Needs Python 3.10+ and a modern pip. macOS ships 3.9 with pip 21, which fails
# on an editable install from pyproject.toml with a misleading "setup.py not
# found" error — so create a venv rather than debugging that.
python3 --version                      # want 3.10 or newer
# older? macOS:  brew install python@3.12   (or use pyenv / uv)
python3 -m venv .venv && source .venv/bin/activate
python3 -m pip install -U pip
python3 -m pip install -e .

export SEAL_DSN="host=... dbname=seal"
python3 storm.py --n 1000
```

## Test YOUR server, not just ours

The exact harness above, generalized into a standalone file with zero
dependency on this repo — copy it, point it at your own write-bearing tool,
and find out for yourself:

```bash
python3 range_safety_test.py --n 1000
```

It demonstrates itself against a known-unsafe target and a known-safe one
before you ever run it for real, so a pass means something. Full writeup,
including the three ways an early version of this test lied to us before it
was fixed: [docs/RANGE-SAFETY-TEST.md](docs/RANGE-SAFETY-TEST.md).

## Usage

```python
from seal import Seal

seal = Seal(dsn); seal.setup()

adm = seal.admit("charge", {"order_id": "123", "amount": 4900})
if adm.fresh:                     # you won — run the effect, then seal it
    result = stripe_charge(...)
    cert = seal.seal(adm.intent, adm.fence, result)
elif adm.cert is not None:        # already done — here is the receipt
    return adm.cert
else:                             # someone else is mid-flight — stand down
    raise InFlight()
```

If the effect fails **before anything irreversible happened**, release the claim
so a retry is legitimate: `seal.fail(adm.intent, adm.fence, reason)`.

## World confirmation — measured against live Stripe, not mocked

A cert saying "admitted once" is a claim about us. The next question is what
Stripe (or Resend, or your bank's webhook) actually recorded — and the answer
is allowed to disagree with us.

```bash
export SEAL_DSN="host=... dbname=..."
export STRIPE_TEST_KEY="sk_test_..."   # your own test-mode key, Dashboard -> API keys
python3 stripe_demo.py
```

What it does, against your real Stripe test account, no mocks:

1. **Two agents fire the same charge at the same instant.** Seal admits one.
   Exactly one real `PaymentIntent` is created.
2. **The witness asks Stripe:** *"how many charges carry this intent?"* Stripe
   says one → the cert upgrades to `WORLD_FINAL`.
3. **A rogue charge is created outside the gateway** — the thing no local fence
   can stop on its own. The witness asks again; Stripe now says two → the cert
   becomes `WORLD_DIVERGED`, the domain freezes, and further spend on it is
   refused automatically.

Two honest things the live run taught us, both fixed and both tested: Stripe's
search index is eventually consistent (a fresh charge can take real seconds to
appear — the witness polls to a definitive answer rather than ever recording a
"not indexed yet" empty read as authoritative absence), and once the world has
contradicted the ledger, a later flaky re-count must never quietly downgrade
the cert back to `WORLD_FINAL` — divergence is sticky by design.

## Pre-commit world freeze — don't act on facts that already moved

`admit()` has always taken a `read_set` — the world facts a decision depends
on (a cart total, an inventory count) — and stored it on the cert. Until now
nothing ever checked it: a caller who believed they had staleness protection
had none. Same defect shape as a bug fixed earlier the same day, one layer up
— a guard present in the schema, never enforced.

```python
from seal.freshness import CallableChecker

fresh = CallableChecker(lambda rs: current_cart_total(rs["order_id"]) == rs["total"])

adm = seal.admit("charge", {"amount": 5000}, key="order-777",
                 read_set={"order_id": "777", "total": 5000}, checker=fresh)
# StaleWorldRead is raised BEFORE a fence is granted if the checker says no —
# nothing runs on facts that already changed. Gateway.propose() takes the
# same read_set/checker kwargs and passes them straight through.
```

Enforcement point is deliberate: before the fence, not after the effect ran.
Checking afterward could only refuse to *claim* success — it can't stop money
moving on stale information, which is the actual failure this exists to
prevent. Opt-in and backward-compatible, same rule as everywhere else in this
library: only engages when the caller supplies both `read_set` and `checker`.
Honest limit, printed where it applies rather than left to be discovered: the
checker call itself can't be made atomic with the admission INSERT, so a
change landing in that narrow gap is a residual window — the same caveat
class as a witness's eventually-consistent provider index.

## Clearance — permission that has to be earned, not declared

The fence proves an action ran once. Clearance is the layer above it that a
company actually buys: which tool paths may an agent fire *unattended*, and on
what evidence.

```python
from seal.clearance import Clearance, CLEARED

cl = Clearance(seal)
cl.set_policy("charge", CLEARED)                       # an operator's intent
cl.record_proof("charge", green=True, storm_n=1000, executions=1)  # from CI

cl.status("charge")["effective"]   # CLEARED — but only because both are true
```

The rule that makes this more than a toggle: **CLEARED is earned, not
declared.** A path only reports effectively `CLEARED` if an operator set it
*and* a green storm proof was recorded recently enough. Let the last proof go
red, or let it go stale, and `status()` reports `HOLD` on its own — nobody has
to remember to downgrade it. `REVOKED` always wins, never auto-recovers, and
`revoke_all()` is one switch that stops every known path at the choke. A
`range_report()` exports counted events and provider-cited certs — the artifact
a security questionnaire or a CFO actually reads.

## Exclusive Authority — agents get tickets, never the credential

Clearance is policy. Policy an agent can walk around if it still holds
`sk_live` itself isn't a rail, it's a suggestion. Exclusive Authority removes
the credential from the agent entirely.

```python
from seal.authority import Gateway

gw = Gateway(seal)
gw.register_executor("charge", lambda args: stripe_charge(args))  # secret lives HERE only

prop = gw.propose("charge", {"amount": 4900}, key="order-777")
if prop["status"] == "cleared":
    result = gw.execute(prop["ticket"], {"amount": 4900})  # gateway calls Stripe, not the agent
```

An agent calls `propose()` and gets back a **ticket** — proof an intent was
admitted, cleared, and budgeted — never a secret. `execute()` is the only place
the provider is ever called, and the ticket is bound to the exact args that
were cleared: it's rejected if what you hand `execute()` doesn't match what was
proposed, single-use, and expires. (The first cut of this didn't bind args to
the signature and would have let a ticket cleared for \$1 be spent on any
amount — found by attacking our own build before it shipped, not after.)

**Custody model, stated plainly:** the gateway runs *inside your own
infrastructure*. AurumFlux never holds, sees, or transports your provider
secret — we ship the software that takes the key out of the agent's hands; we
do not become a vault ourselves. Honest limit: a process on the same host that
can read the gateway's own environment can still steal the secret. This raises
the bar to "steal from the vault," not to physical impossibility.

## Graduated Clearance — maker-checker for the amounts that matter

Binary CLEARED is enough for a $5 API call. It is not what a finance org signs
off on for a $50,000 payout — they sign off on segregation of duties: the
person who proposes a spend is never the person who approves it, on the
record. Graduated Clearance adds thresholds on top of Clearance:

```python
from seal.graduated import GraduatedClearance, APPROVE

gc = GraduatedClearance(seal)
gc.set_thresholds("payout", auto_ceiling=100, dual_ceiling=10_000, required_approvers=2)

# amount 50   -> AUTO, ordinary Clearance applies
# amount 5000 -> DUAL, needs 2 distinct human approvals before it can execute
r = gc.request("payout", 5000, maker="alice", intent=intent)
gc.add_vote(r["id"], "bob", APPROVE)
gc.add_vote(r["id"], "carol", APPROVE)   # now APPROVED — a THIRD person, not alice
```

Wired into the gateway: `Gateway.propose(..., amount=X)` on a path with
thresholds configured returns `{"status": "needs_approval", "tier": "DUAL"}`
instead of a ticket until a satisfied `approval_id` is supplied. The maker
cannot approve their own request — enforced in code, not policy — and one
approver cannot be counted twice even under a genuine concurrent race, because
it's a Postgres `UNIQUE` constraint on (approval, approver), not an
app-level check. A single reject is terminal. An approval authorises exactly
one execution and is bound to the exact intent it was requested for. Every
decided approval — approved or rejected, with every vote — is appended into
the *same* hash chain the execution certs live in, so `seal verify` covers
governance decisions the same way it covers what actually ran.

Backward-compatible by design: a path nobody ran `set_thresholds()` on never
triggers graduated clearance, even if `propose()` is called with an amount —
existing budget-only integrations are unaffected.

Run the whole story end to end — no payment provider needed, nothing charged:

```bash
python3 approval_demo.py
```

A $200 purchase clears on its own; $12,000 is refused until two *distinct*
humans approve; the requester is refused when they try to approve their own;
a duplicate vote from the same approver is refused; one reject is terminal;
$250,000 is never automatic; and one `revoke` stops even the $200 path. It
ends on the Range Report, which states approvals in money — approved and
rejected totals — rather than a count of event kinds.

## What a Seal cert does and does not claim

A cert proves the action was **admitted exactly once at this gateway** and that
the recorded result hasn't been altered since. It does **not** prove the outside
world settled it — every v1 cert carries `world: "unconfirmed"`, permanently and
on purpose. "We admitted this once" and "Stripe took the money" are different
claims; conflating them is exactly the bug class this tool exists to stop.
World confirmation (provider adapters that flip that field against Stripe's or
your provider's own records) is the next layer, and the cert schema already
carries the field so the format won't break.

## Relationship to once-kernel, effectfence, and coherence

[`once-kernel`](https://github.com/aurumflux20/once-kernel-ts) proves one
*process* didn't run an effect twice. [`effectfence`](https://github.com/aurumflux20/effectfence)
guards one MCP server. Seal is the cross-process layer above both, for the
moment your agents outgrow a single machine. The free primitives stay free
(Apache-2.0 / MIT), forever.

For **claim vs proven** on agent PRs and CI (said it ≠ showed it), see the
separate project [`coherence`](https://github.com/aurumflux20/coherence) —
not part of this repo; different package, different git history.

## License

[Business Source License 1.1](LICENSE): read it, run it, use it in production
internally (commercial included) — just don't resell it as a hosted service.
Converts to Apache-2.0 on 2030-08-12.
