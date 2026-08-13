# seal

**Exactly-once admission for irreversible agent actions, across processes.**

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
SEAL_DSN="..." python -m seal verify
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
pip install -e . && export SEAL_DSN="host=... dbname=seal"
python storm.py --n 1000
```

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
python stripe_demo.py
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

## What a Seal cert does and does not claim

A cert proves the action was **admitted exactly once at this gateway** and that
the recorded result hasn't been altered since. It does **not** prove the outside
world settled it — every v1 cert carries `world: "unconfirmed"`, permanently and
on purpose. "We admitted this once" and "Stripe took the money" are different
claims; conflating them is exactly the bug class this tool exists to stop.
World confirmation (provider adapters that flip that field against Stripe's or
your provider's own records) is the next layer, and the cert schema already
carries the field so the format won't break.

## Relationship to once-kernel and effectfence

[`once-kernel`](https://github.com/aurumflux20/once-kernel-ts) proves one
*process* didn't run an effect twice. [`effectfence`](https://github.com/aurumflux20/effectfence)
guards one MCP server. Seal is the cross-process layer above both, for the
moment your agents outgrow a single machine. The free primitives stay free
(Apache-2.0 / MIT), forever.

## License

[Business Source License 1.1](LICENSE): read it, run it, use it in production
internally (commercial included) — just don't resell it as a hosted service.
Converts to Apache-2.0 on 2030-08-12.
