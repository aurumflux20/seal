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
