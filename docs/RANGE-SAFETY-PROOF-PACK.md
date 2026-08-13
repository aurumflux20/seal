# Range Safety for Agent Money  
### Seal — one-page proof pack  
**Copy only · claims limited to what is in git and measured · Aug 2026**

---

## The problem companies still live with

Multi-agent systems, retries, webhooks, and workers all invent “smart” keys.  
Stripe idempotency only helps when **every path shares one key by construction**. They don’t.

Result: double charge, double payout, double send — or automation left **off** forever because legal and security won’t approve unattended money tools.

**Seal is range safety for irreversible agent actions:** admit once, prove under load, confirm against the world when a witness exists, and keep write credentials out of the agent’s hands.

---

## One sentence

> **Agents plan. They do not hold spend keys. Seal is the principal that may execute irreversible money actions — exactly once under concurrency, with permission that expires without continuous proof, and a kill switch when the world disagrees.**

---

## What is proven (not hoped)

| Proof | Result | How to reproduce |
|--------|--------|------------------|
| **Storm** | **1,000 concurrent threads, shared Postgres → ACTUAL_EXECUTIONS = 1** (4 consecutive runs, all PASS) | `python storm.py --n 1000` |
| **Post-seal wave** | 50 late callers → **all replay, 0 re-execute** | Same storm harness |
| **Cert chain** | Tamper-evident hash chain; edit/delete/reorder breaks verify | `python -m seal verify` |
| **Two agents, one charge** | Double-click path → **one** real charge; losers replay or stand down | `python demo.py` |
| **World divergence** | Extra charge **outside** admission → **WORLD_DIVERGED + domain freeze**; further spend refused | Stripe demo / finality tests |
| **Stripe witness** | Live **test-mode** measurement (not vibes-only docs) | `stripe_demo.py` + suite under `SEAL_DSN` |
| **Heal-on-reclaim** | Dead lease: probe world first; **CONFIRMED_ONE heals, does not re-run**; UNKNOWN never blind-retries | Core admit + heal path |
| **Exclusive Authority** | Agent **never receives** provider secret; only **tickets** (HMAC). Executor closes over secret **inside** the gateway | `Gateway.propose` / `execute` · `tests/test_authority.py` |
| **Amount-substitution attack** | Ticket proposed for $1 cannot execute as $999,999 — **args bound into signature** (bug found by attacking our own build; fixed + regression test) | `test_amount_substitution_is_refused` |
| **Single-use tickets** | Replay of a spent ticket refused | Authority suite |
| **Clearance earned** | CLEARED only if policy **and** recent **green** storm proof; missing/red/stale proof → **effective HOLD** alone | `Clearance.status` / `check` |
| **One-switch stop** | `revoke_all` + domain freeze paths | Clearance + `freeze_domain` |
| **Cross-process budget** | Spend ceiling in **Postgres under row lock** (not in-memory per process) | `Budget.reserve` / suite |
| **Effect graphs** | Root not GRAPH_FINAL until required children are **WORLD_FINAL**; compensations are first-class sealed intents (single-fire under concurrency) | `EffectGraph` + demo |

Full write-up of storm numbers, six bugs found by self-attack, and limits: **[STORM-PROOF.md](../STORM-PROOF.md)**.  
Deploy doctrine (keys only in gateway): **[DEPLOYMENT.md](DEPLOYMENT.md)**.

---

## What Seal is *not* (honesty is the product)

| We do **not** claim | Why |
|---------------------|-----|
| Insurance against all money loss | Best-effort control + attestation — not a bond or underwriter |
| Impossible offline bypass | A process with **its own** stolen/copied provider key that never talks to Seal is outside the rail. Exclusive Authority makes bypass **deliberate theft from a vault**, not an accident on Tuesday |
| AurumFlux hosts your live keys | **Self-hosted custody:** gateway runs in **your** infra; we ship software, not a vault of customer `sk_live` |
| Every tool is WORLD_FINAL | Only paths with a **witness adapter** graduate to world-confirmed; others stay honestly **SEALED** (admitted once at the gateway) |
| Magic without Postgres | Cross-process truth requires a shared durable store |

---

## Layers (one product)

```
CLEARANCE          CLEARED | HOLD | REVOKED — CLEARED expires without fresh green proof
EXCLUSIVE AUTHORITY  Agents get tickets; gateway alone holds write secrets (self-hosted)
WORLD FINALITY       Witness provider records; diverge → freeze domain
FENCE / ADMIT        Exactly-once admission + tamper-evident certs (storm-proven)
```

Sell the top. The bottom is already built and measured.

---

## What a buyer gets in a Mission (install language)

1. One money path (e.g. charge) admitted only through Seal  
2. **Gateway** pattern: agents propose → ticket → gateway executes (no key in agent env)  
3. Clearance on that path + CI storm posting green/red proof  
4. Budget ceiling where needed  
5. Incident receipt + range report export for security/finance  
6. Kill: revoke path or freeze domain after incident  

---

## Reproduce in one sitting

```bash
git clone https://github.com/aurumflux20/seal.git && cd seal
pip install -e .
export SEAL_DSN="host=... dbname=seal"   # shared Postgres
python -m pytest tests/ -q
python storm.py --n 1000                 # exit 0 == exactly-once held
python -m seal verify
# Optional: Stripe test-mode demo when SEAL_DSN + test key available
```

Repo: **https://github.com/aurumflux20/seal**  
Contact: **hello@aurumflux.co**

---

## One line to remember

**Range safety for agent money: one principal spends, once under load, permission earned by proof, stoppable when reality disagrees.**

*Seal by AurumFlux · proof pack · no phantom features · verify yourself.*
