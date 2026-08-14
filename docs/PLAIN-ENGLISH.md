# What this is, in plain words

No jargon. If you are not an engineer, read this one and skip the rest.

---

## The problem

You have AI agents doing real work. At some point one of them has to do
something that **cannot be taken back**: charge a card, send a payment, place an
order, delete a file, deploy code.

Those actions are different from everything else an agent does. If an agent
writes a bad sentence, you delete the sentence. If an agent sends $40,000 to the
wrong supplier, you make phone calls.

So two things happen, and both cost you money:

**One — sometimes it happens twice.**
The network hiccups. The agent doesn't hear back, so it tries again. Two agents
pick up the same job at the same second. Now the customer is charged twice, or
the supplier is paid twice. Nobody meant it. It still happened.

**Two — so everybody stops the agent before the last step.**
Because of problem one, your finance and security people say: *fine, the agent
can prepare it, but a human clicks the button.* Every time. Forever. You bought
automation and you got a very fast form-filler. The agent does 95% of the work
and a person still spends their day clicking.

Most companies never notice they have problem one. They just live with problem
two and call it caution.

---

## What we do

We sit in front of the irreversible action, like a gate.

**Nothing gets through the gate twice.**
Before any agent can charge, pay, or send, it has to claim the job in a shared
place. Claiming is one operation — one agent wins, everyone else is told *"that
one is taken, here is the receipt from the agent that did it."* It is not a
check and then an action, where two agents can both check and both act. It is
one step, so there is no gap to slip through.

**We ask the outside world if it really happened.**
After the money moves, we ask the payment provider directly: *how many of these
do you actually have?* If they say one, we mark it done. If they say two, we
stop that customer immediately and tell you. If they say nothing — because their
system is down — we write down "we don't know" and keep it as "we don't know."
We never turn "we don't know" into "it's fine."

**The agent never holds the key.**
The password to your payment system lives in the gate, on your servers. The
agent asks for permission and gets a one-time pass, good for one action, at one
exact amount. If the agent asks for $1 and then tries to spend $999,999 with the
same pass, the gate refuses. An agent that gets confused, or is tricked by
something it read on the internet, cannot go get the key. It doesn't have it.

**Small things go through, big things wait for people.**
You set the lines. Under $500, the agent just does it. Between $500 and $50,000,
two different people have to approve — and the person who asked can never be one
of them, and nobody can approve twice to make the numbers work. Above $50,000, a
human always. This is the part that raises your ceiling: instead of a human on
100% of actions, you get a human on the ones that matter.

**One switch stops everything.**
If something looks wrong, one command and every agent loses permission to spend
— including the small automatic ones. An agent cannot turn it back on. Only a
person can.

**Everything is written down in a log that cannot be quietly edited.**
Every action, every approval, every refusal is chained to the one before it. If
anyone changes or deletes any entry — including us, including you — every entry
after it stops matching, and a one-line check catches it. Your auditor can run
that check themselves without asking us anything.

---

## What you actually get

- Your agents finish the work instead of stopping one step short.
- The same payment cannot go out twice, even across different machines.
- A record you can hand to a security review or a CFO without writing it by hand.
- A stop button that works.

---

## What we do *not* do

We put this in writing because you will find out anyway, and it is better you
hear it from us:

- **We do not check your whole system.** We do one money path, properly. Not a
  survey of everything, which is how you get a report nobody acts on.
- **We never touch your passwords.** The gate runs on your servers. We never see
  a live key.
- **We are not insurance.** If money is lost, we don't pay it back. We reduce
  how often it happens and prove what did happen. That is a different product
  from insurance and we won't blur them.
- **We cannot stop a program that has your password and ignores the gate.** If
  something bypasses us entirely, we can't help. What we change is that
  bypassing has to be deliberate, not an accident.
- **"The provider confirmed it" needs a connector for your provider.** We have
  built and measured the one for Stripe. If you use something else, we build it
  during the work — and until it exists, the record honestly says "we made sure
  this ran once" instead of claiming the provider agreed.

---

## How you can check we're telling the truth, before you talk to us

Everything above is public code. You do not need a call, a demo, or an NDA.

```bash
git clone https://github.com/aurumflux20/seal && cd seal

# Needs Python 3.10 or newer. A Mac ships an older one, so make a clean
# workspace first — this works on any machine and changes nothing outside it.
python3 -m venv .venv && source .venv/bin/activate
python3 -m pip install -U pip
python3 -m pip install -e .

export SEAL_DSN="host=... dbname=seal"

python3 storm.py --n 1000       # 1,000 agents rush the same payment at once.
                               # Exactly one gets through. Count it yourself.

python3 approval_demo.py        # Watch the approval rules. Small purchase goes
                               # through. $12,000 waits for two people. The
                               # person who asked is refused when they try to
                               # approve it themselves.

python3 -m seal verify          # Check the log has not been tampered with.
```

There are 133 tests, and the mean ones are in there: fake permission slips,
reused permission slips, someone changing the amount after approval, someone
approving their own request, two people racing to be the second approver at the
same millisecond.

We also publish the bugs we found in our own system while attacking it, in
[STORM-PROOF.md](../STORM-PROOF.md). We publish those on purpose. A vendor who
has never found a bug in their own product has not looked for one.

---

*Every claim on this page has a test behind it. Where something has a limit, the
limit is printed right next to it.*
