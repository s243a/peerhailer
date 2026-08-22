# Capability as a property of the path

**Status: designed, not built.**

## The gap

A capability is currently a property of a *peer*. `luna` holds `tunnel:acp`, so
`luna` may drive the agent — from anywhere, over anything.

That is not what an operator means. The same machine reached over a tailnet and
reached over a café LAN is not equally trustworthy, because the risk is not
"which machine" but "who else is on the wire and what did they see". The link
today is plaintext, so an untrusted segment means an untrusted *conversation*
even when the peer at the far end is entirely honest.

So a second question belongs beside "who are you": **how did you get here**.

## What the exit can know, and what it is merely told

This is the whole design, and it turns an expensive problem into a free one.

A machine **knows for certain** which of its own listeners received a
connection. `--hail-on wlan0,tailscale0` opens one listener per address; a
request arriving on the tailnet socket arrived over the tailnet, and nothing a
caller says changes that. It is observed, not claimed.

A machine is merely **told** everything else: which networks the peer binds on,
which hops the traffic crossed, what the origin's local conditions were. Useful
as context, worthless as enforcement — a peer that wants to lie about where it
listens can.

The rule that follows: **enforce on what is observed; treat the rest as a hint.**

## The recommendation: label the listeners

Networks get a trust label locally, attached to the thing already in the config:

```
hail daemon --hail-on tailscale0 --hail-on wlan0:untrusted
```

A capability may then require a trusted arrival. `tunnel:acp` does; `hail` does
not. A peer holding `tunnel:acp` that reaches this machine over the labelled-
untrusted LAN is refused *that capability* and keeps the rest — the peer is
still admitted, still hailed, still gossiped with. It has lost a privilege, not
an identity.

Two properties make this cheap:

- **The check is a lookup.** Which listener received this connection is already
  known at the moment the request is handled; the answer is a label on that
  listener. No probing, no round trip, no cryptography.
- **It cannot go stale.** A TCP connection's arrival interface is fixed for its
  lifetime, so checking once at the start is checking for good. A laptop that
  moves networks makes a *new* connection, which is checked again. The
  time-of-check problem simply does not arise.

Peers sharing which networks they bind on is still worth doing — it belongs in
the namespace design as a self-reported ability — but as *diagnosis*, so a
person can see why a capability is missing. Never as the basis for granting one.

## Two other shapes, and why not

### Rules that travel with the traffic

A tunnel could carry its own policy — firewall rules in the manner of iptables,
riding along and stopping the traffic at any boundary that violates them.

The appeal is obvious and the flaw is structural: **a rule carried by the
traffic is enforced by whoever handles the traffic**, and the hop you are
worried about is exactly the hop that will ignore it. It protects against
accident, never against intent. This is why source routing was disabled across
the internet, and it is the same reason "please do not log this" headers do not
work.

There is a version that *is* sound, and it is the recommendation above wearing
different clothes: the rule is enforced at the **exit**, by the party that cares,
against a fact that party can observe for itself. A rule that says "only over a
trusted arrival" is checkable. A rule that says "do not let hop three read this"
is a wish.

### Validating the whole path before starting

Cheaper than per-packet rules, and it answers a question that cannot be answered
honestly. Intermediate hops report their own trustworthiness; a compromised one
reports whatever helps. The only path facts worth anything are the ones with
cryptography behind them, and we already have those: the origin signature, and
whether the immediate peer differs from the origin — *this arrived through
someone else*, which is exactly the "relayed or not" axis the bridge's policy
already names.

So: no path validation. One observed fact at the exit, one signed fact about the
origin, and a hint from the peer for diagnosis.

## How TLS composes

Labelling a network untrusted says the wire is readable. Once a link is TLS with
the certificate pinned to the peer's key, that stops being true — the segment is
still shared, and the conversation is not.

So the rule is not "untrusted network, no tunnels" but "**untrusted network, no
tunnels in plaintext**". Pinned TLS restores the capability over the same wire.
That is the argument for TLS being next after this rather than optional forever,
and for the label describing *the link* rather than the place.

## Testing it

The household LAN is a real untrusted network on real hardware:

1. Label it: `--hail-on wlan0:untrusted --hail-on tailscale0`
2. `hail` still works over the LAN — identity is unaffected
3. A tunnel over the LAN is refused, naming the reason
4. The same tunnel over the tailnet succeeds, same peer, same key
5. And the refusal appears where a person will see it, not only in a log

Step 4 is the one that makes it worth building: **the same peer, two paths, two
answers.** Nothing in the model can express that today.

## Overhead

Near zero for the recommendation — one label lookup per connection. The
expensive designs are the ones rejected above, and they are expensive *and*
unenforceable, which is an unusual combination and a good reason to leave them.
