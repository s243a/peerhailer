# Capability as a property of the path

**Status: designed, not built.**

## The gap

A capability is currently a property of a *peer*. `luna` holds `tunnel:acp`, so
`luna` may drive the agent — from anywhere, over anything.

That is not what an operator means. The same machine reached over a tailnet and
reached over a café LAN does not carry the same risk, because the risk is not
"which machine" but "who else can read this". The protocol is signed and not
encrypted, so a shared segment means a readable *conversation* even when the peer
at the far end is entirely honest.

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

## The recommendation: label the listeners by whether the link is encrypted

The first draft labelled networks *trusted* and *untrusted*. That is the wrong
word, and the right one is narrower.

"Trusted" is a judgement about who else is on a segment — unfalsifiable, prone to
drift, and it ages badly the moment a new device joins. **"Encrypted" is a claim
about the link**, it is the property that actually matters for a plaintext
protocol, and it becomes true by *doing* something rather than by deciding
something. The label goes on the listener:

```
hail daemon --hail-on tailscale0:encrypted --hail-on wlan0
```

`tailscale0` is encrypted because WireGuard is underneath. A plain HTTP listener
on `wlan0` is not. The same `wlan0` behind TLS pinned to the peer's key is —
without anyone revisiting a judgement about the household.

Tunnels then require an encrypted arrival, and that is the default rather than an
option. `hail` does not require one: identity is signed, so a readable hail leaks
who this machine knows and cannot be forged, while a readable *tunnel* leaks
whatever crossed it.

Still operator-asserted — this cannot verify that WireGuard is under
`tailscale0`. But asserting a fact about a link is a smaller act than asserting a
judgement about a network, and a wrong one is discoverable.

A peer holding `tunnel:acp` that reaches this machine over a plaintext LAN
listener is refused *that capability* and keeps the rest — still admitted, still
hailed, still gossiped with. It has lost a privilege, not an identity.

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

## What this means today, and what TLS changes

**Today: tunnels over Tailscale, and nowhere else.** That is the only encrypted
link this project has, so it is the only place the capability survives. The
household LAN carries hails and not tunnels — which is a real restriction rather
than a formality, and the honest state of a project whose protocol is signed and
not encrypted.

**With TLS pinned to the peer's key, the same wire qualifies.** The segment is
still shared and the conversation is not, so a direct peer-to-peer link becomes a
place tunnels may run without Tailscale underneath. That is the payoff, and the
reason TLS is next rather than optional forever: it is not extra safety on top of
what works, it is what makes the fabric work off the tailnet at all.

Note what does *not* need revisiting when that lands. No trust judgement changes,
no peer is re-admitted, no capability is re-granted. A listener's label goes from
plaintext to encrypted because something was configured, and the capability
follows.

## Testing it

The household LAN is a real plaintext segment on real hardware:

1. Label it: `--hail-on wlan0 --hail-on tailscale0:encrypted`
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
