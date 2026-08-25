# Capability as a property of the path

**Status: the encrypted-arrival model is built; the "where a peer has been"
demotion (below) is designed.** A capability is served only where arrival is
encrypted — enforced by serving a marked route only on the encrypted listener
(the "separate the routes" section), plus the `requiresEncryptedArrival` marker
and its encrypted-by-default resolution. The shipped flags are
`--hail-on <iface>` (plaintext), `--hail-on-encrypted <iface>` (asserted), and
`--hail-on-tls <iface>` (pinned mutual TLS) — this doc's earlier drafts write a
`tailscale0:encrypted` suffix, which is the same idea in the form it was sketched
before it shipped. What is *designed, not built* is the demotion machinery from
"Where a peer has been" onward.

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

## Encryption does not protect availability, and that is the stronger argument

A node on the path that can neither read nor alter can still **drop, delay and
reset**. No cipher helps. What that buys an attacker, and what it does not:

**Killing a tunnel mid-turn.** The agent keeps working, the client comes back to
a turn it cannot see — already an open question in
[acp-tunnel.md](acp-tunnel.md), and now with a party who can cause it
deliberately.

**Stalling polls until the gate times out.** Fail-safe in the sense that nothing
is approved, and still sabotage: the agent cannot work. One property from
earlier work matters here. Refusals by a *person* are sticky — the agent is told
not to reword and try again — but **timeouts are deliberately not**: "nobody
refused; you may try once more". So a forced timeout produces a retry rather than
a permanent refusal. Had every denial been made sticky, an on-path attacker could
have manufactured permanent ones by dropping packets.

**And a downgrade.** This is the one that changes the argument. Routes sort by
what has worked, so an attacker who blocks the encrypted path does not merely
deny service — the peer falls back to the path that still answers, which is the
one the attacker can read. Without a rule about the link, blocking a wire
silently moves tunnels onto plaintext, and the attacker has *chosen* the medium
rather than waited for it.

With the rule, the fallback carries hails and refuses tunnels. The attacker can
still deny service; they cannot convert denial into interception. That is why
requiring an encrypted arrival is a **default rather than an option**: it is not
protection against being overheard by accident, it is what stops someone
arranging to overhear.

What none of this prevents is denial itself. A node that can drop traffic can
stop two machines talking, and no policy here changes that — the honest answer is
that availability is the transport's problem, and a fabric of personally-owned
machines fails visibly rather than silently when a link goes.

## Better: separate the routes, not the labels

The design above labels a listener and checks the label when a capability is
used. There is a simpler implementation of the same rule, and it follows from
noticing that **a listener is the unit of firewall policy** — two things needing
different rules need different sockets, because a rule can only tell them apart
by port.

So rather than labelling and checking: **serve tunnel routes only on the
encrypted listener.** A peer arriving over the plaintext LAN does not get a
refusal; it gets a 404, because the route is not there. No label, no lookup, no
branch — the same reason the control API is on its own socket instead of being
filtered inside a handler. Enforcement by socket cannot be got wrong by editing a
conditional.

It also composes with the operating system for free. Different ports mean
`iptables` can admit hails from the household LAN while admitting tunnels only
from the tailnet, without peerhailer being involved in the decision at all — and
a firewall rule that names one port is a rule whose scope a person can read.

What the in-app check is needed for is the case where one listener carries both —
a TLS listener that qualifies for tunnels *and* serves hails. With TLS built,
"encrypted" is no longer only a property of which socket you bound but of the
connection, so something has to ask: that is the `requiresEncryptedArrival` marker
the handler checks (`server.js`/`plugins.js`). Both mechanisms are live — a route
is served only on a listener whose posture satisfies its marker.

The same applies to anything else wanting its own rule: an arbitrary-source chat
belongs on its own port, so it can be filtered without touching the port peers
use.

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

## What this means today, and what TLS changed

**A tunnel runs over a tailnet or a pinned-TLS link, and nowhere else.** Over
Tailscale the encryption is WireGuard's (`--hail-on-encrypted tailscale0`); off
any tailnet, `--hail-on-tls` makes peerhailer terminate its own pinned mutual TLS
so a direct peer-to-peer wire qualifies too. The plaintext household LAN carries
hails and not tunnels — a real restriction, and the honest state of a protocol
that is signed and not encrypted.

TLS pinned to the peer's key was the piece that made the fabric work off the
tailnet at all — not extra safety on top of what works, but what lets a tunnel
run on a direct link with no Tailscale underneath. It is built (see
[tls.md](tls.md)).

Note what did *not* need revisiting when it landed. No trust judgement changed,
no peer was re-admitted, no capability re-granted. A listener's posture is
plaintext or encrypted because of how it was bound, and the capability follows.

## Encrypted by default, and why plaintext cannot cross a relay

The listener's label decides whether a marked capability is served there — but
the *default* is the safe one. A route is served only where arrival is encrypted
**unless the plugin declares otherwise** (`requiresEncryptedArrival`, resolved in
`plugins.js`): a capability that carries content and forgets to say so fails safe
— refused on a plaintext listener rather than served in the clear. Plaintext is a
deliberate opt-out (`false`), which only the discovery layer (`hail`/`directory`)
takes, since a record carries no secrets and hailing must work before any
encrypted channel exists.

That opt-out is a property of a **direct** arrival, and it is the one thing that
must **not** survive a relay. The two are not symmetric, and the reason is worth
stating precisely.

A direct link is one hop. If it is encrypted — Tailscale's WireGuard, or pinned
TLS — the two endpoints are the only parties to the conversation, and an operator
who declares `false` on a trusted direct segment is making a judgement about that
one segment. A relay is not one hop. The **transit** node terminates the
transport it received on and originates a new one onward; it is a *legitimate
endpoint* of each hop, not a bystander the hop's encryption hides things from. So
per-hop WireGuard, which seals a direct link end to end, seals *nothing past the
relay*: at the transit node the payload is decrypted from the inbound hop and
re-encrypted onto the outbound one, and in between it is plaintext the relay can
read — and forge.

What keeps a relay honest is encryption **the relay merely forwards**: an
end-to-end layer (TLS pinned to the *exit's* key, presented by the *origin*) that
the transit node carries as sealed bytes it cannot open — the "dumb forwarder."
That is why a relayed capability's encryption is **mandatory and not
opt-out-able**. `requiresEncryptedArrival: false` says "this one direct segment is
trusted," which is a claim nobody can make on the origin's behalf about a path
through someone else's box. So the rule is simply: **the plaintext opt-out does
not cross a relay.** A capability served `false` directly is still end-to-end
sealed the instant it is relayed, or it is not relayed at all.

This composes with the exit/origin model above: the exit checks the *origin's*
signature, not the last hop, and the origin seals the payload to the *exit's*
key; the transit node reads neither, spending only its bandwidth to forward
sealed bytes for a peer it granted `RELAY`. Relaying *through a third peer* is not
built (see [acp-tunnel.md](acp-tunnel.md); the direct tunnel there is) — this is
written now
so the invariant is fixed before the code that must honour it exists, and in
particular so the plaintext opt-out added for direct arrivals is never quietly
extended across a hop.

## Where a peer has been, and what to do about it

Everything above is about the wire between two machines. A different worry sits
beside it: a machine that spent an afternoon on a hostile segment may have been
attacked while it was there, and coming home does not undo that. No
per-connection check sees it.

Three answers, in increasing friction, and they are worth building in this order.

### 1. Restrict yourself, at the moment you move

A running daemon **observes its own network change** — an interface goes down, an
address changes — as it happens. So a machine knows it has moved before it has
been on the new segment long enough for anything to have happened to it, and can
stop asking for tunnel capabilities immediately.

That makes this the soundest of the three as well as the cheapest. It needs no
agreement from anyone, no protocol, and no trust: a machine declining to ask for
something is not a claim anybody has to believe. The narrow caveat is a machine
asleep when it moves, which learns on waking.

### 2. Record it where it arrives, and warn

For the peers that matter this is not a self-report at all. If a peer hails me
over a plaintext listener, I have **observed** that it was on a shared segment —
the same fact the encrypted-arrival check already reads. Record it against the
peer, change nothing, and warn until someone acts.

That is deliberately the shape used for a competing key: evidence kept, privilege
untouched, warning that does not scroll past. It fails *open*, which is the
honest cost of it.

Read at a moment of decision, the same record answers the narrower question too —
*you are about to grant tunnel access to a machine that was on an unknown network
yesterday* — so warning-at-promotion needs no separate mechanism, only somewhere
to look.

### 2b. Announce the move, so honest peers learn at once

A machine that notices its own move can tell the peers it talks to, and they may
demote on it. **Off by default on both sides** — announcing is a choice about
what you reveal, and acting on it is a choice about how much friction you accept.
This suits a particular posture rather than everyone. This is safe to believe for the reason at the
bottom of this section: it only ever costs the announcer something.

It earns its place because it covers a case observation cannot. A laptop that
moves to a café and still reaches you **over the tailnet** never arrives on your
plaintext listener, so nothing is observed and nothing is recorded. Without the
announcement you would not learn at all.

Three constraints, and the design is wrong without them:

**Never restore on an announcement.** "I am back on a trusted network" is a
*granting* claim — unverifiable, useful to the claimant, and precisely what a
compromised machine would say to get its tunnel access back. Demotion may be
automatic; restoration is a person's act. The same rule read in both directions.

**Absence means nothing.** A compromised machine does not announce, and a peer
that never announced is indistinguishable from one that never moved. So this is
timeliness for honest peers layered over the observed fallback, never the only
mechanism. Treating silence as "still where it was" would be the whole security
value inverted.

**Signed and fresh.** Without a freshness window the announcement is replayable:
capture one and re-present it whenever stripping a peer's capabilities is
convenient. That is the attacker-triggerable demotion rejected below, arriving
through a different door. The hail protocol's `at` and `FRESHNESS_MS` are the
existing machinery.

And a cost to weigh rather than dismiss: telling every peer when you change
network tells them when you travel. Over months that is a movement history held
by everyone you have ever admitted. Announcing only to peers holding capabilities
the move would affect is narrower and probably right, since nobody else has a
decision to make with it.

### 3. Demote automatically — opt-in, per capability

For people who want it to fail closed. **Off by default**: removing a privilege
without a person acting is a real cost, and "my laptop joined café wifi and now
cannot reach my server" is a bad surprise.

Which capabilities are worth arming follows from what a compromised holder gets:

| Held by a compromised peer | What it gets them | Worth arming |
| --- | --- | --- |
| `tunnel:<endpoint>` | drives a local service — the agent runs commands here | **yes, first** |
| `RELAY` | carries others' traffic: metadata, and the power to drop it | yes |
| `INTRODUCE` | puts names and keys in a candidate list nothing admits | rarely |
| `DIRECTORY` | learns who this machine knows | rarely |
| `HAIL` | learns this machine exists, which it already did | no |

The tension does not go away: the peer most worth arming this for is usually your
own laptop, which is also the one you most want working. The friction lands
hardest exactly where the protection is most valuable — an argument for trivial
restoration and a visible reason, not for skipping it.

### Tighter still: downgrade when a peer goes silent

The limitation above — *absence means nothing* — can be turned into a policy
rather than accepted. If going quiet costs privilege, a compromised machine can
no longer hide by not announcing, because saying nothing is itself the trigger.

**Much of this already exists.** A grant expires unless renewed, and renewing
requires contact, so anything grant-carried already downgrades on silence with no
new mechanism. What is missing is the profile-assigned case: a capability granted
by a profile survives any amount of quiet.

The cost is that it **ties trust to uptime**, which is a poor proxy for
integrity. An always-on server keeps everything; a laptop closed overnight is
demoted by morning; a phone is never trusted at all. That is tolerable when the
peers holding dangerous capabilities are machines that are supposed to be up, and
intolerable when they are not — so it belongs to a posture, not to the project.

If built: the timeout should be per capability like the rest, generous enough
that ordinary sleep does not trip it, and restoration should be one command with
the reason visible. A privilege that vanishes overnight and takes a person ten
minutes to find is worse than one that never existed.

### The attack this cannot defend against

If an attacker extracts a machine's **private key**, that machine is spoofable
completely. Every signature verifies, every check passes, and nothing here is
being fooled — the fabric is working exactly as designed for what it believes is
the right peer.

No capability policy helps, because none of it is an authentication question any
more. What the design can do is three things, and it is worth being clear that
they are mitigation rather than defence:

**Make extraction hard.** The identity file is mode 600, which is what a
filesystem offers and no more — and [decisions.md](decisions.md) already records
that this buys little on Windows, where the ACL decides. Hardware-backed keys, a
TPM or a secure enclave, are the real answer and are out of scope here; worth
naming so nobody mistakes a file permission for a boundary.

**Bound what a stolen key is worth.** This is where the capability model pays:
the attacker gets exactly what that peer held, and nothing else. `tunnel:acp` not
being part of `trusted` is precisely this — a stolen key from a machine that
could only hail is worth a directory listing, not a shell.

**Make recovery possible.** `hail block` refuses by key, so blocking survives a
rename. `hail rotate` replaces a key deliberately. Neither undoes what was done
with the key before anyone noticed.

There is no detection story, and inventing one would be dishonest: two machines
holding one key look like one machine to everything in this design. The competing
key warning does not fire, because there is no competing key.

### Not this: demoting on a key conflict

A tempting fourth, and wrong. Capabilities attach to a record and authentication
is by key, so a peer presenting a *different* key already gets nothing — it is an
unknown peer, and a genuine rotation leaves the real machine unable to
authenticate until `hail rotate`. A changed key never carries a capability.

Demoting the **record** because a conflict was seen would hand strangers a lever
on your own directory: anyone sitting at a stale address can present a self-signed
key, and a machine that demoted on that could have its real peers stripped from
across the room. Recording and warning costs an attacker the same effort and buys
them nothing.

### Believing a peer only when it costs them

Point 1 rests on a peer's own report, while this design says elsewhere that
self-reports are hints rather than evidence. Both hold, because of an asymmetry
worth stating plainly:

**A self-report is unsafe to believe when it would grant, and safe when it would
restrict.** A peer claiming a trusted network to *gain* a capability is claiming
something it benefits from, unverifiable, and exactly what an attacker would say.
A peer saying "I am on a café network" only ever loses something. Nobody lies
their way into less.

That is the test to apply whenever this design is tempted to trust a claim: which
direction does it move privilege.

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
