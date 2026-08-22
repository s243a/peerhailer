# Tunnels, and ACP as the first one

**Status: designed, not built.**

Once the payload is sealed and lands at an endpoint the operator declared, the
tunnel carries bytes and nothing about it is specific to ACP. ACP is the first
endpoint because it is the one worth having; the mechanism is general.

## Why this one first

Every other plugin idea is a feature. This one is the reason the fabric exists:
a phone running T3 Code, driving a coding agent on a machine at home, over a
link authenticated by keys neither end had to type.

It is also the honest replacement for something worse.
[shared-namespace.md](shared-namespace.md) starts from a T3 token crossing a
clipboard to reach another instance — snoopable, unrevocable, the thing this
project keeps refusing to store. A tunnel removes the need to move the token at
all: the agent stays where it is, and the peer link carries the conversation.

## The layering: who, then what

The first design put ACP inside the plugin, which meant peerhailer had to
understand a protocol that is not its business. The better split is that the
payload stays **sealed until it reaches the thing that speaks it**:

| Layer | Answers | Sees |
| --- | --- | --- |
| peerhailer | *who* is this, and may they open a tunnel at all | metadata |
| the bridge | *what* are they asking, and is it allowed | plaintext |
| the gate and the human | should this particular action run | the card |

peerhailer carries bytes for a peer it has authenticated to an endpoint declared
locally. It never parses them. That keeps the fabric protocol-agnostic — a
second tunnel needs no second plugin — and means a compromised relay, or a
compromised daemon, learns who talked to whom and not what was said.

### The primitive is dangerous and must be narrowed

"Deliver these bytes to a local process" is a port forward into this machine. If
a caller can name the destination, a peer can aim the tunnel at any local port
— including services that trust localhost precisely because they assume nothing
remote can reach them.

So **the endpoint is named in local configuration and referenced by name.** The
caller says `acp`, not `127.0.0.1:9000`. An unknown name is refused. This is the
same rule as everywhere else here: a peer may cause something, never choose it.

### One capability per endpoint

It follows that "may open a tunnel" cannot be a single permission. A generic
carrier with one capability would mean granting a peer the agent endpoint also
grants it every other declared one — a database, a printer, whatever a later
version adds. Each endpoint carries its own capability, and holding one says
nothing about the others.

This is what keeps a general mechanism from being a general-purpose door.

## What has to cross

ACP is bidirectional, and the awkward direction is the one that matters:

| Message | Direction | Note |
| --- | --- | --- |
| `session/prompt`, `session/cancel` | client → agent | ordinary request/response |
| `session/update` | agent → client | streamed, many per turn |
| `session/request_permission` | agent → client | **blocks** until answered |

That last row is the difficulty. The permission card is the point of the bridge,
and it is the agent asking the client a question and waiting for an answer.

A peerhailer plugin route is a request that returns JSON. It cannot originate a
message, so it cannot carry that as it stands.

## Three transports, and why polling comes first

**Poll.** The client asks for pending messages; the daemon answers with whatever
queued. Needs **no change to the plugin contract** — a route that returns JSON is
exactly what a plugin already is. Costs latency and empty round trips.

**Stream (SSE) plus POST.** What MCP Streamable HTTP does, and what the bridge
already speaks on its other side. Correct shape, lower latency, and it requires
plugin routes to hold a response open — a change to what a plugin *is*.

**WebSocket.** Cleanest protocol fit, largest change to the daemon.

Polling first, deliberately. The hard part is not the transport, it is whether a
remote peer may drive an agent at all, and polling answers that without changing
what a plugin is allowed to be. If the trust path holds, the transport can be
replaced underneath it; if it does not, nothing was spent building a streaming
layer for something that will not ship.

## The trust question, which is the real one

**This is the most dangerous capability in the system.** A peer holding it can
drive an agent that runs commands on this machine. Diagnostics leak information;
this executes.

It does not live in `trusted`. `trusted` means "my own machines, may hail and see
who I know" — driving an agent is a different order of thing, and bundling them
would mean every machine you own can run code on every other by virtue of being
yours. It gets its own capability and its own profile, the way `DIAGNOSTICS` is
held by `operator` rather than by everyone trusted.

**Opened against a grant, not a standing permission.** A tunnel is a session with
a lifetime, which the namespace design already identifies as the thing closest to
a credential here. Grants are the existing answer: subject-bound so the bytes are
useless to anyone else, expiring in minutes, renewed rather than held. A tunnel
that outlives the intent that opened it is a back door.

## Method policy belongs to the bridge, and is deny-by-default

ACP method names are a **closed, enumerable set**. Deciding that a remote client
may not call `session/set_config_option` is exact — no normalising, no variant
spelling, none of the guesswork that made matching shell commands unsound.

What is *not* bounded is the content: prompt text, tool arguments, prose.
Filtering on that would be guessing at meaning, and a filter that guesses fails
quietly in the direction of permitting.

So: an allowlist of methods, refusing by default, **inside the bridge** — the
only place the payload is plaintext, and already the place that gates tool calls.
Not an optional plugin. If the allowlist were a separate install, the unfiltered
tunnel would be what you get by following the instructions, and the safe
configuration would be the one you had to remember.

## Identity travels with the payload

Sealing hides the content from the fabric. It does not hide the sender, because
peerhailer is the thing that verified them — so a delivery is a pair: an
identity the daemon vouches for, and bytes it cannot read. Without that, the
bridge sees anonymous bytes arriving on a local socket and cannot tell a phone
from anything else on the machine.

**The hand-off has to be authenticated too**, or the chain unravels at the last
inch. If the bridge's tunnel endpoint accepts any local connection, any local
process can claim to be the daemon relaying from a trusted peer — the same class
of problem as the control API answering on loopback with no credential, and the
same answer: a mode-600 shared secret between daemon and bridge.

## Verify the origin; do not trace the route

A route is a claim by whoever reports it, and an intermediary with a reason to
lie about the path can. **An origin signature is verifiable end to end**, needs
no understanding of topology, and survives any number of hops.

- **Direct.** The immediate peer is the origin, and the two agree.
- **Relayed.** The bridge verifies the origin's signature, and the fact that the
  immediate peer *differs* is itself the useful signal: this arrived through
  someone else. Cheap, and enough to express "no agent traffic that was relayed".
- **Full path**, if ever needed, is a chain of signed hops — which is what grant
  attenuation already does, so the machinery would be borrowed rather than
  invented.

## Source and destination

Policy at the bridge keys on both ends, and both are configurable.

**Source** is the verified origin, not the socket. Different peers get different
answers: a machine you sit at may prompt and cancel; a phone may prompt but not
change configuration; a relayed request may be refused outright.

**Destination** is the workspace. Bridge sessions already carry a `cwd`, so
per-workspace policy is a cut that already exists in the model — and a useful
one, since it is the difference between letting a phone poke at a scratch repo
and letting it into the one with credentials in it.

The rules themselves live at the bridge, in the policy system it already has,
because that is the only place the payload is plaintext. See its `design.md`.

## Sealed or inspectable, and who the relay is

Encryption decides what an intermediary can enforce, and the answer depends on
what the intermediary *is* to you:

| The relay is | Want | Because |
| --- | --- | --- |
| a machine you own, bridging your own networks | inspectable | the policy enforced is yours |
| someone else's machine carrying for you | sealed end to end | their inspection is surveillance |

There is a second argument for sealing that is about the carrier rather than the
sender: **carrying what you cannot read is safer for the one carrying it.** A
relay that can read what it passes has acquired knowledge, and responsibility,
about what crossed its machine. Blind carriage is what makes offering `RELAY` to
someone else a reasonable thing to do at all.

The two are not exclusive. Hop-by-hop encryption with a sealed payload gives a
relay what it needs to route — who it is for, how large, when — while the content
opens only at the end. That degrades sensibly: an inspecting relay becomes a
deliberate arrangement between machines one person owns, rather than the default
that happens because nothing was encrypted.

**Today's baseline, stated plainly:** the hello protocol is signed and *not*
encrypted. Directory contents are readable on-path — forgery-proof, not private.
An encrypted tunnel is new capability, and it is the same machinery as the
deferred covert mode, so the two should be designed together rather than one
bolted onto the other.

**And sealing is not invisibility.** That a tunnel exists, to whom, how big and
how often, all remain visible to anyone on the path. Hiding that needs padding
and cover traffic, which is covert mode's problem and not this one's.

## Where the supervisor goes

A supervisor — subscribing to permission events and deciding to approve, reject,
or pass to the human — needs plaintext. Sealing the payload settles where it can
live: **the bridge**, which is where it was first sketched, not the peer
boundary. One component rather than two.

## What this is not

**Not a VPN**, though the reason is not that it speaks ACP — it is that
destinations are *declared* rather than dialled. A VPN carries whatever you aim
at whatever host you name; this carries whatever you like to a service its
operator wrote down in advance, for a peer holding that endpoint's capability.
It is closer to a reverse proxy with peer authentication than to a network.

If that rule ever weakens — if a caller can supply an address — it becomes a
port forward into the machine, and Tailscale already does that job with far more
scrutiny behind it.

**TCP and UDP are not equally ready.** A stream has a beginning and an end for a
grant to bound and a session to resume. Datagrams have neither, need framing over
a request-shaped transport, and an endpoint that answers unauthenticated
datagrams is an amplification reflector. Authentication removes that particular
risk, but UDP should follow TCP rather than arrive with it.

**Not a way to reach a machine you could not otherwise reach.** The tunnel runs
over a peer link that already exists. Bridging networks is a separate question,
answered in [decisions.md](decisions.md): introductions cross, packets do not.

## Open

- **One tunnel or many.** Two clients driving one agent is a conflict the ACP
  session model does not describe.
- **A link that drops mid-turn.** The agent keeps working; a reconnecting client
  needs to find the turn it left, or cancel it.
- **Debuggability of an opaque payload.** Sealing means the daemon's diagnostics
  cannot help. An operator should be able to opt into plaintext at their own
  endpoint, which is a deliberate act and should look like one.
