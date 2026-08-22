# Tunnels, and ACP as the first one

**Status: designed, not built.**

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

**Not a VPN.** One protocol, one named endpoint, one capability. The narrowness
is what makes it reviewable.

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
