# Tunnels, and ACP as the first one

**Status: the direct tunnel is built; relaying *through* a third peer is not.**

What works today: the tunnel plugin (a named, per-capability endpoint the
operator declares), the caller-side client (`hail tunnel <peer> <name> pipe`),
and driving a `bridge --listen` on another peer through it — the "phone driving a
coding agent at home" case this doc opens with, proven end to end over pinned
mutual TLS with an ACP `initialize` round-trip. See the worked example at the
bottom.

What remains designed: relaying *through* a third peer (the **transit** role
below), the payload sealing that makes such a relay safe, subject-binding, and
the inspection choices. So read the doc this way — where a section is about a
caller reaching a declared endpoint *directly*, it is built and in use; where it
is about a relay carrying bytes for someone else across a hop, it is design, and
gated by the invariant in [network-trust.md](network-trust.md#encrypted-by-default-and-why-plaintext-cannot-cross-a-relay).

Once the payload lands at an endpoint the operator declared, the tunnel carries
bytes and nothing about it is specific to ACP. ACP is the first endpoint because
it is the one worth having; the mechanism is general.

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

The cost lands on the worst possible message. `session/request_permission` blocks
the agent while a human decides, and the bridge's gate times out at 120 seconds —
which now has to cover the poll interval, the trip to a phone, and a person
noticing. A timeout denies, so this fails safe, but the MVP's most important
interaction becomes the one most likely to expire. Either the gate timeout grows
for tunnelled sessions, or permission requests jump the poll queue, or this is
the reason streaming stops being optional.

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

## Three roles, and who has to trust whom

A machine can play three parts, and they are separate permissions because they
are separate risks:

| Role | The ask | Capability | Costs you |
| --- | --- | --- | --- |
| **origin** | I want to reach an endpoint | — | nothing here |
| **transit** | carry this onward for me | `RELAY` | bandwidth, exposure, being a party to it |
| **exit** | deliver this to your local endpoint | `tunnel:<name>` | whatever that endpoint can do |

`RELAY` already exists and `carrier` already grants it; the per-endpoint
capability is new. Both are ordinary capabilities, so **whether they live in one
list or two is the operator's choice, not the design's**: a profile is a named
set, and someone who wants a peer to both carry and terminate writes one profile
granting both. A peer holds one profile, so combining is how you express "these
machines do everything for me" — and keeping them apart is how you express "this
box relays but is never a destination".

That falls out of the profile model rather than needing anything added, which is
a decent sign the model was cut in the right place.

### Transit checks the neighbour; exit checks the origin

The two roles ask different questions, and swapping them breaks both.

**Exit must check the origin, not the last hop.** If an exit only asked "does the
peer handing me this hold the endpoint capability", then any trusted relay could
launder anyone's traffic into a local endpoint — the relay holds it, so the check
passes, and whoever actually sent it was never examined. The origin signature
exists precisely so the exit can ask about the party that matters.

**Transit must check both ends.** A relay decision has two parties: who asked,
and where it is going. Only checking the asker means a peer with `RELAY` can use
this machine to reach *anyone* — including peers this machine has blocked. That
would make blocking defeatable by indirection, which is worth stating as a rule:

> **A relay must never be usable to reach a peer this machine has blocked.**

Blocking is by key, so the check is available; it just has to be made on the
next hop as well as on the requester. Without it, `hail block` protects only the
front door.

## Identity travels with the payload

Sealing hides the content from the fabric. It does not hide the sender, because
peerhailer is the thing that verified them — so a delivery is a pair: an
identity the daemon vouches for, and bytes it cannot read. Without that, the
bridge sees anonymous bytes arriving on a local socket and cannot tell a phone
from anything else on the machine.

The seal is **not optional for a relayed capability.** A direct arrival may be
declared plaintext-safe (`requiresEncryptedArrival: false`) — a judgement about
one trusted segment — but that opt-out does not survive a hop: a transit node
terminates the transport and would otherwise read the payload in the clear. So a
relayed capability is end-to-end sealed regardless of any direct-arrival opt-out,
or it does not relay. See
[network-trust.md](network-trust.md#encrypted-by-default-and-why-plaintext-cannot-cross-a-relay).

**The identity that crosses is the key, never the name.** A name is a label the
model deliberately allows two machines to share, and a rename must not transfer a
policy decision to a different machine. The bridge keys its source axis on the
origin's public key; the name travels only so a human can read the log.

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

**What the signature covers is the whole of it.** A signature over a generic
message is replayable: capture one sealed tunnel-open and re-present it later,
through any relay, and it verifies exactly as well. The signed body has to name
*this* endpoint and carry a timestamp, checked against a freshness window — the
same lesson the hello protocol already learned with `at` and `FRESHNESS_MS`. An
origin signature that does not bind the endpoint is an origin signature for
whichever endpoint the holder chooses.

## Source and destination

Policy at the bridge keys on both ends, and both are configurable.

**Source** is the verified origin, not the socket. Different peers get different
answers: a machine you sit at may prompt and cancel; a phone may prompt but not
change configuration; a relayed request may be refused outright.

**Destination** is the workspace. Bridge sessions already carry a `cwd`, so
per-workspace policy is a cut that already exists in the model — and a useful
one, since it is the difference between letting a phone poke at a scratch repo
and letting it into the one with credentials in it.

**Relayed-or-not is its own axis**, not an inference. It is derivable — the
immediate peer differs from the origin — but deriving it makes a policy depend on
topology, and topology is the thing this design keeps refusing to trust. Naming
it costs nothing and keeps "no agent traffic that was relayed" true by
construction rather than by arithmetic.

The rules themselves live at the bridge, in the policy system it already has,
because that is the only place the payload is plaintext. See its `design.md`.

## What subject-binding protects, and what it does not

A grant is useless to whoever intercepts it: it names its subject by key, so the
bytes buy nothing without the matching private key. That is real, and it is why
a tunnel can be opened over a plaintext link without the *authorisation* being
at risk.

It says nothing about the payload. Unencrypted, anyone on the path reads what
crosses — prompts, file contents, command output, an agent's reasoning about a
codebase. Subject-binding protects the right to open a tunnel, not the contents
of one.

And the second endpoint has a sharper version of the same gap. The T3 design
deliberately sends a **short-lived bearer token**, and a bearer token is usable
by whoever holds the bytes — that is what the word means. Minting it narrow and
brief limits the damage; it does not make interception harmless.

So the two endpoints have different requirements, and it is worth stating them
separately rather than settling on one answer:

| Endpoint | Plaintext link | Why |
| --- | --- | --- |
| agent (ACP) | acceptable on a trusted transport | the authorisation is subject-bound; the payload is a conversation |
| T3 credential | **no** | what crosses is a bearer token, and bearing is the whole mechanism |

### The order this gets built in

**First, no encryption of our own.** Over Tailscale the link is already
WireGuard; over a household LAN it is not, and that is a documented gap rather
than a solved problem. This is enough to prove the thing worth proving — that a
peer can reach one declared local endpoint and nothing else.

**Then TLS, pinned to the peer's key.** Node has TLS; a self-signed certificate
per machine, accepted only when its key matches the one the directory holds.
That reuses an implementation many people have attacked, and the part written
here is the pinning, which is small and checkable.

**Never a hand-rolled transport cipher.** An ephemeral X25519 exchange signed by
the identity keys is the textbook shape and entirely writable — and it would be
the most dangerous code in this project, written by whoever is quickest to
volunteer, in a codebase whose safety argument is that it is small enough to
read. Reviews of this project have found defects in far less subtle code, in the
same week it was written.

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

## A second endpoint: T3 to T3, without moving the token

The namespace design starts from a T3 token crossing a clipboard to reach
another instance. The tunnel removes the need for that, and there are two ways
to do it — one obvious and one better.

**Mint one on request, scoped and expiring.** Nothing is stored ahead of time
and the long-lived token never moves. T3 already supports this: a session
carries `expiresAt`, and a pairing carries scopes. So the thing that crosses is
not the credential — it is a *derived* one, narrower and short-lived, which is
`mintGrant` semantics wearing T3's clothes.

- **Revocation stays per-peer.** Stop minting, or `hail block`. Rotating a
  shared token ends everyone's access, which is the reason nobody rotates.
- **The secret that matters never leaves.** What crosses expires on its own,
  so a copy left behind is worthless rather than dangerous.
- **The tunnel stays a byte carrier**, which is the property everything else
  here depends on.

**The alternative, and why it is not the recommendation.** The exit could
terminate the session itself: open a loopback connection to the local T3,
attach its own credential, and let the remote authenticate purely as a peer, so
that nothing resembling a token crosses at all. Cleaner on paper, and it is what
"offers, not values" would suggest.

The cost is that it stops being a tunnel. The entrance has to be something a
local T3 client can pair with and open a WebSocket against; the exit has to be a
real T3 client holding its own credential — T3 authenticates with a bearer
header, a `wsTicket` query parameter, and a DPoP variant bound to the holder's
key. That is protocol machinery at both ends, for one endpoint, in a design
whose whole point is that a second endpoint needs no second plugin.

A derived credential that expires is the better trade: the tunnel keeps knowing
nothing, and what it carries is worthless a few minutes later.

### The cost, said plainly

An exit that attaches its own credential is a **confused deputy**: it acts with
full local authority on instructions from somewhere else. Every reason to be
careful about the agent endpoint applies here, and one more — an agent endpoint
runs commands a reviewer can see, while this one drives an application that has
its own permissions and its own idea of who is asking.

So: its own capability, never part of `trusted`; opened against a grant rather
than a standing permission; and bounded by the source and destination policy the
bridge already documents, since "which peer, reaching which instance" is exactly
what that answers.

**Encrypted end to end**, for the same reason as everything else here: what a
relay cannot read, it cannot leak, and a machine carrying traffic it cannot read
is safer for the one carrying it. Sealing is not invisibility — that a session
exists, to whom, and how long it lasted all remain visible on the path.

## A worked example: driving a remote agent (built)

The case the doc opens with, working today. On the machine that holds the
agents, run one bridge per agent as an ACP listener on a loopback port, declare a
tunnel endpoint for each, grant them, and serve over pinned mutual TLS:

```sh
# on the agent's machine
mcp-acp-bridge --agent claude    --listen 9100 &     # ACP over a loopback TCP port
mcp-acp-bridge --agent codex     --listen 9101 &     # codex via `codex exec` (single-turn, -s read-only)
mcp-acp-bridge --agent codex-mcp --listen 9103 &     # codex via `codex mcp-server`: native gate + multi-turn
hail tunnels add acp-claude    127.0.0.1:9100        # needs tunnel:acp-claude
hail tunnels add acp-codex     127.0.0.1:9101
hail tunnels add acp-codex-mcp 127.0.0.1:9103
hail profiles add agents --allows hail,tunnel:acp-claude,tunnel:acp-codex,tunnel:acp-codex-mcp   # granted deliberately
hail daemon --hail-on-tls tailscale0 --port 7645     # mutual TLS over the tailnet
```

From the machine running T3, point its ACP `command` at the tunnel:

```sh
hail tunnel <peer> acp-claude pipe
```

`pipe` pumps T3's ACP stdio through the tunnel to the remote bridge, so T3 drives
the remote agent as if it were local — peerhailer authenticates the caller (its
key plus `tunnel:acp-claude`), binds the hail to the target, and encrypts the
wire (mutual TLS), all before a byte reaches the bridge. Swap `acp-claude` for
`acp-codex` to change agent with **no other change**: T3's config only ever names
the relay, so local-vs-remote and which-agent are the relay's decision, not T3's.
Proven end to end — an ACP `initialize` round-trips and the bridge answers.

The `codex-mcp` endpoint is worth calling out: it drives codex through its own
`codex mcp-server`, so codex asks *the bridge* to approve each shell command and
patch, and those approvals ride back out as ordinary permission cards — a real
gate on a remote agent's actions, not just an observed stream. The whole path
(pinned mutual TLS → granted tunnel → ACP → the codex gate → an allow that runs
the command → a second turn that recalls the first) is verified on a single
machine by `npm run test:codex-fabric` in peerhailer, the loopback stand-in for
the two-machine case.

The bridge binds loopback and carries no auth of its own, deliberately: what may
reach it is the peerhailer tunnel, and the fabric is what authenticates. Binding
it to a public interface would expose an unauthenticated agent — the operator's
mistake to avoid, the same as binding the control API outward.

## A worked example: inspecting a remote browser

Chrome's DevTools Protocol is a good fit, and a good illustration of the whole
model on one concrete thing. Started with `--remote-debugging-port=9222`, Chrome
speaks CDP as a WebSocket over HTTP on a loopback port. The tunnel carries
arbitrary TCP bytes and a WebSocket upgrade is just bytes, so it rides through
untouched:

```sh
hail tunnels add devtools 127.0.0.1:9222     # needs tunnel:devtools
```

A peer holding `tunnel:devtools` can then attach DevTools to a browser on the far
machine — inspect the page, read the console, watch the network. For a fabric
whose point is reaching machines you own from somewhere else, that is genuinely
useful: debug the GUI on the box in the other room from the one in your hand.

It is also the sharpest example of why the capability has to be taken seriously,
because CDP is **unauthenticated and total**. Anything that reaches `9222` reads
every open page, every cookie and stored token, runs arbitrary JavaScript, and
navigates anywhere. So `tunnel:devtools` is not a mild grant — it is
`command:pair`-tier, *may drive my browser and everything it is logged into*, and
belongs in a deliberately-granted profile rather than a general one. The model
already expresses that; this is a reminder to use it, not new machinery.

**And it must arrive encrypted**, which is the encrypted-arrival rule
([network-trust.md](network-trust.md)) earning its keep on a case you can picture:
a CDP stream in plaintext is a browser session anyone on the wire can hijack, live.
That means **over a tailnet (WireGuard) or a pinned-TLS LAN link** — both of which
peerhailer serves now (`--hail-on-encrypted tailscale0`, or `--hail-on-tls` for a
direct peer-to-peer wire off any tailnet). And since a tunnel carries content the
fabric cannot vouch for, it is encrypted by default anyway: the operator would
have to *deliberately* declare it plaintext, which the tunnel plugin does not.

One practical note: Chrome binds `9222` to loopback, which is correct — the tunnel
is what reaches it, and the daemon reaches loopback. It needs a browser on the
remote machine, so it inspects a browser that is running; peerhailer's own page
serves from plain Node and needs no browser there.

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
