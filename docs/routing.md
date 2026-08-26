# Routing: reaching a node you can't address directly

**Status: design + staged roadmap. Nothing here is built.** Today peerhailer
reaches a peer with a signed `callPeer` to an address it already holds, and a
single **relay** hop (`RELAY`/carrier) can carry a message one step onward. This
document is the plan for **multi-hop routing** — delivering to a node across the
peer graph when there is no direct address — written as a roadmap so the hard,
dangerous parts come last and each stage earns the next.

It began as a rough sketch (probabilistic best-next-hop, back off to more distant
routes on failure, cluster the table by key, average seven hops, keep peers on
separate clusters, optional shared metadata, some anonymity). Several of those
instincts re-derive real systems; a few will bite. The design below keeps the good
ones, corrects the rest, and says why.

## The reframe: route through the trust graph, not an overlay

peerhailer already authenticates who may relay through whom (`RELAY`, the carrier
profile, block-by-key, the "a relay must never reach a peer this machine has
blocked" rule in `docs/acp-tunnel.md`). **That admission graph is the routing
substrate: a message only ever steps to an admitted peer.** This is friend-to-friend
(F2F) / "darknet" routing, and it is the single most important decision here —
because it is also the security foundation.

Open overlays (Kademlia, IPFS's DHT, Ethereum's) spend enormous effort defending
against **Sybil** and **eclipse** attacks: an adversary generating a million cheap
identities to fill your routing table or surround a target. Almost all of a DHT's
structural complexity exists *because it cannot trust its neighbours*. peerhailer
can. Routing only through peers you admitted makes those attacks require **social
compromise, not key generation** — so most of the machinery an open overlay needs,
this design gets to skip. We are not building a DHT. We are building delivery over a
graph we already authenticate.

## Principles: build on what already exists

A few lenses the whole roadmap is read through. The reframe above was the first
application of the first one.

1. **Leverage what already exists — twice over.** *Inside* peerhailer: multi-hop
   routing is mostly *composing* machinery that is already here — the admission
   graph, `RELAY`, block-by-key, the per-capability rate limits, and the sealed
   relay already sketched in `docs/chat.md` and `docs/acp-tunnel.md`. It needs few
   genuinely new primitives. *Outside* peerhailer: encrypted-mesh routing is a
   solved problem (Yggdrasil, CJDNS) and so is anonymity (Tor, I2P). **Prefer
   delegating to a proven system or reimplementing a well-understood algorithm over
   inventing a novel router.** Novel routing is a swamp of subtle, expensive failure
   (loops, grayholes, eclipse, traffic analysis); very little here should be new.

2. **Zero-dependency in-process** — a router runs next to the identity key, so the
   supply-chain argument from `docs/file-backends.md` applies in full. The delegated
   families (route *over* an external mesh) are the deliberate, visible escape hatch,
   not an in-process dependency.

3. **The trust graph is an asset, not a limit.** Design *with* F2F — it is what buys
   the Sybil resistance — rather than treating "only admitted peers" as a constraint
   to engineer around.

4. **Minimal-first; earn complexity.** Each stage must stand alone and be provable
   before the next is built. A stalled greedy router that cannot fall back is worse
   than a slow source route that always arrives.

5. **The objectives are the operator's.** Performance and anonymity are *knobs* —
   usually set by the same person who runs the node — not properties baked into the
   whole network. The design's job is to make the trade legible and adjustable, not
   to choose for everyone.

6. **Honesty about trade-offs** — the file-backends lesson: say plainly where an
   approach is weak, and never let a demo imply a guarantee it does not give
   (an efficient route is not a hidden one).

## The split that makes "each node picks its own approach" safe

Local autonomy over routing is right — but only for *policy*, never for *protocol*.
A message that crosses several machines needs invariants **everyone** honours, or it
loops, amplifies, or gets stranded. So:

- **The protocol is fixed, minimal, and shared.** A routing envelope carries:
  a **destination key**, a **hard TTL** (a loop/cost ceiling nobody may raise), a
  **visited-set or path** (so a hop is never repeated), the **sealed payload**, and
  a **signed origin** (or onion layers — see anonymity). The rules for decrementing
  TTL, refusing a revisit, and never relaying toward a blocked key are not
  negotiable.
- **The policy is local and pluggable.** *Which* admitted peer to step to, how much
  to randomise, how long to wait, when to retry a more distant route, whether to
  share metadata — all local. This is your "each node chooses its own approach,"
  made safe by keeping it above a protocol that cannot be bent into a loop.

## Config families: `custom` always, named presets beside it

Routing policy is configured the way capabilities are: `profiles` are named
capability bundles; **config families** are named *policy* bundles. Two kinds, and
the parallel to `docs/file-backends.md` is deliberate:

- **`custom`** — the hand-rolled baseline, always available: you set the primitives
  directly (next-hop metric, randomisation, TTL, retry, metadata sharing, anonymity
  layering).
- **Named families** — curated presets that implement a coherent strategy, each
  inspired by a system that already solved a version of this. A family is either
  **native** (our own zero-dependency implementation of the *idea*) or **delegated**
  (route *over* an external overlay the operator runs — the "shell out to system
  binaries" move from `docs/file-backends.md`, applied to routing: you get a
  battle-tested mesh without adding an in-process dependency, at the cost of an
  external daemon).

At the start the choice is small and honest: **`custom`** plus **one native named
family** (the source-routed one below). A faithful Yggdrasil-style greedy router or
a delegated Yggdrasil/CJDNS integration are later families, not first ones —
promising them at Stage 1 would be the same over-promise the file-backends doc
warns against.

## The roadmap

Each stage ships something usable and safe by itself, and proves the ground the
next stage stands on.

### Stage 1 — deliverable multi-hop, loop-free by construction

The floor: get a message across several hops without ever looping, over the trust
graph, on a small network. **Reactive source routing**, the way MANET protocols
**DSR/AODV** do it: flood a bounded, deduplicated *route request* to discover a path
to the destination, then the origin **source-routes** subsequent traffic along the
discovered path and caches it. Loop-free because the path is fixed and the
visited-set is carried; bounded because the hard TTL and peerhailer's existing
per-capability rate limits apply. Ships `custom` + a **`source-route`** family
(CJDNS-flavoured in spirit). Stats are **first-party** only at this stage: your own
observed round-trip and success per next hop. Prove it on a 3–5 node loopback graph.
*(Covers outline items 1's delivery half, 2's bound, and 5.)*

### Stage 2 — adaptive next-hop (greedy, with the honest caveat)

Now let each hop *decide* rather than follow a fixed path: **greedy toward the
destination key** (XOR distance, or a learned coordinate), with **weighted-random
selection among the top-k closest** for load-balancing and path diversity, and your
**back-off-to-a-more-distant-route on failure**. This is the Q-routing / AntNet /
Yggdrasil-greedy family. **The caveat you must hear:** greedy routing on an
*arbitrary* trust graph can get **stuck in local minima** — the closest peer you can
step to may still be far from the target, and none of *its* reachable peers are
closer. Greedy only works well when the graph has **small-world structure** (Kleinberg
long-range links distributed by distance), which in F2F comes only from *trusted
introductions* to distant peers, or from location assignment (Freenet swaps node
locations to manufacture it — and that is a known deanonymisation vector, so it is
not free). So Stage 2 always keeps Stage 1's flood-discovery as the **recovery path**
when greedy stalls. Ships a **`greedy`** family. *(Covers outline item 1 fully.)*

### Stage 3 — structured tables, only if the network is large

Your instinct to **cluster the routing table by identity key and balance the
clusters** is exactly **Kademlia's k-buckets**: the table partitioned by XOR-distance
prefix, k entries per bucket, self-balancing by design. But Kademlia is engineered
for *millions* of nodes; a friend graph of tens does not need it, and adding it early
is complexity for scale you do not have. So bucket structure is a **Stage 3 option**,
reached only when a real network is large enough that "your peers plus learned
reachability hints" stops covering the space. "Keep direct peers on separate
clusters" resolves here too — you cannot pick your friends' keys, but the bucket
structure is how you *use* whatever spread they have, and trusted introductions are
how you widen it. Ships a **`kademlia`** family. *(Covers outline item 3.)*

### Stage 4 — shared metadata, gated and verified

Optional metadata sharing to optimise routes — and the stage where security gets
hard, so it comes late. A peer can **lie** in shared metadata to attract traffic (then
blackhole it) or to deny a route. Rules: accept metadata **only from admitted peers**,
treat every claim as a **hint** not a fact, and **verify with first-party probes** —
a node reporting its own quality is the fox counting the hens. Two shapes, with a
tradeoff to state plainly: **path-vector** (carry the path, BGP-style) gives clean
loop-avoidance and verifiable claims but **reveals the path**, which is the opposite
of anonymity; **link-state gossip** spreads reachability without full paths. Make the
shape a knob, defaulting to the least-revealing one. *(Covers the "share metadata"
item.)*

### Stage 5 — the anonymity knob

Anonymity is a per-operator objective, so it is a *knob*, not a mode of the whole
network — and it must be built on the right mechanism. Probabilistic routing gives
**position blurring** (a relay is unsure how close it is to the origin — your
"average seven hops via a drop probability" instinct, done as a randomised
*hop-count near the endpoints*, Freenet-style, **not** a drop probability that kills
real messages, and with a hard TTL underneath for safety). But position-blurring is
**not source anonymity**: a relay still sees who and what unless the payload is
**onion/garlic-wrapped** so each hop learns only its predecessor and successor. That
layered relay is already sketched (unbuilt) in `docs/chat.md` and
`docs/acp-tunnel.md`; **that** is the anonymity mechanism, and probabilistic routing
complements it. Strong anonymity against a global passive observer (cover traffic,
mixing, timing defence — Tor/mixnet territory) is a separate project an order of
magnitude larger, and this roadmap does **not** promise it. Ships a **`freenet`**
family (F2F small-world + probabilistic HTL + onion payload) and the
performance↔anonymity operator knob. *(Covers outline item 4's anonymity half.)*

### Stage 6 — delegated families (route over an existing mesh)

For an operator who wants proven routing today and will run an external daemon:
**delegated** families that carry peerhailer traffic *over* **Yggdrasil** or **CJDNS**
— self-organising, encrypted meshes that already solved overlay routing. peerhailer's
contribution becomes the trust/capability layer on top, not the router. This is the
`docs/file-backends.md` shell-out mitigation applied to routing: no in-process
dependency, an external daemon whose absence is a clear error rather than a silent
TCB expansion. Ships `yggdrasil-delegate` / `cjdns-delegate` families.

## Tensions, stated without flinching

- **Performance vs anonymity.** Shared metadata and path-vectors make routing fast
  and verifiable *by revealing topology and paths*; onion layering hides them *by
  giving up global optimisation*. You cannot fully have both. This is why it is an
  operator knob (Stage 4/5), not a fixed choice.
- **Scale vs simplicity.** Kademlia structure pays off at millions of nodes and is
  dead weight at tens. Match structure to the graph you actually have; do not import
  a DHT to route among your friends.
- **Optimisation vs trust.** Every bit of routing intelligence you take from *other*
  nodes is a bit an adversary can poison. First-party measurement is the trustworthy
  core; reported metadata is a hint to be verified.

## Security, concretely

- **Sybil / eclipse:** defended *structurally* by the F2F reframe — you route only
  through admitted peers, so surrounding a target costs social compromise, not keys.
  Do not reopen this hole with open-overlay discovery.
- **Routing attacks** (blackhole, grayhole, misdirection): mitigated by first-party
  success/RTT measurement feeding the next-hop weights (a peer that silently drops
  loses weight fast), by trust-weighting, and by keeping the "never relay toward a
  blocked key" invariant.
- **Loops and amplification:** the hard TTL, the carried visited-set, and reuse of
  peerhailer's existing per-capability rate limits. Probabilistic multi-path must be
  bounded so retries cannot fan out into a flood.
- **Traffic analysis:** out of scope for a strong (global-observer) threat model;
  Stage 5's position-blurring and onion layers raise the bar cheaply, and the doc is
  honest that that is *all* they do.

## Statistics

**First-party is primary:** your own observed round-trip time and success per next
hop, kept as a decaying average, feeding the policy's weights. **Reported statistics
are hints**, accepted only from admitted peers and verified before they change a
decision. **Ping is the first-party fallback** when a node does not report — good
precisely *because* it is your own measurement, and it assumes only that the node
answers a ping. Statistics may be kept per next-hop, and (once Stage 3's buckets
exist) aggregated per cluster.

## Prior art, and the space it maps out

peerhailer's ethos is "most of this already exists," and for overlay routing it
emphatically does. Read these before building — you may find the problem is 80%
solved and the remaining 20% is the F2F constraint and the sealed relay we already
have. More useful than a list is a map, because these systems sit at different
points of the same trade-off space and each **config family** is really a choice of
where on it to stand:

| System | Trust model | Anonymity | Performance / reach | What to borrow |
| --- | --- | --- | --- | --- |
| **Yggdrasil** | open-ish (any peer) | low — efficient, not hidden | high, self-organising | greedy-on-tree metric; zero-config; a delegated family |
| **CJDNS** | peer-invite | low | high | label-switched **source routes** (Stage 1); a delegated family |
| **DSR / AODV** | ad-hoc / local | none | good on small dynamic graphs | on-demand flood-discovery + source routing — **Stage 1** |
| **Kademlia / libp2p / IPFS** | open (Sybil-exposed) | none | high, scales to millions | XOR **k-buckets** — **Stage 3**, only at scale |
| **Scuttlebutt (SSB)** | **F2F / social graph** | low | offline-first, eventual | gossip + replication over the *trust graph* — Stage 4 metadata |
| **ZeroNet** | open | **low by default**, optional via Tor | **high** — direct + BitTorrent swarming | anonymity-as-*optional-overlay*; reuse existing infra (see below) |
| **Freenet (darknet)** | **F2F** | **high** — position hidden | **low** — store-and-forward | probabilistic HTL; small-world over friends — **Stage 5** |
| **I2P / Tor / GNUnet** | open / directory / F2F | **high** — layered crypto | moderate to low | **onion / garlic** layering — the real anonymity mechanism; Tor as a *delegated* anonymity layer |

**The frontier, read off the table.** Systems cluster into two camps, and the split
is exactly the one you spotted between **ZeroNet and Freenet**. Direct connections
and swarming — ZeroNet, Yggdrasil, IPFS — are **fast, and expose who is talking to
whom** (IPs and paths are visible). Store-and-forward with layered crypto — Freenet,
I2P, Tor, GNUnet — **hide who is talking to whom, and pay for it in latency**. There
is no free lunch on this axis: a route that is efficient to compute is, almost by
construction, legible to observe; hiding it means adding hops, layers, and
uncertainty that cost performance. ZeroNet is the honest data point — it chose speed
and made anonymity an *optional Tor overlay* rather than an intrinsic property (and,
worth noting, it is only lightly maintained now; the lesson outlives the project).

**Where this puts peerhailer.** The F2F reframe already buys the thing the fast camp
lacks — **Sybil-resistant reachability** — cheaply, without a DHT. Performance then
comes from short, direct paths through the trust graph. Anonymity is a **bolt-on you
pay for only when you want it**: either intrinsic (Freenet-style probabilistic HTL +
our own onion payload, Stage 5) or delegated (route the sealed traffic over Tor,
Stage-6 style). This is why anonymity is a knob and not a mode, and why two presets
are both legitimate: a **performance-first** family (ZeroNet/Yggdrasil-flavoured —
direct, optional external anonymity) beside an **anonymity-first** one
(Freenet-flavoured — F2F, probabilistic, onion). ZeroNet's other lesson — *reuse
what is already built* (it stood on BitTorrent) — is Principle 1: peerhailer should
stand on its own trust graph and sealed relay, and may stand on Tor for anonymity or
Yggdrasil for reach, rather than reinvent either.

**The composite-network lesson.** ZeroNet's deepest lesson is that a network need
not be homogeneous: **not every node talks over Tor**, and the ones that do still
interoperate with the ones that don't. Strikingly, ZeroNet-over-Tor is still *faster
than Freenet* — a well-built overlay with anonymity added as an **optional per-node
or per-path overlay** beats a design that makes the *whole* network pay anonymity's
latency intrinsically. That is a direct argument for this design's shape: build one
fast substrate (F2F direct, short paths), let each node choose its own policy
(Principle 5) — some direct, some onion, some routing over Tor — and let those
choices **mix in a single network**. A `performance-first` node and an
`anonymity-first` node are not two networks; they are two policies over one protocol
(the fixed envelope), which is exactly why the protocol/policy split and the config
families are the load-bearing decisions. Anonymity becomes a cost the nodes that want
it pay, not a tax on everyone.

Two named references for the mechanics: **Q-routing / AntNet** for the adaptive,
feedback-weighted next-hop of Stage 2, and **Kleinberg's small-world result** for
*why* greedy routing needs long-range links distributed by distance — the reason
Stage 2 carries the local-minima caveat.

## What this roadmap will not do

- Build an **open DHT** that reopens Sybil/eclipse — the trust graph is the point.
- Promise **strong anonymity** against a global observer — position-blurring and
  onion layers only.
- Fix a **seven-hop average** — hop count follows the graph's diameter and a hard
  TTL, not a target.
- **Trust reported statistics** — first-party measurement rules; reports are verified
  hints.
- Ship **greedy routing without a recovery path** — flood-discovery backstops a
  stalled greedy step, because greedy stalls on real trust graphs.

## Questions for review

1. Is F2F-only routing too restrictive for the reachability people actually want, or
   is the Sybil resistance worth the smaller reachable set?
2. Is Stage 1's flood-discovery acceptable on the networks we expect, or does even a
   bounded flood cost too much — pushing us to source routes handed in out-of-band?
3. Should the first named family be `source-route` (safest) or a `*-delegate` over
   an existing mesh (least code, most proven) — i.e. is Stage 6 actually Stage 1?
4. Where does the sealed/onion relay (currently unbuilt) sit — a prerequisite for
   *any* multi-hop, or only for the Stage 5 anonymity knob?
5. Is a routing plugin the right unit at all, or should this be a mode of the
   existing relay path rather than a new plugin surface?
