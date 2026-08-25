# Decisions

Choices that would otherwise be re-litigated, with the reasoning that produced
them and what would change them back.

## JavaScript with JSDoc, not TypeScript

**Decided.** The library is JavaScript, annotated with JSDoc, and type-checked
by `tsc` in strict mode. `npm run types` emits `.d.ts` files for anything
embedding it.

TypeScript is the better default for most projects, and this is not an argument
against types. The checking here *is* TypeScript's: `strict`,
`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, the same inference and
the same errors, on the same compiler. Turning it on found 49 errors on the
first run, two of which were latent bugs where a `null` return was assigned
straight into the directory. The question was never whether to have types.

The question was whether to have a **build step**, and for this program the
answer is no.

**The file you edit is the file that runs.** This daemon's failure mode is
silence: nothing answers, which is also what working looks like. Diagnosing that
usually means being on the machine, opening the file, changing something and
restarting. A compile step in that loop is a step in the wrong place, and source
maps are a poor substitute for a stack trace that points at the line you are
reading.

Three smaller consequences follow from the same property. `node --test` runs the
shipped files, so tests cannot pass against a build that differs from what is
published. There is nothing to install before the daemon runs, on machines whose
whole appeal is that they are small and already there. And an npm release is the
source, so what someone reads is what executed.

**What this costs.** JSDoc is more verbose than type annotations, and generics
or conditional types are awkward enough that the code avoids them. That is
affordable here because this is records, maps and HTTP handlers rather than a
type-level library — but it is a real cost, not a free lunch.

**What would change it.** If the covert transport arrives and brings a key
schedule and handshake state machine with it, the type-level work may stop being
awkward and start being necessary. Converting is cheap while the annotations are
already correct: JSDoc is most of the labour of a port, and the rest is
mechanical. It gets more expensive the longer it waits, which is worth
remembering rather than discovering.

## The daemon is optional

**Decided.** Every CLI command works against the stored directory with nothing
running.

A tool for reaching machines that must itself be running before it will answer
questions fails exactly when it is needed — during an outage, on a box that has
just rebooted, when something is already wrong. The daemon exists to *answer*
hails from elsewhere, not to be the only way in to what this machine knows.

## The directory is a file you can read

**Decided.** Plain JSON under `~/.config/peerhailer/`, written atomically.

The same reasoning. When nothing answers, the first useful question is "what
does this machine actually believe", and the fastest answer is `cat`. A format
requiring the tool to interpret it makes the tool a prerequisite for debugging
the tool.

Atomic because the alternative is a directory truncated by a crash mid-write,
which is a machine that has quietly forgotten every peer it knew.

## Identity is a key; the name is a label

**Decided.** Every machine holds an Ed25519 keypair, generated on first use, and
records are signed. A name identifies a peer to a person; the key identifies it
to the software.

Names cannot carry the weight. Two machines may choose the same one, a peer may
rename itself tomorrow, and a name arriving over the network is a claim anyone
could make. Without a key, an address in a record is a stranger's suggestion
about where to find your machine.

Generated on first use rather than asked for, because a setup step people skip
protects nothing. The private key lives beside the directory, not in it, at mode
600 — the directory is a file people are invited to read and paste into bug
reports.

Ed25519 from Node's own crypto: small keys, small signatures, no dependencies,
and no parameters to get wrong.

## A peer is admitted into a profile

**Decided.** `trusted` by default, and it grants hailing and directory access —
not everything.

Admission is not one thing. "I know this machine exists" and "this machine may
use my services" are different grants, and collapsing them makes every peer you
can name a peer that can act. Relaying in particular spends this machine's
bandwidth and exposure on someone else's traffic; enrolment changes how it is
reachable. Both are decisions, not consequences of being known.

An unknown profile name resolves to `trusted` rather than to nothing. Failing
shut would mean a peer that silently stops working after a config edit or a
version bump — a failure indistinguishable from a network problem, which is the
worst way for this to break.

## Profiles are an ordered list, with `trusted` pinned

**Decided.** Profiles are offered pinned-first then alphabetically, `trusted`
pinned by default, and the pinning is the user's to change. Users may define
their own profiles alongside the built-ins.

Pinning grants nothing. It is worth thinking about anyway, because **whatever is
at the top of a list is what gets chosen by someone moving quickly**. Pin the
profile that should apply without thought — and be wary of pinning a permissive
one, since the risk is not that pinning confers power but that it decides what
people pick. `trusted` is pinned because it is the honest answer nearly every
time: these are your own machines.

The rest sort alphabetically so the order does not shift as profiles are added,
which would move the target under someone's cursor between releases.

An override records only what the user changed. Repinning `trusted` does not
copy what it grants, so a later version that narrows it still reaches everyone
who merely moved it up the list — the alternative is a security change that
silently skips the users who customised anything.

## A peer's profile is decided, not just assigned

**Decided.** Four sources, in a fixed order:

1. **Blocked** — denied everything, whatever else says otherwise.
2. **Assigned** — a profile a person chose for this peer.
3. **Derived** — what the trust model concludes, for peers nobody assigned.
4. **Unknown** — the default for peers we hold no opinion about.

Deny is checked first so blocking never has to out-argue another rule.
Assignment beats derivation because a person deciding should not be quietly
overruled by a heuristic — derivation only fills a silence. The decision carries
its reason, since "why can this machine do that" is the question asked once
something has already gone wrong, and reconstructing it from four sources
afterwards is how authorization becomes folklore.

**Blocking matches on the key.** A name is a label a peer chooses, so blocking
one is defeated by picking another. Where no key is held the name is all there
is, and the CLI says so rather than implying a protection it cannot give.

**Trust models decide only the silence.** `direct` is the default and answers
"nothing" for anyone unassigned, which is the honest answer for a network nobody
can join freely — and that is usually what this is.

The interface is pluggable; the shipped example is not a design. `vouch-sketch`
counts vouches, and counting vouches counts identities: two colluding peers meet
any threshold on a network anyone can join, which is the Sybil problem in one
line. It is named and described as experimental so nobody mistakes it for
something to rely on.

A real model needs something identities cannot be minted around. Freenet's
answer is instructive — vouching *or* solving a puzzle, the second being what an
open network needs and the first sufficing for a closed one. That is a design,
not a parameter, and deliberately not attempted here: it is too early to pick
one, and shipping a weak one under a confident name is worse than shipping
none.

**Unknown is a real profile, not a special case.** It grants nothing by default,
and a fabric that wants to answer strangers can grant it something without the
code growing a branch for it.

## A refusal answers, unless you say otherwise

**Decided.** `deny` is the default rejection style, configurable per profile,
with `blocked` set to `drop`.

Silence is a bad default for a refusal. The peer on the other end is usually
your own machine, and its operator is usually you — a refusal nobody can see
gets debugged as a network fault, at length, in the wrong place. Answering costs
little in a fabric whose peers already know each other exists.

What the answer must not do is say *which* rule refused. Unknown peer, bad
signature, wrong key, missing capability and blocked all return the same
`denied`, or the reply becomes an oracle for working out which one to attack.
The real reason goes to this machine's log, where the person who needs it is.

`blocked` drops instead, because a peer you blocked is one you have already
decided to stop talking to, and a reply is something it can act on.

Note what `drop` does not achieve. The connection was accepted before the
decision was made, so it hides the refusal rather than this machine. Being
genuinely unfindable means refusing before accepting, which needs a transport
that can — the argument for UDP in the covert-mode design.

## Diagnostics need two keys, and the window closes itself

**Decided.** A `diagnostics` capability, answered only when the caller holds it
*and* this node is inside a debug window an operator opened. The window expires
on its own.

This endpoint answers the question every other refusal deliberately refuses:
which rule turned you away. That oracle is worth having — without it an operator
sees `denied` and guesses, usually from the wrong machine — and it is worth
locking twice, because either lock alone rots. A grant left on a peer would
answer forever. A mode with no grant would answer anyone. Both together mean a
deliberate act on this machine *and* a decision already made about that peer.

The window expires because a debug mode nobody remembers to turn off is a
permanent one, and this one is permanent in the worst way: quiet, and only
interesting to somebody else.

`diagnostics` is not in `trusted`. Most peers you trust have no business asking
why others were refused, so it lives in `operator` — the machine you debug from.

Refusals are recorded whether or not the window is open, since the useful
question is "why did that fail a minute ago", asked after the failure and too
late to have turned recording on. The history is bounded: this is a debugging
aid, not an audit log.

The report carries this node's clock, because a hail refused as stale is usually
two machines disagreeing about the time — invisible from either end until
something says so.

## Everything else is a plugin

**Decided.** The core is a directory, a hello protocol, and who may ask for
what. Tunnels, file transfer and the rest are plugins, loaded by explicit
configuration.

The reason is inheritance. A project embedding this to find its own machines
should not acquire a file-transfer service because somebody else wanted one.
What belongs in the core is what every peer must agree on to talk at all; what
belongs in a plugin is a service some peers offer and others have never heard
of. A peer that does not load the tunnel plugin has no tunnel capability to
grant, and says the same nothing it says to any other request it will not serve.

Tunnels stay a plugin even though they are wanted, because there are many
possible implementations and the core should not pick one.

**A plugin never sees an unauthenticated request.** Every route declares the
capability it requires, and the daemon checks identity and capability before the
handler is reached. A plugin cannot opt out, cannot grant itself a capability,
and cannot be reached by a peer nobody admitted. A route declaring no capability
is refused at load — that is the one mistake this arrangement exists to prevent,
and load time is the last place to catch it.

**A plugin's profiles are suggestions.** Loading one changes what this machine
*can* offer, never who may use it. No peer holds a plugin's profile until
somebody assigns it.

**Loaded by name, never by scanning a directory.** A tool whose job is deciding
who may talk to your machines should not execute code because it appeared on
disk. A plugin that fails to load is reported and skipped rather than fatal: a
broken tunnel must not stop a machine answering hails, which was its job before
any plugin existed.

**Two plugins cannot claim one path.** The conflict is refused rather than
resolved by order, since the winner would otherwise depend on configuration
order — which nobody would think to check.

## The GUI is one file the daemon serves

**Decided.** A single self-contained page on the same loopback address as the
local API. No build step, no framework, no external requests.

A GUI earns its place here for a specific reason rather than convenience: "who
can reach me", "why is that peer refused" and "what did I actually grant" are
awkward to hold in your head and trivial to read from a table. The page shows
each peer's *effective* profile with the reason for it, which is the four-source
precedence made visible.

Loopback, because the page can admit and block. A page that can change who may
talk to your machines has no business being reachable from anywhere else.

Read-mostly on purpose. It offers the actions that are safe to take quickly —
admit, change a profile, block, forget — and each is the same call the CLI
makes. Anything whose consequences deserve thought stays where thought is
easier.

## Writing into T3's peer list, and why it does not

**Not done.** peerhailer hands over an address; it does not write T3's saved
environments.

The mechanism will not support it honestly. T3's saved environments are a
desktop-only registry, and the bearer token in each record is encrypted with
Electron's `safeStorage`, which is backed by the OS keychain. An outside process
cannot produce that blob, so the entry it could write is one without a usable
token — the user still pairs by hand, having gained nothing, while peerhailer
writes an undocumented versioned file that the desktop app may rewrite
underneath it.

What works instead is what T3 already accepts: a pairing URL, or an address to
paste. If the integration is worth tightening later, the right shape is a plugin
on the T3 side reading peerhailer's local API — not this side reaching into
another application's private storage.

## Grants are minted, never stored

**Decided.** A grant is a short-lived signed assertion naming one subject key
and one set of capabilities. It is not kept in the directory, not replicated,
and worthless once it expires.

This completes the rule the directory already follows. Records carry no
credentials, which is right and leaves a gap: sometimes a peer must prove to a
*third* machine that it is allowed something — that `luna` may relay through
`mars`, on `sol`'s say-so — and that machine has never heard of it.

Three properties keep this from becoming a bearer token by accident:

**A grant names its subject by key.** It authorises that machine, not whoever
holds the bytes, and the presenter must sign the request with the key the grant
names. Intercepting one gains nothing.

**A grant cannot widen.** An issuer may only delegate what it holds, checked
twice: at minting, against what the issuer is allowed to pass on, and at
verification, against what the checking machine grants that issuer. Re-minting
may only narrow, and a child cannot outlive its parent.

**A grant expires, and briefly.** Five minutes by default, an hour at most.
Anything long-lived is a credential in all but name, and a credential is the
thing this design keeps refusing to store.

The issuer must also hold `delegate`, which no default profile grants. A peer
that can delegate introduces capability to machines you never admitted —
bounded by what it holds, which is a real bound and still wider than being able
to act itself.

A grant is a way *in*, not merely an extra capability: a peer nobody admitted
can be let through on one, which is the whole point and why the checks above are
where the weight sits.

## The hello protocol is a plugin too

**Decided.** `/hail` and `/diagnostics` are bundled plugins, not core routes.
The core is the directory, identity, profiles, trust and grants — a model, with
no server behaviour of its own.

The point was never modularity for its own sake. It is that **answering is a
service**. A project embedding this to keep track of its own machines should not
begin answering the network because it imported a library, and should not have
to find a switch to turn that off. A host with no plugins loaded serves nothing:
`POST /hail` returns 404 because no plugin claimed that path.

The CLI is opinionated where the library is not. `hail daemon` loads the hello
and diagnostics plugins, because a daemon that answers no hails is not a daemon.
Someone composing their own host loads whichever they want.

Both routes were already capability-gated, which is why this was a move rather
than a redesign: the plugin contract *is* what the core was doing.

**A plugin refuses without deciding how a refusal looks.** Returning `refuse()`
hands the decision back to the host, so a refusal from a plugin is
indistinguishable from any other — a plugin cannot accidentally reveal which
rule turned a caller away.

## peerhailer as a T3 plugin

**Not possible as a drop-in, and worth stating why.** T3 has no plugin system.
Providers are a static array (`BUILT_IN_DRIVERS`) resolved at build time, with
each driver's service requirements satisfied by the runtime layer's type. There
is no runtime loading of code anywhere in it.

So integration means changing T3, which is a fork patch rather than a plugin —
and the right shape for that patch is T3 reading peerhailer's local HTTP API,
writing its own storage through its own code. That keeps the dependency pointing
the way it should: peerhailer knows nothing about T3, and T3 needs only an
address.

## The file arbitrates between writers, not the daemon

**Decided.** Every change locks the directory file, reads it *inside* the lock,
applies the change to what is there, and writes. The daemon does the same, then
adopts the result.

There are two writers by design. The daemon persists what the page did; a person
at a terminal persists what they typed. Both were writing the whole file from
their own copy, so a peer added at the terminal vanished at the daemon's next
save — silently, with nothing to connect the loss to the command that caused it.

The daemon could have been made the sole writer, with the CLI talking to it.
That is rejected because *the daemon is optional*: a tool for reaching machines
that must itself be running before it will answer is one that fails exactly when
it is needed. So the file arbitrates, and both writers cooperate through it.

Locking is an exclusive create, atomic everywhere this runs and needing no
dependency. A lock older than ten seconds is assumed to belong to a process that
died holding it — the alternative is a tool that stays broken until somebody
finds a file they have never heard of.

Reading inside the lock is the part that actually fixes it. Locking alone
prevents interleaved writes and does nothing about a change computed from state
loaded minutes ago, which was the original bug wearing a different hat.

## Stale addresses are kept, and never believed

**Decided.** A peer's routes are bounded per transport rather than only by
recency, and a hail is believed only when the reply is signed by the key held
for that peer.

Two failures pull in opposite directions, and an earlier version had both.

**Evicting by recency alone loses working routes.** A machine that moves between
home and office is reachable at each, alternately and indefinitely. Dropping the
one it is not using right now guarantees a slow rediscovery every time it moves
back — and worse, a laptop that joins many networks accumulates enough LAN
leases to crowd out the overlay address that is the only way to reach it from
anywhere else. So eviction keeps a few routes per transport, and the least
recently useful within a transport goes first.

**Keeping an address is only safe because identity is a key.** A DHCP lease
expires and that address may now be a different machine — one that would answer
a hail perfectly well. Until this was fixed the reply was taken at face value:
the stranger was marked reachable as the peer, its route earned a success, and
the peers it named were merged into the directory. Anyone inheriting an address
could seed names into a neighbour's directory.

The hail reply carries a signed record, and now it is checked against the key
held for that peer. Which is what makes a stale address cost a timeout rather
than a wrong answer — and therefore what makes keeping stale addresses a
reasonable thing to do at all.

**Two orders, not one.** Storage is eviction order and always keeps a route that
has worked above one that has not; dialing order prefers whatever is most likely
to answer *now*, which after a machine moves is an address reported this morning
rather than one that worked last week. Conflating them meant a burst of fresh
reports evicted the only known-good route, which is a worse mistake than trying
a dead address first.

**Lifetime is guessed from what an address is.** A peer that knows its own
network may say `stable` or `dynamic` and is believed, since a false claim only
misorders a dial. Where it says nothing — a phone, or anything that cannot ask
its network what lease it holds — the shape decides: RFC1918 is where DHCP
lives, so a day; overlay transports assign per node and keep it until the node
is removed, so a month; and Tailscale's `100.64/10` is recognised by shape,
since it looks public while behaving like an overlay.

These are guesses, and they are only allowed to reorder. A wrong guess that
reorders costs a timeout; a wrong guess that deletes costs the only route to a
machine.

## What peers share, and how it stays credential-free

Presence alone is inert: the GUI shows machines and addresses with nothing to do
with any of them. A namespace of what each peer *will answer for* is designed in
[shared-namespace.md](shared-namespace.md) — addressed by fingerprint rather
than by position or name, with visibility split from readability so listing a
service and reading it are separate permissions.

The invariant it has to keep is the one grants already state: the directory
holds no credentials. It keeps it by making leaves **offers rather than values**
— reading one is an authorised request answered on demand, never a value that
lands in a record. A stolen directory still tells an attacker only what exists.

Not built, and blocked on whether admitting a candidate grants `trusted`, since
that decides what the default visibility can be.

## Finding peers, and who gets told you exist

Three ways to learn an address, designed in [discovery.md](discovery.md):
someone tells you (`hail add`, works now), a peer you trust tells you (`walk`
plus `INTRODUCE`, works now), or a machine announces itself on the local segment
(a beacon, not built).

Announcing and listening are separate settings, because a laptop in a café wants
to find its home server without telling the café it exists — and each is a list
of interfaces rather than a boolean, since `eth0`, `wlan0`, `tailscale0` and
`docker0` are not one decision. Both default to none.

Accept policy is a third setting and a different kind of thing: it decides
whether we parse a caller's bytes, never what they may do. If being on a network
could confer a capability, joining a café network would hand it to strangers.

Port scanning is deliberately not offered. It is reconnaissance, it trips
intrusion detection, and `nmap` composes with `hail add` for anyone who wants it.

## Two ports, so the firewall means what it says

The control API and the page hold no authentication of their own; their boundary
is that they normally answer only on loopback. `--host 0.0.0.0` removes that
boundary for everything at once, which is why the LAN half of the two-machine
test is deferred: opening a firewall port for hails would also open the endpoint
that admits peers.

The fix is not to filter `/api/*` by socket inside the request handler. That is a
check that can be got wrong, and being wrong once is enough. **Two listeners:**

| Listener | Binds | Serves |
| --- | --- | --- |
| control | `127.0.0.1` | the page, `/api/*` |
| hail | chosen interfaces | `/hail`, plugin routes |

The separation is then enforced by the operating system rather than by a
conditional — the control API is not listening on the external interface, so
there is nothing to reach and nothing to get wrong. A firewall rule admitting the
hail port admits only hails, which is what someone writing that rule believes
they are doing.

It also makes the accept policy in [discovery.md](discovery.md) implementable as
stated: which interfaces answer hails becomes a property of a socket, not a
branch.

**Built.** `hail daemon --hail-on wlan0,tailscale0` opens one listener per
address, serving plugin routes only; the page and `/api/*` stay on loopback.

Two details that were not obvious until it ran. The config names **interfaces,
not addresses**, because the name is the stable half — `wlan0` outlives the
address DHCP gives it, and a daemon bound to yesterday's address answers nothing
while looking healthy. And an address that cannot be bound is logged and
skipped rather than taken as fatal: a laptop whose wifi is not up should still
answer on its tailnet.

Which machine can do what turns out to differ. A WSL2 host has no interface on
the household network at all — only a virtual NAT, a loopback and a tailnet
address — so it cannot host a LAN listener whatever the config says. You cannot
bind an address you do not have.

## Bridging carries introductions, not packets

A machine with more than one listener is *in* more than one network, which is
what makes it a bridge at all — and `RELAY` has existed as a capability, granted
by `carrier`, with nothing implementing it. Two listeners are the missing half.

Three constraints, before any of it is built. Being multi-homed must not imply
willing to carry: binding a second interface cannot quietly enrol a laptop as
transit for other people's traffic. Direction is not expressible as a boolean —
letting a household device reach your tailnet peers is a different act from
letting tailnet peers reach into the household segment. And what crosses should
be **introductions rather than packets**: forwarding traffic is a VPN, and
Tailscale already does that better, while carrying the fact that a peer exists
and how to reach it is `INTRODUCE`, which already exists.

One rule falls out that is easy to forget later: addresses learned on one
listener must not be republished on another. `192.168.1.68` is useless to a
tailnet peer, leaks internal topology, and fills a route list that evicts real
routes to make room.

## The first tunnel plugin carries ACP

Designed in [acp-tunnel.md](acp-tunnel.md). A phone running T3 Code driving an
agent on a machine at home is what this fabric is for, and it replaces something
worse — the T3 token crossing a clipboard that motivated the namespace design.

The payload stays **sealed until it reaches the thing that speaks it**, so
peerhailer never learns what ACP is: it answers *who*, the bridge answers *what*.
That keeps the fabric protocol-agnostic, means a second tunnel needs no second
plugin, and leaves a compromised relay knowing who talked to whom and not what
was said. The cost is one sharp edge — "deliver these bytes to a local process"
is a port forward, so the endpoint is named in local configuration and referenced
by name. A caller says `acp`, never `127.0.0.1:9000`.

The obstacle is shape, not trust: a plugin route is a request that returns JSON,
and ACP needs the agent to originate messages — `session/update` streams, and
`session/request_permission` blocks waiting for an answer. Polling first, because
it needs no change to what a plugin is, and the question worth answering first is
whether a remote peer may drive an agent at all.

A second endpoint follows the same rule: T3 reaching another T3, without the
long-lived token going anywhere. It is minted on request instead — scoped and
expiring, which T3 already supports — so what crosses is a derived credential
worthless a few minutes later, and revocation stays per-peer rather than meaning
"rotate a secret everyone shares".

Terminating the session at the exit, so that nothing token-shaped crosses at all,
is cleaner on paper and was the first answer. It was wrong: T3 authenticates with
a bearer header, a `wsTicket` parameter and a DPoP variant bound to the holder's
key, so an exit attaching its own credential has to be a real T3 client and the
entrance has to be pairable — protocol machinery at both ends, in a design whose
point is that a second endpoint needs no second plugin. A derived credential
keeps the tunnel knowing nothing, which is what everything else here rests on.

That capability does not belong in `trusted`. Driving an agent executes code;
`trusted` means hailing and seeing who we know. It gets its own profile the way
diagnostics got `operator`, and a tunnel opens against a grant rather than a
standing permission, because a session with a lifetime is the closest thing here
to a credential.

## Assignments and grants are different things

Half a review went on an argument that turned out to be terminological. Two
objects had one word:

| | Lives | Expires | Answers |
| --- | --- | --- | --- |
| **assignment** | here, in the directory | optionally | a peer this machine already admitted |
| **grant** | nowhere — it travels | always, in minutes | a peer this machine has *never* admitted |

An assignment is a profile on a peer: visible in `hail peers`, revoked by
`block` or `forget`, and durable by default because re-authorising your own
phone every five minutes is not security, it is friction.

A grant is a signed assertion carried over the wire so a third machine can be
told, by one it trusts, that a stranger is allowed something. It is minted on
demand and stored by nobody. **A non-expiring grant is refused** — at that point
it is an assignment that lives nowhere, appears in no list, and survives
`forget`.

The test for which you want: *does the verifier already know this peer?* If yes,
it is an assignment. Grants exist for exactly the case where it does not.

### Optional expiry belongs on assignments

`--until 7d` raises a peer's profile for a while and then lets it fall back to
what it held before — a temporary raise, not a temporary existence, with the
fallback captured when the raise happens rather than guessed at months later.

This is safer than an expiring grant, and it is worth being precise about why:
**the clock is local.** A grant's expiry is a timestamp one machine writes and
another believes, inheriting every question about skew. An assignment's expiry
is checked by the machine that made the decision, against its own clock, when
the question is asked. Nothing to skew, nothing to trust.

It is resolved on read rather than swept on a timer, because a directory that
only tells the truth while a daemon is running is worse than one that works it
out when asked. And it is shown wherever profiles are — `[operator until
2026-09-01T…]` — since a peer that silently stops working is the same failure as
a key conflict nobody was told about.

The precedent was already here: `hail daemon --debug [minutes]` opens a
diagnostics window that closes itself. This generalises it.

### The gap that made an indefinite grant look necessary

`hail profiles` could pin a profile and set its rejection style, and could not
**define** one. The library took custom profiles; nothing exposed making one, so
"my phone may use the tunnel and nothing else" meant editing the state file by
hand. `hail profiles add <name> --allows a,b` closes it. Ergonomics were pushing
toward the wrong mechanism.

## The control API answers only its own page

Binding to loopback keeps the network out. It does nothing about the browser you
are already running: any page you visit can issue a request to `127.0.0.1`, and
while the reply is unreadable to it, the **effect** lands. Demonstrated rather
than argued — one line of `curl` shaped like a browser's simple request admitted
a peer as `trusted`:

```
curl -X POST -H 'content-type: text/plain' \
  -d '{"name":"csrf-demo","profile":"trusted"}' http://127.0.0.1:7645/api/peers
```

Three checks, none of them authentication. They are the difference between a
local API and an API every website can reach.

**Content type.** Only `application/json` is accepted for anything with a body.
`text/plain`, form encodings and the rest are *simple* request types a page may
send without asking permission first; requiring JSON forces a preflight, and we
answer no preflight, so the request is never sent.

**Origin.** A request carrying an `Origin` that is not this page's own is
refused, reads included. Cross-origin reads were already blocked by the browser
— we send no `Access-Control-Allow-Origin` — but blocking the *reply* still lets
the request run.

**Host.** Only names this daemon actually bound. Origin and Host agreeing proves
nothing: a page at `evil.example` whose DNS answers `127.0.0.1` sends both as
`evil.example`, and a check comparing them to each other calls that same-origin,
after which the browser hands over the reply. Answering only to names we chose
is what closes it.

### The order is part of the rule

The guard runs **above every control route**, and that is a requirement rather
than a tidiness preference:

1. plugin routes — authenticated on their own terms, unaffected
2. **the guard**, for paths this door serves (`/` and `/api/*`)
3. control routes

It was written below `/api/peers` GET first, and reads walked straight past it
while writes were refused — a hole that reads exactly like a working fix. **A
control route added above the guard is unguarded, silently.** A test covers the
read path specifically, so moving the guard back down fails the suite rather
than passing quietly.

It is scoped to paths this door serves so an unknown path still answers "no such
thing" rather than "refused", which tells a stranger less.

### Cross-origin is an allowlist, and empty

`--allow-origin http://localhost:3000` names an origin that may use the control
API, and there is no wildcard. A named origin also receives the CORS headers and
a preflight answer, because an allowlist without them refuses in the browser
while appearing to permit. The default is empty: the page this daemon serves is
same-origin and needs nothing, and a page you did not write has no business
admitting peers.

## The page is surface, and it is optional in principle

Everything above exists because there is a web interface. Without one, this
daemon needs no HTTP server a browser can reach, no control API, and none of the
origin machinery — the boundary would be filesystem permissions on the state
file, which is simpler and far better understood.

What the page costs, stated plainly:

- **A port a browser can reach.** Every page you visit can send it requests. The
  reply is hidden from them; the effect is not. That is the whole CSRF class, and
  it exists only because a browser is in the picture.
- **A surface that keeps moving.** Which request shapes count as "simple", what
  a preflight covers, how `Origin` behaves in edge cases — these are browser
  rules, revised by browser vendors, not by us. A check that is correct today is
  correct until Chromium changes its mind.
- **The page itself as a target.** Script injected into it runs same-origin and
  inherits the control API completely. Everything rendered from a peer's data —
  names, addresses, plugin descriptions — is attacker-influenced text.
- **A second implementation of every rule.** Capability changes have to land in
  the CLI and the page. This session added key-conflict warnings and elevation
  expiry to the CLI and forgot the page until it was asked about.

None of that argues for deleting it. Seeing the fabric is genuinely worth
something, and the tree makes rules visible that prose does not — most people
will reach for it over the CLI, and that is a reason to keep it good rather than
a reason to serve it always.

So it is **opt-in**: `hail daemon --ui`. The control listener exists *only* for
the page — the CLI reads the state file directly and never speaks HTTP — so
without it there is no port a browser can reach at all, rather than a port
serving 404s. A headless daemon carries none of this surface.

Opt-in, and **said out loud**. A daemon started without it prints where the page
would be and how to ask for it, because a safe default that hides the feature
only produces people who cannot find it.

### The T3 plugin does not have to open a second one

Making peerhailer a T3 plugin looks like it re-introduces everything above. It
need not, and the difference is whether T3 embeds the *library* or talks to the
*daemon*.

Embedded, there is no HTTP at all: T3's server is Node, this package has no
dependencies, and `createDirectory` is an import. The test named *"a host with no
plugins serves no protocol"* exists for exactly this — the split between the
directory and the daemon is what makes embedding open nothing.

Talking to a running daemon is the other shape, and it costs a port plus a
cross-origin consumer. That is what the `--allow-origin` allowlist is for, and it
is a worse position than embedding: the same three checks, plus a second process
to keep running, for a machine T3 is already on.

Either way the *plugin's own* interface is T3's surface rather than this
project's — rendered in a webview T3 sandboxes, on T3's origin, under whatever
trust levels its plugin manager settles on. Which is the right place for it: T3
already had to solve showing a page safely, and solving it twice differently is
how the two disagree later.

### Would Electron help?

Partly, and less than it looks.

**The real win is dropping HTTP entirely.** An Electron renderer talks to its
main process over IPC, not a socket. No port, no `Origin`, no preflight, no DNS
rebinding — the entire class of problem above stops existing, rather than being
defended against. That is a categorical improvement over getting three checks
right and keeping them right.

**The costs are not small.** It bundles Chromium, which is a far larger attack
surface than anything here and must be kept current — a stale Electron is a
stale browser. It would take a project with **zero dependencies**, which runs on
an old PuppyLinux box, and give it one of the largest in software. And Electron
misconfigured is worse than a loopback server: `nodeIntegration` with remote
content is remote code execution, not information disclosure.

**And it does not answer the case that motivated all of this.** The point of
this fabric is reaching a machine from a phone. An Electron app is a desktop
window; the moment you want the interface remotely you are serving over a
network again, and back to needing tokens, origins and the rest. Electron
removes the browser problem for people sitting at the machine, which is the case
that already had the safest answer available — the CLI.

The middle option, if the page is ever wanted beyond loopback, is a token in the
URL the way T3 Code pairs a browser: it authenticates the page rather than
trusting its position, and it works remotely. That is a bigger decision than a
flag, and it is not needed while the page is local and optional.

## The same peer, two paths, two answers

A capability is a property of a peer today: `luna` holds `tunnel:acp`, so `luna`
may drive the agent from anywhere over anything. That is not what an operator
means — the same machine reached over a tailnet and over a café LAN is not
equally trustworthy, because the risk is who else is on the wire rather than who
is at the far end.

Designed in [network-trust.md](network-trust.md), and the whole thing turns on
one distinction: **a machine knows which of its own listeners received a
connection, and is merely told everything else.** Since `--hail-on` already opens
one listener per address, labelling those listeners makes the check a lookup —
and a TCP connection's arrival interface cannot change mid-life, so checking once
is checking for good.

Two richer shapes were considered and rejected. Rules travelling with the traffic
— firewall rules riding along and stopping at any boundary that violates them —
are enforced by whoever handles the traffic, which is precisely the hop you are
worried about; they protect against accident and never against intent. Validating
the whole path asks intermediate hops how trustworthy they are, and a compromised
one answers whatever helps. The only path facts worth anything already have
cryptography behind them: the origin signature, and whether the immediate peer
differs from it.

The label is **encrypted**, not *trusted*. "Trusted" is a judgement about who
else is on a segment — unfalsifiable and prone to drift. "Encrypted" is a claim
about the link, it is the property that matters for a protocol that is signed and
not encrypted, and it becomes true by configuring something rather than by
deciding something.

The stronger argument for making it a default is not confidentiality but
**downgrade**. Encryption never protected availability: a node on the path can
drop and delay without reading anything. Routes sort by what has worked, so an
attacker who blocks the encrypted path does not merely deny service — the peer
falls back to the path that still answers, which is the one they can read.
Requiring an encrypted arrival means the fallback carries hails and refuses
tunnels, so denial cannot be converted into interception.

So a tunnel runs over a tailnet or a pinned-TLS link. Over Tailscale the
encryption is WireGuard's; `--hail-on-tls` makes peerhailer terminate its own
pinned mutual TLS so a direct peer-to-peer wire qualifies too — not extra safety
on top of what works, but what makes the fabric work off the tailnet at all. It
is built (see [tls.md](tls.md)). Nothing was re-judged when it landed; a
listener's posture is how it was bound, and the capability follows.

## A chat plugin, and the danger of an unauthenticated one

Designed in full in [chat.md](chat.md); the reasoning is summarised here.

Not presence and not discovery, so a plugin — which is what plugins are for, and
it keeps anyone who does not want a chat from having one. **Memory only**: a
message dies with the process, nothing reaches the directory file, and the
credential-free invariant survives contact with a feature whose obvious use is
passing a pairing URL to somebody.

The proposed second half is where the care goes: piping an **arbitrary
connection** into the chat, labelled by its source address rather than by a peer
name, for talking to something that is not a peer.

### Why that combination is a phishing surface

Three things we have already discussed, put together: a chat, senders nobody
authenticated, and the habit of passing pairing URLs through it. An unauthenticated
sender writes *"here is your pairing URL"*, and a person pastes it into T3. The
five-minute TTL does not help; the human does the work. This is the one place in
the design where the payload and the channel make each other worse.

So, if it exists at all:

- **Off by default**, and a separate setting from the chat capability itself.
- **Never rendered as a peer.** An address, visibly distinct, never resolved to a
  name — a name is what makes a message look vouched for.
- **Never actionable.** No clickable links and nothing that shortens the path
  from an unauthenticated message to a redeemed credential.
- Probably a **separate inbox** rather than a label in the same view. A label on
  a busy screen is a thing people stop seeing; a different place is not.

The reservation is narrow rather than fatal: the feature is useful exactly when
you cannot authenticate the other end, which is exactly when you cannot tell a
stranger from the machine you were expecting.

### Source lists bound reachability, not identity

Allow and deny lists in the manner of iptables are the right instinct and the
right size. Two things to be clear about.

**They are the weaker of two options where both exist.** The operating system
already has a firewall, better tested than anything here, and the listener
machinery already binds per interface — so on Linux the honest answer is a
firewall rule plus a bound address. An app-level list earns its place on Windows,
where there is no `iptables` to lean on, and for visibility: a list the GUI can
show is a list someone will read.

**And they say where, never who.** A rule about `192.168.1.0/24` is a rule about
whatever holds those addresses today. It reduces "anyone" to "anyone in the
house", which is worth having and is not authentication.

If built: **CIDR, never string patterns** — `192.168.1.*` also matches
`192.168.10.5` and has nothing to say about IPv6. Deny checked before allow, and
default deny, so an empty configuration admits nobody rather than everybody.

## A node can mint T3 credentials without being a T3 plugin

The one case Tailscale and `t3 pair` do not cover is the unattended one: a
machine asking another machine for access with nobody at either keyboard.
Everything else — short-lived tokens, QR delivery, `--tailscale` pairing — assumes
a person is present to run a command and move the output.

A peerhailer node closes it by running the command itself. Designed in
[commands.md](commands.md), as a sibling of the tunnel plugin: a tunnel exposes a
local *service*, a declared command exposes a local *command*.

The rule that makes it safe is the tunnel's rule. **The operator declares the
command and the caller names it** — `hail commands add pair "t3 pair --ttl 5m"`,
and a peer may ask for `pair` and nothing else. No caller-supplied arguments in
any form, because a caller-supplied TTL is a number until somebody passes
`5m; rm -rf ~`, and validating it is the defence this project has already refused
for shell commands and for URL prefixes. If a command must vary, declare two.

One capability per command, none granted by anything built in. And said plainly:
this is a remote execution primitive narrowed by declaration, comparable to the
tunnel rather than to anything smaller — with the first declared command being
one whose **output is a bearer credential**, so holding `command:pair` means *may
obtain control of my T3*.

It also removes the last reason to wait for a plugin system: the credential path
needs no T3 plugin, because the CLI is already an interface.

## The operator chooses the surface

Worth stating as a principle, because it is the point of the plugin architecture
rather than a side effect. Everything is off until turned on: a capability is
granted and never inherited, a plugin is loaded and never assumed, the page and
the chat and each tunnel endpoint are separate opt-ins. So **the attack surface
is exactly what the operator chose, and nothing more** — a headless relay has no
inbox, a machine that declares no command cannot run one, and `tunnel:acp` says
nothing about `service:agent`. Nobody carries a feature they did not ask for,
which means nobody carries its risk.

## A third plugin shape: services

Tunnels connect to something already listening; commands run and finish. Neither
can *start a thing that keeps running* — which is what spawning `bridge --listen`
on a remote machine, so a peer can drive an agent there, requires. Designed in
[services.md](services.md): the operator declares the service, the caller names
it, the machine picks the port and returns it, and reaching it is a tunnel.

It is the top of the danger ladder — `service:agent` starts a process that runs
arbitrary commands, unattended, which is more than any fixed dangerous capability
does. So its own capability, an encrypted arrival without exception, per-peer
bounds, and a life tied to the peer that started it. The last, most dangerous,
and most deliberately-granted thing the fabric can offer.

## TLS pinned to the peer's key

Designed in [tls.md](tls.md). The thing that makes an encrypted arrival possible
without Tailscale — a direct peer-to-peer wire the tunnels can run on. The one
rule shapes it: no hand-rolled cipher, because that would be the most dangerous
code in a project whose safety is that it is small enough to read. Node's `tls`
does the crypto; this project writes only the *pinning* — a self-signed cert
carrying the peer's existing Ed25519 identity key, verified by comparing its key
to the one the directory holds, the same check every hail already makes. Not a
CA, not the web PKI, and not trust-on-first-use: the key is pinned before the
connection, from the directory, and a cert whose key we do not already hold is
refused rather than remembered.

## A shell plugin is the top of the ladder

Designed in [shell.md](shell.md), and framed there without softening: an
interactive PTY a peer can open is remote shell access — SSH through the fabric.
It is the one plugin that cannot hold the rule every other one does (nothing a
caller sends reaches a shell), because letting a peer choose what runs is its
entire purpose. So it gets its own capability in no built-in profile, an
encrypted arrival without exception, an always-on recorded session, and bounds —
and it deliberately screens nothing, because deciding security by parsing shell
input is the mistake this project already refused twice. The narrower answer is a
`command:` for the specific thing; `shell` is for when you actually mean a
terminal, and it is the natural place the supervisor should be requireable.

