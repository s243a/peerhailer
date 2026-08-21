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
