# File backends: what ships, what doesn't, and why

**Status: decision record.** The files plugin (`docs/files.md`) serves a share
through a **backend** — where the bytes actually live. Two ship: `local` and
`http`. This document records the backends we considered and left out, the case
for and against each, why the line falls where it does, and a mitigation —
**optional, opt-in builds** — for the operators the line excludes. It is written to
be argued with, and to be reviewed alongside the implementation.

## The rule the line is drawn against

peerhailer is a **security fabric**, not an application. The daemon holds the
identity private key, the grants store, and a loopback control port that mints
grants, rotates keys, and reloads plugins. Anything in that process runs with that
authority, and so does everything in its dependency tree.

That is why the project is **zero-dependency**, and the reason matters here more
than anywhere else in the codebase, because a file backend is the one component
whose job is to **parse bytes chosen by someone else**:

- **Supply chain is the main attack surface.** A single compromised, typo-squatted,
  or abandoned-then-hijacked transitive package sits next to the identity key. Zero
  deps means the entire trusted computing base is this repository — auditable in one
  place, by anyone, including the many people who run forks.
- **Longevity and reach.** The daemon runs headless on minimal boxes — a phone
  under Termux, a PuppyLinux node, a small VPS — for a long time. No native builds,
  nothing in `node_modules` to rot across the years a fabric is meant to keep
  running.
- **The blast radius is total.** A tunnel plugin that mis-parses input leaks a
  tunnel. A file backend that mis-parses input runs code next to the key. The two
  are not the same risk, and the second one is the one a dependency brings.

So the test for a backend is not "is it useful" — SMB is extremely useful — but
"can it be carried without expanding that trusted computing base." That is a high
bar on purpose, and it is worth saying plainly that **it excludes things people
genuinely want**. The rest of this document is honest about that cost.

## The backends, one at a time

### `local` — ships

A directory subtree on this machine. Native `fs`, no parsing of a wire protocol,
and the whole security story is containment: a caller path is resolved *inside* the
root and re-checked against the realpath'd root, so `..`, an absolute path, a drive
letter, `~`, or an escaping symlink is refused, not clamped. This is the 90% case
and it carries no dependency and no new attack surface. Nothing to argue.

### `http(s)` — ships

Fronts a URL store this machine reaches by address, using the platform `fetch`. No
dependency (fetch is in the runtime), and it is the natural way to expose an
internal artifact store, object bucket over a signed URL, or a small static file
server to a peer without that store trusting the peer. Its only real limit is that
plain HTTP has no directory listing, so `list` is unsupported and says so. An
**S3/object-storage** backend and a **remote-WebDAV** backend are both variations
of this one — `fetch` with a different request shape — and would ship on the same
terms if a use case pulled them in. They are *not* rejected; they are simply
unwritten.

### `ftp` — deferred, not rejected

**For.** FTP is old, ubiquitous on NAS boxes and lab equipment, and — critically —
**implementable in raw `node:net` sockets** in ~150 lines. It stays inside the
zero-dependency rule. It is the obvious next backend.

**Against.** It is not free of concerns, just free of *dependencies*. Plain FTP is
cleartext, so a share fronting it leaks the upstream credentials and data on the
LAN between this machine and the server — which is only acceptable because that hop
is the operator's own network, and the peer-facing hop is still the fabric's
encrypted arrival. FTP's control/data split (PASV vs active, binary vs ASCII mode,
multi-line reply codes) is fiddly to get right, and getting it *wrong* in a parser
is exactly the risk the zero-dep rule exists to bound — so a hand-rolled FTP client
must be written defensively and tested against a real server, not waved through.
**FTPS** (FTP-over-TLS) is doable with `node:tls` and no dependency; plain SFTP is
not (see below).

**Decision.** Addable, zero-dep, when someone needs it — and when it can be given
the test harness a byte parser deserves. Left out of the first cut only to avoid
shipping a shaky protocol implementation ahead of a real user.

### `smb` — rejected by default

**For.** SMB/CIFS is what a huge number of real file stores actually speak — every
Windows share, most NAS appliances, corporate file servers. A share that fronted
SMB would let a peer reach the files people already have, and the OS mounts SMB
trivially. The utility is not in question.

**Against.** There is **no native SMB in Node**, so this needs a third-party client
library, and SMB is close to the worst case for the zero-dep rule: a **complex
binary protocol** (SMB1/2/3, dialect negotiation, NTLM/Kerberos auth), a long and
active **CVE history** across implementations, and client libraries that are heavy
and sometimes carry **native bindings** (which reintroduce the build-and-rot
problem on the minimal boxes the fabric targets). It would parse attacker- or
server-influenced bytes with the daemon's full authority — the precise combination
the rule is meant to keep out of the default build.

**Decision.** Excluded from the default build. The utility is real and the cost is
real; the mitigation below is how an operator who needs it opts in without imposing
that cost on everyone else.

### `sftp` — rejected by default

**For.** Secure by default, universal wherever SSH is, and the thing many people
*mean* when they say "just copy the file over."

**Against.** SFTP is a subsystem of SSH, so a client needs a **full SSH/crypto
stack** — key exchange, ciphers, host-key handling — none of it in the Node
runtime. That is a large dependency doing cryptography next to the identity key,
which is a strictly worse thing to get from a package than a plain byte parser.

**Decision.** Excluded from the default build, same as SMB, for a heavier reason.
Note that a share fronting SFTP is *different* from reaching the peer over SSH: here
**this machine** is the SSH client to some upstream, and the peer never sees it.

### FUSE (a real filesystem mount) — out of scope

Worth naming because it is adjacent to the mount mode. A true kernel mount (so
external tools see real files, not a WebDAV URL) needs a FUSE binding — a native
dependency — so it is out under the same rule. The mount mode uses **WebDAV**
precisely because it is HTTP: zero-dependency, and every OS mounts it natively. See
`docs/files.md`.

## The tension, stated without flinching

Drawing the line at zero-dependency means **peerhailer cannot, by default, front
the file stores a large fraction of people actually have** — the Windows share, the
NAS, the SFTP box. "Use Tailscale and mount it yourself" is a real answer for
machines you own, and a poor one for the case the fabric is *for*: reaching across
an admitted-peer boundary that is not a shared tailnet. So the exclusion has a cost,
and pretending the zero-dep rule is free would be dishonest. The question is not
whether to pay it but **who pays it, and when** — and that is what the mitigation is
about.

## Mitigations, best first

This section was rewritten after a review round (see the note at the end): the
first draft reached for npm optional dependencies, which turn out not to be opt-in
at all. Two better answers came out of that, and the honest correction is kept
below so the mistake is visible.

The invariant worth protecting is not "no operator ever reaches an SMB store." It
is that **the default, shipped, audited fabric is zero-dependency**, and anyone who
leaves that posture does so **deliberately, visibly, and only for themselves**.

### 1. Shell out to system binaries — preferred for SMB and SFTP

Spawn the tools the operating system already ships and maintains — `sftp`/`ssh`,
`rsync`, `smbclient`, or a `sshfs`/`mount` for the mount mode — as **child
processes**. The crypto and the protocol parsing stay inside OS-maintained
binaries, in *their* address space, not the daemon's. A backend `get` becomes an
`smbclient -c "get …"`; a `put`, a `put`.

Why this is the strongest answer for exactly the protocols this doc agonises over:

- **The identity key is never in the blast radius.** A vulnerability in the SMB or
  SSH parser is a vulnerability in a *child* with a constrained view (the share
  path, the upstream credential), not in the process holding the key, the grants
  store, and the control port. That is a categorically smaller risk than importing
  the same parser into the daemon's address space.
- **The in-process zero-dep rule holds unbroken.** Nothing is added to
  `node_modules`; the audit statement is still "this repo."
- **It is the idiomatic peerhailer move.** The project already spawns shells,
  services, and composer children, with the group-kill and scrubbed-environment
  discipline in `docs/shell.md`. A shell-out backend inherits that discipline
  rather than inventing a new trust mechanism.

The cost is honest and bounded: the binary must be present. On a minimal box it may
not be — but that is a **deployment error message** (`smbclient not found; install
it or use a different backend`), not an expansion of the trusted computing base. A
missing binary fails a share; a bad dependency compromises a key.

### 2. A third-party plugin package, via the loader that already exists

For a backend that is genuinely pure JavaScript (an object-store SDK, say), the
opt-in is **not** a build flag — it is peerhailer's existing plugin loader.
`hail plugins add <module>` already loads a module-specifier plugin at startup
(`loadPlugins(stored.plugins)`), and a backend adapter is just a plugin that
registers a backend. This is the only honest form of "opt-in dependency":

- Installing it is a **distinct act** the operator performs, not a side effect of
  `npm install peerhailer`.
- The trust boundary is **structurally visible**: `hail plugins` lists exactly the
  third-party code that will run. An auditor reads that list, not a lockfile diff.
- It reuses a mechanism the project already vouches for, instead of inventing an
  "optional build" the project would have to reason about separately.

### Consent binds to the config, not to what happens to be installed

With either mitigation, a share that names `backend: smb` must **refuse to serve
until an explicit acknowledgement is set** — a `--i-accept-external-backends` flag,
or a one-time confirmation written to state. A library or binary merely being
*present* (a polluted `node_modules`, another tool's dependency, a base image that
ships `smbclient`) is not the operator consenting to expand this daemon's reach.
Availability is not consent; the config plus an explicit acknowledgement is.

### Why not npm optional or peer dependencies (the corrected mistake)

The first draft proposed `optionalDependencies`. That is wrong: `npm install` pulls
`optionalDependencies` **by default** — only `--omit=optional` skips them — and
npm ≥7 auto-installs `peerDependencies` as well. Either would make "the default
install is zero-dep" **false in practice** for most users, which defeats the entire
point. A dependency you have to *actively avoid* is not opt-in. Only a separately
installed package (2) or an external binary (1) is.

### Vouch for the loader, never the adapter

The distinction that keeps the audit story true: the project vouches for the
**loading mechanism** and for *this repository*, never for a third-party adapter.
Adapters live in their own repositories with their own audit statements; the
quickstart never imports one. With the plugin-package form (2) this is automatic —
the daemon's TCB statement stays "this repo," and `hail plugins` is where an
operator sees what they added on top.

## What none of these do

- **Not** bundling an SMB library in the default build behind a runtime flag. A flag
  that flips on code already in `node_modules` has already paid the supply-chain
  cost — the dependency is present whether or not the flag is set.
- **Not** "just `npm install` the library and it works" with no acknowledgement and
  no log. Silent expansion of the TCB is the failure mode; the visibility and the
  config-bound consent above are load-bearing, not decoration.
- **Not** shipping a hand-rolled `ftp` parser without the test bar below. Zero
  dependencies is not zero attack surface.

## The bar an in-process FTP backend must clear

FTP is the one protocol we would implement in-process, so it must be held to the
standard the rest of this doc implies for byte parsers:

- **PASV only**, no active mode (no inbound connection the daemon must accept).
- A **strict reply state machine** — no regex-parsing of multi-line reply codes.
- **Bounded line lengths** and a bounded overall transfer, like every other channel
  here.
- A **fuzz harness** feeding truncated and adversarial replies, and **CI against a
  real server** (e.g. `pyftpdlib`).
- **FTPS** (over `node:tls`) for anything crossing an untrusted hop; plain FTP only
  on a network the operator already owns.

If a backend cannot carry that harness, it does not ship — which is simply this
document's own deferral reasoning, applied consistently to our own code.

## The mount mode does not change the calculus

It is tempting to argue that because the WebDAV mount already exposes a share to
every local process, the marginal trust of an SMB *backend* is small. That is a
rationalisation, and it conflates two different axes:

- A **mount** exposes *already-shared bytes* to local processes — a **data-exposure**
  axis the operator explicitly chose by mounting.
- An **in-process SMB backend** imports *new parsing code* into the **key-holding
  process** — a **daemon-integrity** axis.

The second is not a larger amount of the first; it is a different and worse kind of
risk. A mount cannot leak the identity key. A compromised in-process parser can.
The mount changes nothing about whether SMB belongs in the daemon's address space —
and the answer stays no, which is why mitigation (1) puts it in a child instead.

## Provenance

The first version of this document argued for optional builds via npm
`optionalDependencies`. A review (Kimi, round G) showed that those are installed by
default and so are not opt-in, and surfaced the two mitigations above — shelling out
to system binaries, and the existing plugin-package loader — as the honest answers.
This version supersedes the first; the mistake is left described rather than deleted
because the reasoning that corrected it is the useful part.
