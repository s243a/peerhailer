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

## Mitigation: optional, opt-in builds

The invariant worth protecting is not "no operator ever runs an SMB client." It is
"**the default, shipped, audited fabric is zero-dependency**, and anyone who leaves
that posture does so **deliberately, visibly, and only for themselves**." Optional
build parameters give exactly that.

The shape:

1. **The default install pulls nothing.** `npx`/`npm install` of peerhailer has an
   empty (or `local`+`http`-only) dependency set. The promise — auditable TCB, no
   native builds, runs on a phone — holds for everyone who does nothing.

2. **Dependency-backed backends are opt-in, and self-declaring.** An SMB or SFTP
   backend lives behind an **optional dependency** the operator installs on purpose
   (`optionalDependencies`, a `peerDependency` they add, or a dropped-in plugin
   package). The backend adapter loads its library through a **guarded dynamic
   `import()`**: present → the backend registers; absent → declaring
   `hail shares add <name> --backend smb …` fails with a clear message naming the
   package to install and the trust it costs. Nothing is bundled; nothing loads
   unless an operator asked for it.

3. **The registry already supports it.** `filesPlugin`'s backend map is a small
   interface (`supports`, `list`, `get`, `put`). An optional backend is a new entry
   registered at startup when its dependency resolves — additive, not a fork of the
   plugin.

4. **The trust becomes visible, not silent.** A daemon built with an optional
   backend **says so at startup** (`[share] repo — smb (optional backend; adds
   <pkg> to this daemon's trusted code)`) and in `hail status`, so the expanded TCB
   is a fact the operator sees every run, not a footgun buried in a config file. An
   auditor can tell a zero-dep daemon from an SMB-enabled one at a glance.

5. **The audit story survives.** Because the default artifact is unchanged, "read
   the whole repo" is still true for the fabric everyone else runs. The opt-in is a
   per-operator, logged decision about *their* box — which is the correct place for
   a trust trade to live.

A rough sketch, to be argued with, not adopted as written:

```js
// filesPlugin backend registry — optional backends load only if present.
async function loadOptionalBackend(kind) {
  try {
    const mod = await import(OPTIONAL_BACKENDS[kind]); // e.g. a peer/optional dep
    return mod.createBackend;
  } catch {
    return null; // not installed → backend simply not offered
  }
}
```

```jsonc
// package.json — nothing here is installed by a default `npm install --omit=optional`
"optionalDependencies": {
  // present ONLY to document the contract; the operator opts in explicitly.
}
```

## What this mitigation is *not*

- **Not** bundling an SMB library in the default build behind a runtime flag. A
  flag that flips on code already in `node_modules` has already paid the supply-chain
  cost — the dependency is present whether or not the flag is set. The point is that
  the default install *does not have it*.
- **Not** "just `npm install` the library and it works" with no guard and no log.
  Silent expansion of the TCB is the failure mode; the visibility in (4) is load-
  bearing, not decoration.
- **Not** a promise that the optional backends will be written by this project. The
  contract is the interface and the opt-in mechanism; who writes and audits an SMB
  adapter is itself a trust decision an operator makes.

## Questions for review

Written down so a reviewer attacks the design, not just the prose:

1. **Does an optional dependency actually reduce risk, or move it?** If a common
   installer pulls `optionalDependencies` anyway, the "default is zero-dep" claim is
   false for those users. Is a separate package / explicit `peerDependency` the only
   honest form of "opt-in"?
2. **Is a startup log enough signal?** Should an optional backend require a second,
   louder acknowledgement (a `--i-accept-the-dependency` flag, a one-time confirmation
   written to state) before it will serve?
3. **Where is the optional backend audited?** The interface is small, but the
   library behind it is not. Does the project vouch for specific adapters, or only
   for the loading mechanism — and how is that distinction made visible?
4. **Is FTP's hand-rolled parser a hidden version of the same risk?** Zero
   dependencies is not zero attack surface; a bespoke FTP client is new byte-parsing
   code in the trusted process. What test bar clears it?
5. **Does the mount mode change the calculus?** A WebDAV mount already exposes a
   share to every local process; if an operator will run a mount anyway, is the
   marginal trust of an SMB *backend* smaller than it looks — or is that a rationalisation?
