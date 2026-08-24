# Binding a hail to its target

**Status: built.** The contract change shipped with the TLS work, as the design
below recommended (both want "address, key, and now `to`, all from one signed
record read once"). What landed:

- **`to` in the signed hail.** `hailBody` signs `from = {name, at, to}` where
  `to = fingerprint(target.publicKey)`, read from the same record the address
  came from (`callPeer`). Absent only for a keyless target.
- **The verifier** (`identify` in `server.js`) refuses a hail whose present `to`
  is not our fingerprint — always, so a captured hail is inert off-target the
  moment both sides speak v1, with no migration step.
- **Mandatory on grant, day one.** A grant-bearing hail with no `to` is refused
  outright: a grant-presenter carries no record to advertise support from, so
  there is nothing to migrate.
- **The signed, sticky support signal.** A peer advertises `v` in its signed
  self-record (`TARGET_BINDING_VERSION`); a verifier records it monotone by
  `max` (`directory.noteBinding`, kept through `keepOurs`, set on a verified
  `walk` reply), and refuses a `to`-less hail from any caller it knows binds —
  the downgrade guard.
- **The flag day.** `createDaemon({requireTargetBinding: true})` refuses every
  `to`-less hail — the fully-closed state, for a fleet that has finished moving.

What was **not** built: the cheaper `callPeer` provenance-plus-shape interim
(below). Target-binding is the strictly stronger guarantee — it makes the
credential meaningless off-target rather than merely hard to misdeliver — so the
interim is left as documented composable defence-in-depth, not a shipped path.

The design below is kept as the record of why each choice is what it is.

## The leak

A hail authenticates *who* is calling: `from = {name, at}`, signed, and the
receiver verifies that signature against the key it holds for `name`. It does not
say *whom the caller meant to reach*. So the same signed bytes authenticate the
caller at **any** peerhailer that holds their key — not just the one they dialed.

`callPeer` makes that reachable. It dials the addresses in a peer record, in
`orderForDialing` order, and sends the signed hail to the first that answers. The
addresses are self-reported by the peer, gossiped through `walk`, or typed by an
operator — none vetted. A peer whose record carries `http://169.254.169.254/`, an
internal IP, or an attacker's box receives a **valid, fresh, signed** hail, and
can replay it — for the freshness window (`FRESHNESS_MS`, 5 minutes) — against any
peerhailer that knows the caller, acting as the caller there, for whatever that
peer's profile grants the caller.

It is bounded: the operator chose to call that peer, the signature only unlocks
what the caller's profile already allows at the replay target, and the window is
short. But it is the credential-leak shape this project refuses everywhere else —
signed identity material flowing to an address the party being called chose. The
shell env-scrub, the tunnel self-port guard, and the `command:` no-interpolation
rule are all the same instinct; this is the one place it is not yet applied.

## The fix, in one line

Sign the **target** into the payload, and reject a hail whose target is not us.
`from = {name, at, to}`; the receiver checks `to` against its own identity and
refuses otherwise. A captured hail then names the peer it was for, so a replay to
any other peer fails verification. The credential stops being bearer.

## What `to` is: the key, never the name

The obvious `to` is the target's name. It is the wrong choice, for a reason this
project already knows: **names are mutable** (`hail rotate` aside, `hail name`
renames a machine), so "is this hail addressed to me" would rest on a string a
peer can change, and a receiver that was renamed mid-window would reject hails
correctly addressed to its old name — or, worse, a design that tolerates that
slack reopens the gap.

`to` is the target's **public-key fingerprint** — `fingerprint(theirKey)`, the
compact stable form the caller already holds from the directory (it is what the
caller pins to). The receiver computes `fingerprint(self.publicKey)` and compares.
The key is the identity; the name is a label on it. Binding to the key means:

- a rename never affects addressing — the fingerprint is unchanged;
- the caller already has the value (it read the record to get the address), so
  nothing new is exchanged;
- `hail rotate`, which *does* change the key, forces a re-pin anyway — the same
  live-read the pinning design already requires — so the fingerprint the caller
  signs is the current one or the call was going to fail regardless.

So: **`to = fingerprint(target.publicKey)`, read from the same record the address
came from.** This also composes with the TLS pin rule ("the pinned key and the
address must come from the same lookup") — `to`, the address, and the pinned cert
key are then all one record read once.

## Why this is a breaking change, and the shape of the migration

Old peers sign over `{name, at}`; new peers sign over `{name, at, to}`. A verifier
that requires `to` rejects every old peer; a signer that sends `to` is harmless to
an old verifier (which ignores the extra field) but gains nothing until the
verifier checks it. So the two sides must move in a known order, and the
in-between state is where the danger is.

The naive in-between — **dual-accept**: verifiers accept a hail with `to` *or*
without — reopens the exact hole for its whole duration. An attacker replaying a
captured hail simply presents it in its `to`-less form (or strips `to`), and a
dual-accepting verifier takes it. Dual-accept is not a safe transition on its own;
it is the hole with a deprecation notice.

The transition has to be **per-peer and authenticated**, not global and optional:

1. **Advertise support, in signed state.** A peer that verifies `to` says so in
   the record it returns from `walk` — and that record is already signed
   (`signRecord`/`verifyRecord`). So "peer X requires target-binding" is a fact a
   caller learns from X's *signed* record, not a per-hail claim a man-in-the-middle
   could strip. Stripping it would break the record signature.

2. **Require `to` from peers known to support it.** Once a caller's directory
   holds a signed record in which X advertises target-binding, the caller *always*
   sends `to` to X, and — the load-bearing half — X *rejects* a `to`-less hail
   that claims to be from any peer X believes supports it. That closes the
   downgrade: a replayed old-style hail from an upgraded caller is refused, because
   the verifier knows that caller signs `to`. The residual acceptance of `to`-less
   hails is scoped to peers that genuinely have not upgraded, which shrinks to zero
   as the fleet moves.

3. **Flag day, eventually.** When enough of the fleet advertises support, drop the
   `to`-less path entirely: require `to` from everyone. This is the only fully
   closed state; steps 1–2 are how to reach it without a synchronized upgrade.

Two subtleties in step 2, and both are load-bearing.

**The support signal must be signed *and* sticky.** Binding it to X's signed
record stops it being *stripped* in transit — a record's signature covers its
body, so removing the bit breaks the signature. But signed is not *recent*:
records carry no nonce and no expiry, and `verifyRecord` accepts a validly signed
record of any age, so every pre-upgrade record a peer ever signed stays valid and
keeps circulating in gossip. A *rollback* — presenting an older, genuinely-signed,
support-absent record — would clear the require-clause without forging anything.
So the observation must be **monotone**: once a directory has seen any valid
signed record in which caller C advertises target-binding, it never un-sees it,
and no older record can lower it. Merge with OR (or, if the signal is a wire-
format *version integer*, keep `max(seen)` — which gives the stickiness for free,
one more reason to prefer a version integer over a capability bit). Sticky-plus-
signed narrows the residual to "verifiers that genuinely never saw C after C
upgraded", which is the honest statement of what the migration buys before flag
day.

**A per-hail unsigned claim would be strippable.** The bit cannot live in an
unsigned per-hail field or be inferred from behavior; either is a forced
downgrade. The signed record is the only place it is safe.

**And `to` is mandatory whenever a hail carries a `grant`, from day one — not
migrated.** A grant-presenting caller is, by construction, one the verifier may
hold *no record* for (`identify` falls back to the grant's subject key precisely
for unadmitted peers). No record means no support observation means the
require-clause can never fire — so throughout the migration a grant-carried hail
would be accepted `to`-less, and grant-carried hails are the highest-value replay
target, since a grant is how an unadmitted peer acts at all. There is nothing to
migrate here: with no support-check to consult, `to` is simply required on any
hail bearing a grant. The cost is only that a subject of an old grant-issuer
cannot present grants at an upgraded verifier until it too signs `to` — which is
the correct failure direction — and it closes the widest window on day one.

## The cheaper interim, and whether it is enough

The alternative closes the leak without touching the contract: **`callPeer` sends
signed material only to an address whose provenance it trusts.** But "trusted
transport" must be stated carefully, because a naive reading of it trusts the
attacker. Two traps:

- **The `transport` field is a label the wire supplies.** `normalizeAddresses`
  takes `transport` from untrusted input, so a gossiped or self-reported address
  can *claim* `transport: "tailscale"` while pointing at any box. A rule keyed on
  `address.transport` alone therefore trusts an attacker-chosen string. What
  partly saves it — a claimed tailnet address cannot earn `lastOk` unless the real
  peer answers there, and an attacker cannot put a box on our tailnet — does not
  save the *first* dial, which is sent before any verification: the credential
  leaks on contact.

- **Gossip crowds the dial set even when it cannot overwrite.** `mergePeerRecord`
  keeps an operator/verified address (`lastOk` survives; gossiped ones enter with
  `lastOk: null`), so a typed address is not lost — but a *fresh* gossiped address
  can sort into an earlier `orderForDialing` band and be tried first.

So the interim rule is **provenance plus shape**, not a transport label: send
signed material only to an address that is **operator-entered**, or that **carries
`lastOk` *and* a value whose shape matches its claimed transport** (a `tailscale`
label on a `100.64/10` address — `presumedLifetime` already does exactly this
shape check, so the vocabulary exists). A label alone is not provenance, and the
rule must gate the *first* dial, since that is where the credential goes.

Stated that way, it is smaller, non-breaking, and closes the *leak* today. What it does not give
is the positive property target-binding gives: even a hail that legitimately
reaches the wrong peer (a misconfigured record, a shared address) is inert there.
Target-binding makes the credential meaningless off-target; the provenance rule
makes the credential hard to *misdeliver*. The first is a stronger guarantee; the
second is available now and composes with the first later.

**Recommendation.** Ship the provenance-plus-shape restriction now (it is a
`callPeer` change and an address-provenance check, no protocol move), and treat
target-binding as the eventual contract change, sequenced by the signed-
advertisement migration
above — most naturally landed *with* the TLS work, since both want the same
"address, key, and now `to`, all from one signed record read once" discipline, and
TLS is already a coordinated version bump.

## Open

- **Where the "supports target-binding" bit lives in the record.** A version
  integer on the signed peer record, or an explicit capability list? A version is
  simpler and orders cleanly; a capability list generalizes to the next contract
  change. Lean version integer, since this is about the hail wire format, not
  about peer capabilities.
- **`to` for a keyless candidate.** A peer admitted by address with no key yet
  cannot be given a fingerprint to sign, and cannot verify one either. Those hails
  are already the weakest path (`identify` refuses a keyless peer without a grant);
  target-binding simply does not apply until the key is bound on first verified
  contact, which is the same moment everything else about that peer becomes real.
- **Grant-carried identity** is no longer open — it is the mandatory-on-grant
  rule in the migration section above: because a grant-presenter may have no
  record to carry a support signal, there is nothing to migrate, so `to` is
  simply required on any hail bearing a grant, from day one. Left here only as a
  pointer, since a reader arriving at "open questions" would otherwise expect it.
