# Binding a hail to its target

**Status: designed, not built. A breaking change to the signed-hail contract —
the design exists so the migration can be decided before any peer moves.**

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

The subtlety in step 2: the "does X support it" bit must come from X's signed
record and nothing weaker. A capability advertised in an *unsigned* per-hail field,
or inferred from behavior, is strippable, and a strippable upgrade signal is a
forced downgrade. Binding the signal to the signed record is what makes the
require-clause safe.

## The cheaper interim, and whether it is enough

Kimi's alternative closes the leak without touching the contract: **`callPeer`
dials only trusted-transport addresses.** The leak is identity material reaching
an *untrusted address*; if callPeer refuses to send a signed hail to an address
whose transport is not trusted — send only over the tailnet, over a pinned-TLS
link, or to an operator-typed address, never to a gossiped or DNS-resolved one —
then the party being called cannot choose where the credential goes, and the
replay target cannot be an attacker's box.

This is smaller, non-breaking, and closes the *leak* today. What it does not give
is the positive property target-binding gives: even a hail that legitimately
reaches the wrong peer (a misconfigured record, a shared address) is inert there.
Target-binding makes the credential meaningless off-target; trusted-transport
makes the credential hard to *misdeliver*. The first is a stronger guarantee; the
second is available now and composes with the first later.

**Recommendation.** Ship the trusted-transport restriction now (it is a `callPeer`
change and an address-provenance tag, no protocol move), and treat target-binding
as the eventual contract change, sequenced by the signed-advertisement migration
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
- **Grant-carried identity.** A hail can carry a `grant` naming a subject key
  instead of being from an admitted peer. The `to` binding is orthogonal — it
  constrains *where* the hail is valid regardless of *how* the caller is
  identified — but the migration's require-clause must treat a grant-presenting
  caller by the same signed-support rule, which needs its own line when built.
