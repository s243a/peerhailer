# Design: a durable receiver-side seal ratchet

**Status: design / proposed, for review.** The per-session downgrade ratchet
shipped in PR #49 (`sealedFrom` in `chatPlugin.js`). This proposes the durable
follow-up Kimi flagged — a `requireSealFrom` marker that survives a restart — and,
honestly, weighs whether it earns its machinery. Nothing here is built yet.

## What it buys, and the honest cost

The shipped ratchet is per-instance: an operator `reload`/restart empties it, and
the peer's next sealed message re-arms it. Kimi's assessment of that window: the
adversary **cannot open it** (reload is operator-only, loopback control plane), and
inside it the worst case is accepting cleartext *from the genuine, hail-authenticated
key-holder* — either the peer really sent it (their sender-side `sealRequired` floor
is monotone, so their send path still fails closed), or it is a replay of
pre-sealing-era cleartext, which exposes nothing that was ever encrypted. So the
durable marker closes a **small, operator-triggered** window.

Against that: a new persisted record field, its floor/merge handling, a host seam
so a plugin can persist, and an operator override. That is real surface. This doc
lays out the cleanest version so the trade can be judged — it may well be worth
*designing* now and *building* only when a second seal consumer (routing) forces
the durable path anyway.

## The obstacle: a plugin cannot durably change a record

`applyChange(mutate)` (bin/hail.js) does not mutate the live directory. It builds a
**fresh** directory from what is on disk, applies the mutation to *that*, writes it,
and then `directory.adopt()`s the result back over the live one. Two consequences:

1. A plugin that calls `directory.noteSealRequired(...)` on the **live** directory
   does not persist — and worse,
2. the change is **wiped** by the next `applyChange`, whose `adopt` replaces the
   live directory with disk state.

So the durable path must go *through* `change`/`applyChange`. The chat receive
handler is a plugin, and a plugin's input is `{ body, caller, directory, identity,
log }` — no `change`. That is the "small host seam" to add.

### Seam options

- **A — hand plugins `change`.** Add `change` to the plugin handler input. Simplest,
  but broad: any plugin could then persist arbitrary directory mutations. Too much
  power for the constrained plugin model (a plugin should decide *what to do about*
  an authenticated request, not rewrite the directory).
- **B — a declarative directive the host applies (recommended).** The handler
  result already flows back to the host (`send(response, 200, result)`). Let it
  carry a narrow, typed request — e.g. a `SEAL_REQUIRED` symbol keyed to
  `caller.publicKey` — and have the *host* apply it via `change(dir =>
  dir.noteSealRequired(...))` after a successful handler. The plugin can only
  *request* a monotone, safe mark; the host owns `change` and the exact mutation.
  Narrow, and it keeps the capability boundary intact.

Recommendation: **B**. It is the smallest seam that does not widen what a plugin can
do to the directory.

## The record field, and the floor

`requireSealFrom: boolean` on the peer record, handled exactly like the existing
`sealRequired` floor so it cannot be silently lost:

- **`mergeByRevision`** — an **OR-floor** (`winner.requireSealFrom ||
  loser.requireSealFrom`), so a stale writer whose snapshot predates the mark cannot
  roll it back, even if that writer wins the revision on an unrelated field. This is
  Kimi's explicit requirement.
- **`keepOurs`** — preserved across a local rebuild (`...(existing?.requireSealFrom ?
  { requireSealFrom: true } : {})`), like `sealSeen`/`sealRequired`.
- **`adopt` / `snapshot`** — rides along with the record, no special handling.
- **`rotateKey`** — kept, not dropped (a rotation must not reopen cleartext), same as
  `sealRequired`. Note the shipped per-session behaviour *does* reset on rotation
  (the new key has not sealed yet); the durable version deliberately tightens that.

`noteSealRequired(nameOrKey)` sets it true via `commit` (monotone — only ever sets).

The receive check becomes: refuse cleartext when the peer's record has
`requireSealFrom` **and** no operator override (below) — replacing today's
in-memory `sealedFrom.has(...)`.

## The override, and why it is a separate field

A monotone OR-floor **cannot be cleared** — set it false on one side and the merge
resurrects it from the other. So the operator override that Kimi requires (for the
peer that keeps its identity but loses its seal keypair, and is now permanently
refused) must **not** try to clear `requireSealFrom`. Instead, a second field:

- **`sealCleartextOk: boolean`** — a deliberate operator decision, set by e.g.
  `hail seal allow-cleartext <peer>`. It is **revision-based, not a floor**: a stale
  writer that drops it simply reinstates the refusal, which is the fail-safe
  direction. The check is `requireSealFrom && !sealCleartextOk`.

This keeps the security floor write-once and simple, and puts the "accept a
downgrade for this peer" decision where it belongs — an explicit, reversible
operator act, distinct from the automatic ratchet. Clearing it (`hail seal
require-seal <peer>`) re-imposes refusal.

Open question for review: is a per-peer override the right grain, or should the
lost-keypair recovery instead be "re-verify the peer's new sealing key" (a walk),
which is the real fix, with `allow-cleartext` reserved for genuine "this peer is
legacy cleartext now" decisions? The walk path is cleaner where the peer *can*
re-key; `allow-cleartext` is the escape hatch where it cannot.

## The relayed-consumer caveat (unchanged, louder)

Both the sender-binding and this ratchet key on `caller` today, which is correct
only for **direct** chat. A relayed/routed consumer must key both on the origin
authenticated from *inside* the sealed payload, never on the last-hop `caller` — see
the NOTE in `chatPlugin.js`. The durable field does not change this; it makes it more
important, because a wrongly-keyed durable ratchet would persist a false refusal.

## Migration

A new optional boolean field, absent on every existing record, defaulting to "not
required" — so old state files load unchanged and the ratchet arms only as peers
send sealed messages after the upgrade. No migration map needed.

## Questions for the reviewer

1. Seam: is directive-B the right boundary, or is there a cleaner host seam than a
   symbol-keyed result directive?
2. Override: separate `sealCleartextOk` field vs. re-verify-by-walk as the primary
   recovery — which is the right default, and is the two-field split worth it over
   just re-arming per session?
3. Is the incremental security (closing an operator-only restart window) worth the
   field + floor + seam + override, or is the per-session ratchet the right
   stopping point until routing forces a durable seal path?
