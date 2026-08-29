# Design: a durable receiver-side seal ratchet

**Status: deferred, after review.** A first design was reviewed by Sol
(gpt-5.6, medium) and by Kimi's earlier PR #49 notes. Verdict: **do not implement
as proposed.** The per-session ratchet shipped in PR #49 (`sealedFrom` in
`chatPlugin.js`) stays; the durable version is deferred until a second seal consumer
(routing) justifies a *general* durable seal-observation seam. This doc is kept as
the corrected design record for that day — with the review's fixes folded in so the
next attempt does not repeat the mistakes.

## Review outcome (why deferred)

The exposure the durable marker would close is small: the window is opened only by
an operator-controlled reload/restart, closed by the peer's next valid sealed
message, still bounded by hail authentication and the sender-side fail-closed floor,
and it never discloses previously-encrypted content. Against that, a correct durable
version needs cross-process merge semantics, failure ordering, an identity-rotation
policy, an override state machine, CLI/API surface, and mixed-version behaviour.
**That trade is presently negative.** Two of the first draft's justifications were
also simply wrong (below), which is its own reason to slow down. Revisit when
routing creates a second consumer, and then design **one general, origin-keyed
durable security-observation seam**, not a chat-specific result directive.

## Corrected design (for when it is built)

### The obstacle stands

`applyChange(mutate)` builds a **fresh** directory from disk, mutates that, persists,
and `adopt`s it back over the live one. So a plugin mutating the live directory
directly is both unpersisted and then **wiped** by the next `applyChange`. The
durable path must go through `change`, which a plugin's handler input
(`{ body, caller, directory, identity, log }`) does not include.

### Seam — a caller-bound host capability, not a result directive

The first draft proposed a declarative directive on the handler *result*, applied by
the host after the handler returns. Sol rejected this on **ordering**: the chat
handler spends the nonce, arms the in-memory ratchet, and appends the message
*before* returning, so a directive applied afterward can fail (persistence throws, or
the peer is gone from fresh disk state) *after* the message was already accepted —
strictly less safe than the in-memory version it would replace.

Corrected seam: the host passes the handler a narrow capability, e.g.
`markSealedCaller()`, that

- is **bound by the host to the authenticated `caller.publicKey`** — the plugin
  cannot supply a name or an arbitrary key;
- applies through `applyChange` (so it persists);
- is called **after** the sealed message fully validates but **before** the nonce is
  spent and the message appended;
- **fails the request** if persistence fails; and
- **keeps the in-memory `sealedFrom` set** as an immediate, failure-safe cache — the
  durable field is added protection, not a replacement.

Note this is **API least-authority, not a sandbox**: installed plugins run trusted
in-process JavaScript. The seam limits what an *honest* plugin is handed; it does not
constrain a malicious one, and the design must not imply otherwise.

### The floor is sound; the override as drafted is not

`requireSealFrom` as a monotone OR-floor in `mergeByRevision` (like `sealRequired`),
preserved in `keepOurs`, is correct and cannot be silently rolled back by a stale
writer.

The drafted operator override — a revision-based `sealCleartextOk` boolean — is
**not** sound under record-level revision merge. Failure case (Sol): a stale process
holding `{ sealCleartextOk: true, rev: 8 }` performs unrelated mutations up to rev
11, after the operator cleared the override on disk at rev 10;
`mergeByRevision` selects the stale record wholesale and **resurrects** the override,
bypassing the floor despite the later operator decision.

If a reversible override is ever wanted it needs its **own field-level
version/register**, merged independently of the peer's general `rev`, advanced only
by explicit override operations — and a newly-validated sealed message should
**auto-revoke** it, or "allow cleartext temporarily" silently becomes "forever."
Preferably, for now: **no persistent override at all.**

### Recovery — the first draft's premise was wrong

The draft justified the override by "a peer that keeps its identity but loses its
seal keypair." That is backwards. **A peer does not need its own X25519 sealing
keypair to send *us* sealed messages** — sending seals to *our* sealing public key
with an ephemeral X25519 key, signed by the peer's Ed25519 *identity* key. Losing its
sealing keypair stops it from *opening* messages sent *to* it; it does not stop it
from sealing *to us*. And walking/accepting the peer's new sealing key repairs *our
sender-side* ability to encrypt to it — it does not touch this receiver-side ratchet.

So key-loss is not the recovery case. The genuine escape case is narrower: the peer
deliberately downgraded to software that cannot seal, or can no longer obtain our
current sealing public key. That is an explicit **security reset**, not routine
recovery — and `forget` + deliberate re-admit is likely the right, appropriately
loud escape hatch. A convenient persistent bypass is not yet justified.

### Identity rotation — reset, do not carry

The session ratchet is keyed by **signing public key**. Carrying `requireSealFrom`
across `rotateKey` (as the draft proposed, mirroring `sealRequired`) attaches the
policy to the *logical named peer* instead. But once the identity key rotates, old
signed cleartext no longer authenticates as the peer, so the original downgrade/replay
concern does not carry across cryptographic identities. **Reset the receiver-side
floor on a deliberate identity rotation** unless the project explicitly chooses a
stronger named-peer policy and documents its availability cost. The sender-side
`sealRequired` floor survives rotation for a *different* reason (not sending secrets
in cleartext to the logical peer); the two floors need not share rotation semantics.

### Migration and mixed versions

A new optional boolean defaulting to "not required" loads old state files unchanged.
But the durable **guarantee** holds only once **every** writer touching the state
file runs the new version: an older binary does not know to preserve or OR-merge
`requireSealFrom` and can erase it, and downgrading the binary may lose the field.
State that explicitly.

### Relayed consumers — a hard requirement

Both the sender-binding and this ratchet key on `caller` today, which is correct only
for **direct** chat. A relayed/routed consumer must key both on the origin
authenticated from *inside* the sealed payload, never the last-hop `caller` — a
last hop must never be able to durably mark another origin, or itself on behalf of
every origin it relays. The durable field makes this more important, not less: a
wrongly-keyed durable ratchet persists a false refusal. When routing arrives, build
the seam origin-keyed from the start.
