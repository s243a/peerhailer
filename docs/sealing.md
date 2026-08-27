# Sealing: end-to-end confidentiality for content the fabric carries

**Status: decision record. Not built.** peerhailer authenticates *who* a peer is
(Ed25519 signatures) and encrypts each *hop* (TLS). It has no way to seal *content*
so that only the intended recipient can read it. This document is the case for adding
that — one primitive, used in several places — and the one decision it turns on: which
key the seal uses.

## Why this is not a routing feature

The need shows up wherever a message passes through a party that is not its
destination:

- **Routing** (`docs/routing.md`, Stage 1.5): a relay terminates the incoming TLS,
  reads the message, and re-encrypts to the next hop — so at Stage 1 every relay can
  read everything it carries. Admission means "trusted to relay," which is not
  "trusted to read."
- **The sealed relay** already sketched (unbuilt) in `docs/chat.md` and
  `docs/acp-tunnel.md`: reaching a non-peer, or crossing an inspecting relay, wants the
  payload opaque to everyone but the endpoints.
- **Tunnel exits and chat to a non-peer**: same shape.

So sealing is a **fabric-level primitive** — "encrypt a blob so only peer *X* can open
it" — that routing, chat, and tunnels all *call*. To be precise about what is unified: the
**crypto core is shared** (the X25519 key, the ECDH → HKDF → AES-GCM construction, and the
seal-then-sign binding), while the **framing differs per consumer** — routing seals
*per block* because it is store-and-forward and blocks take different paths; a live tunnel
would seal *per frame over a stream* because both ends are online. Same primitive, same
keys, different envelope — so the claim is "one audited crypto core, consumer-specific
framing," not "one wire format everywhere." It is written here once rather than reinvented,
and each consumer doc (`docs/chat.md`, `docs/acp-tunnel.md`, `docs/routing.md`) should say
which framing it uses. Per-hop TLS stays (it protects the wire and hides size/timing from a
passive observer); the seal protects the *content* from the relays themselves. It is
**distinct from anonymity** (`docs/routing.md`, Stage 5): sealing hides *what* is carried;
anonymity hides *who* is talking.

## The gap

Identities are **Ed25519** (`src/identity.js`) — a *signing* key. Ed25519 signs and
verifies; it does not do key agreement, so it cannot, as-is, encrypt to a recipient.
Sealing needs an **X25519** (Curve25519 ECDH) capability: derive a shared secret between
sender and recipient, run it through a KDF, and encrypt with an AEAD (AES-256-GCM) — all
of which Node's built-in `crypto` provides with **no dependency**. The only question is
where the X25519 key comes from.

## The decision: which key seals

### Option A — add an X25519 encryption key to each identity

Each identity gains a second, dedicated key pair used only for sealing. A peer's public
record carries both the Ed25519 signing key and the X25519 sealing key; the hello/directory
exchange learns both.

**Pros**
- **Standard and well-trodden.** This is the "sealed box" / `crypto_box` shape; `node:crypto`
  supports `generateKeyPairSync('x25519')` + `diffieHellman()` + HKDF + AES-GCM directly. No
  hand-rolled curve math — which matters most in exactly this kind of code.
- **One key, one job (defence in depth).** The signing key signs; the sealing key seals.
  This is a *defence-in-depth* preference, not a load-bearing requirement — production
  systems (Signal's XEdDSA) safely share one key for both with careful **domain
  separation**, which is the property actually doing the work. A avoids having to make
  that argument at all.
- **Forward secrecy is available.** Sealing with an *ephemeral* sender key against the
  recipient's static key gives per-message forward secrecy for free.
- **Rotatable independently.** A compromised sealing key can be rotated without touching the
  identity's signing key (and vice versa).

**Cons**
- **Identities grow.** Every peer record now carries a second public key that must be
  published, learned, kept in sync, and versioned in the hello/directory protocol.
- **Migration.** Existing identities have no sealing key; they must generate and distribute
  one, and peers must tolerate a record that has a signing key but not yet a sealing key.
- **More surface to keep consistent.** Key rotation, blocking, and target-binding now reason
  about two keys instead of one.

### Option B — derive an X25519 key from the existing Ed25519 key

No new key is published. The X25519 key is computed deterministically from the Ed25519 key
every peer already holds (the Edwards and Montgomery forms of Curve25519 are birationally
related; libsodium exposes this as `crypto_sign_ed25519_pk_to_curve25519`).

**Pros**
- **Nothing new to distribute.** The sealing key falls out of the signing key everyone
  already has — no identity change, no directory change, no migration.
- **Smaller identity and directory.** One key per peer, as today.

**Cons**
- **`node:crypto` has no conversion, and we are zero-dependency.** To be fair to B: the
  Ed25519→X25519 map is *not* exotic — it is a published, audited construction
  (libsodium's `crypto_sign_ed25519_pk_to_curve25519`, Signal's X3DH) used in production
  at scale. The problem is specific to *this* project: peerhailer uses **only
  `node:crypto`, which does not provide the map**, so B here means either **hand-rolling
  curve field arithmetic** (the "don't hand-roll crypto" line we hold everywhere) *or*
  **adding a crypto dependency** (breaking the zero-dependency rule). So B is dismissed
  not because the conversion is unsafe — it isn't — but because neither way of getting it
  here is acceptable. If we ever accepted a vetted crypto dependency, B would be back on
  the table.
- **One key doing two jobs.** Sharing key material for signatures *and* key agreement is
  a *defence-in-depth* concern, not automatically unsafe — with proper domain separation
  it is fine (Signal does it). It is one more thing to argue rather than avoid.
- **Rotation is coupled.** Rotating the signing key rotates the sealing key and vice versa;
  you cannot retire one without the other.

## Recommendation

**Option A — but on honest grounds.** The decisive factor is the **zero-dependency
constraint**, not any claim that B's conversion is unsafe (it is production-proven). Under
zero-dep-on-`node:crypto`, B forces a choice between hand-rolling curve math and adding a
crypto dependency, and A avoids that choice with only standard `node:crypto` calls. The cost
of A — a second key in the identity and directory — is ordinary, one-time protocol work with
a clear migration path. If the project ever accepts a vetted crypto dependency that ships the
Ed25519→X25519 map, **B becomes a legitimate, smaller-footprint alternative**. And it
need not be an all-or-nothing choice: the resolution below makes **A the mandatory
default** and lets B (or any dependency-bearing suite) ride an **opt-in plugin**, so the
dependency question is each operator's, not the project's.

## The resolution: negotiate suites; A is the mandatory floor

The choice is not really A *or* B for the whole network — it is a **per-node policy,
negotiated**, the way SSH negotiates ciphers. Each identity advertises the sealing
**suites** it supports and prefers; a sender picks the best suite it shares with the
recipient and tags the block with that suite's id. This turns "which key" from a
one-time global decision into **crypto agility** — suites can be added (a
post-quantum one, later) and retired without a flag day, and each operator sets their
own floor and preference while the default stays auditable and dependency-free.

- **Suite A (X25519 sealed-box) is mandatory.** Every node supports it, so there is
  always a common suite and no "no shared suite" failure. It is the zero-dependency
  default, in the core with only `node:crypto`.
- **Other suites are opt-in plugins, not build flags.** B (the Ed25519-derived key),
  and later a post-quantum suite, ship as a **separate plugin package** that registers
  a suite through peerhailer's existing plugin loader (`hail plugins add`). This is
  deliberately *not* a build flag: a flag flips on code already in `node_modules`, so
  the supply-chain cost is paid whether or not it is set, whereas a separately installed
  plugin is a genuine opt-in and `hail plugins` shows exactly what a node added (the
  same reasoning as `docs/file-backends.md`). A node that adds no plugin runs pure
  zero-dep A.
- **Offline recipients ⇒ advertise-and-select, not a live handshake.** Sealing is
  store-and-forward; you cannot run an interactive SSH-style exchange with an offline
  peer. So the recipient's suites are published in its **signed identity/directory
  record**, the sender selects from them, and the chosen suite id is **bound into the
  seal** (AEAD associated data, or covered by the signature). A live consumer (a tunnel)
  *can* negotiate interactively, but advertise-and-bind serves both, so it is the one
  mechanism.
- **Close the downgrade attack.** Negotiation's classic failure is an active party
  forcing the weakest mutually-allowed suite. Two defenses, both required: a **hard
  per-node floor** — a node refuses a suite it deems too weak, so "allowed" is a floor,
  not merely a preference — and **binding the suite id into the authenticated part of
  the seal**, so a relay cannot rewrite the tag to a weaker suite without breaking the
  signature. (This is why seal-then-sign / AEAD-AD, above, is load-bearing here too.)

## Forward secrecy and the offline recipient

Use **ephemeral-static ECDH**, and it works even when the recipient is offline. The sender
generates a throwaway X25519 key per message, does ECDH against the recipient's *static*
sealing key, derives the AEAD key, and carries the **ephemeral public key inside the block**;
the recipient decrypts later, when it comes online (this is exactly how PGP and Signal
pre-keys handle an absent recipient). This gives per-message forward secrecy on the *sender's*
side — the ephemeral key is discarded — so a relay that stored the block cannot later
decrypt it even if it compromises the sender. **Static-static ECDH is never the right
default**: it adds no forward secrecy and buys nothing here.

The residual, stated plainly: forward secrecy is one-sided. If the *recipient's* static
sealing key is later compromised, blocks stored for it are decryptable. The mitigation is
recipient-side key freshness — rotating the sealing key periodically, or publishing one-time
**pre-keys** — which bounds the window a single key exposes. That is a Stage-later refinement,
not a Stage 1.5 blocker.

## What sealing does *not* do (scope)

- **It hides content, not metadata — here is exactly what still leaks.** "End-to-end sealed"
  is not "private"; a relay on the path learns a great deal that the seal does not touch:

  | Sees it | A relay on the path | The directory | A passive network observer |
  | --- | --- | --- | --- |
  | Payload content | — (sealed) | — | — |
  | Destination key it is asked to reach | ✅ | — | — |
  | Its previous / next hop | ✅ | — | — (sees the two endpoints of each hop) |
  | Block size and count | ✅ | — | ✅ |
  | Timing / traffic pattern | ✅ | — | ✅ |
  | That a peer *has* a sealing key | ✅ | ✅ | — |

  Hiding *who* and *when* is the anonymity work (`docs/routing.md`, Stage 5) — onion layering
  for the hops, and padding / fixed-size blocks / cover traffic for size and timing — and
  against a global observer it is a far larger project this primitive does not promise.
  Fixed-size blocks (Stage 1.5's chunking) already blunt the size channel a little.
- **It is not authentication — and the order matters.** The seal proves confidentiality;
  the Ed25519 signature still proves *who sent it*, and a block must carry one so a relay
  cannot substitute content undetected. Use **seal-then-sign** (sign the ciphertext) or bind
  the signature/MAC as the AEAD's **associated data** — *not* sign-then-seal. Signing the
  ciphertext lets a relay verify the outer routing envelope **without decrypting**, and
  avoids the decryption-DoS of sign-then-seal (which forces the recipient to decrypt
  attacker-chosen bytes before it can reject them). This is the Noise/WireGuard pattern.

## The consumer contract

A crypto review (round J) confirmed the suite-A primitive sound and surfaced four
obligations that live in the *consumer*, not the primitive. A consumer that wires the
seal into routing, chat, or a tunnel MUST honour these — they are recorded here so the
first consumer does not rediscover them.

1. **Authentication is opt-in, and `from` must be checked.** `open()` returns
   `from: null` for a block sealed without a signer. Because `from` is bound into the
   AEAD, a *signed* block cannot be silently stripped to unsigned — deleting `from`
   breaks decryption — but an unsigned block (including one an attacker sealed
   themselves) still carries `from: null`. So a consumer that requires an authenticated
   sender MUST reject `from === null`, or call `openSigned`, which does.

2. **An authenticated `from` is only worth its binding to an identity.** `from` is a
   bare Ed25519 public key. For it to mean "this peer sent it," the consumer must map
   `from` to a peerhailer identity — which holds only if the **sealing signer key is the
   identity's Ed25519 key** (or the directory/hello record binds the two). Until that
   binding exists, `from` is an unanchored self-assertion, worth no more than an
   unsigned block. Adding the identity/directory binding is therefore a **correctness
   prerequisite** for any authenticated consumer, not an independent feature — the
   signer should be the identity key.

3. **Freshness is the consumer's job.** A sealed block is a *bearer artifact*: captured,
   it opens identically forever. The seal gives confidentiality, integrity, and
   (optionally) authentication — **not** freshness. A consumer that must not act on a
   replayed block puts a nonce / id / timestamp **inside the plaintext** (routing already
   has its envelope-id dedup; chat and tunnels need their own).

4. **Recipient binding is implicit — do not "optimise" it away.** The recipient's static
   key is the ECDH input, so a block that opens under one recipient's key cannot open
   under another's; recipient identity is bound *by the ciphertext*, not by an AD field.
   This is why there is no unknown-key-share gap for suite A. **A future suite that
   derives the key from anything other than the recipient's static key** (a pre-shared
   key, a PAKE) **must move the recipient identity into the associated data**, or that
   gap becomes real.

5. **Seal only to a *verified* sealing key.** The recipient's sealing key rides its
   signed record, but a key that reached the directory any other way — a gossip mention,
   an introducer's candidate — is an unverified claim, and a malicious introducer can
   staple its own X25519 key beside a peer's real identity key. A consumer MUST seal only
   to a key a walk bound from the peer's *verified* record (`directory.sealKeyFor`, backed
   by the `sealSeen` marker `directory.bindSealKey` sets), never to `record.sealPublicKey`
   raw. Once bound, the marker is sticky across merges and re-admits, so a peer known to
   seal cannot be silently downgraded to cleartext; a peer with **no** verified key yet
   (an older build) legitimately falls back to cleartext until its first walk. **Deferred
   (chat):** the *receiver* still accepts a cleartext message from a peer whose sealing key
   it holds — closing that (refuse/warn on an unexpected cleartext) needs the plugin to
   consult the directory, and is tracked for a follow-up.

**Forward-secrecy scope, stated for consumers:** sender-side only. If the *recipient's*
static sealing key is later compromised, every past block sealed to it is decryptable
(mitigate with recipient key rotation / one-time pre-keys). A compromised *sender*
signing key permits forgery of that sender's blocks but does not decrypt anyone else's.

## Questions for review

1. Is the directory/hello cost of carrying a second key (Option A) acceptable? *Largely
   resolved above*: A is the mandatory zero-dep default and B rides an opt-in plugin, so the
   footprint is A's second key plus whatever a node opts into. Open: the exact suite-id
   registry and how a node advertises its floor/preference in the signed record.
2. Static-static vs ephemeral-static ECDH — *resolved above*: ephemeral-static, which works
   for offline recipients and gives sender-side forward secrecy; static-static is never the
   default. Open: recipient-side pre-keys/rotation cadence.
3. Should the seal bind the sender identity (sign-then-seal, or an AEAD associated-data field
   carrying the signed origin) so a relay cannot substitute a block?
4. Does this subsume the "sealed relay" designs in `docs/chat.md` / `docs/acp-tunnel.md`?
   *Leaning*: same crypto core, different framing (per-block vs per-stream) — those docs should
   adopt this core and declare their framing, rather than roll their own.
5. Block-level sealing (each block independently decryptable) vs message-level (seal once,
   then chunk) — the routing Stage 1.5 assumes per-block; is that the right default for
   everyone, or routing-specific?

## Provenance

Reviewed (round I). The review sharpened the honest grounds for Option A — it wins on the
**zero-dependency** constraint, not because B's Ed25519→X25519 conversion is unsafe (it is
production-proven) — reframed "one key, one job" as defence-in-depth resting on domain
separation, replaced sign-then-seal with **seal-then-sign / AEAD-AD**, corrected the
forward-secrecy analysis (**ephemeral-static works for offline recipients**), added the
explicit metadata-leakage table, and made the fabric-unification claim precise (shared crypto
core, consumer-specific framing). The A-vs-B decision was then resolved by **negotiated
suites** (SSH-style): A mandatory and zero-dep, other suites as opt-in plugins, selection
advertised in the signed record and bound into the seal against downgrade.
