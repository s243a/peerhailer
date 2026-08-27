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
it" — that routing, chat, and tunnels all *call*. It is written here, once, rather than
reinvented in each. Per-hop TLS stays (it protects the wire and hides size/timing from a
passive network observer); the seal is what protects the *content* from the relays
themselves. It is **distinct from anonymity** (`docs/routing.md`, Stage 5): sealing hides
*what* is carried; anonymity hides *who* is talking.

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
- **One key, one job.** The signing key signs; the sealing key seals. No key is asked to do
  two cryptographic jobs, so there is no cross-protocol interaction to reason about.
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
- **`node:crypto` does not expose the conversion.** There is no built-in Ed25519→X25519 map,
  so Option B means **hand-rolling curve field arithmetic** in a security fabric — precisely
  the "don't hand-roll crypto" line the project holds everywhere else. A subtle bug here is a
  silent confidentiality failure, the hardest kind to notice.
- **One key doing two jobs.** Using the same key material for signatures *and* key agreement
  is generally discouraged: a signing oracle and a decryption oracle over one key are a
  cross-protocol interaction that has to be argued safe for the specific constructions, not
  assumed. Production systems that do share a key (Signal's XEdDSA) use a carefully audited
  scheme — not an ad-hoc conversion.
- **Rotation is coupled.** Rotating the signing key rotates the sealing key and vice versa;
  you cannot retire one without the other.

## Recommendation

**Option A.** The decisive factors are the two the project already weights most: it keeps us
from **hand-rolling curve math**, and it keeps **one key to one job**. The cost — a second
key in the identity and directory — is ordinary protocol work with a clear migration path,
and it is the kind of cost that is paid once. Option B trades that one-time protocol cost for
a permanent, hard-to-audit cryptographic risk, which is the wrong trade for a fabric whose
value is being auditable.

## What sealing does *not* do (scope)

- **It hides content, not metadata.** A relay still sees the destination it is asked to reach,
  the block sizes, and the timing. Hiding *those* is the anonymity work (`docs/routing.md`,
  Stage 5), and against a global observer it is a much larger project this does not promise.
- **It is not authentication.** The seal proves confidentiality to the recipient; the existing
  Ed25519 signature is still what proves *who sent it*. A sealed block should also be signed (or
  the AEAD keyed so only the intended sender could have produced it) so a relay cannot swap
  content undetected.

## Questions for review

1. Is the directory/hello cost of carrying a second key (Option A) acceptable, or is the
   single-key footprint of Option B worth revisiting with a *well-audited* conversion (not a
   hand-rolled one)?
2. Static-static ECDH (simplest, no forward secrecy) vs ephemeral-static (per-message forward
   secrecy, an ephemeral key in each block) — which is the Stage 1.5 default?
3. Should the seal bind the sender identity (sign-then-seal, or an AEAD associated-data field
   carrying the signed origin) so a relay cannot substitute a block?
4. Does this subsume the "sealed relay" designs in `docs/chat.md` / `docs/acp-tunnel.md`, or
   are they a different layer that sits on top of this primitive?
5. Block-level sealing (each block independently decryptable) vs message-level (seal once,
   then chunk) — the routing Stage 1.5 assumes per-block; is that the right default for
   everyone, or routing-specific?
