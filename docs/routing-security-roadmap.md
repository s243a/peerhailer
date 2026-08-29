# Routing security roadmap: from admission-gated delivery to authenticated sealed relay

**Status: design / reviewed (Kimi, then Sol — depth pass).** `docs/routing.md` is
the full routing roadmap. This is the security-focused companion: it sequences
*origin authentication*, *duplicate suppression (replay)*, *key trust*, and
*confidentiality* by their dependencies. Kimi corrected the original spine (signing
was conflated with sealing); Sol then corrected six over-strong claims and supplied
the concrete protocol. Both are folded in below; where a claim was walked back, it
says so.

## Where we are, honestly (Stage 1, shipped)

Admission-gated, loop-free-**by-construction-among-honest-relays**, best-effort
multi-hop delivery over the F2F graph. What it does not give:

- **Payloads are cleartext to every relay.**
- **`origin` is unsigned** — a relay can spoof it.
- **Replay is not closed.** `send()` mints an envelope `id`, but `relay()`'s child
  envelope drops it, so the destination dedup never fires for relayed traffic.
- **"Loop-free" is a cooperative property, not a security one.** The visited-set / TTL
  / budget stop loops among relays that *follow the protocol*. A relay that does not —
  it can strip visited entries, reset TTL/budget, fork the envelope, and reinject it
  into a cycle — is not stopped by any end-to-end signature. The defences against that
  are and remain **local**: clamp every field on receipt, exclude the authenticated
  immediate caller, rate-limit by caller, cap concurrent forwarding work, and treat
  visited/TTL/budget as *cooperative routing controls, never authenticated facts*.

## The corrected spine — two independent roots

Only confidentiality needs encryption. Origin-authentication and replay need
*integrity/authenticity* — a **signature** over an envelope manifest, using the
origin's already-distributed identity key — not privacy:

```
origin's Ed25519 identity key (already distributed & verified)
    └── signed manifest → origin-auth + replay          … no key discovery
destination's X25519 sealing key (learned over relays, tiered)
    └── sealed payload → confidentiality                 … the smaller key-trust step
```

Signed ≠ named: a signature proves "the holder of key K produced this," not "this is
alice." Routing is keyed by key (`N(dest)`), so that is the right granularity — but a
routed origin the destination never walked is treated as *unknown-profile, surfaced,
never silently admitted*, and a routed key is never auto-bound to a name.
**Authenticated ≠ admitted.**

## The authenticated route manifest (M1's core)

The origin signs a fixed manifest; hop-mutated fields stay outside it.

- **Signed (end-to-end):** `domain` (`"peerhailer/routed-block"` — prevents
  cross-protocol signature reuse), `version`, `originKeyId`, `destinationKeyId`,
  `messageId`, `blockIndex`, `blockCount`, `issuedAt`, `expiresAt`, `payloadMode`
  (`clear` | `sealed`), `payloadDigestAlgorithm`, `payloadDigest`.
- **Unsigned, hop-mutated:** `visited`, remaining `ttl`, remaining `budget`.
- **Local transport fact:** the immediate `caller` (used for rate-limiting and
  same-hop authorization, never as the origin).

Notes that matter:

- `messageId` ≥ 128 random bits; there is **no** global origin sequence (it would
  complicate legitimate out-of-order delivery). `blockIndex`/`blockCount` are present
  from the start (`0`/`1` unchunked) so chunking is not a schema break, and `seq` is
  *defined* as `blockIndex`.
- `payloadMode` and a bound `payloadDigestAlgorithm` (not "SHA-256 forever") mean the
  same bytes cannot be reinterpreted across the clear→sealed milestones, and one outer
  schema serves both.
- **`payloadDigest` covers the exact transported bytes.** Clear milestone: serialize
  the payload to bytes **once** at the origin; relays carry those bytes verbatim (never
  reparse-and-restringify a JS object). Sealed milestone: hash the exact ciphertext
  bytes on the wire, not the plaintext.
- Key ids are **full SHA-256 of the canonical SPKI DER key**, not the short human
  fingerprint and not PEM text.

**Canonicalization:** a **fixed-order JSON array** (easier to audit than a generic
canonical-object algorithm), with strict canonical base64url ids/hashes, safe
nonnegative integers, explicit maximum lengths, and no optional field whose absence has
more than one encoding — so a relay cannot alter a field and still produce a verifying
signature.

**Delivery discipline:** the destination compares the *signed* `destinationKeyId` to
its own identity and **rejects any manifest not addressed to it**; it takes the origin
**only** from the signed manifest and ignores the outer `origin` for authorization. A
relay may redirect the outer routing target, but then only earns a refusal/availability
failure.

## Replay, expiry, and state (M1)

The signed manifest makes replay *detectable*; it does not close replay *without
state* — and a signed expiry does **not** make an in-memory cache restart-safe
(corrected from the prior draft). The restart hole: destination records `(origin,id)`
in memory, restarts while the envelope is still unexpired, cache is empty, a relay
replays the valid envelope, it is accepted again. So **M1 must pick one and say which**:

- **session-only** dedup — in-memory, *explicitly not restart-safe*; or
- **across-restart** dedup — durable, retained until `expiresAt` (+ skew).

A signed expiry makes the durable state **bounded and garbage-collectable** — valuable
— but not unnecessary.

Validation, enforced locally regardless of what the origin signed:

- both `issuedAt`/`expiresAt` are safe integers; `expiresAt > issuedAt`;
  `expiresAt - issuedAt ≤ MAX_VALIDITY` (minutes, not hours); `issuedAt ≤ now +
  CLOCK_SKEW`; `expiresAt ≥ now − CLOCK_SKEW`.
- keep a dedup entry until `expiresAt + CLOCK_SKEW`. A relay that holds a message until
  just before expiry spends its lifetime; it does not extend it.

Dedup key: `(originKeyId, messageId)` unchunked, `(originKeyId, messageId, blockIndex)`
for blocks.

Processing order (cheap-and-safe first, allocate nothing for messages policy will
refuse): shape/size → verify manifest → check signed destination → classify/authorize
origin → time window → consult/reserve dedup → deliver. Bounds: global + per-origin
live-entry caps, last-hop rate limit, fixed message-id length. **At capacity, fail
closed on the new message — never evict an unexpired entry while still claiming replay
suppression.**

Delivery semantics, stated honestly: the protocol cannot promise *exactly-once* for
arbitrary consumer side effects (reserve-first risks loss on a crash, deliver-first
risks a duplicate). Call it **bounded duplicate suppression / at-most-once attempt**;
a consumer needing transactional exactly-once supplies its own idempotency store.

## Key trust for a routed destination — tiered, and *partially* ordered

The tiers stand, but "Tier-1 is strictly better than cleartext" does **not** (corrected).
Stale-key counterexample: D rotates `S_old`→`S_new`, `S_old` is compromised, a relay
preserves the old validly-signed record, an origin with no prior observation encrypts
to `S_old`, the holder of the retired key decrypts. **Nothing fails loudly at send
time** — a later walk *may* reveal it, but confidentiality is already lost, and absent
a walk the origin may never learn. So the guarantees are **partially ordered**: Tier-1
beats a *passive* relay that lacks the stale private key, but has weaker freshness and
revocation than Tier 0.

- **Tier 0 — walk-verified** (`bindSealKey`): full trust, current liveness.
- **Tier 1 — record-carried**: the destination's signed record rode the discovery path
  and its identity equals the routing target — check with `verifyRecord(envelope,
  dest)` (or at least `sameKey`), **not raw string equality**. Signed, but no liveness.
- **Tier 2 — gossip / unsigned / mismatched**: never seal.

**Policy: default verified-only** for confidential routed content; Tier-1 is an explicit
operator opt-in (`allow-record-carried`). When Tier-1 is used, surface *before*
transmission — tier, sealing-key fingerprint, signed-record age, the path that supplied
it, and the absence of a liveness proof — and **do not show the Tier-0 lock indicator**.
State model and rules: keep `record-carried` and `record-conflict` distinct from the
Tier-0 `verified`/`reverify`/`conflict` states; Tier 0 always wins over Tier 1; a
matching Tier-1 record adds no authority; differing Tier-1 records cause Tier-1 refusal
(not auto-selection); a later walk upgrades/replaces a Tier-1 key; two conflicting Tier-0
keys keep the existing deliberate-resolution path. (Signed key epochs / short-lived
records reduce stale exposure but cannot fully solve first-observation revocation without
an online authority, a transparency log, or a prior monotonic observation.)

## Destination confidentiality floor

A signed advertised floor helps honest senders avoid doomed cleartext, but the
**destination's local enforcement is the actual mechanism** — a relay can suppress the
record, replay an older one lacking the floor, or hide the current policy, yet cannot
make the destination accept cleartext if the destination checks its **current local
policy at delivery**:

1. destination stores `requireSealedRouting` locally;
2. the field rides its signed public record (advisory to honest senders);
3. the signed manifest binds `payloadMode`;
4. the destination rejects `payloadMode = clear` whenever its local floor requires
   sealing — the local check wins over any record a sender presents;
5. a relay cannot turn sealed content into valid cleartext (it cannot produce the
   origin's signature over a different mode + digest).

"Loud refusal" is loud *locally*; a relay can suppress any response, so if the origin
must distinguish a refusal from a grayhole, the destination returns a **signed refusal
receipt bound to `(origin, messageId)`**. Lowering the floor is a deliberate
destination-side change; a replayed remote record never lowers local enforcement.

## Milestones (reordered per the review)

- **M0 — honesty.** Correct `routing.md` (done). Optionally propagate the existing
  *unsigned* `id` into `relay()`'s child so the live-but-starved dedup catches
  **accidental** duplicates (real: with `fanout:3`, a diamond delivers twice with no
  adversary) — a **correctness** fix, explicitly *not a security control*. **Do not mark
  it done until `child.id` actually exists in `routing.js`** — it does not yet; this is
  a separate one-line code change + test.
- **M1 — authenticated route manifest.** The fixed canonical schema above; origin
  authentication; payload commitment; destination binding; the explicit expiry rules;
  and **either durable replay state or a stated per-process replay guarantee**. Re-key
  dedup on `(origin, id)` here. Docs must say plainly: **signed ≠ private** — relays
  still read payloads at this milestone.
- **M2 — destination record discovery.** Verify the destination record against the
  routing target; introduce Tier-1 state and policy; add the signed floor advertisement;
  define Tier-1 replacement/conflict rules. Piggybacks on a route-discovery
  response/probe or an earlier authenticated *clear* delivery — **not** on the first
  confidential delivery (the origin needs the key *before* producing that).
- **M3a — authenticated-origin capability seam.** The general durable observation API,
  with a request-scoped authenticated-origin proof (below). Built and testable *before*
  it is load-bearing.
- **M3b — sealed routed payload.** Encrypt the exact payload bytes to a Tier-0 (or
  explicitly permitted Tier-1) key; **keep the manifest signature *outside* the seal,
  committing to the ciphertext** — moving it inside breaks verify-before-decrypt and is
  circular (it cannot commit to a ciphertext it is inside). Header privacy, if ever
  wanted, is a later nested/versioned format that accepts decrypt-before-auth — a
  metadata/anonymity change, not this. Enforce the local destination floor; arm the
  routed downgrade observation *before* accepting delivery.
- **M4+** — chunking, cached source routes, reassembly quotas, later anonymity.

## The observation seam (M3a)

The deferred seal-ratchet's design carries over (caller-bound, `applyChange`-backed,
request-failing, OR-floored, rotation-resetting), generalized by one parameter — *who
may name the key*. A raw `recordObservation({ key, kind })` is too easy for an honest
plugin to call with the last-hop key or an unverified field; this is not a
malicious-plugin sandbox (plugins are trusted in-process), but there is a cheap
**correctness** boundary: core verification returns an opaque, request-scoped
`AuthenticatedOrigin` handle (holds the normalized origin key, no public constructor;
validated via a closure / private symbol / `WeakSet`), and `recordObservation(handle,
kind)` accepts only a handle issued this request. Better still, a host helper does the
verification and returns the proof:

```
proof = authenticateRoutedOrigin(signedManifest)   // routed consumer
recordObservation(proof, "requireSealFrom")
```

Direct consumers get an analogous proof from the authenticated caller — one seam, no
pretence of sandboxing.

## Net effect

Kimi's two-root split and the equality-bound record discovery stand — routed key
discovery is a piggyback plus a check, not a lookup protocol. Sol's corrections keep it
honest: authenticate the exact bytes first (M1), establish destination-key policy second
(M2), then add confidentiality without conflating it with freshness, replay state, or
anonymity (M3). The remaining genuinely-new work is M1's manifest schema and replay
discipline, and the tier/floor policy — all bounded and specified above.
