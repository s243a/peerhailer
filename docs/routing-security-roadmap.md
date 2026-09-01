# Routing security roadmap: from admission-gated delivery to authenticated sealed relay

**Status: M0–M2 merged to `main`; M3b (sealed routed payload) + the confidential-by-default
hardening implemented on `routing-m3b-sealed`, in review.** `docs/routing.md` is the full
routing roadmap. This security-focused companion sequences *origin authentication*,
*duplicate suppression (replay)*, *key trust*, and *confidentiality* by their dependencies.
Kimi corrected the original spine (signing was conflated with sealing); Sol then corrected
several over-strong claims and, in an integrated review, surfaced the system-level
composition gaps folded in below.

**What is true today (m3b branch):** routed application data is **confidential by default** —
a send with no *usable* key (Tier-0 walk-verified, or a Tier-1 discovered key an operator
has **approved**) is refused, never sent in the clear; cleartext requires an explicit
`public` opt-out, which is also how a **data-free discovery probe** learns a peer's key.
Tier-0 posture is aggregated per identity key; a Tier-0 event invalidates a stale Tier-1
key synchronously; the resolver fails closed on any ambiguous or incoherent input. Bodies
are cleartext only when explicitly public; the *response* path is still unsigned and
unsealed (below), and replay/Tier-1 remain per-process.

## Where we are, honestly (M1 branch)

Admission-gated, loop-free-**by-construction-among-honest-relays**, best-effort
multi-hop delivery over the F2F graph, now with an origin-signed cleartext wrapper:

- **Application-data payloads are confidential by default** (m3b branch): a send with no
  usable key is refused, sealed sends are opaque to relays, and only an explicit `public`
  payload (a discovery probe, or data the caller marked public) is cleartext to relays.
- The outer **`origin` remains unsigned**, but it is discarded at delivery; consumers
  receive only the manifest's authenticated full-width `originKeyId`.
- Replay is bounded per process by `(originKeyId,messageId,blockIndex)` until signed
  expiry + skew. The guard survives daemon config reloads, **not process restart**.
- The pure engine's unsigned M0 `id` cache is deliberately bypassed by the M1 plugin:
  it runs before cryptographic open and would otherwise be poisonable by a relay.
- **"Loop-free" is a cooperative property, not a security one.** The visited-set / TTL
  / budget stop loops among relays that *follow the protocol*. A relay that does not —
  it can strip visited entries, reset TTL/budget, fork the envelope, and reinject it
  into a cycle — is not stopped by any end-to-end signature. The defences against that
  are and remain **local**: clamp every field on receipt, exclude the authenticated
  immediate caller, rate-limit by caller, cap concurrent forwarding work (eight
  searches per plugin across host + peer entries, two per immediate peer caller), and treat
  visited/TTL/budget as *cooperative routing controls, never authenticated facts*.
- Endpoint rollout is a flag day until route-version negotiation exists. Old and new
  intermediate relays carry the opaque wrapper, but old/new destination behavior is
  not interoperable; upgrade destinations before originating M1 messages.
- The threaded response is still unsigned **and unsealed**. `delivered`, acknowledgements,
  and refusal reasons are routing feedback, **not cryptographic proof that the destination
  acted**; an intermediary can forge, alter, or suppress them. And M3b seals only the
  *request* body — the consumer's response travels back through the same relays in the
  clear. Today's consumer only acks, but the first content-returning consumer (a routed
  `files get`) would send its payload back cleartext through the very relays the sealed
  request bypassed; it must seal its own response. Signed/sealed receipts are later work.
- Sealing to a **Tier-1** destination does not survive a restart. The record-carried key
  store is session-scoped, so after a restart the first send to a Tier-1-only destination
  resolves `cleartext` (no key, no dispute) — and that first send is also the
  re-discovery vehicle, so the payload that was sealed pre-restart goes out clear once.
  Tier-0 peers are protected by `sealRequired`'s durable floor; Tier-1 peers have no
  equivalent until durable observation (M3a). The destination's own floor is the only
  restart-safe backstop today.
- **Multi-writer state can restore a retired Tier-0 sealing key (pre-existing, out of
  routing scope).** The directory merges concurrent state via a per-record monotone `rev`
  (higher wins). That is not a causal clock: a process that loaded a stale snapshot and
  made several mutations reaches a higher `rev` than another process's newer one-step
  identity rotation, and its OLD identity/sealing key wins the merge. This predates the
  routing work and affects all sealed state, not just routed keys; a real fix is a
  directory-concurrency change (causal ordering, or a single-writer discipline where the
  CLI signals the daemon rather than writing disk itself — the SIGHUP reload is a step
  toward that). Tracked separately, not in this branch.
- **A keyless current record does not drop an approved routed key, deliberately.** If a
  discovered record for a destination arrives with no sealing key, an already-approved key
  is kept — because a relay can replay an *old* keyless record, and letting that drop an
  approved key would be an availability lever (force-refuse). Retirement is handled by a
  Tier-0 walk (which invalidates Tier 1), not by trusting a keyless record.

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

- `messageId` is exactly 16 random bytes encoded as 22-character unpadded base64url
  (128 random bits); there is **no** global origin sequence (it would complicate
  legitimate out-of-order delivery). `blockIndex`/`blockCount` are present
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
replays the valid envelope, it is accepted again. The implementation picks the first:

- **session-only** dedup — in-memory, *explicitly not restart-safe* (**implemented**);
  the daemon retains this same guard across plugin/config reloads; or
- **across-restart** dedup — durable, retained until `expiresAt` (+ skew).

A signed expiry makes the durable state **bounded and garbage-collectable** — valuable
— but not unnecessary.

Validation, enforced locally regardless of what the origin signed:

- both `issuedAt`/`expiresAt` are safe integers; `expiresAt > issuedAt`;
  `expiresAt - issuedAt ≤ MAX_VALIDITY` (minutes, not hours); `issuedAt ≤ now +
  CLOCK_SKEW`; `expiresAt ≥ now − CLOCK_SKEW`.
- keep a dedup entry until `expiresAt + CLOCK_SKEW`. A relay that holds a message until
  just before expiry spends its lifetime; it does not extend it.
- hold local wall time to a process high-water mark. If the clock jumps forward and
  entries are swept, a later rollback fails closed rather than reopening them.

Dedup key: `(originKeyId, messageId)` unchunked, `(originKeyId, messageId, blockIndex)`
for blocks.

Processing order (cheap-and-safe first, allocate nothing for messages policy will
refuse): shape/size/claimed-destination preflight → verify record + manifest →
classify/authorize the authenticated origin → non-reserving time/replay/capacity check
→ canonical payload/digest/strict-JSON validation → repeat-and-reserve replay state →
deliver. Bounds: global + per-origin live-entry caps, last-hop rate limit, fixed
message-id length, a 700 kB serialized-body ceiling, and a 950 kB total signed-wrapper
ceiling below the 1 MB peer request limit. **At capacity, fail closed on
the new message — never evict an unexpired entry while still claiming replay
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

**Policy (as implemented): confidential-by-default with per-key approval.** A discovered
Tier-1 key is held **pending** and is not usable for sealing until a person **approves** it
by fingerprint (`approveRoutedSeal` / the `/api/route/seal-approve` control endpoint) — the
Tier-1 analogue of a walk, and what replaces the earlier global `allow-record-carried`
opt-in. A confidential send with only a pending, conflicted, or absent key is **refused**,
never sent clear. When approving or before a Tier-1 send, surface the tier, sealing-key
fingerprint, and the absence of a liveness proof — and **do not show the Tier-0 lock**. (No
record *age* is surfaced: a relay selects which past record it replays, so age would be an
attacker-chosen value wearing a freshness label.)
State model and rules: `record-approved` / `record-carried` (pending) / `record-conflict`
are distinct from the Tier-0 `verified`/`reverify`/`conflict` states; Tier 0 always wins
over Tier 1; a matching Tier-1 record adds no authority; differing Tier-1 records cause
Tier-1 refusal (not auto-selection) and void any approval; a Tier-0 event (walk, accept,
rotation, forget) invalidates the Tier-1 entry synchronously; two conflicting Tier-0 keys
keep the existing deliberate-resolution path. (Signed key epochs / short-lived
records reduce stale exposure but cannot fully solve first-observation revocation without
an online authority, a transparency log, or a prior monotonic observation.)

## Destination confidentiality floor

A signed advertised floor helps honest senders avoid doomed cleartext, but the
**destination's local enforcement is the actual mechanism** — a relay can suppress the
record, replay an older one lacking the floor, or hide the current policy, yet cannot
make the destination accept cleartext if the destination checks its **current local
policy at delivery**:

1. destination stores `requireSealedRouting` locally (**implemented**);
2. the field rides its signed public record (advisory to honest senders) — **not yet
   implemented**: the discovery record is key-only, so an honest sender cannot pre-flight
   the floor and instead learns it from a `cleartext-refused` refusal (which now carries
   the destination's key so the sender can retry sealed);
3. the signed manifest binds `payloadMode` (**implemented**);
4. the destination rejects `payloadMode = clear` whenever its local floor requires
   sealing — the local check wins over any record a sender presents;
5. a relay cannot turn sealed content into valid cleartext (it cannot produce the
   origin's signature over a different mode + digest).

"Loud refusal" is loud *locally*; a relay can suppress any response, so if the origin
must distinguish a refusal from a grayhole, the destination returns a **signed receipt
bound to `(origin, messageId, blockIndex, outcome)`** (**implemented**, `src/routeReceipt.js`).
The destination signs it with its **identity key** — the key the origin routed to — for both
a `delivered` and any *authenticated* refusal (a refusal before authentication carries no
receipt: there is no authenticated origin to bind, only relay-tampered bytes). The origin
verifies it against the routing target it chose and the id it minted, so a relay can neither
forge a `delivered` for a key it does not hold, replay a receipt onto a different message, nor
silently downgrade a refusal reason; a *missing* receipt is itself the signal (treat it as a
possible grayhole, not a delivery). The receipt is signed, not private — it names key ids and
an outcome, nothing secret.

A receipt attests *one presentation*, not the message id's final fate. A relay holding a valid
wrapper can obtain a genuine `refused` receipt for the same `(origin, messageId)` that also
delivers. With a payload-mangled copy the order is refuse-then-deliver: the manifest still
authenticates, so the destination signs a `payload-digest` refusal *before* it reserves
(`guard.admit` is last), and the real wrapper still delivers afterward. The `replay:duplicate`
variant is the mirror image — the real wrapper lands and admits *first*, then a replayed copy
refuses. Either way the destination signs two true receipts for one id, and a forking relay
forwards only the `refused` one while swallowing the `delivered`. So the origin can be shown a
*true, verified* `refused` for a message that in fact landed. This is strictly weaker than the
grayhole a relay could already cause (a dropped receipt), and it can never manufacture a false
`delivered` — that requires the destination's key. Treat a verified `refused` as "at least one
presentation was refused", not "nothing was delivered". Binding a receipt to the message id's
terminal outcome would need the destination to persist per-id state (M3a durable observation),
out of scope here.

One outcome deliberately carries **no** receipt: a sealed wrapper a destination cannot open
(it holds no sealing key) is refused `unsupported-mode` in the pre-authentication capability
gate, so the origin sees `present:false` (a possible grayhole). This is a *destination
misconfiguration* — a record advertised a sealing key the daemon does not actually hold — not
a relay-reachable state, since `payloadMode` is signed and a relay cannot flip a send to
sealed. Making it receiptable would mean authenticating before the cheap capability check and
splitting the mode gate three ways, to serve a misconfiguration signal; deferred. The
operational reading meanwhile: a sealed send to a peer whose record advertised a seal key that
returns `present:false` most likely means the destination cannot open sealed (misconfig), not
a grayhole. If it is ever fixed, move both halves of the mode gate (capability + floor)
post-authentication in one change so the gate is not split.

Lowering the floor is a deliberate destination-side change; a replayed remote record never lowers
local enforcement.

## Milestones (reordered per the review)

- **M0 — honesty. Done.** `routing.md` corrected, and the *unsigned* `id` now
  propagates into `relay()`'s child, so the live-but-starved dedup catches **accidental**
  duplicates (real: with `fanout:3`, a diamond delivers twice with no adversary) — a
  **correctness** fix, explicitly *not a security control* (an unsigned id is strippable
  and re-mintable by a dishonest relay; that is M1). Regression test: a two-hop replayed
  id is delivered once.
- **M1 — authenticated route manifest. Implemented on `routing-m1-wrapper`.** Fixed
  canonical schema; Ed25519 origin authentication; destination + payload commitment;
  explicit expiry/skew/high-water rules; a stated per-process replay guarantee; and
  plugin wrap/open wiring around an unchanged crypto-agnostic engine. The unsigned M0
  cache is bypassed, IDs are 128 random bits, authorization precedes replay allocation,
  recursive searches are capped globally/per caller, downstream work claims cannot
  replenish budget, and malformed/oversized encodings fail closed. **Signed ≠ private** — relays still
  read payloads at this milestone.
- **M2 — destination record discovery. Implemented (Tier-1 store + discovery wiring) on
  `routing-m2-tier1`.** Verify the destination record against the routing target; introduce
  Tier-1 state and policy; define Tier-1 replacement/conflict rules. Piggybacks on a
  route-discovery response/probe or an earlier authenticated *clear* delivery — **not** on
  the first confidential delivery (the origin needs the key *before* producing that). The
  destination attaches a **key-only** signed record (name + identity key + sealing key,
  *no addresses*): discovery is key discovery, and handing direct addresses to return-path
  relays would undercut F2F reachability. The store is session-scoped and identity-key-
  indexed, quarantined from Tier-0's persisted model; two differing keys for one target are
  a sticky conflict, not a selection; conflicts survive capacity eviction. No record "age"
  is surfaced — a Tier-1 record carries no liveness, and any age would be a value a relay
  selects. The **signed floor advertisement** folds into M3b, where it is enforceable (a
  destination rejecting `clear` needs a sealed alternative to exist first).
- **M3a — authenticated-origin capability seam.** The general durable observation API,
  with a request-scoped authenticated-origin proof (below). Built and testable *before*
  it is load-bearing.
- **M3b — sealed routed payload. Implemented on `routing-m3b-sealed`.** `wrap` seals the
  body to the destination's X25519 key signed by the origin identity; the manifest commits
  to the ciphertext and `payloadMode:"sealed"`. `open` runs every M1 gate first, then
  decrypts and binds the seal's signer to the authenticated manifest origin. `send`
  resolves the seal target through the single `{tier,key,state}` resolver (Tier 0 wins,
  Tier 1 opt-in, a conflict at either tier refuses — never cleartext), and the local floor
  (`requireSealed`) refuses a clear delivery. F2 lands (a Tier-0 posture forgets Tier 1);
  the seal key is validated at construction; a live A→B→D Tier-1 test proves relays carry
  only ciphertext. Encrypt the exact payload bytes to a Tier-0 (or
  explicitly permitted Tier-1) key; **keep the manifest signature *outside* the seal,
  committing to the ciphertext** — moving it inside breaks verify-before-decrypt and is
  circular (it cannot commit to a ciphertext it is inside). Header privacy, if ever
  wanted, is a later nested/versioned format that accepts decrypt-before-auth — a
  metadata/anonymity change, not this. Enforce the local destination floor; arm the
  routed downgrade observation *before* accepting delivery.

  **Acceptance criteria carried from the M2 review (Kimi), where the design can silently
  go wrong:**
  - **A Tier-1 `record-conflict` must refuse the sealed send, never fall through to
    cleartext.** A relay replaying an older signed record manufactures the conflict; if
    the send policy reads "no usable Tier-1 key → send clear," the relay has a downgrade
    lever. The rule: conflict → refuse; any cleartext fallback is operator opt-in, loud,
    never automatic — and the **destination floor is the actual lever-closer** (a relay
    can suppress the record but cannot make a floored destination accept `clear`). This
    extends "refusal, not selection" from the key-selection layer down to the *send
    decision*. Where the origin had *no* Tier-0 key to begin with, conflict-refusal costs
    availability, not confidentiality — the message was never going to be sealed; the
    invariant bites only when a conflict displaces a key the origin already had. (Aside:
    a loud refusal is also a remote oracle — a relay replays a stale record and learns
    sealed-vs-refused; inherent to any fail-loud design, one line in the doc, low.)
  - **A single resolver, `{tier, key, state}`, so no call site can consult Tier-1 while a
    Tier-0 key exists.** Implemented (`src/routedSealResolver.js`); "Tier 0 always wins"
    is now code, and an unrecognised state fails closed.
  - **Tier-0 supersedes a Tier-1 entry.** Implemented *lazily*: `send` calls
    `routedKeyStore.forget(destKeyId)` whenever Tier 0 has any posture
    (`state !== "unverified"`). This is sufficient because the single resolver already
    makes a stale Tier-1 entry unreadable once Tier 0 has posture — the forget is hygiene
    (keeping the surface honest), not correctness. A walk-triggered forget would clear it
    a send earlier but needs the store threaded into the walk path; deferred.
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
anonymity (M3). **M0–M3b are implemented** — authenticated manifest + per-process replay
(M1), Tier-1 key discovery (M2), and sealed payloads with confidential-by-default sends,
per-key Tier-1 approval, identity-aggregated Tier-0, and the enforced floor (M3b), all
hardened after Sol's integrated review, and driveable from the CLI (`hail route
status|approve|send` against a live `--ui` daemon's control API, since the Tier-1 store is
in-memory). The remaining work is deferred and named where it arises above: durable
(restart-safe) replay/Tier-1 and the M3a observation seam, signed response/refusal
receipts, the signed floor *advertisement*, and the later M4+ chunking/anonymity.
