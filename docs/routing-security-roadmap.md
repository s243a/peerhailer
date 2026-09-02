# Routing security roadmap: from admission-gated delivery to authenticated sealed relay

**Status: M0–M3b merged to `main`, plus signed delivery receipts, durable
(restart-safe) replay/Tier-1, the High-1 causal identity/seal merge, and the M3a observation
seam — now ARMED: the per-origin `requireSealFrom` downgrade floor is wired and enforcing, with
an operator `hail route discard` recovery surface. Latest: durable Tier-1 *invalidation* fixes
the ordinary offline forget/rotate path, with three retirement/restart corner cases still open
(see the What-is-true-today bullet).** `docs/routing.md` is the full routing roadmap. This
security-focused companion sequences *origin authentication*, *duplicate suppression
(replay)*, *key trust*, and *confidentiality* by their dependencies. Kimi corrected the
original spine (signing was conflated with sealing); Sol then corrected several over-strong
claims and, in successive integrated reviews, surfaced the system-level composition gaps
folded in below.

**What is true today (m3b branch):** routed application data is **confidential by default** —
a send with no *usable* key (Tier-0 walk-verified, or a Tier-1 discovered key an operator
has **approved**) is refused, never sent in the clear; cleartext requires an explicit
`public` opt-out, which is also how a **data-free discovery probe** learns a peer's key.
Tier-0 posture is aggregated per identity key; a Tier-0 event invalidates a stale Tier-1 key
synchronously in a running daemon, and an *offline* forget/rotation is reconciled at the next
cold start via durable identity tombstones (below); the resolver fails closed on any ambiguous
or incoherent input. Bodies
are cleartext only when explicitly public; the *response* path now carries a **signed
delivery receipt** (below). Replay and Tier-1 are **restart-safe**: both persist to a
daemon-owned sidecar beside `directory.json`, so a bounce neither reopens a still-unexpired
replay window nor drops an approved sealing key to a first cleartext re-discovery.

## Where we are, honestly (M1 branch)

Admission-gated, loop-free-**by-construction-among-honest-relays**, best-effort
multi-hop delivery over the F2F graph, now with an origin-signed cleartext wrapper:

- **Application-data payloads are confidential by default** (m3b branch): a send with no
  usable key is refused, sealed sends are opaque to relays, and only an explicit `public`
  payload (a discovery probe, or data the caller marked public) is cleartext to relays.
- The outer **`origin` remains unsigned**, but it is discarded at delivery; consumers
  receive only the manifest's authenticated full-width `originKeyId`.
- Replay is bounded by `(originKeyId,messageId,blockIndex)` until signed expiry + skew. The
  guard survives daemon config reloads **and process restart** — reservations persist to a
  sidecar (`route-replay.json`), rehydrated on start with expired entries dropped, so a
  still-unexpired envelope cannot be replayed once by bouncing the daemon. (A crash between
  the reservation and the consumer completing is still at-most-once *attempt*, as before.)
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
  request bypassed; it must seal its own response. A **signed delivery receipt** now proves
  *what the destination did* with the request (delivered/refused, implemented); **sealing the
  response body** is still later work.
- Sealing to a **Tier-1** destination now survives a restart. The record-carried key store
  persists to a sidecar (`route-keys.json`), so an **approved** key is usable immediately on
  restart — no first send resolving `cleartext` and re-discovering. A merely *pending* key is
  still unusable until approved, and its binding is re-verified against the signed record on
  load, so a hand edit cannot inject an unsigned key.
- **Tier-1 *invalidation* is durable, cap-safe against count/forged crowding, clock-
  independent, and now causal under concurrent writers (generations are allocated under the
  state lock); a narrowed conflict crash-window and a pre-fix persisted-collision residual
  remain (Sol's re-reviews — the lock-allocation primitive seeds the causal-merge workstream).**
  The mechanism: `forget`/`rotateKey` write durable identity
  **tombstones** (`{keyId, at, reason, gen}`, union-merged in `reconcilePersist`) into
  `directory.json` — the CLI-writable, daemon-read channel that needs no sidecar write; a daemon
  **cold-start reconcile** forgets any entry a tombstone causally outranks (below), runs a Tier-0
  posture sweep, then durably persists and consumes, before serving. A never-walked entry has no
  tombstone and no posture, so absence-from-directory is never a forget signal. **Status of the
  residuals (sequential path robust; a concurrency residual remains — Sol's second re-review):**
  1. *Tombstone-cap eviction (R1, HIGH) — count-based crowding CLOSED; concurrent-writer
     consumption CLOSED (for forward writes).* Count-based eviction is abolished: a tombstone is
     dropped only once the daemon has DURABLY applied it (`routeGenApplied`, a `directory.json`
     high-water integer, gates a `gen <= routeGenApplied` prune), so nothing pending is ever evicted
     and 256 forged tombstones cannot crowd a real one out. `MAX_TOMBSTONES` (256) is now an advisory
     warn-once threshold; the startup sequence (apply → durable sidecar persist → consume under the
     lock → `markTombstonesApplied`) loses neither a tombstone nor its forget to a crash. Consumption
     treats the scalar `routeGen` as a contiguous global prefix — now SOUND, because generations are
     lock-allocated (residual 2): a retirement finalized after this boot's load reads a disk whose max
     is `>= N` and allocates `>= N+1`, so no unseen retirement can carry a gen `<= N` and be pruned as
     already-applied.
  2. *Wall-clock ordering (R2, HIGH) — wall-clock hazard CLOSED; the generation is now causal under
     concurrency, CLOSED for forward writes (Sol F1).* A file-global monotone `routeGen` counter
     (load-as-max over the field, the tombstones' gens, AND `routeGenApplied`, max-merge everywhere)
     stamps every retirement and every Tier-1 claim; the reconcile compares by `gen` not the wall
     clock (an approval outranks a retirement iff `gen >= t.gen`), so the clock-regression hazard is
     gone. **The concurrent-writer gen-collision is now closed:** `tombstone()` mints a PROVISIONAL
     tombstone (`gen: null`) and defers allocation to `finalizeRouteGens`, which runs UNDER the state
     lock (in both `reconcilePersist` and the daemon's `applyChange`) and stamps each provisional
     strictly above the merged on-disk `max(routeGen, routeGenApplied, tombstone gens)`. Writes to
     `directory.json` are serialized by that lock, so allocated generations are globally unique and
     strictly increasing in file-write order — two stale writers (a CLI `forget` racing a page-driven
     `forget`) can no longer both mint `N+1`, the strict `<` no longer reads a spurious tie as "the
     approver had seen the retirement", and a second retirement can no longer be discarded as
     already-applied. **Residuals:** (a) a gen collision *already persisted by the old racing code
     before this fix* keeps its spurious tie-keep — undetectable after the fact (it required running
     the pre-fix code under a concurrent race) and accepted; no migration rewrite. (b) The
     uniqueness guarantee holds while the state lock is actually held; `withStateLock` gives up after
     ~20s of continuous contention (or steals a stale lock) and proceeds lock-less, where two writers
     could again collide — but that same fallback already permits a torn read-modify-write that loses
     whole tombstones (a strictly worse outcome), so it adds no new failure class. Both losses of
     exclusivity now emit a loud `[state]` log line (a silent give-up would have turned the causal
     invariant best-effort with nothing in the audit trail). The proper close is the deferred
     causal-merge workstream (lock-serialized per-record allocation), for which `finalizeRouteGens`
     is the first primitive.
  3. *Conflict restart window (R3, medium) — power-loss durability improved; the crash window
     remains, narrower.* `saveState(_, _, { durable })` fsyncs the temp fd before the rename and
     best-effort fsyncs the parent directory after, on the restricting sidecar persists, the retry
     write, and the startup reconcile persist; and `persistDegraded` now clears only on a DURABLE
     write, so a non-durable additive persist can no longer cancel a pending recovery (Sol F3).
     **Honest residuals:** (a) ANY initial restricting-write failure followed by a restart *before
     the first successful retry* still sheds a conflict — not only permanently-failing media, just
     a narrower window, flagged by the `SECURITY` log and `persistDegraded`; (b) the parent-dir
     fsync is best-effort and its error is swallowed, so the rename-survival guarantee holds only
     where directory fsync succeeds (POSIX journaling filesystems; degraded elsewhere). A durable
     conflict marker was deliberately not added (relay-forceable DoS surface).

  `routeGen` is the shared **logical-generation primitive** the deferred directory causal-merge
  workstream (below) would generalize per-record — the max-merge discipline here is exactly what
  that work needs and is not throwaway. `finalizeRouteGens` (lock-serialized allocation that
  rebases pending claims against on-disk truth) is that workstream's first primitive: the
  per-record `rev` machinery would apply the same "allocate/rebase under the lock" discipline
  instead of trusting a stale writer's pre-lock number.
- **Multi-writer identity/seal merge is now causal (High-1, `48f25a5`); a non-security
  residual remains.** The directory once merged concurrent state by a per-record monotone
  `rev` (higher wins), which is not a causal clock — a stale multi-writer could restore a
  retired Tier-0 identity/sealing key. That is fixed: `mergeByRevision` uses the writer's
  baseline as a causal ancestor so whichever side actually rotated the identity carries the
  identity+seal unit, and a same-identity seal is a fail-closed 3-way merge
  (`directory.js` sameCanonicalKey/sealUnit). Residual (pre-existing, non-security): the
  *non-security* record fields (profile/addresses/note) still follow whole-record `rev`, so a
  stale writer can clobber a concurrent non-security edit, and two concurrent rotations to
  *different* identities fall back to `rev`. A full causal directory (vector clocks, or a
  single-writer CLI-signals-daemon discipline) is the larger optional workstream — and would
  generalize the Tier-1 `routeGen` logical generation (above) per-record, reusing its max-merge
  discipline rather than reinventing it.
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
replays the valid envelope, it is accepted again. Both options now exist and the durable
one is wired:

- **session-only** dedup — in-memory, not restart-safe (**implemented**); the guard runs
  this way whenever no persistence port is injected (all in-process consumers, tests); or
- **across-restart** dedup — durable, retained until `expiresAt` (+ skew) (**implemented**).
  The guard takes an injected `persist`/`initial` port; the daemon wires it to a sidecar
  (`route-replay.json`), writing each new reservation and rehydrating on start (expired
  dropped). The module itself stays pure — it does no I/O. Sidecars are daemon-owned and
  written last-writer-wins (no `withStateLock`, unlike `directory.json`, which is multi-
  writer): one daemon per home is assumed, and two daemons on one home clobber each other's
  sidecars — fail-directions are availability (a lost reservation reopens a bounded window; a
  lost key refuses), acceptable, since that configuration is already broken for directory
  reasons. One honest edge: the monotonic time high-water mark is *deliberately not*
  persisted. So the NTP-rollback fail-closed property is per-process, not across-restart — a
  >skew backward clock jump spanning a restart could make any swept envelope whose `exp` falls
  in the rollback span admissible again (a per-envelope-class reopening, each bounded by its
  signed ≤7-min window; duplicate delivery, never a confidentiality loss). Persisting the
  high-water would close that but at a worse cost: a transient *forward* clock error would then
  persist a far-future mark that refuses all routed traffic until wall time catches up — and a
  restart, the natural recovery, could no longer clear it. Restart-as-recovery for a bad clock
  is worth more than closing a bounded, duplicate-only replay edge, so this stays documented.

A signed expiry makes the durable state **bounded and garbage-collectable** (the live set is
the ~7-minute window), which is what makes write-per-reservation cheap enough to be safe.

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
rotation, forget) invalidates the Tier-1 entry synchronously in a running daemon, and an
*offline* forget/rotation is reconciled at the next cold start via durable identity
tombstones + a startup Tier-1 reconcile; two conflicting Tier-0 keys keep the existing
deliberate-resolution path. (Signed key epochs / short-lived
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
- **M3a — authenticated-origin capability seam. Implemented and ARMED.** The durable
  observation store (`src/routedObservation.js`), the request-scoped `AuthenticatedOrigin`
  proof, and the first observation kind (`requireSealFrom`) are built and wired:
  `openRoutedMessage` mints the proof and surfaces `sealed`; the route plugin records the
  marker on every sealed delivery (durably, best-effort, before accepting delivery); the
  daemon persists it to a sidecar. The enforcement floor is now **armed**: `bin/hail.js`
  wires `requireSealFrom` to that store, so a clear message from an origin the destination has
  opened a seal from is refused `downgrade-refused` (post-authentication, receiptable), and
  the refusal carries the key-only discovery record so recovery is one resend. Always-on, no
  disarm flag — the floor is per-origin and fires only for an origin that *demonstrably*
  sealed to us, it only ADDS refusals (monotone), and a local disarm would be a standing
  downgrade invitation. The one escape hatch stays the offline capacity/rotation recovery:
  prune `route-observations.json` and restart. See "The observation seam (M3a)" below for the
  refuse-all-clear decision, the `seal`-refusal re-teach, and the discard recovery flow.
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

**Implemented (mechanism).** `src/routedObservation.js` holds the proof (`authenticatedOrigin`
mints an opaque handle validated by a `WeakSet` — a bare key is not a proof) and the durable
store: key-indexed, OR-floored (a marker is never cleared — a relay must not shed a
downgrade defence), rotation-resetting for free (a rotated identity is a new key), and
fail-closed at capacity (a flood of throwaway identities cannot evict an existing marker).
`openRoutedMessage` mints the proof on a verified open and surfaces `sealed`; the route plugin
records `requireSealFrom` on each sealed delivery, before accepting it. The store persists to
a `route-observations.json` sidecar, like the replay guard and Tier-1 key store.

**Armed.** `openRoutedMessage` refuses a clear message `downgrade-refused` when the injected
`requireSealFrom(origin)` says so (post-authentication, so receiptable), and the plugin attaches
the key-only discovery record to that refusal as it does for the `cleartext-refused` floor.
`bin/hail.js` now supplies that policy — `requireSealFrom(k) = routedObservationStore.has(k,
"requireSealFrom")` — so the floor enforces against the same durable markers recording writes.
Two questions settled at arming:

- *Refuse-all-clear, `public` included — a one-way ratchet.* An origin that has sealed to us may
  still *intend* a later clear message (an explicit `public` send), but on the wire a deliberate
  `public` send and a confused-deputy clear send are byte-identical (`payloadMode:"clear"`,
  signed by the origin either way); the destination has no signal to tell intent from mistake,
  and any carve-out would need a new signed field the confused deputy would also set. Since a
  relay cannot forge a clear message (`payloadMode` is under the manifest signature), the floor's
  whole value is refusing to participate in the origin's *own* downgrade mistakes — so refusing
  the deliberate `public` too is the acceptable cost. The consequence, documented: per-origin
  confidentiality ratchets upward — an origin **whose marker was successfully recorded** must seal
  everything to this destination thereafter (until the *origin's* identity key rotates; the marker
  is key-indexed by origin, so a new origin key is a fresh start — the destination rotating its own
  identity does not reset a marker it holds). It can still say anything — sealed. The ratchet binds
  only recorded origins: if the marker was not recorded (the store was at capacity, §capacity), that
  origin's later clear is still accepted — "once sealed, thereafter refused" is scoped to a
  recorded marker, and recording is now a durable, retried write (below) so a persist failure no
  longer silently drops the floor.
- *The clear-after-seal recovery flows, and the `seal` re-teach.* An earlier draft claimed the
  discovery-probe deadlock does not recur "because a routed origin that sealed already holds our
  key." Wrong (Kimi, M3a review): it recurs in two flows, which is why the refusal must carry the
  discovery record. (1) A relay shows the origin a second, different record for the destination →
  the origin's Tier-1 entry goes `record-conflict`, its key voided, and re-learning the key rides
  a clear probe. (2) The destination rotates its sealing key → the origin seals to the retired
  key. Armed, both probes are refused `downgrade-refused` — a deadlock — *unless the refusal
  teaches the current key*, which it now does; the origin then reseals in one retry. For flow (2)
  the arming commit also attaches the record to a post-authentication **`seal`** refusal (only
  `seal` — the decrypt-failed rotation signal — not `sealed`/`seal-origin-mismatch`/`body`, which
  are malformed/attack/origin-bug and must teach nothing): a rotated-away origin's next sealed
  send comes back `seal` + record, its `observeDiscovery` flips it to a loud local
  `record-conflict`, and all further sends refuse *locally* (`seal-refused:tier1-conflict`)
  instead of spraying the network. The sticky conflict is correct — from the origin's seat,
  rotation and relay-replay are indistinguishable hearsay, so a human decides — and the recovery
  is the discard surface below.

**Recovery — the operator discard surface.** Both flows end in a sticky origin-side
`record-conflict` that only an explicit operator act may clear. `router.discardRoutedSeal(dest)`
(control `POST /api/route/seal-discard`, CLI `hail route discard`) drops the Tier-1 *key* state
so the key can be re-discovered and re-approved. It preserves the sticky property that protects
against auto-clear downgrade: it is reachable only through the control API/CLI (no code path
calls it, no wire input triggers it); it is monotone-restricting (it only deletes — the state
after is `none`, which the resolver refuses, never cleartext); and it **never touches the
`requireSealFrom` marker**, so the armed downgrade posture cannot be shed through it. Re-sealing
still needs a fresh discovery observation AND a separate operator `approve` — the same human gate
Tier-1 always had, so a fooled operator can lose a key but not bind a wrong one; a relay that loops
conflicts just forces the operator back to the review step, never picking the winner. The safe
workflow is to **pin** the approval (`hail route approve --seal-key-file <reviewed>`): the pin is
*recommended, not mechanically enforced* — `approve` without a pin still requires the explicit
operator act, and if the operator blesses a relay-replayed stale key it fails at the destination as
`seal`, re-teaches, and flips back to conflict (a loud loop, not a confidentiality break). Discard's
CLI output spells out the pinned form. Deliberately NOT built: a "resolve conflict to key X" op —
discard + re-discover + pinned approve reaches the same end state through the existing, already-
audited gates.

Operational note: the observation store is fail-closed at capacity and never evicts, so a flood
of throwaway sealed identities (cheap for an admitted relay) can fill it permanently; an operator
recovers coverage by pruning `route-observations.json` (a new origin then gains no marker and its
clear still delivers; existing markers keep refusing). The daemon logs the armed marker count at
startup so an operator whose sidecar pre-recorded markers sees the floor take effect.

## Net effect

Kimi's two-root split and the equality-bound record discovery stand — routed key
discovery is a piggyback plus a check, not a lookup protocol. Sol's corrections keep it
honest: authenticate the exact bytes first (M1), establish destination-key policy second
(M2), then add confidentiality without conflating it with freshness, replay state, or
anonymity (M3). **M0–M3b are implemented**, plus signed delivery receipts, durable
(restart-safe) replay/Tier-1, and the **M3a observation seam — now armed** — authenticated
manifest + replay dedup (M1), Tier-1 key discovery (M2), and sealed payloads with
confidential-by-default sends, per-key Tier-1 approval, identity-aggregated Tier-0, and the
enforced floor (M3b), all hardened after Sol's integrated review, driveable from the CLI
(`hail route status|approve|discard|send` against a live `--ui` daemon's control API, since the
Tier-1 store is in the daemon's memory), with the response path proven by a signed receipt,
replay + Tier-1 state persisted across a restart, and the durable observation seam recording each
sealed delivery against a request-scoped authenticated-origin proof and enforcing the per-origin
`requireSealFrom` downgrade floor (refuse-all-clear, one-way ratchet, `seal`-refusal re-teach,
operator discard recovery). The remaining work is deferred and named where it arises above:
binding a receipt to a message's *terminal* outcome on the same durable seam, the signed floor
*advertisement*, sealing the response *body*, and the later M4+ chunking/anonymity.
