# Routing security roadmap: from admission-gated delivery to authenticated sealed relay

**Status: design / for review.** `docs/routing.md` is the full routing roadmap
(discovery, caching, adaptive tables, anonymity). This is the security-focused
companion: it sequences the *security* properties — replay, origin authentication,
confidentiality, key trust — by their dependencies. **Substantially revised after a
Kimi review** that corrected the original spine (which conflated signing with
sealing) and, in doing so, shrank the "hard, novel" part from an unbuilt primitive to
a piggyback plus one equality check. It supersedes the earlier narrow replay-options
note.

## Where we are, honestly (Stage 1, shipped)

Stage 1 gives **admission-gated, loop-free, best-effort multi-hop delivery** over the
F2F trust graph. What it does **not** give:

- **Payloads are cleartext to every relay.**
- **`origin` is unsigned** — advisory, so a relay can spoof it.
- **Replay is not closed.** `send()` mints an envelope `id`, but `relay()`'s child
  envelope drops it, so the destination dedup never fires for relayed traffic. The
  guard is present but **dead**. `routing.md` used to claim replay was "handled in
  Stage 1"; that was false and is corrected (M0).

The Stage-1 metadata's weakness is that it is **unsigned**, not that it is unsealed —
the distinction the rest of this roadmap turns on.

## The corrected spine — two independent roots

The original draft claimed replay, origin-auth, and confidentiality were "three uses
of one sealed block." That is wrong: only confidentiality needs *encryption*. Replay
and origin-auth need *integrity/authenticity* — a **signature** a relay cannot forge —
not privacy. So there are two independent roots, not one:

```
origin's Ed25519 identity key  (already distributed & verified — signRecord/verifyRecord)
    └── SIGNED header  →  replay + origin-authentication          … no key discovery
destination's X25519 sealing key  (must be learned over relays)
    └── SEALED payload →  confidentiality                          … the (smaller) M2
```

Consequences that reorder everything:

1. **Replay and origin-auth land *before* any key-discovery problem** — they need only
   a signed envelope header, using the identity key the fabric already distributes.
2. **A signed *expiry* lets the replay dedup stay in-memory.** Dedup only has to
   outlive the window a captured envelope is valid; a signature-covered expiry bounds
   that window, so the `seen` map never needs durability. (The absence of an expiry is
   exactly what makes today's dedup and chat's nonce cache nervous about restarts.)
3. **Signed ≠ named.** A signed header proves "the holder of key K signed this," not
   "this is alice" — sybil origins are free. Routing is keyed by **key**, not name
   (`N(dest)`), so key-level authenticity is the right granularity — but the
   destination's *acceptance* policy must keep the existing discipline: an unknown
   origin gets unknown-profile treatment, **surfaced, never silently admitted**.
   *Authenticated ≠ admitted*, and a routed key is never auto-bound to a name (that is
   the gossip-trust hole the block-candidate fix closed).

## Key trust for a routed destination — a tier, not a new primitive

The confidentiality direction (origin must trust the destination's *sealing* key)
looked like the hard, novel part. It mostly isn't. Decompose what a **walk** actually
buys: (i) the record is **signed by the identity key** — the cryptographic binding of
sealing key to identity; and (ii) **liveness/provenance** — it arrived over a
connection authenticated as that identity, just now. Point (i) is **portable**: a
signed record carries it over any relay. The staple/gossip attack the key ban exists
to stop works only on *unsigned* bindings — a relay **cannot fabricate** a record
binding the victim's Ed25519 key to an attacker's X25519 key.

And routing hands us the check that makes a relayed key safe: **the routing target is
the destination's identity key.** So the discovery primitive is a **piggyback**: the
route probe (or first delivery) carries the destination's *signed record*, and the
origin accepts the sealing key iff, after `verifyRecord`, **`record.publicKey ===
envelope.dest`**. A relay that substitutes its own or an accomplice's record breaks
that equality and is caught; it can only **withhold** (an availability failure, and
visible) or replay a **stale** record (a pre-rotation key) — and the stale case is
already handled: a later walk that disagrees raises `sealConflict` → fail closed →
operator resolves. Confidentiality never fails open; it fails to *refusal*.

The coherent model is therefore **tiered**, reusing existing machinery:

- **Tier 0 — walk-verified** (`bindSealKey` today): full trust, unchanged.
- **Tier 1 — record-carried**: signed, identity-key-equal-to-`dest`, but relay-delivered
  (no liveness). Sealing to it is *strictly better than cleartext* — passive relays are
  shut out, and the residual attacks (withholding, stale key) both fail **loud**. Allowed,
  with the tier **surfaced** on the conversation/route (honesty, not silence).
- **Tier 2 — gossip / unsigned / key-mismatched**: never seal. Unchanged.

"Restrict sealed routing to previously-walked peers" folds in as a per-operator
**policy floor** on top (refuse Tier 1), not the architecture — and the likely F2F
mobility case (two laptops that met on a LAN, now reachable only through friends) is
already Tier 0. Two implementation notes: `sealKeyFor` is name-keyed while routing is
key-keyed, so the discovery path needs a key-indexed `sealKeyForKey`; and Tier-1 keys
must live in their own marked slot (a relayed record is **not** `sealSeen`), or the
tier semantics blur into the ambiguity `sealState` exists to remove.

## Milestones (revised order)

### M0 — honesty, with M1 folded in as a labelled non-security fix *(done here)*
`routing.md` corrected: Stage 1 has no replay/confidentiality/origin guarantee. And
the **mechanical dedup fix** (propagate `id` into `relay()`'s child so the live-but-
starved `firstDelivery` receives relayed ids) rides here as a **correctness** fix, not
a security control. It is real — with default `fanout: 3`, a diamond topology has two
parents forward to the destination independently, so *delivered-twice* happens without
any adversary. But against a malicious relay it closes nothing (a Stage-1 relay rewrites
the *payload*; the id is the least of it), so it is labelled "not a security control."
Dedup re-keys on `(origin, id)` at M2′, not here (a spoofable origin makes it cosmetic
now).

### M2′ — signed envelope header *(new; the actual replay + origin fix)*
`{ origin, dest, id, seq, expiry, payloadHash }` **signed by the origin's identity
key**, with the origin's signed self-record attached. The **destination** verifies
(self-record signature → key; header signature → same key). Closes replay **and**
origin-spoofing **against a malicious admitted relay** — the relay can't mint ids for
an origin it isn't, strip the id, swap the payload (hash), or extend the expiry. **No
key discovery needed.** Re-key dedup on `(origin, id)`; the signed expiry keeps it
in-memory. Relays verify only optionally, and **destination-only is the safe default**
— inviting every relay to verify attacker-chosen envelope signatures is a CPU-DoS
lever. Docs must say plainly: **signed ≠ private** — relays still read payloads here.

### M2 — record-piggyback key discovery *(rescoped, much smaller)*
The destination's signed record rides the probe / first delivery; the origin accepts
its sealing key on the linchpin check `record.publicKey === dest` after `verifyRecord`;
conflicts fail closed into the existing `sealConflict` path; Tier-1 keys are marked and
surfaced. No lookup service, no new trust assumption.

### M3 — sealed payloads + the shared observation seam
Seal payloads to the destination key (Tier 0 always; Tier 1 per policy, default
allow-with-surfacing), and move the origin signature *inside* the sealed block (hiding
the header fields too). Stand up **one origin-keyed durable observation seam** — the
generalization of the deferred seal-ratchet (`docs/durable-seal-ratchet.md`): the same
caller-bound, `applyChange`-backed, request-failing, OR-floored, rotation-resetting
capability, with exactly one parameter changed — **who may name the key**. Direct
consumers: the host binds it to `caller.publicKey`. Routed consumers: the plugin
supplies the origin it authenticated *from inside the verified payload* (the host
can't see that far) — contract: *the key passed must be one the plugin cryptographically
authenticated in this request*. Interface sketch: `recordObservation({ key, kind })`,
kinds extensible (`requireSealFrom` first), host-owned. This is where PR #49's
receiver-side downgrade ratchet gets its routed generalization: **cleartext routed
delivery is an allowed mode — sender-chosen, destination-floored** (the destination
advertises a sealed-only floor in its record and refuses cleartext routed delivery when
set; relays never decide).

### M4+ — performance and trust
Chunking / route caching / reassembly quotas (`routing.md` Stage 1.5), first-party
statistics for grayhole down-weighting (Stage 2), the anonymity knob (Stage 5).

## Net effect of the review

The original roadmap's "hard, novel, gates-everything" M2 is demoted to a piggyback,
an equality check, and a tier marker. The genuinely new work is M2′'s envelope schema
and the destination-floor policy — both bounded. Replay and origin-auth (M2′) can ship
without touching the key-trust question; confidentiality (M2 + M3) follows on the tier
model, not a new primitive.

## Open questions still worth a second reviewer

1. **M2′ envelope schema and canonicalization.** What exactly is signed, and how is it
   canonicalized so a relay cannot mutate-yet-reverify (field ordering, the `payloadHash`
   over cleartext vs ciphertext, whether `visited`/`ttl`/`budget` are inside or outside
   the signature — they are relay-mutated by design, so they must be *outside*, which
   means the signature must not cover them and replay/loop rules must tolerate that).
2. **Tier-1 surfacing and policy.** Is default-allow-with-surfacing right, or should
   Tier-1 sealing be default-off until an operator opts in per peer? Where is the tier
   shown so it is not ignored (the parked-marker lesson)?
3. **The destination sealed-only floor.** Its record advertises it; is that floor itself
   authenticated (signed record) so a relay can't strip it, and what is the failure mode
   if a routed sender ignores it — refuse at the destination (loud) is the intent.
4. **The seam's routed contract.** "The plugin passes a key it authenticated this
   request" is a least-authority convention, not an enforced boundary (plugins are
   trusted in-process). Is a convention enough, or is there a cheap enforcement?
