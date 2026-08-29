# Routing security roadmap: from admission-gated delivery to authenticated sealed relay

**Status: design / for review.** `docs/routing.md` is the full routing roadmap
(stages 1–6: discovery, caching, adaptive tables, anonymity). This is the narrower,
security-focused companion: it sequences the *security* properties — replay, origin
authentication, confidentiality, key discovery — by their **dependencies**, corrects
a false claim in `routing.md`, and situates the one near-term choice (a mechanical
replay fix) on that path. It supersedes the earlier narrow replay-options note.

## Where we are, honestly (Stage 1, shipped)

Stage 1 gives **admission-gated, loop-free, best-effort multi-hop delivery** over the
F2F trust graph. What it does **not** give, said plainly:

- **Payloads are cleartext to every relay.** A relay reads everything it carries.
- **`origin` is unsigned** — advisory only, so a relay can spoof it.
- **Replay is not actually closed.** `send()` mints an envelope `id`, but `relay()`'s
  child envelope drops it, so every *relayed* message reaches the destination with no
  id and the destination dedup (`firstDelivery`) never fires. The guard is present but
  **dead for all relayed traffic**. `routing.md` contradicts itself here — one passage
  confirms the hole, another claims replay was "handled in Stage 1." It was not; that
  claim is corrected as milestone M0 below.

None of this is a Stage-1 bug to be ashamed of — Stage 1's honest promise is
*reachability under admission*, not confidentiality or replay safety. The problem is
only the doc that over-promised.

## Where we want to be (the target)

Fully-realized routing carries **end-to-end sealed** payloads (relays hold opaque
blocks), authenticates the **origin** cryptographically (replies are addressable, no
spoofing), and closes **replay** with a signed `id`/sequence/expiry — all three bound
*inside* the sealed block so no relay on the path can read, forge, or replay them.
(Performance — chunked probe-and-cache, reassembly quotas — and statistical trust and
anonymity are `routing.md`'s stages 1.5-perf / 2 / 5, referenced not re-specified.)

## The dependency spine — why these three cluster

The load-bearing prerequisite is **one primitive: an end-to-end sealed block to a
routed destination.** Every security property hangs off it:

```
  sealing-key discovery for a routed destination   (the root — novel, unbuilt)
              │
              ▼
     end-to-end sealed block to `dest`
        ├── confidentiality  (the block is opaque to relays)
        ├── authenticated origin  (signed INSIDE the block, not the last-hop caller)
        └── replay-safe id/seq/expiry  (signature-covered INSIDE the block —
                                        mutable outer metadata a relay can rewrite
                                        is not enough)
```

Two consequences fall out of this shape:

1. **Replay, origin-auth, and confidentiality are not independent features.** They are
   three uses of one sealed block. Building them piecemeal on unsealed outer metadata
   gives protections a relay defeats; they must be built *together*.
2. **The true root is key discovery.** Sealing to a destination needs its sealing key,
   which today comes from a **walk** — a direct verification. But a *routed* destination
   is reached only through relays; you cannot walk it. So the fabric needs **public,
   data-free sealing-key discovery for a routed destination**. That primitive does not
   exist, and it gates everything above it. It is the hard, novel part of this roadmap.

## Milestones

### M0 — honesty (now, plan-independent)
Correct `routing.md`'s replay claim: Stage 1 has **no** replay/confidentiality/origin
guarantee. Non-negotiable and independent of every choice below. (Done in this change.)

### M1 — mechanical replay dedup *(optional interim; = the old "Option A")*
Propagate the `id` through `relay()`'s child envelope so the **existing** destination
dedup functions. Closes **accidental** duplication and **naive** capture-and-reinject on
a plaintext hop; explicitly **not** a defence against a malicious admitted relay (which
can strip, rewrite, or re-mint the unsigned id). **Off the critical path to the target:**
M3 supersedes it, reusing only the dedup *machinery* (the `seen` map), not the outer-id
line. Cost ~one line + a test. **Worth it iff M2/M3 are far off; skip if going soon.**

### M2 — sealing-key discovery for a routed destination *(the root primitive)*
A public, data-free way to learn a routed destination's sealing key without a direct
walk. This is the gating dependency for M3 and the genuinely unsolved design problem —
see the open questions.

### M3 — authenticated sealed relay *(= the old "Option B" / Stage 1.5 security core)*
End-to-end sealed blocks; **signed origin** and **signed+sealed id/seq/expiry**, so
replay and origin-spoofing are closed against a malicious admitted relay. Depends on M2.
Crucially, this is **the same origin-keyed sealed-observation seam** the deferred durable
seal-ratchet needs (`docs/durable-seal-ratchet.md`): both want to act on an origin
authenticated from inside a sealed payload. **Build one seam, not two** — design M3 and
the durable ratchet together.

### M4+ — performance and trust
Chunking / route caching / reassembly quotas (`routing.md` Stage 1.5), first-party
statistics for grayhole down-weighting (Stage 2), the anonymity knob (Stage 5).
Referenced here only to place them *after* the confidentiality/replay spine.

## The replay decision, situated

- **M0 is mandatory now** — the doc is currently wrong, plan or no plan.
- **"Go straight to B" = do M2 + M3** — a real subsystem gated on an unbuilt primitive,
  not a shortcut past M1.
- **M1 is an optional, off-path interim.** Its code is nearly disposable (only the
  outer-id propagation is superseded), so the question is purely: *is closing the
  fault/naive-replay cases worth a line and a test while M2/M3 are pending?*

**Recommendation:** M0 now; M1 only if M2/M3 are not imminent; and when M2/M3 come,
design them with the durable-seal seam so the fabric grows one authenticated origin-keyed
primitive rather than several bespoke ones.

## Open questions for review

1. **M2 is the crux.** Is a separate "sealing-key discovery" lookup the right shape, or
   can the destination's *signed* sealing key be **piggybacked on the discovery path
   itself** (the probe that finds a route also returns the dest's signed record), avoiding
   a new lookup service? What binds that key to the destination's identity without a walk?
2. Should M3 and the durable seal-ratchet share **one** origin-keyed sealed-observation
   seam from the first line, and what is its interface (a host capability keyed by the
   in-payload origin)?
3. Does confidentiality (M3) gate **every** multi-hop of private data, or is Stage-1
   cleartext delivery an allowed mode for explicitly non-private payloads? (`routing.md`
   Q4's open half.)
4. Is M1 worth shipping at all, or does its partialness argue for **M0-only until M3**?
   (Honest documentation is the reason it need not read as false confidence — but it is
   the one judgment call.)
