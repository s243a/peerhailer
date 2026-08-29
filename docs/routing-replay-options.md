# Routing replay hole — options to pick a plan

**Status: decision doc.** `docs/routing.md` contradicts itself on replay — it both
*confirms* a live hole and *claims* replay is "already handled in Stage 1." This
resolves that: it states the actual hole, lays out the two fixes the backlog names,
and recommends one. Whatever is chosen, the false claim in `routing.md` must be
corrected in the same change.

## The hole, precisely

`send()` mints an envelope `id` (`src/routing.js`, `newId()`), and the **first**
envelope carries it. But when `relay()` forwards to the next hop it builds a `child`
envelope — `{ dest, ttl, budget, visited, payload, origin }` — that **omits `id`**.
So every relayed message reaches the destination with `id === undefined`, and
`firstDelivery(undefined)` returns `true` (no dedup). The destination replay guard
(`seen` map, keyed by `id`) is therefore **dead code for all relayed traffic**: it
fires only for a message whose `send()` target is the local node — never for one that
actually crossed a relay.

Net effect: a captured or retransmitted relayed envelope is **delivered again** at the
destination — the destination re-*acts* on it. `docs/routing.md:171` confirms this
("delivered twice"); `docs/routing.md:223` wrongly says it was closed. It was not.

## Threat model at Stage 1

- **Relays are admitted, not trusted** (F2F — only admitted peers relay). The concern
  is an *admitted malicious relay*, plus a *passive network attacker* on a plaintext
  hail hop.
- The `id` is **mutable outer metadata**: unsigned, and (Stage 1) the payload is
  **cleartext to every relay** — there is no sealed block yet.
- The `origin` field is **unsigned** at Stage 1 (advisory only), so a relay can spoof
  it.

These three facts bound what any Stage-1 fix can promise.

## Option A — mechanical: propagate the id, keep destination dedup

Add `id` to the `child` envelope in `relay()` (one field), so the id the origin minted
survives to the destination and the **existing** dedup starts working.

- **Fixes:** accidental duplication (a relay's own retry double-sends), and a passive
  capture-and-reinject of an *unchanged* envelope on a plaintext hop. It turns dead code
  into a functioning per-destination, windowed replay guard.
- **Does not fix:** an *admitted malicious relay*, which can **strip** the id (disabling
  dedup), **rewrite** it (forcing re-delivery under a fresh id), or **replay under a new
  id**. Nor origin spoofing (origin is unsigned). These are out of reach without signing
  and sealing.
- **Cost:** ~one line plus a test (a two-hop replay of the same id must be deduped;
  today it is delivered twice). Zero new machinery.
- **Honesty:** the guarantee must be documented as *accidental / naive replay only,
  within a window* — explicitly **not** a defence against a malicious admitted relay.
  That correction replaces the false "replay is already handled" claim.

## Option B — authenticated: fold into Stage 1.5

Make `id`, a sequence number, an expiry, and `origin` **signature-covered inside the
end-to-end sealed block** to the destination, so no relay on the path can strip, alter,
or replay them, and the origin is authenticated from *inside* the payload (never from
the last-hop `caller`).

- **Fixes:** replay *and* origin spoofing against a malicious admitted relay — the
  complete version.
- **Requires Stage-1.5 primitives that do not exist at Stage 1:**
  1. an end-to-end **sealed block to the destination**, which needs *public, data-free
     sealing-key discovery for a routed destination* (a destination reached only through
     relays cannot be walked — `routing.md:160`); and
  2. **origin-from-inside-the-sealed-payload** authentication (the "do not copy the chat
     `caller`-binding into a relayed path" note).
- **Cost:** a real subsystem, gated on the sealed-relay work. This is also where the
  **deferred durable seal-ratchet** (`docs/durable-seal-ratchet.md`) reconnects: both
  want *one general, origin-keyed sealed-observation seam* at Stage 1.5 rather than two
  bespoke ones. Design them together.

## Recommendation

**Do A now, and plan B for Stage 1.5 — they are not mutually exclusive.**

A is nearly free, it makes an already-present guard actually function, and — the
decisive point — the doc currently *claims a protection that does not exist*. Shipping
A with an honestly-scoped claim is strictly better than today's state (dead guard +
false doc), and it costs a line and a test. It closes the accidental and naive-network
replay cases, which are the ones a non-malicious fault or a passive plaintext-hop
attacker actually hits.

A does **not** pretend to stop a malicious admitted relay; that is B, and B genuinely
needs Stage 1.5's sealed block and signed origin. Defer B, build it origin-keyed from
the start, and design it alongside the durable seal-ratchet seam so the fabric grows
one authenticated origin-keyed primitive, not several.

Concretely, if A is chosen:
1. add `id` to the `child` envelope in `relay()`;
2. add a two-hop replay-dedup test;
3. replace `routing.md:223-226` ("replay is already handled") with the honest scope,
   and reconcile it with the confirmed-hole note at `routing.md:171` (which becomes: the
   Stage-1 guard covers accidental/naive replay; the signed-and-sealed version is Stage
   1.5).

## Open question for the decision

Is the accidental/naive-replay guarantee from A worth shipping on its own, or does its
partialness risk false confidence enough to prefer waiting for B? The recommendation is
that honest documentation resolves that — a guard that says exactly what it does is not
false confidence — but it is the one judgment call here.
