/**
 * The destination replay guard (M1). What matters: a fresh in-window message is
 * admitted once, a replay is refused, an expired/future/over-long envelope is
 * refused, and at capacity it fails *closed* rather than evicting a live reservation.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createRouteReplayGuard } from "../src/routeReplayGuard.js";

const T = 1_700_000_000_000;
/** A manifest-shaped object (already verified by the time it reaches the guard). */
const man = (over = {}) => ({
  originKeyId: "O",
  messageId: "m-1",
  blockIndex: 0,
  issuedAt: T,
  expiresAt: T + 60_000,
  ...over,
});

test("a fresh in-window message is admitted; an identical replay is refused", () => {
  const g = createRouteReplayGuard({ now: () => T });
  assert.deepEqual(g.check(man()), { ok: true }, "preflight accepts without reserving");
  assert.equal(g.size(), 0, "preflight is non-reserving");
  assert.deepEqual(g.admit(man()), { ok: true });
  assert.deepEqual(g.check(man()), { ok: false, reason: "duplicate" }, "preflight cheaply catches a replay");
  assert.deepEqual(g.admit(man()), { ok: false, reason: "duplicate" });
  // A different messageId from the same origin is fresh.
  assert.deepEqual(g.admit(man({ messageId: "m-2" })), { ok: true });
  // A different blockIndex is a distinct block, not a duplicate.
  assert.deepEqual(g.admit(man({ blockIndex: 1 })), { ok: true });
});

test("the time window is enforced with skew, whatever the origin signed", () => {
  const g = createRouteReplayGuard({ now: () => T, clockSkewMs: 1000, maxValidityMs: 60_000 });
  assert.deepEqual(g.admit(man({ issuedAt: T + 2000, expiresAt: T + 62_000 })), { ok: false, reason: "not-yet-valid" });
  // Valid-length window (48s < 60s max), but it ended more than the skew ago.
  assert.deepEqual(g.admit(man({ issuedAt: T - 50_000, expiresAt: T - 2000 })), { ok: false, reason: "expired" });
  assert.deepEqual(g.admit(man({ issuedAt: T, expiresAt: T + 120_000 })), { ok: false, reason: "validity-too-long" });
  // Just inside the skew on each edge is fine.
  assert.equal(g.admit(man({ issuedAt: T + 1000, expiresAt: T + 30_000 })).ok, true);
});

test("the reservation dedups for exactly as long as the window admits (no one-tick gap)", () => {
  let clock = T;
  const g = createRouteReplayGuard({ now: () => clock, clockSkewMs: 1000, maxValidityMs: 60_000 });
  const m = man({ expiresAt: T + 30_000 }); // reservation lives until exp = T+31_000
  assert.equal(g.admit(m).ok, true);
  // At the exact last admissible instant (exp), a replay is still a duplicate — and
  // the message itself is still in-window, so the two agree rather than leaving a gap.
  clock = T + 31_000;
  assert.deepEqual(g.admit(m), { ok: false, reason: "duplicate" });
  // One ms later both flip together: the window refuses it as expired.
  clock = T + 31_001;
  assert.deepEqual(g.admit(m), { ok: false, reason: "expired" });
});

test("at global capacity a new message fails closed — a live reservation is never evicted", () => {
  const g = createRouteReplayGuard({ now: () => T, maxEntries: 2, maxPerOrigin: 100 });
  assert.equal(g.admit(man({ messageId: "a" })).ok, true);
  assert.equal(g.admit(man({ messageId: "b" })).ok, true);
  assert.deepEqual(g.admit(man({ messageId: "c" })), { ok: false, reason: "at-capacity" });
  // The two live ones are still deduped (not evicted to make room).
  assert.deepEqual(g.admit(man({ messageId: "a" })), { ok: false, reason: "duplicate" });
});

test("per-origin ceiling stops one origin filling the cache; others are unaffected", () => {
  const g = createRouteReplayGuard({ now: () => T, maxEntries: 100, maxPerOrigin: 1 });
  assert.equal(g.admit(man({ originKeyId: "O", messageId: "a" })).ok, true);
  assert.deepEqual(g.admit(man({ originKeyId: "O", messageId: "b" })), { ok: false, reason: "origin-at-capacity" });
  assert.equal(g.admit(man({ originKeyId: "P", messageId: "a" })).ok, true, "a different origin still has room");
});

test("expired reservations are swept, reclaiming slots (and the message itself then fails the window)", () => {
  let clock = T;
  const g = createRouteReplayGuard({ now: () => clock, maxEntries: 1, maxPerOrigin: 100, clockSkewMs: 0 });
  assert.equal(g.admit(man({ messageId: "a", expiresAt: T + 10_000 })).ok, true);
  assert.equal(g.size(), 1);
  // A new message at capacity, but the first has expired — its slot is reclaimed.
  clock = T + 20_000;
  assert.equal(g.admit(man({ messageId: "b", issuedAt: T + 19_000, expiresAt: T + 25_000 })).ok, true);
  assert.equal(g.size(), 1, "the expired reservation was swept, not accumulated");
  // And the original message, replayed now, is refused by the window (expired), not the cache.
  assert.deepEqual(g.admit(man({ messageId: "a", expiresAt: T + 10_000 })), { ok: false, reason: "expired" });
});

test("a wall-clock rollback never reopens a reservation swept after a forward jump", () => {
  let clock = T;
  const g = createRouteReplayGuard({ now: () => clock, maxEntries: 1, maxPerOrigin: 100, clockSkewMs: 0 });
  const original = man({ messageId: "old", expiresAt: T + 10_000 });
  assert.equal(g.admit(original).ok, true);

  // Advance far enough that admitting a current message sweeps the old entry.
  clock = T + 20_000;
  assert.equal(g.admit(man({ messageId: "new", issuedAt: T + 19_000, expiresAt: T + 25_000 })).ok, true);

  // Correct the wall clock backwards into the old envelope's signed window. The
  // guard retains a high-water mark and fails closed instead of replaying it.
  clock = T + 5_000;
  assert.deepEqual(g.admit(original), { ok: false, reason: "expired" });
});

test("size reports live entries and garbage-collects an expired reservation", () => {
  let clock = T;
  const g = createRouteReplayGuard({ now: () => clock, clockSkewMs: 0 });
  assert.equal(g.admit(man({ expiresAt: T + 1000 })).ok, true);
  assert.equal(g.size(), 1);
  clock = T + 1001;
  assert.equal(g.size(), 0);
});

test("a misconfigured guard fails loudly at construction rather than silently disabling replay", () => {
  // clockSkewMs:NaN would make exp NaN and `existing.exp >= t` always false -> replays admitted.
  assert.throws(() => createRouteReplayGuard({ clockSkewMs: NaN }), /clockSkewMs/);
  assert.throws(() => createRouteReplayGuard({ maxValidityMs: Infinity }), /maxValidityMs/);
  assert.throws(() => createRouteReplayGuard({ maxEntries: -1 }), /maxEntries/);
});

// --- Durability: with an injected persistence port the reservations survive a restart, so a
// still-unexpired envelope cannot be replayed by bouncing the daemon (routing roadmap). ---

/** The module's composite dedup key, mirrored for building an `initial` snapshot by hand. */
const dedupKey = (m) => `${m.originKeyId}\0${m.messageId}\0${m.blockIndex}`;

test("persist is called on a reservation, not on a preflight check", () => {
  const calls = [];
  const g = createRouteReplayGuard({ now: () => T, persist: (entries) => calls.push(entries) });
  g.check(man());
  assert.equal(calls.length, 0, "a non-reserving check writes nothing");
  g.admit(man());
  assert.equal(calls.length, 1, "a reservation persists once");
  assert.equal(calls[0][0].k, dedupKey(man()), "the persisted entry is the reserved one");
  g.admit(man()); // a duplicate reserves nothing
  assert.equal(calls.length, 1, "a refused duplicate does not persist");
});

test("a persisted snapshot rehydrates: a replay is refused across the restart, a fresh id admits", () => {
  const g1 = createRouteReplayGuard({ now: () => T });
  g1.admit(man());
  const snapshot = g1.snapshot();
  assert.equal(snapshot.length, 1);
  // A new process loads the snapshot: the same envelope is still a duplicate.
  const g2 = createRouteReplayGuard({ now: () => T, initial: snapshot });
  assert.deepEqual(g2.admit(man()), { ok: false, reason: "duplicate" }, "the reservation survived the restart");
  assert.deepEqual(g2.admit(man({ messageId: "m-2" })), { ok: true }, "a different envelope is still fresh");
});

test("an already-expired reservation in the snapshot is dropped on load", () => {
  const g = createRouteReplayGuard({
    now: () => T,
    initial: [{ k: dedupKey(man()), exp: T - 1, origin: "O" }],
  });
  assert.equal(g.size(), 0, "the expired entry is not rehydrated");
  assert.deepEqual(g.admit(man()), { ok: true }, "so the same key is admissible again");
});

test("a malformed snapshot entry is skipped, never fatal", () => {
  const g = createRouteReplayGuard({
    now: () => T,
    initial: [null, { k: 1, exp: T + 1, origin: "O" }, { k: "ok", exp: "soon", origin: "O" }, { k: dedupKey(man()), exp: T + 180_000, origin: "O" }],
  });
  assert.equal(g.size(), 1, "only the well-formed, in-window entry loads");
  assert.deepEqual(g.admit(man()), { ok: false, reason: "duplicate" });
});

test("a snapshot entry at exactly exp === t loads and still refuses as a duplicate at t", () => {
  // The keep/drop seam: load drops exp < t, so exp === t must load and dedup at the same t.
  const g = createRouteReplayGuard({ now: () => T, initial: [{ k: dedupKey(man()), exp: T, origin: "O" }] });
  assert.equal(g.size(), 1, "exp === t is still in-window on load");
  assert.deepEqual(g.admit(man()), { ok: false, reason: "duplicate" });
});

test("a far-future exp in a snapshot is rejected on load — no indefinite denial", () => {
  const g = createRouteReplayGuard({ now: () => T, initial: [{ k: dedupKey(man()), exp: Number.MAX_SAFE_INTEGER, origin: "O" }] });
  assert.equal(g.size(), 0, "an exp beyond any legitimate reservation is not loaded");
  assert.deepEqual(g.admit(man()), { ok: true }, "so the key is admissible");
});

test("rehydration honors the per-origin ceiling, not just the global one", () => {
  const initial = [0, 1, 2].map((i) => {
    const m = man({ messageId: `m-${i}` });
    return { k: dedupKey(m), exp: m.expiresAt + 120_000, origin: m.originKeyId };
  });
  const g = createRouteReplayGuard({ now: () => T, maxPerOrigin: 2, initial });
  assert.equal(g.size(), 2, "only up to the per-origin ceiling is rehydrated");
});
