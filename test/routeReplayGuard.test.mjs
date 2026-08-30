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
