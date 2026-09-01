/**
 * The observation seam (M3a). What matters: a durable per-origin marker can only be written
 * with an authenticated-origin proof (a bare key is refused); markers are OR-floored (never
 * cleared) and key-indexed; the store fails closed at capacity (a flood cannot evict an
 * existing marker); and it round-trips through the persistence port with malformed lines
 * skipped, never fatal.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { generateIdentity } from "../src/identity.js";
import { keyId } from "../src/routeManifest.js";
import { authenticatedOrigin, isAuthenticatedOrigin, createRoutedObservationStore } from "../src/routedObservation.js";

/** A fresh origin key id. */
const originId = () => keyId(generateIdentity().publicKey);

test("a proof is only what the mint issued; a look-alike object is not", () => {
  const id = originId();
  const proof = authenticatedOrigin(id);
  assert.equal(isAuthenticatedOrigin(proof), true);
  assert.equal(proof.originKeyId, id);
  // A bare object of the same shape is NOT a proof — membership, not structure, is the check.
  assert.equal(isAuthenticatedOrigin({ originKeyId: id }), false);
  assert.equal(isAuthenticatedOrigin(null), false);
  assert.equal(isAuthenticatedOrigin("x"), false);
});

test("the mint rejects a non-key id, so the correctness boundary is self-consistent", () => {
  assert.throws(() => authenticatedOrigin(42), /origin key id/);
  assert.throws(() => authenticatedOrigin("too-short"), /origin key id/);
});

test("observe requires a proof and a known kind; a bare key or bad kind throws", () => {
  const store = createRoutedObservationStore();
  const id = originId();
  assert.throws(() => store.observe({ originKeyId: id }, "requireSealFrom"), /authenticated-origin proof/);
  assert.throws(() => store.observe(authenticatedOrigin(id), "notAKind"), /unknown observation kind/);
  assert.equal(store.observe(authenticatedOrigin(id), "requireSealFrom"), "recorded");
  assert.equal(store.has(id, "requireSealFrom"), true);
});

test("a marker is OR-floored: recording it again is a no-op and does not persist", () => {
  const calls = [];
  const store = createRoutedObservationStore({ persist: (entries) => calls.push(entries) });
  const id = originId();
  assert.equal(store.observe(authenticatedOrigin(id), "requireSealFrom"), "recorded");
  assert.equal(calls.length, 1, "the first record persists");
  assert.equal(store.observe(authenticatedOrigin(id), "requireSealFrom"), "already");
  assert.equal(calls.length, 1, "re-recording the same marker persists nothing");
  store.has(id, "requireSealFrom"); // a read never persists
  assert.equal(calls.length, 1);
});

test("at capacity a new origin is refused, never evicting an existing marker", () => {
  const store = createRoutedObservationStore({ maxEntries: 1 });
  const a = originId();
  const b = originId();
  assert.equal(store.observe(authenticatedOrigin(a), "requireSealFrom"), "recorded");
  assert.equal(store.observe(authenticatedOrigin(b), "requireSealFrom"), "at-capacity", "a flood cannot displace a marker");
  assert.equal(store.has(a, "requireSealFrom"), true, "the existing marker stands");
  assert.equal(store.has(b, "requireSealFrom"), false);
  assert.equal(store.size(), 1);
});

test("a marker survives a restart through the persistence port", () => {
  const store = createRoutedObservationStore();
  const id = originId();
  store.observe(authenticatedOrigin(id), "requireSealFrom");
  const restored = createRoutedObservationStore({ initial: store.snapshot() });
  assert.equal(restored.has(id, "requireSealFrom"), true, "the marker is durable across the restart");
});

test("a malformed persisted line is skipped, never fatal, and unknown kinds are filtered", () => {
  const good = originId();
  const store = createRoutedObservationStore({
    initial: [
      null,
      { id: "not-a-key-id", kinds: ["requireSealFrom"] },
      { id: originId(), kinds: "requireSealFrom" }, // kinds must be an array
      { id: originId(), kinds: ["madeUpKind"] }, // filtered to empty → not stored
      { id: good, kinds: ["requireSealFrom", "madeUpKind"] }, // the unknown kind is dropped
    ],
  });
  assert.equal(store.size(), 1, "only the well-formed line with a known kind loads");
  assert.equal(store.has(good, "requireSealFrom"), true);
  assert.equal(store.has(good, "madeUpKind"), false, "the unknown kind was filtered out on load");
});
