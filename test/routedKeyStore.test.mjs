/**
 * Discovered sealing keys for routed destinations. What matters: a signed self-record
 * whose identity equals the routing target contributes a PENDING key that is not usable
 * for sealing until approved; a record for a different identity, one with no sealing key,
 * or a malformed one contributes nothing; two differing keys become a sticky conflict
 * that refuses to pick (and voids approval); and the store stays session-bounded, keeping
 * approved keys and conflicts under capacity pressure while evicting pending entries.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { generateIdentity, normalizeKey } from "../src/identity.js";
import { keyId } from "../src/routeManifest.js";
import { signRecord } from "../src/peerRecord.js";
import { createRoutedKeyStore } from "../src/routedKeyStore.js";

/** A machine with an identity, a sealing key (normalized, as the store stores it), and
 * its target key id. */
const machine = (name) => {
  const id = generateIdentity();
  return {
    id,
    keyId: keyId(id.publicKey),
    sealPublicKey: normalizeKey(id.sealPublicKey),
    name,
  };
};

/** A signed self-record for `m`, optionally with a substituted sealing key or age. */
const recordOf = (m, { sealPublicKey = m.sealPublicKey, lastSeen } = {}) =>
  signRecord(
    {
      name: m.name,
      publicKey: m.id.publicKey,
      ...(sealPublicKey ? { sealPublicKey } : {}),
      addresses: [],
      ...(lastSeen !== undefined ? { lastSeen } : {}),
    },
    m.id.privateKey,
  );

test("a discovered key is pending until approved, then usable", () => {
  const store = createRoutedKeyStore();
  const d = machine("dest");
  assert.equal(store.observe(d.keyId, recordOf(d)), "record-carried");
  assert.equal(store.recordState(d.keyId), "record-carried");
  assert.equal(store.recordSealKey(d.keyId), null, "a pending key is not usable for sealing");
  assert.deepEqual(store.recordDetail(d.keyId), { sealKey: d.sealPublicKey, name: "dest", approved: false });
  // Approve it -> now usable, and re-observing keeps it approved.
  assert.deepEqual(store.approve(d.keyId), { ok: true, sealKey: d.sealPublicKey });
  assert.equal(store.recordState(d.keyId), "record-approved");
  assert.equal(store.recordSealKey(d.keyId), d.sealPublicKey);
  assert.equal(store.observe(d.keyId, recordOf(d)), "record-approved");
});

test("approval needs a matching fingerprint and is void on conflict or an unknown target", () => {
  const store = createRoutedKeyStore();
  const d = machine("dest");
  const other = generateIdentity();
  assert.deepEqual(store.approve(d.keyId), { ok: false, reason: "unknown" }); // nothing discovered
  store.observe(d.keyId, recordOf(d));
  assert.deepEqual(store.approve(d.keyId, normalizeKey(other.sealPublicKey)), { ok: false, reason: "mismatch" });
  assert.equal(store.recordState(d.keyId), "record-carried", "a mismatched approval does not take");
  assert.deepEqual(store.approve(d.keyId, d.sealPublicKey), { ok: true, sealKey: d.sealPublicKey });
  // A later differing record voids the approval and cannot be re-approved past the conflict.
  const stale = generateIdentity();
  store.observe(d.keyId, recordOf(d, { sealPublicKey: stale.sealPublicKey }));
  assert.equal(store.recordState(d.keyId), "record-conflict");
  assert.deepEqual(store.approve(d.keyId), { ok: false, reason: "conflict" });
  assert.equal(store.recordSealKey(d.keyId), null);
});

test("an approved key survives capacity pressure, like a conflict", () => {
  const store = createRoutedKeyStore({ maxEntries: 2 });
  const t = machine("t");
  const u = machine("u");
  const v = machine("v");
  store.observe(t.keyId, recordOf(t));
  store.approve(t.keyId); // approved -> sticky
  store.observe(u.keyId, recordOf(u)); // pending
  store.observe(v.keyId, recordOf(v)); // full: evicts u (pending), keeps approved t
  assert.equal(store.recordState(t.keyId), "record-approved", "the approved key was preserved");
  assert.equal(store.recordState(u.keyId), "none", "the pending entry was evicted instead");
  assert.equal(store.recordState(v.keyId), "record-carried");
});

test("a record for a different identity than the target is not stored", () => {
  const store = createRoutedKeyStore();
  const d = machine("dest");
  const other = machine("other");
  // `other` correctly signs its own record, but we are routing to `d`.
  assert.equal(store.observe(d.keyId, recordOf(other)), "not-target");
  assert.equal(store.recordSealKey(d.keyId), null);
  assert.equal(store.size(), 0);
});

test("a record with no sealing key offers no Tier-1 key", () => {
  const store = createRoutedKeyStore();
  const d = machine("dest");
  assert.equal(store.observe(d.keyId, recordOf(d, { sealPublicKey: null })), "no-seal-key");
  assert.equal(store.recordSealKey(d.keyId), null);
  assert.equal(store.size(), 0);
});

test("two differing sealing keys for one target become a sticky conflict", () => {
  const store = createRoutedKeyStore();
  const d = machine("dest");
  const stale = generateIdentity(); // a retired/rotated sealing key, still signed by d
  assert.equal(store.observe(d.keyId, recordOf(d)), "record-carried");
  assert.equal(store.observe(d.keyId, recordOf(d, { sealPublicKey: stale.sealPublicKey })), "record-conflict");
  assert.equal(store.recordSealKey(d.keyId), null, "a conflicted target seals to nothing");
  assert.equal(store.recordState(d.keyId), "record-conflict");
  assert.equal(store.recordDetail(d.keyId), null);
  // Re-presenting either key does not resolve the conflict — the store never picks.
  assert.equal(store.observe(d.keyId, recordOf(d)), "record-conflict");
  assert.equal(store.recordSealKey(d.keyId), null);
});

test("the same sealing key observed again adds no authority and no second entry", () => {
  const store = createRoutedKeyStore();
  const d = machine("dest");
  assert.equal(store.observe(d.keyId, recordOf(d)), "record-carried");
  assert.equal(store.observe(d.keyId, recordOf(d)), "record-carried");
  assert.equal(store.size(), 1);
  assert.deepEqual(store.recordDetail(d.keyId), { sealKey: d.sealPublicKey, name: "dest", approved: false });
});

test("a malformed or unsigned envelope contributes nothing", () => {
  const store = createRoutedKeyStore();
  const d = machine("dest");
  const good = recordOf(d);
  for (const bad of [null, undefined, {}, { record: good.record, signature: "AA==" }, "x"]) {
    assert.equal(store.observe(d.keyId, bad), "unverified");
  }
  // A malformed targetKeyId is refused too.
  assert.equal(store.observe("not-a-keyid", good), "unverified");
  assert.equal(store.size(), 0);
});

test("forget drops a destination's Tier-1 entry (as a Tier-0 walk would supersede it)", () => {
  const store = createRoutedKeyStore();
  const d = machine("dest");
  store.observe(d.keyId, recordOf(d));
  assert.equal(store.size(), 1);
  store.forget(d.keyId);
  assert.equal(store.recordState(d.keyId), "none");
  assert.equal(store.size(), 0);
});

test("a conflict survives capacity pressure — it is evidence, not evicted like a plain key", () => {
  const store = createRoutedKeyStore({ maxEntries: 2 });
  const t = machine("target");
  const stale = generateIdentity();
  const u = machine("u");
  const v = machine("v");
  store.observe(t.keyId, recordOf(t)); // carried
  store.observe(t.keyId, recordOf(t, { sealPublicKey: stale.sealPublicKey })); // -> conflict
  store.observe(u.keyId, recordOf(u)); // size 2: {t(conflict), u}
  store.observe(v.keyId, recordOf(v)); // full: evicts u (oldest NON-conflicted), keeps t
  assert.equal(store.recordState(t.keyId), "record-conflict", "the conflict was preserved");
  assert.equal(store.recordState(u.keyId), "none", "the plain entry was evicted instead");
  assert.equal(store.recordState(v.keyId), "record-carried");
  // And a replayed single record cannot resurrect a usable key past the conflict.
  assert.equal(store.observe(t.keyId, recordOf(t)), "record-conflict");
  assert.equal(store.recordSealKey(t.keyId), null);
});

test("the store stays bounded, evicting the oldest destination when full", () => {
  const store = createRoutedKeyStore({ maxEntries: 2 });
  const a = machine("a");
  const b = machine("b");
  const c = machine("c");
  store.observe(a.keyId, recordOf(a));
  store.observe(b.keyId, recordOf(b));
  store.observe(c.keyId, recordOf(c)); // evicts a (oldest)
  assert.equal(store.size(), 2);
  assert.equal(store.recordState(a.keyId), "none", "the oldest was evicted");
  assert.equal(store.recordState(b.keyId), "record-carried");
  assert.equal(store.recordState(c.keyId), "record-carried");
});
