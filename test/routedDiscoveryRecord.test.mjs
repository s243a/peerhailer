/**
 * The routing-owned discovery record. What matters: a floor-OFF record is byte-identical to
 * `signRecord(keyOnly)` (back-compat is a no-op, not a tolerance); a floor-ON record carries
 * `routed.requireSealed` under the identity signature, verifies UNCHANGED through the old
 * `verifyRecord` (the field is invisible to old readers), and surfaces `floor:true` through
 * `verifyDiscoveryRecord`; and a relay cannot add, strip, or flip `routed` without breaking the
 * signature. Reading is lenient: only a plain object with `requireSealed:true` is a floor.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { generateIdentity, signPayload } from "../src/identity.js";
import { signRecord, verifyRecord } from "../src/peerRecord.js";
import { signDiscoveryRecord, verifyDiscoveryRecord } from "../src/routedDiscoveryRecord.js";

const machine = (name) => {
  const id = generateIdentity();
  return { id, name, self: { name, publicKey: id.publicKey, sealPublicKey: id.sealPublicKey } };
};

test("1. a floor-off discovery record is byte-identical to signRecord(keyOnly)", () => {
  const m = machine("bob");
  const advert = signDiscoveryRecord({ self: m.self, requireSealed: false, privateKey: m.id.privateKey });
  const plain = signRecord({ name: m.name, publicKey: m.id.publicKey, sealPublicKey: m.id.sealPublicKey, addresses: [], lastSeen: null }, m.id.privateKey);
  assert.deepEqual(advert, plain, "Ed25519 is deterministic: floor off means the identical record AND signature");
});

test("2. a floor-on record carries routed, verifies unchanged, and surfaces the floor", () => {
  const m = machine("bob");
  const on = signDiscoveryRecord({ self: m.self, requireSealed: true, privateKey: m.id.privateKey });
  assert.deepEqual(on.record.routed, { requireSealed: true });
  // Old readers accept it and never see `routed`.
  const old = verifyRecord(on, null);
  assert.equal(old.ok, true);
  assert.equal(old.record.routed, undefined, "the typed view drops the routed policy");
  // The new reader surfaces the floor.
  assert.equal(verifyDiscoveryRecord(on).floor, true);
  const off = signDiscoveryRecord({ self: m.self, requireSealed: false, privateKey: m.id.privateKey });
  assert.equal(verifyDiscoveryRecord(off).floor, false);
});

test("3. a relay cannot add, strip, or flip the signed routed policy", () => {
  const m = machine("bob");
  // Add to an unfloored record without re-signing.
  const injected = signDiscoveryRecord({ self: m.self, requireSealed: false, privateKey: m.id.privateKey });
  injected.record = { ...injected.record, routed: { requireSealed: true } };
  assert.equal(verifyDiscoveryRecord(injected).ok, false, "injecting routed breaks the signature");
  // Strip routed from a floored record.
  const floored = signDiscoveryRecord({ self: m.self, requireSealed: true, privateKey: m.id.privateKey });
  const bare = { ...floored.record };
  delete bare.routed;
  assert.equal(verifyDiscoveryRecord({ record: bare, signature: floored.signature }).ok, false, "stripping routed breaks the signature");
  // Flip to false.
  const flipped = signDiscoveryRecord({ self: m.self, requireSealed: true, privateKey: m.id.privateKey });
  flipped.record = { ...flipped.record, routed: { requireSealed: false } };
  assert.equal(verifyDiscoveryRecord(flipped).ok, false, "flipping routed breaks the signature");
});

test("4. the reader is lenient: only a plain object with requireSealed:true is a floor", () => {
  const m = machine("bob");
  // Each genuinely re-signed by the identity, so `ok` is true; only the floor reading differs.
  const sign = (routed) => {
    const base = signDiscoveryRecord({ self: m.self, requireSealed: false, privateKey: m.id.privateKey }).record;
    const record = { ...base, routed };
    return { record, signature: signPayload(record, m.id.privateKey) };
  };
  assert.equal(verifyDiscoveryRecord(sign("yes")).floor, false);
  assert.equal(verifyDiscoveryRecord(sign({ requireSealed: "true" })).floor, false);
  const extra = verifyDiscoveryRecord(sign({ requireSealed: true, extra: 1 }));
  assert.equal(extra.ok, true);
  assert.equal(extra.floor, true, "unknown sibling keys are ignored; requireSealed:true still reads as a floor");
});
