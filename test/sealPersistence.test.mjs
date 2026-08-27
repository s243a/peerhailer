/**
 * The sealing key's trust must survive the write path and rotation, not just the
 * happy load path. These cover the persistence reconciliation (a stale writer
 * must not erase a verified key), the tri-state gate (verified / conflict /
 * unverified), the walk's TOCTOU guard, and that a real walk binds the key from
 * a signed record.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createDirectory, carryVerifiedSeal } from "../src/directory.js";
import { generateIdentity, sameKey } from "../src/identity.js";
import { walk } from "../src/hail.js";
import { makePeerRecord, signRecord } from "../src/peerRecord.js";

const bob = generateIdentity();
const bob2 = generateIdentity();

test("carryVerifiedSeal: a stale writer never erases a verified sealing key", () => {
  const onDisk = [{ name: "bob", publicKey: bob.publicKey, sealPublicKey: bob.sealPublicKey, sealSeen: true }];
  // A writer that loaded before the bind snapshots bob without a sealing key.
  const snap = [{ name: "bob", publicKey: bob.publicKey }];
  const [merged] = carryVerifiedSeal(onDisk, snap);
  assert.equal(merged.sealSeen, true, "verified key carried forward");
  assert.equal(merged.sealPublicKey, bob.sealPublicKey);
});

test("carryVerifiedSeal: a rotated identity does not resurrect the old sealing key", () => {
  const onDisk = [{ name: "bob", publicKey: bob.publicKey, sealPublicKey: bob.sealPublicKey, sealSeen: true }];
  // Same name, different identity key (a rotation this writer performed).
  const snap = [{ name: "bob", publicKey: bob2.publicKey }];
  const [merged] = carryVerifiedSeal(onDisk, snap);
  assert.equal(merged.sealSeen, undefined, "old sealing key not carried onto a new identity");
  assert.equal(merged.sealPublicKey, undefined);
});

test("carryVerifiedSeal: two different verified keys become a conflict, not a silent pick", () => {
  const onDisk = [{ name: "bob", publicKey: bob.publicKey, sealPublicKey: bob.sealPublicKey, sealSeen: true }];
  const snap = [{ name: "bob", publicKey: bob.publicKey, sealPublicKey: bob2.sealPublicKey, sealSeen: true }];
  const [merged] = carryVerifiedSeal(onDisk, snap);
  assert.equal(merged.sealPublicKey, bob.sealPublicKey, "on-disk key kept");
  assert.ok(merged.sealConflict, "disagreement flagged");
});

test("tri-state gate: unverified → verified → conflict, and sealKeyFor/sealState agree", () => {
  const dir = createDirectory({ self: { name: "me", publicKey: generateIdentity().publicKey } });
  dir.admit({ name: "bob", publicKey: bob.publicKey, addresses: [{ value: "https://127.0.0.1:9" }] });

  assert.equal(dir.sealState("bob"), "unverified");
  assert.equal(dir.sealKeyFor("bob"), null);

  dir.bindSealKey("bob", bob.sealPublicKey, bob.publicKey);
  assert.equal(dir.sealState("bob"), "verified");
  assert.ok(sameKey(dir.sealKeyFor("bob"), bob.sealPublicKey));

  // A different verified key raises a conflict: the send path must fail closed.
  dir.bindSealKey("bob", bob2.sealPublicKey, bob.publicKey);
  assert.equal(dir.sealState("bob"), "conflict");
  assert.equal(dir.sealKeyFor("bob"), null, "no key handed out under conflict");

  // Re-confirming the held key resolves the conflict.
  dir.bindSealKey("bob", bob.sealPublicKey, bob.publicKey);
  assert.equal(dir.sealState("bob"), "verified");
});

test("bindSealKey refuses when the identity changed under it (walk TOCTOU)", () => {
  const dir = createDirectory({ self: { name: "me", publicKey: generateIdentity().publicKey } });
  dir.admit({ name: "bob", publicKey: bob.publicKey, addresses: [{ value: "https://127.0.0.1:9" }] });
  // The walk verified against bob2's identity, but the record is bob's now.
  dir.bindSealKey("bob", bob.sealPublicKey, bob2.publicKey);
  assert.equal(dir.sealState("bob"), "unverified", "proof for a different identity is refused");
});

test("rotateKey drops the sealing binding so the next walk re-verifies", () => {
  const dir = createDirectory({ self: { name: "me", publicKey: generateIdentity().publicKey } });
  dir.admit({ name: "bob", publicKey: bob.publicKey, addresses: [{ value: "https://127.0.0.1:9" }] });
  dir.bindSealKey("bob", bob.sealPublicKey, bob.publicKey);
  assert.equal(dir.sealState("bob"), "verified");
  dir.rotateKey("bob", bob2.publicKey);
  assert.equal(dir.sealState("bob"), "unverified", "rotation invalidates the old sealing binding");
  assert.equal(dir.sealKeyFor("bob"), null);
});

test("a real walk binds the sealing key from the peer's signed record", async () => {
  const dir = createDirectory({ self: { name: "here", publicKey: generateIdentity().publicKey } });
  dir.admit({ name: "bob", publicKey: bob.publicKey, addresses: [{ transport: "lan", value: "http://bob:8787" }] });
  assert.equal(dir.sealKeyFor("bob"), null, "not sealed to before any walk");

  // Bob answers with a record signed by his identity, carrying his sealing key.
  const signed = signRecord(makePeerRecord({ name: "bob", publicKey: bob.publicKey, sealPublicKey: bob.sealPublicKey }), bob.privateKey);
  const fetchImpl = async (url) => {
    if (url.replace(/\/hail$/, "") !== "http://bob:8787") throw new Error("ECONNREFUSED");
    return { ok: true, json: async () => ({ self: { name: "bob" }, peers: [], signed }) };
  };

  const result = await walk(dir, { fetchImpl });
  assert.deepEqual(result.reached.map((p) => p.name), ["bob"]);
  assert.equal(dir.sealState("bob"), "verified", "the walk bound the sealing key");
  assert.ok(sameKey(dir.sealKeyFor("bob"), bob.sealPublicKey));
});
