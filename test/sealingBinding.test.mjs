/**
 * A peer's X25519 sealing key rides the signed self-record, so a peer that admitted
 * the identity's signing key learns the sealing key bound to it — a relay cannot
 * swap it to MITM the confidentiality.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { generateIdentity } from "../src/identity.js";
import { generateSealKeyPair } from "../src/sealing.js";
import { signRecord, verifyRecord, publicRecord, makePeerRecord } from "../src/peerRecord.js";

test("the record carries and publishes sealPublicKey", () => {
  const id = generateIdentity();
  const rec = makePeerRecord({ name: "bob", publicKey: id.publicKey, sealPublicKey: id.sealPublicKey, addresses: [] });
  assert.equal(rec.sealPublicKey, id.sealPublicKey.trim());
  assert.equal(publicRecord(rec).sealPublicKey, id.sealPublicKey.trim(), "it is in the public (signed) body");
});

test("sealPublicKey is signed by the identity and verifies against it", () => {
  const bob = generateIdentity();
  const envelope = signRecord({ name: "bob", publicKey: bob.publicKey, sealPublicKey: bob.sealPublicKey, addresses: [] }, bob.privateKey);
  const result = verifyRecord(envelope, bob.publicKey);
  assert.equal(result.ok, true, "the record verifies against bob's identity key");
  assert.equal(result.record.sealPublicKey, bob.sealPublicKey.trim(), "and carries the sealing key");
});

test("a swapped sealPublicKey breaks the signature — no confidentiality MITM", () => {
  const bob = generateIdentity();
  const mallory = generateSealKeyPair();
  const envelope = signRecord({ name: "bob", publicKey: bob.publicKey, sealPublicKey: bob.sealPublicKey, addresses: [] }, bob.privateKey);
  // A relay substitutes Bob's sealing key with Mallory's, leaving the signature.
  envelope.record.sealPublicKey = mallory.publicKey;
  const result = verifyRecord(envelope, bob.publicKey);
  assert.equal(result.ok, false, "the tampered record does not verify");
  assert.match(result.error, /did not verify/);
});
