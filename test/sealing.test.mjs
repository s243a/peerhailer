/**
 * The suite-A seal. The round-trip is the easy part; the tests that matter are the
 * refusals — a tampered field, a wrong key, a forged or substituted signature must
 * never open, and a signed block must fail its signature *before* it is decrypted.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { seal, open, generateSealKeyPair, SUITE } from "../src/sealing.js";

const edKeyPair = () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
};

test("round-trips content the recipient can read (unsigned)", () => {
  const bob = generateSealKeyPair();
  const sealed = seal("a secret note", bob.publicKey);
  assert.equal(sealed.suite, SUITE);
  const { plaintext, from } = open(sealed, bob.privateKey);
  assert.equal(plaintext.toString(), "a secret note");
  assert.equal(from, null, "unsigned block has no authenticated sender");
});

test("round-trips and authenticates the sender when signed", () => {
  const bob = generateSealKeyPair();
  const alice = edKeyPair();
  const sealed = seal("hi bob", bob.publicKey, { signer: alice });
  assert.equal(sealed.from, alice.publicKey);
  const { plaintext, from } = open(sealed, bob.privateKey);
  assert.equal(plaintext.toString(), "hi bob");
  assert.equal(from, alice.publicKey, "the authenticated sender is reported");
});

test("a relay cannot read it — a third party's key does not open it", () => {
  const bob = generateSealKeyPair();
  const relay = generateSealKeyPair();
  const sealed = seal("not for the relay", bob.publicKey);
  assert.throws(() => open(sealed, relay.privateKey), /./, "the wrong recipient key fails");
});

test("tampering the ciphertext is caught by the AEAD", () => {
  const bob = generateSealKeyPair();
  const sealed = seal("integrity", bob.publicKey);
  const bytes = Buffer.from(sealed.ct, "base64");
  bytes[0] ^= 0x01;
  const tampered = { ...sealed, ct: bytes.toString("base64") };
  assert.throws(() => open(tampered, bob.privateKey), /./);
});

test("tampering any bound field (suite, epk, nonce) is caught", () => {
  const bob = generateSealKeyPair();
  const sealed = seal("bound", bob.publicKey);
  assert.throws(() => open({ ...sealed, suite: "B" }, bob.privateKey), /unsupported suite/);
  const otherEph = generateSealKeyPair().publicKey;
  assert.throws(() => open({ ...sealed, epk: otherEph }, bob.privateKey), /./, "a swapped ephemeral key fails");
  const n = Buffer.from(sealed.nonce, "base64");
  n[0] ^= 0x01;
  assert.throws(() => open({ ...sealed, nonce: n.toString("base64") }, bob.privateKey), /./, "a changed nonce fails");
  const salt = Buffer.from(sealed.salt, "base64");
  salt[0] ^= 0x01;
  assert.throws(() => open({ ...sealed, salt: salt.toString("base64") }, bob.privateKey), /./, "a changed salt fails");
});

test("a signed block verifies BEFORE it decrypts — a bad signature is rejected", () => {
  const bob = generateSealKeyPair();
  const alice = edKeyPair();
  const sealed = seal("signed", bob.publicKey, { signer: alice });
  // Flip a signature byte.
  const sig = Buffer.from(sealed.sig, "base64");
  sig[0] ^= 0x01;
  assert.throws(() => open({ ...sealed, sig: sig.toString("base64") }, bob.privateKey), /signature does not verify/);
  // A substituted `from` (attacker's key, but original signature) also fails.
  const mallory = edKeyPair();
  assert.throws(() => open({ ...sealed, from: mallory.publicKey }, bob.privateKey), /signature does not verify/);
});

test("a half-signed block (from without sig, or vice versa) is refused", () => {
  const bob = generateSealKeyPair();
  const alice = edKeyPair();
  const sealed = seal("x", bob.publicKey, { signer: alice });
  assert.throws(() => open({ ...sealed, sig: undefined }, bob.privateKey), /must carry both/);
});

test("empty and larger payloads round-trip", () => {
  const bob = generateSealKeyPair();
  assert.equal(open(seal("", bob.publicKey), bob.privateKey).plaintext.length, 0);
  const big = Buffer.alloc(200_000, 7);
  assert.deepEqual(open(seal(big, bob.publicKey), bob.privateKey).plaintext, big);
});

test("two seals of the same content differ (fresh ephemeral key + nonce)", () => {
  const bob = generateSealKeyPair();
  const a = seal("same", bob.publicKey);
  const b = seal("same", bob.publicKey);
  assert.notEqual(a.ct, b.ct, "no deterministic ciphertext");
  assert.notEqual(a.epk, b.epk, "a fresh ephemeral key each time");
});
