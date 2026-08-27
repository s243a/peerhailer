/**
 * The suite-A seal. The round-trip is the easy part; the tests that matter are the
 * refusals — a tampered field, a wrong key, a forged or substituted signature must
 * never open, and a signed block must fail its signature *before* it is decrypted.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { seal, open, openSigned, generateSealKeyPair, SUITE } from "../src/sealing.js";

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

test("a signed block cannot be silently stripped to unsigned; openSigned enforces auth", () => {
  const bob = generateSealKeyPair();
  const alice = edKeyPair();
  const signed = seal("auth me", bob.publicKey, { signer: alice });
  // `from` is bound into the AEAD, so stripping the signature breaks decryption —
  // a signed block cannot be downgraded to a working unsigned one.
  const stripped = { ...signed };
  delete stripped.sig;
  delete stripped.from;
  assert.throws(() => open(stripped, bob.privateKey), /./, "stripping a signed block's from breaks decryption");
  // The only from:null case is a block sealed without a signer; openSigned refuses it.
  const unsigned = seal("anon", bob.publicKey);
  assert.equal(open(unsigned, bob.privateKey).from, null);
  assert.throws(() => openSigned(unsigned, bob.privateKey), /authentication is required/);
  assert.equal(openSigned(signed, bob.privateKey).from, alice.publicKey, "a signed block passes openSigned");
});

test("a non-contributory (low-order) ephemeral key is rejected", () => {
  const bob = generateSealKeyPair();
  const sealed = seal("x", bob.publicKey);
  // The all-zero X25519 point (valid encoding, low order → all-zero shared secret).
  const zeroSpki = Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), Buffer.alloc(32)]);
  const zeroEpk = "-----BEGIN PUBLIC KEY-----\n" + zeroSpki.toString("base64") + "\n-----END PUBLIC KEY-----\n";
  assert.throws(() => open({ ...sealed, epk: zeroEpk }, bob.privateKey), /non-contributory|malformed/);
});

test("malformed fields are rejected with legible errors before any crypto", () => {
  const bob = generateSealKeyPair();
  const sealed = seal("y", bob.publicKey);
  assert.throws(() => open({ ...sealed, nonce: "AAAA" }, bob.privateKey), /nonce wrong length/);
  assert.throws(() => open({ ...sealed, salt: "!!!!not base64!!!!" }, bob.privateKey), /salt is not canonical/);
  assert.throws(() => open({ ...sealed, epk: "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n" }, bob.privateKey), /malformed ephemeral/);
  const ed = edKeyPair();
  assert.throws(() => open({ ...sealed, epk: ed.publicKey }, bob.privateKey), /not an X25519 key/);
});
