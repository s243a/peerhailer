/**
 * The authenticated route manifest (M1). What matters: a relay cannot forge the
 * origin, alter any signed field, or reuse a signature for a different origin — and a
 * malformed manifest from the wire fails verification rather than crashing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";

import { generateIdentity } from "../src/identity.js";
import {
  buildManifest,
  keyId,
  payloadDigest,
  signManifest,
  verifyManifest,
  manifestProblem,
  MANIFEST_DOMAIN,
} from "../src/routeManifest.js";

const alice = generateIdentity();
const bob = generateIdentity();
const now = 1_700_000_000_000;

/** A well-formed manifest for a clear payload from alice to bob. */
const sampleParts = () => ({
  originKeyId: keyId(alice.publicKey),
  destinationKeyId: keyId(bob.publicKey),
  messageId: createHash("sha256").update("m-1").digest().subarray(0, 16).toString("base64url"),
  issuedAt: now,
  expiresAt: now + 60_000,
  payloadMode: /** @type {const} */ ("clear"),
  payloadDigest: payloadDigest(Buffer.from("hello")),
});

test("round-trip: a signed manifest verifies against the origin's key", () => {
  const m = buildManifest(sampleParts());
  const sig = signManifest(m, alice.privateKey);
  assert.equal(verifyManifest(m, sig, alice.publicKey), true);
});

test("keyId is the SHA-256 of SPKI DER: stable across PEM whitespace, full-width, per-key", () => {
  const id = keyId(alice.publicKey);
  assert.match(id, /^[A-Za-z0-9_-]{43}$/, "43-char base64url of a 32-byte hash");
  // Whitespace variation in the PEM must not change the id (DER is canonical).
  const reflowed = alice.publicKey.replace(/\n/g, "\r\n") + "\n";
  assert.equal(keyId(reflowed), id, "PEM whitespace does not change the id");
  assert.notEqual(keyId(bob.publicKey), id, "a different key has a different id");
});

test("tampering with any signed field breaks verification", () => {
  const m = buildManifest(sampleParts());
  const sig = signManifest(m, alice.privateKey);
  for (const [field, value] of [
    ["messageId", createHash("sha256").update("other").digest().subarray(0, 16).toString("base64url")],
    ["expiresAt", m.expiresAt + 1],
    ["payloadDigest", payloadDigest(Buffer.from("HELLO"))], // a swapped payload
    ["destinationKeyId", keyId(generateIdentity().publicKey)],
    ["blockCount", 2],
  ]) {
    const tampered = { ...m, [field]: value };
    assert.equal(verifyManifest(tampered, sig, alice.publicKey), false, `tampered ${field} must fail`);
  }
});

test("a signature does not verify for a different origin key (origin binding)", () => {
  const m = buildManifest(sampleParts());
  const sig = signManifest(m, alice.privateKey);
  // Bob presents alice's validly-signed manifest under his own key: refused, because
  // keyId(bob) !== manifest.originKeyId even before the signature is checked.
  assert.equal(verifyManifest(m, sig, bob.publicKey), false);
  // And a manifest that claims bob as origin but is signed by alice: refused.
  const claimsBob = buildManifest({ ...sampleParts(), originKeyId: keyId(bob.publicKey) });
  const aliceSig = signManifest(claimsBob, alice.privateKey);
  assert.equal(verifyManifest(claimsBob, aliceSig, alice.publicKey), false, "signer must equal the named origin");
});

test("malformed manifests fail verification without throwing", () => {
  const m = buildManifest(sampleParts());
  const sig = signManifest(m, alice.privateKey);
  assert.equal(verifyManifest(null, sig, alice.publicKey), false);
  assert.equal(verifyManifest({ ...m, domain: "evil" }, sig, alice.publicKey), false);
  assert.equal(verifyManifest({ ...m, version: 999 }, sig, alice.publicKey), false);
  assert.equal(verifyManifest(m, "not-a-signature", alice.publicKey), false);
  assert.equal(verifyManifest(m, `${sig}!!!!`, alice.publicKey), false, "non-canonical base64 is refused");
  assert.equal(verifyManifest(m, sig, "not-a-key"), false);
  // An unsigned extra property is not covered by the signature — refuse it.
  assert.equal(verifyManifest({ ...m, sneaky: "x" }, sig, alice.publicKey), false, "extra unsigned field is refused");

  const inherited = Object.assign(Object.create({ domain: m.domain }), m);
  delete inherited.domain;
  assert.match(manifestProblem(inherited), /missing domain/, "signed fields must be own properties");
});

test("route identities are Ed25519 — other asymmetric algorithms are refused", () => {
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const rsaPublic = rsa.publicKey.export({ type: "spki", format: "pem" }).toString();
  assert.throws(() => keyId(rsaPublic), /Ed25519/);
  const m = buildManifest(sampleParts());
  assert.equal(verifyManifest(m, signManifest(m, alice.privateKey), rsaPublic), false);
});

test("manifestProblem catches out-of-range fields; buildManifest refuses to assemble them", () => {
  assert.equal(manifestProblem(buildManifest(sampleParts())), null, "a good one is clean");
  assert.match(manifestProblem({ ...buildManifest(sampleParts()), blockIndex: 5, blockCount: 2 }), /out of range/);
  assert.match(manifestProblem({ ...buildManifest(sampleParts()), expiresAt: now, issuedAt: now }), /not after/);
  assert.match(manifestProblem({ ...buildManifest(sampleParts()), messageId: "short" }), /messageId/);
  assert.match(
    manifestProblem({ ...buildManifest(sampleParts()), messageId: "BBBBBBBBBBBBBBBBBBBBBB" }),
    /messageId/,
    "unused pad-bit aliases are not canonical 16-byte ids",
  );
  assert.match(manifestProblem({ ...buildManifest(sampleParts()), blockIndex: -0 }), /block index/);
  assert.match(manifestProblem({ ...buildManifest(sampleParts()), payloadMode: "onion" }), /payloadMode/);
  assert.throws(() => buildManifest({ ...sampleParts(), expiresAt: now - 1 }), /invalid manifest/);
  assert.equal(buildManifest(sampleParts()).domain, MANIFEST_DOMAIN);
});
