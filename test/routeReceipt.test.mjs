/**
 * The signed delivery receipt. What matters: a receipt round-trips only when verified
 * against the destination key that signed it; any tampered field, a receipt signed by the
 * wrong key, or a malformed one fails; and the delivered/refused + reason rules hold.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { generateIdentity } from "../src/identity.js";
import { buildReceipt, keyId, receiptProblem, signReceipt, verifyReceipt } from "../src/routeReceipt.js";

const T = 1_700_000_000_000;
const MSG_ID = "_9_dyjXkLPnraDMak3Jg0w"; // 16 bytes, canonical base64url

/** A well-formed receipt from `dest` about a message from `origin`. */
const receipt = (origin, dest, over = {}) =>
  buildReceipt({
    originKeyId: keyId(origin.publicKey),
    destinationKeyId: keyId(dest.publicKey),
    messageId: MSG_ID,
    outcome: "delivered",
    issuedAt: T,
    ...over,
  });

test("a receipt the destination signed verifies against the destination key", () => {
  const a = generateIdentity();
  const d = generateIdentity();
  const r = receipt(a, d);
  const sig = signReceipt(r, d.privateKey);
  assert.equal(verifyReceipt(r, sig, d.publicKey), true);
  // Signed by the destination, so a stranger's key does not verify it.
  assert.equal(verifyReceipt(r, sig, generateIdentity().publicKey), false);
});

test("the signer must be the destination the receipt names", () => {
  const a = generateIdentity();
  const d = generateIdentity();
  const other = generateIdentity();
  // `other` signs a receipt that still names `d` as destination — verify with `other`'s
  // key: the manifest-style keyId(pub) === destinationKeyId binding rejects it.
  const r = receipt(a, d);
  const forged = signReceipt(r, other.privateKey);
  assert.equal(verifyReceipt(r, forged, other.publicKey), false, "keyId(signer) != destinationKeyId");
});

test("any change to a signed field breaks the signature", () => {
  const a = generateIdentity();
  const d = generateIdentity();
  const r = receipt(a, d, { outcome: "refused", reason: "cleartext-refused" });
  const sig = signReceipt(r, d.privateKey);
  assert.equal(verifyReceipt(r, sig, d.publicKey), true);
  for (const [field, value] of [
    ["messageId", "Zm9vYmFyYmF6cXV4MTIzNDU2"],
    ["outcome", "delivered"],
    ["reason", "origin-unauthorized"],
    ["blockIndex", 1],
    ["issuedAt", T + 1],
    ["originKeyId", keyId(generateIdentity().publicKey)],
  ]) {
    assert.equal(verifyReceipt({ ...r, [field]: value }, sig, d.publicKey), false, `${field} tamper refused`);
  }
});

test("outcome/reason rules are enforced", () => {
  const a = generateIdentity();
  const d = generateIdentity();
  // delivered must carry an empty reason (buildReceipt normalises it).
  assert.equal(buildReceipt({ originKeyId: keyId(a.publicKey), destinationKeyId: keyId(d.publicKey), messageId: MSG_ID, outcome: "delivered", reason: "ignored", issuedAt: T }).reason, "");
  // a refused receipt keeps its reason.
  const refused = receipt(a, d, { outcome: "refused", reason: "replay:duplicate" });
  assert.equal(refused.reason, "replay:duplicate");
  // an unknown outcome, an over-long or non-slug reason, and a delivered-with-reason all fail validation.
  assert.equal(receiptProblem({ ...refused, outcome: "maybe" }), "bad outcome");
  assert.equal(receiptProblem({ ...refused, reason: "x".repeat(65) }), "bad reason");
  assert.equal(receiptProblem({ ...refused, reason: "has spaces!" }), "bad reason");
  assert.equal(receiptProblem({ ...refused, outcome: "delivered" }), "delivered carries a reason");
});

test("a re-spelled (non-canonical) signature does not verify — no wire malleability", () => {
  const a = generateIdentity();
  const d = generateIdentity();
  const r = receipt(a, d);
  const sig = signReceipt(r, d.privateKey);
  assert.equal(verifyReceipt(r, sig, d.publicKey), true);
  // Same 64 signature bytes, but a non-canonical base64 spelling (a trailing newline, or
  // the standard 88-char form re-encoded with junk) must be rejected, matching the manifest.
  assert.equal(verifyReceipt(r, sig + "\n", d.publicKey), false, "trailing whitespace rejected");
  assert.equal(verifyReceipt(r, sig.slice(0, -1) + (sig.endsWith("=") ? "==" : "="), d.publicKey), false, "bad padding rejected");
});

test("malformed receipts are refused, not thrown", () => {
  const a = generateIdentity();
  const d = generateIdentity();
  const r = receipt(a, d);
  const sig = signReceipt(r, d.privateKey);
  for (const bad of [null, undefined, 42, {}, { ...r, extra: 1 }]) {
    assert.equal(verifyReceipt(bad, sig, d.publicKey), false);
  }
  // buildReceipt throws on a programming error (an invalid part).
  assert.throws(() => buildReceipt({ originKeyId: "short", destinationKeyId: keyId(d.publicKey), messageId: MSG_ID, outcome: "delivered", issuedAt: T }));
});
