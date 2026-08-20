/**
 * Grants: permission made when it is needed.
 *
 * Most of these are about a grant *not* being a bearer token — it names its
 * holder, it cannot widen, and it stops working shortly. Those three are what
 * make it safe to hand over a channel a directory entry could never travel.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { attenuate, mintGrant, verifyGrant } from "../src/grants.js";
import { generateIdentity } from "../src/identity.js";

const sol = generateIdentity();
const luna = generateIdentity();
const mallory = generateIdentity();

const grantFor = (subject, capabilities, extra = {}) =>
  mintGrant({
    issuer: "sol",
    issuerKey: sol.publicKey,
    privateKey: sol.privateKey,
    subjectKey: subject.publicKey,
    capabilities,
    ...extra,
  });

test("a valid grant verifies for the machine it names", () => {
  const envelope = grantFor(luna, ["relay"]);
  const checked = verifyGrant(envelope, { presenterKey: luna.publicKey, capability: "relay" });
  assert.equal(checked.ok, true);
  assert.deepEqual(checked.grant.capabilities, ["relay"]);
});

test("a grant is worthless to anyone else holding it", () => {
  // The rule that stops this being a bearer token. Intercepting the bytes gains
  // nothing without the private key it was minted for.
  const envelope = grantFor(luna, ["relay"]);
  const stolen = verifyGrant(envelope, { presenterKey: mallory.publicKey, capability: "relay" });
  assert.equal(stolen.ok, false);
  assert.match(stolen.error, /minted for another machine/);
});

test("a grant only carries what it was minted with", () => {
  const envelope = grantFor(luna, ["relay"]);
  const overreach = verifyGrant(envelope, { presenterKey: luna.publicKey, capability: "diagnostics" });
  assert.equal(overreach.ok, false);
  assert.match(overreach.error, /does not carry diagnostics/);
});

test("an altered grant fails, whichever field was touched", () => {
  const envelope = grantFor(luna, ["relay"]);
  const tampered = {
    ...envelope,
    grant: { ...envelope.grant, capabilities: ["relay", "diagnostics"] },
  };
  assert.equal(verifyGrant(tampered, { presenterKey: luna.publicKey }).ok, false);

  const extended = { ...envelope, grant: { ...envelope.grant, expires: Date.now() + 10 ** 9 } };
  assert.equal(verifyGrant(extended, { presenterKey: luna.publicKey }).ok, false);
});

test("an issuer cannot delegate what it does not hold", () => {
  // `allowed` is what the issuer may pass on. Asking for more yields less, not
  // an error, so a caller over-asking still gets what it can have.
  const envelope = grantFor(luna, ["relay", "diagnostics"], { allowed: ["relay"] });
  assert.deepEqual(envelope.grant.capabilities, ["relay"]);

  const nothing = grantFor(luna, ["diagnostics"], { allowed: ["relay"] });
  assert.equal(nothing, null, "a grant carrying nothing is not minted at all");
});

test("a grant expires, and says so", () => {
  const now = 1_000_000;
  const envelope = grantFor(luna, ["relay"], { ttlMs: 60_000, now });

  assert.equal(verifyGrant(envelope, { presenterKey: luna.publicKey, now: now + 59_000 }).ok, true);
  const stale = verifyGrant(envelope, { presenterKey: luna.publicKey, now: now + 61_000 });
  assert.equal(stale.ok, false);
  assert.match(stale.error, /expired/);
});

test("a grant cannot be minted to outlive the ceiling", () => {
  const now = 1_000_000;
  const envelope = grantFor(luna, ["relay"], { ttlMs: 10 ** 9, now });
  // Anything long-lived is a credential in all but name.
  assert.ok(envelope.grant.expires - now <= 60 * 60_000);
});

test("attenuating narrows and never widens", () => {
  const now = 1_000_000;
  const parent = grantFor(luna, ["relay", "hail"], { ttlMs: 300_000, now });

  const child = attenuate(parent, {
    issuer: "luna",
    issuerKey: luna.publicKey,
    privateKey: luna.privateKey,
    subjectKey: mallory.publicKey,
    capabilities: ["relay", "diagnostics"],
    now,
  });

  assert.deepEqual(child.grant.capabilities, ["relay"], "diagnostics was never in the parent");
  assert.ok(child.grant.expires <= parent.grant.expires, "a child cannot outlive its parent");
});

test("only the subject of a grant may attenuate it", () => {
  const parent = grantFor(luna, ["relay"]);
  const forged = attenuate(parent, {
    issuer: "mallory",
    issuerKey: mallory.publicKey,
    privateKey: mallory.privateKey,
    subjectKey: mallory.publicKey,
  });
  assert.equal(forged, null);
});

test("a grant from an unexpected issuer is refused", () => {
  const envelope = grantFor(luna, ["relay"]);
  const checked = verifyGrant(envelope, {
    presenterKey: luna.publicKey,
    issuerKey: mallory.publicKey,
  });
  assert.equal(checked.ok, false);
  assert.match(checked.error, /different key/);
});
