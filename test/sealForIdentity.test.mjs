/**
 * Tier-0 sealing posture aggregated by identity key (routing review #3). A destination is
 * a key, and one key may hold several admitted names; the routed send must not be able to
 * read a stale/unverified alias and miss a verified one, nor slip past a conflict.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createDirectory } from "../src/directory.js";
import { generateIdentity, normalizeKey } from "../src/identity.js";

const dir = () => createDirectory({ self: { name: "me", publicKey: generateIdentity().publicKey } });

test("a verified alias is used even when another unverified alias of the same identity exists", () => {
  const d = dir();
  const peer = generateIdentity();
  d.admit({ name: "alias-1", publicKey: peer.publicKey });
  d.admit({ name: "alias-2", publicKey: peer.publicKey });
  assert.deepEqual(d.sealForIdentity(peer.publicKey), { state: "unverified", key: null });

  // A walk verifies alias-2's sealing key. alias-1 stays unverified.
  d.bindSealKey("alias-2", peer.sealPublicKey, peer.publicKey);
  const r = d.sealForIdentity(peer.publicKey);
  assert.equal(r.state, "verified", "the unverified alias does not hide the verified one");
  assert.equal(r.key, normalizeKey(peer.sealPublicKey));
});

test("aliases verified to different keys fail closed as a conflict", () => {
  const d = dir();
  const peer = generateIdentity();
  const otherSeal = generateIdentity();
  d.admit({ name: "a1", publicKey: peer.publicKey });
  d.admit({ name: "a2", publicKey: peer.publicKey });
  d.bindSealKey("a1", peer.sealPublicKey, peer.publicKey);
  d.bindSealKey("a2", otherSeal.sealPublicKey, peer.publicKey);
  assert.equal(d.sealForIdentity(peer.publicKey).state, "conflict", "disagreeing verified keys never seal");
});

test("an unknown identity is unverified", () => {
  assert.deepEqual(dir().sealForIdentity(generateIdentity().publicKey), { state: "unverified", key: null });
});
