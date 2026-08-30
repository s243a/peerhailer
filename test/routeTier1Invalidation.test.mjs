/**
 * Synchronous Tier-1 invalidation on a Tier-0 event (routing review #7). A walk, accept,
 * rotation, or forget must drop a discovered/approved Tier-1 key immediately — so a
 * superseded or retired key can never be sealed to in the window before a lazy clear.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createDirectory } from "../src/directory.js";
import { generateIdentity, normalizeKey } from "../src/identity.js";
import { keyId } from "../src/routeManifest.js";
import { signRecord } from "../src/peerRecord.js";
import { createRoutedKeyStore } from "../src/routedKeyStore.js";

const dir = () => createDirectory({ self: { name: "me", publicKey: generateIdentity().publicKey } });
const recordOf = (id) =>
  signRecord({ name: "peer", publicKey: id.publicKey, sealPublicKey: id.sealPublicKey, addresses: [], lastSeen: null }, id.privateKey);

test("a Tier-0 event notifies the seal-posture listener with the identity key", () => {
  const d = dir();
  const peer = generateIdentity();
  const seen = [];
  d.setSealPostureListener((pk) => seen.push(normalizeKey(pk)));
  d.admit({ name: "p", publicKey: peer.publicKey });

  d.bindSealKey("p", peer.sealPublicKey, peer.publicKey);
  assert.ok(seen.includes(normalizeKey(peer.publicKey)), "a walk notifies");
  seen.length = 0;
  d.forget("p");
  assert.ok(seen.includes(normalizeKey(peer.publicKey)), "a forget notifies");
});

test("adopt (the daemon's real commit path) invalidates a Tier-1 key for a Tier-0-posture peer", () => {
  // The daemon commits every mutation via applyChange -> directory.adopt, NOT via the
  // per-mutator bindSealKey/forget. So invalidation must fire from adopt too.
  const d = dir();
  const store = createRoutedKeyStore();
  d.setSealPostureListener((pk) => store.forget(keyId(pk)));

  const peer = generateIdentity();
  const kid = keyId(peer.publicKey);
  store.observe(kid, recordOf(peer));
  store.approve(kid);
  assert.equal(store.recordState(kid), "record-approved");

  // Adopt a state in which the peer now carries a walked Tier-0 seal posture.
  d.adopt({
    admitted: [{
      name: "peer",
      publicKey: peer.publicKey,
      sealPublicKey: normalizeKey(peer.sealPublicKey),
      sealSeen: true,
      sealRequired: true,
      profile: "trusted",
    }],
  });
  assert.equal(store.recordState(kid), "none", "adopt fired the Tier-1 invalidation");

  // A peer with NO Tier-0 seal posture keeps its approved Tier-1 key across an adopt.
  const other = generateIdentity();
  const okid = keyId(other.publicKey);
  store.observe(okid, recordOf(other));
  store.approve(okid);
  d.adopt({ admitted: [{ name: "other", publicKey: other.publicKey, profile: "trusted" }] });
  assert.equal(store.recordState(okid), "record-approved", "an unwalked peer's approved key survives adopt");
});

test("a walk invalidates an approved Tier-1 key — no sealing to a superseded key", () => {
  const d = dir();
  const store = createRoutedKeyStore();
  d.setSealPostureListener((pk) => store.forget(keyId(pk)));

  const peer = generateIdentity();
  const kid = keyId(peer.publicKey);
  // Discover and approve a Tier-1 key for the peer.
  store.observe(kid, recordOf(peer));
  store.approve(kid);
  assert.equal(store.recordState(kid), "record-approved");

  // A walk binds a Tier-0 key -> the listener forgets the now-moot Tier-1 entry at once.
  d.admit({ name: "peer", publicKey: peer.publicKey });
  d.bindSealKey("peer", peer.sealPublicKey, peer.publicKey);
  assert.equal(store.recordState(kid), "none", "the approved Tier-1 key was invalidated by the walk");
});
