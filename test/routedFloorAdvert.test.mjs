/**
 * Signed floor advertisement over a two-plugin A->B wire. What matters: an honest sender that
 * has learned a destination's advertised `routed.requireSealed` DEMOTES an explicit `public`
 * application-data send to confidential — sealing it if a key is approved, else refusing it
 * LOCALLY (nothing on the wire); the data-free `null` probe is never demoted (deadlock
 * exemption); the floor is advisory (the destination's local floor is the mechanism); and no
 * relay action (suppress, replay an older no-floor record, inject a floor) turns a would-be
 * sealed send clear or forges a floor. F7 (a replayed-newer floor after the destination lowers
 * its floor) is covered at the store layer by the latest-wins test in routedKeyStore.test.mjs
 * plus the probe exemption (F2): recovery is a `null` probe that re-learns the current value.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { generateIdentity } from "../src/identity.js";
import { keyId } from "../src/routeManifest.js";
import { createRoutePlugin, ROUTED_RECORD_FIELD } from "../src/builtin/routePlugin.js";
import { createRoutedKeyStore } from "../src/routedKeyStore.js";
import { signDiscoveryRecord } from "../src/routedDiscoveryRecord.js";

const machine = (name) => {
  const identity = generateIdentity();
  return {
    name,
    identity,
    keyId: keyId(identity.publicKey),
    record: { name, publicKey: identity.publicKey, sealPublicKey: identity.sealPublicKey, addresses: [] },
  };
};

const cryptoDeps = (self, over = {}) => ({
  self: self.identity.publicKey,
  privateKey: self.identity.privateKey,
  selfRecord: () => self.record,
  authorizeOrigin: () => true,
  neighbors: () => [],
  forward: async () => ({ delivered: false, spent: 0 }),
  deliver: () => ({ received: true }),
  sealPrivateKey: self.identity.sealPrivateKey,
  ...over,
});

/** A signed discovery record for `m`, optionally advertising its floor. */
const advertOf = (m, requireSealed = false) =>
  signDiscoveryRecord({ self: { name: m.name, publicKey: m.identity.publicKey, sealPublicKey: m.identity.sealPublicKey }, requireSealed, privateKey: m.identity.privateKey });

/**
 * A→B wire where A is Tier-0 UNVERIFIED for B (so an advertised floor is what governs the send),
 * B optionally floors, and `tamper` may mutate B's response before A sees it. `forwards()` counts
 * outbound forwards, so a pre-flight (local) refusal is provable by "nothing left the node".
 */
const floorWire = (a, b, { bRequireSealed = true, bDeliver = (body) => ({ received: true, echo: body }), tamper = (r) => r } = {}) => {
  let pluginB;
  let forwards = 0;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => {
      forwards += 1;
      const res = await pluginB.router.relay(envelope, a.identity.publicKey);
      return tamper(res);
    },
    deliver: () => assert.fail("origin A must not deliver"),
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, {
    neighbors: () => [a.identity.publicKey],
    sealPrivateKey: b.identity.sealPrivateKey,
    ...(bRequireSealed ? { requireSealed: true } : {}),
    deliver: bDeliver,
  }));
  return { pluginA, get pluginB() { return pluginB; }, forwards: () => forwards };
};

test("F1: learn the floor from a refusal, then demote — refuse locally until approved, then seal", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const { pluginA, forwards } = floorWire(a, b);
  const B = b.identity.publicKey;

  // (a) first public send goes clear; B's floor refuses it, and the refusal teaches the key + floor.
  const r1 = await pluginA.send(B, { x: 1 }, { public: true });
  assert.equal(r1.refused, true);
  assert.equal(r1.response?.reason, "cleartext-refused");
  assert.equal(pluginA.router.routedSealState(B), "record-carried");
  assert.equal(pluginA.router.routedSealDetail(B)?.requireSealed, true);
  const afterFirst = forwards();

  // (b) second public send is DEMOTED and refused LOCALLY (key still pending) — nothing forwarded.
  const r2 = await pluginA.send(B, { x: 2 }, { public: true });
  assert.equal(r2.delivered, false);
  assert.equal(r2.reason, "seal-refused:floor-advertised");
  assert.deepEqual(r2.seal, { decision: "refuse", tier: null, state: "tier1-pending", floor: "advertised" });
  assert.equal(forwards(), afterFirst, "a pre-flight refusal forwards nothing");

  // (c) approve the key -> the demoted public send is sealed proactively and delivered.
  assert.equal(pluginA.router.approveRoutedSeal(B).ok, true);
  const r3 = await pluginA.send(B, { x: 3 }, { public: true });
  assert.equal(r3.delivered, true);
  assert.deepEqual(r3.seal, { decision: "seal", tier: 1, state: "record-approved", floor: "advertised" });
  assert.deepEqual(r3.responseSeal, { expected: true, state: "sealed" });
  assert.deepEqual(r3.receipt, { present: true, verified: true, outcome: "delivered", reason: "" });
  assert.deepEqual(r3.response?.echo, { x: 3 }, "B saw the demoted (now sealed) payload");
});

test("F2: the data-free null probe is never demoted (deadlock exemption)", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const { pluginA, forwards } = floorWire(a, b);
  const B = b.identity.publicKey;
  await pluginA.send(B, { x: 1 }, { public: true }); // learn the floor
  assert.equal(pluginA.router.routedSealDetail(B)?.requireSealed, true);
  const before = forwards();
  // A null probe is NOT demoted: it goes to the wire and is refused cleartext-refused (teaching the record).
  const probe = await pluginA.send(B, null, { public: true });
  assert.equal(forwards(), before + 1, "the probe forwards; it is not pre-flight refused");
  assert.equal(probe.refused, true);
  assert.equal(probe.response?.reason, "cleartext-refused");
  assert.equal(probe.seal?.state, "public");
  assert.equal(probe.seal?.floor, undefined, "a probe is never marked demoted");
});

test("F3: floor off — no demotion, and A learns no floor", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const { pluginA } = floorWire(a, b, { bRequireSealed: false });
  const B = b.identity.publicKey;
  // Unfloored B delivers a public app-data send clear, with today's seal shape (no floor key).
  const r = await pluginA.send(B, { x: 1 }, { public: true });
  assert.equal(r.delivered, true);
  assert.equal(r.refused, undefined);
  assert.equal(r.seal.decision, "cleartext");
  assert.equal(r.seal.floor, undefined);
  assert.equal(pluginA.router.routedSealDetail(B)?.requireSealed, undefined, "no floor advertised");
});

test("F4: a relay that suppresses the advert falls back to today's round trip", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const { pluginA, forwards } = floorWire(a, b, {
    tamper: (r) => { if (r?.response) delete r.response[ROUTED_RECORD_FIELD]; return r; },
  });
  const B = b.identity.publicKey;
  const r1 = await pluginA.send(B, { x: 1 }, { public: true });
  assert.equal(r1.refused, true);
  assert.equal(pluginA.router.routedSealState(B), "none", "no record learned (advert suppressed)");
  const r2 = await pluginA.send(B, { x: 2 }, { public: true });
  assert.equal(r2.refused, true, "still goes to the wire and is refused remotely");
  assert.equal(forwards(), 2, "both sends forwarded — no pre-flight, exactly today's path");
});

test("F5: a relay replaying an older no-floor record learns the key but no floor", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const bare = advertOf(b, false); // genuine B-signed, same key, no floor
  const { pluginA, forwards } = floorWire(a, b, {
    tamper: (r) => { if (r?.response?.[ROUTED_RECORD_FIELD]) r.response[ROUTED_RECORD_FIELD] = bare; return r; },
  });
  const B = b.identity.publicKey;
  const r1 = await pluginA.send(B, { x: 1 }, { public: true });
  assert.equal(r1.refused, true);
  assert.equal(pluginA.router.routedSealState(B), "record-carried", "the key is learned (same identity, no conflict)");
  assert.equal(pluginA.router.routedSealDetail(B)?.requireSealed, undefined, "but no floor was learned");
  const before = forwards();
  const r2 = await pluginA.send(B, { x: 2 }, { public: true });
  assert.equal(forwards(), before + 1, "not demoted (no floor); forwarded, refused remotely");
  assert.equal(r2.refused, true);
});

test("F6: a relay cannot inject a floor the destination did not sign", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const { pluginA } = floorWire(a, b, {
    bRequireSealed: false,
    tamper: (r) => {
      const rec = r?.response?.[ROUTED_RECORD_FIELD];
      if (rec?.record) rec.record = { ...rec.record, routed: { requireSealed: true } }; // no re-sign
      return r;
    },
  });
  const B = b.identity.publicKey;
  // Unfloored B delivers clear; the injected `routed` breaks the signature, so nothing is learned.
  const r1 = await pluginA.send(B, { x: 1 }, { public: true });
  assert.equal(r1.delivered, true, "unfloored B delivers the clear send");
  assert.equal(pluginA.router.routedSealState(B), "none", "the injected floor breaks the signature -> nothing learned");
});

test("F8: the advertised floor rides a delivery response, not only a refusal", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const B = b.identity.publicKey;
  // A holds an approved (floored) key; a CONFIDENTIAL send delivers sealed and B's record carries the floor.
  const store = createRoutedKeyStore();
  store.observe(b.keyId, advertOf(b, true));
  store.approve(b.keyId);
  let pluginB;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [B],
    forward: async (_p, env) => pluginB.router.relay(env, a.identity.publicKey),
    routedKeyStore: store,
    deliver: () => assert.fail("A must not deliver"),
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, { neighbors: () => [a.identity.publicKey], sealPrivateKey: b.identity.sealPrivateKey, requireSealed: true, deliver: () => ({ received: true }) }));
  const r = await pluginA.send(B, { hi: 1 }); // confidential (no public)
  assert.equal(r.delivered, true);
  assert.deepEqual(r.responseSeal, { expected: true, state: "sealed" });
  assert.equal(r.response?.[ROUTED_RECORD_FIELD]?.record?.routed?.requireSealed, true, "the floor rides the delivery response");
});

test("F9: a Tier-0 posture is not demoted and forgets the Tier-1 floor entry", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const B = b.identity.publicKey;
  // Pre-load A's store with an approved, FLOORED Tier-1 entry for B.
  const store = createRoutedKeyStore();
  store.observe(b.keyId, advertOf(b, true));
  store.approve(b.keyId);
  assert.equal(store.recordFloor(b.keyId), true);
  let pluginB;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [B],
    forward: async (_p, env) => pluginB.router.relay(env, a.identity.publicKey),
    routedKeyStore: store,
    tier0Seal: (dest) => (keyId(dest) === b.keyId ? { state: "verified", key: b.identity.sealPublicKey } : { state: "unverified", key: null }),
    deliver: () => assert.fail("A must not deliver"),
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, { neighbors: () => [a.identity.publicKey], sealPrivateKey: b.identity.sealPrivateKey, requireSealed: true, deliver: (body) => ({ received: true, echo: body }) }));
  // Tier-0 verified -> not demoted; the public opt-out stands, so the send goes clear. The stale
  // Tier-1 entry is forgotten (its approval dropped); B's floor then refuses the clear send and
  // re-teaches only a PENDING entry, so the approved key is gone even though a floor is re-learned.
  const r = await pluginA.send(B, { x: 1 }, { public: true });
  assert.equal(r.seal.floor, undefined, "a Tier-0 posture is never demoted");
  assert.equal(r.seal.decision, "cleartext");
  assert.equal(store.recordState(b.keyId), "record-carried", "the approved Tier-1 entry was forgotten (re-learned pending)");
  assert.equal(store.recordSealKey(b.keyId), null, "no approved key survives under a Tier-0 posture");
});
