/**
 * Sealed routed RESPONSES (routing security arc, item #3). What matters: a sealed request
 * carries the origin's X25519 response key inside its authenticated plaintext; the destination
 * seals a `{messageId, body}` reply to it and signs with its identity; and the origin verifies
 * sealer == routing target and messageId BEFORE decrypting, WITHHOLDING the body on any
 * clear/unopenable/wrong-sealer/mismatched reply — never handing up content it asked to receive
 * sealed. Response mode follows request mode: a clear request keeps a clear reply. A confidential
 * send from an origin with no sealing key of its own is refused locally.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, createPrivateKey, randomBytes } from "node:crypto";

import { generateIdentity } from "../src/identity.js";
import { buildManifest, keyId, payloadDigest, signManifest } from "../src/routeManifest.js";
import { signRecord } from "../src/peerRecord.js";
import { seal } from "../src/sealing.js";
import { createRouteReplayGuard } from "../src/routeReplayGuard.js";
import { createRoutedKeyStore } from "../src/routedKeyStore.js";
import {
  RoutedMessageInputError,
  ROUTED_RESPONSE_SEAL_KEY_FIELD,
  wrapRoutedMessage,
  openRoutedMessage,
  sealRoutedResponse,
  openRoutedResponse,
} from "../src/routedMessage.js";
import {
  createRoutePlugin,
  ROUTED_RECORD_FIELD,
  ROUTED_RECEIPT_FIELD,
  ROUTED_SEALED_RESPONSE_FIELD,
} from "../src/builtin/routePlugin.js";

const T = 1_700_000_000_000;
const MSG_ID = "_9_dyjXkLPnraDMak3Jg0w"; // 16 bytes, canonical base64url
const MARKER = "top-secret-response-marker";

/** A machine usable by both the routedMessage unit tests and the plugin wire tests. */
const machine = (name) => {
  const identity = generateIdentity();
  return {
    name,
    identity,
    keyId: keyId(identity.publicKey),
    record: { name, publicKey: identity.publicKey, sealPublicKey: identity.sealPublicKey, addresses: [] },
  };
};

const guardAt = (t = T) => createRouteReplayGuard({ now: () => t });

/** A signed key-only record for `m` (default advertising its own sealing key). */
const recordOf = (m, sealPublicKey = m.identity.sealPublicKey) =>
  signRecord({ name: m.name, publicKey: m.identity.publicKey, sealPublicKey, addresses: [], lastSeen: null }, m.identity.privateKey);

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

/** Wrap sealed from `origin` to `dest`, optionally carrying `origin`'s response key. */
const wrapSealed = (origin, dest, body, { responseSealKey, ...over } = {}) =>
  wrapRoutedMessage({
    self: origin.record,
    privateKey: origin.identity.privateKey,
    destinationKeyId: dest.keyId,
    body,
    messageId: MSG_ID,
    now: T,
    validityMs: 60_000,
    sealTo: { recipientKey: dest.identity.sealPublicKey, ...(responseSealKey !== undefined ? { responseSealKey } : {}) },
    ...over,
  });

/** Open a wrapper at `dest`, supplying its sealing key by default. */
const openAt = (wrapper, dest, extra = {}) =>
  openRoutedMessage(wrapper, {
    selfKeyId: dest.keyId,
    guard: guardAt(),
    authorizeOrigin: () => true,
    sealPrivateKey: dest.identity.sealPrivateKey,
    ...extra,
  });

/** Hand-build a sealed wrapper whose SEALED plaintext is exactly `innerObj` (signed by origin). */
const forgeSealedInner = (origin, dest, innerObj) => {
  const sealed = seal(Buffer.from(JSON.stringify(innerObj), "utf8"), dest.identity.sealPublicKey, {
    signer: { publicKey: origin.identity.publicKey, privateKey: origin.identity.privateKey },
  });
  const transported = Buffer.from(JSON.stringify(sealed), "utf8");
  const manifest = buildManifest({
    originKeyId: origin.keyId,
    destinationKeyId: dest.keyId,
    messageId: MSG_ID,
    issuedAt: T,
    expiresAt: T + 60_000,
    payloadMode: "sealed",
    payloadDigest: payloadDigest(transported),
  });
  return {
    manifest,
    manifestSignature: signManifest(manifest, origin.identity.privateKey),
    originRecord: signRecord(origin.record, origin.identity.privateKey),
    payload: transported.toString("base64"),
  };
};

/** The base64 body of a PEM (header/footer/whitespace stripped), for on-the-wire absence checks. */
const pemBase64 = (pem) => pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");

// --- Unit: routedMessage response header + response envelope ---

test("1. the response-sealing header round-trips and never appears on the wire", () => {
  const a = machine("alice");
  const b = machine("bob");
  const w = wrapSealed(a, b, { hello: "graph" }, { responseSealKey: a.identity.sealPublicKey });
  const opened = openAt(w, b);
  assert.equal(opened.ok, true);
  assert.deepEqual(opened.body, { hello: "graph" }, "the consumer sees only its body, header stripped");
  assert.equal(opened.responseSealKey, a.identity.sealPublicKey, "the origin's X25519 response key is surfaced");
  const wire = Buffer.from(w.payload, "base64").toString("utf8");
  assert.ok(!wire.includes(pemBase64(a.identity.sealPublicKey)), "the response key is sealed, not on the wire");
});

test("2. a sealed request without the header opens as a legacy raw body", () => {
  const a = machine("alice");
  const b = machine("bob");
  const opened = openAt(wrapSealed(a, b, { x: 1 }), b);
  assert.equal(opened.ok, true);
  assert.deepEqual(opened.body, { x: 1 });
  assert.equal(opened.responseSealKey, undefined, "no header carried, no response key");
});

test("3. the discriminator is the exact two-key shape; a 3-key object is a raw body", () => {
  const a = machine("alice");
  const b = machine("bob");
  const raw = { [ROUTED_RESPONSE_SEAL_KEY_FIELD]: a.identity.sealPublicKey, body: 1, extra: 2 };
  const opened = openAt(wrapSealed(a, b, raw), b); // no responseSealKey → wrap does not add a header
  assert.equal(opened.ok, true);
  assert.deepEqual(opened.body, raw, "an origin-authored 3-key body is delivered as-is");
  assert.equal(opened.responseSealKey, undefined);
});

test("4. a header key that is not X25519 refuses receiptably (origin bug)", () => {
  const a = machine("alice");
  const b = machine("bob");
  // Exact two-key header, but the key is Ed25519 — post-authentication, so receiptable.
  const w = forgeSealedInner(a, b, { [ROUTED_RESPONSE_SEAL_KEY_FIELD]: a.identity.publicKey, body: { x: 1 } });
  const r = openRoutedMessage(w, { selfKeyId: b.keyId, guard: guardAt(), authorizeOrigin: () => true, sealPrivateKey: b.identity.sealPrivateKey });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "response-key");
  assert.deepEqual(r.authenticated, { originKeyId: a.keyId, messageId: MSG_ID, blockIndex: 0 });
});

test("5. wrap rejects a non-X25519 response key at the origin", () => {
  const a = machine("alice");
  const b = machine("bob");
  assert.throws(() => wrapSealed(a, b, { x: 1 }, { responseSealKey: a.identity.publicKey }), /response sealing key/);
});

test("6. sealRoutedResponse/openRoutedResponse round-trips; the body never appears clear", () => {
  const a = machine("alice");
  const d = machine("dest");
  const sealed = sealRoutedResponse({ self: d.identity.publicKey, privateKey: d.identity.privateKey, responseSealKey: a.identity.sealPublicKey, messageId: MSG_ID, body: { secret: MARKER } });
  assert.ok(!JSON.stringify(sealed).includes(MARKER), "the response body is sealed, not on the wire");
  assert.deepEqual(
    openRoutedResponse(sealed, { destinationKeyId: d.keyId, messageId: MSG_ID, sealPrivateKey: a.identity.sealPrivateKey }),
    { ok: true, body: { secret: MARKER } },
  );
  // undefined becomes null; an array body round-trips as an array.
  const nul = sealRoutedResponse({ self: d.identity.publicKey, privateKey: d.identity.privateKey, responseSealKey: a.identity.sealPublicKey, messageId: MSG_ID, body: undefined });
  assert.deepEqual(openRoutedResponse(nul, { destinationKeyId: d.keyId, messageId: MSG_ID, sealPrivateKey: a.identity.sealPrivateKey }), { ok: true, body: null });
  const arr = sealRoutedResponse({ self: d.identity.publicKey, privateKey: d.identity.privateKey, responseSealKey: a.identity.sealPublicKey, messageId: MSG_ID, body: [1, 2, 3] });
  assert.deepEqual(openRoutedResponse(arr, { destinationKeyId: d.keyId, messageId: MSG_ID, sealPrivateKey: a.identity.sealPrivateKey }), { ok: true, body: [1, 2, 3] });
});

test("7. a reply not sealed by the routing target is wrong-sealer (checked before decrypt)", () => {
  const a = machine("alice");
  const d = machine("dest");
  const mallory = machine("mallory");
  // Sealed to A's key and signed by mallory: the sealer is not the routing target D.
  const sealed = sealRoutedResponse({ self: mallory.identity.publicKey, privateKey: mallory.identity.privateKey, responseSealKey: a.identity.sealPublicKey, messageId: MSG_ID, body: { evil: 1 } });
  assert.deepEqual(openRoutedResponse(sealed, { destinationKeyId: d.keyId, messageId: MSG_ID, sealPrivateKey: a.identity.sealPrivateKey }), { ok: false, reason: "wrong-sealer" });
  // A non-key `from` string is caught by the same gate before any decryption.
  assert.deepEqual(openRoutedResponse({ ...sealed, from: "not-a-key" }, { destinationKeyId: d.keyId, messageId: MSG_ID, sealPrivateKey: a.identity.sealPrivateKey }), { ok: false, reason: "wrong-sealer" });
});

test("8. a reply bound to another messageId is message-mismatch", () => {
  const a = machine("alice");
  const d = machine("dest");
  const sealed = sealRoutedResponse({ self: d.identity.publicKey, privateKey: d.identity.privateKey, responseSealKey: a.identity.sealPublicKey, messageId: MSG_ID, body: { ok: 1 } });
  assert.deepEqual(
    openRoutedResponse(sealed, { destinationKeyId: d.keyId, messageId: "AAAAAAAAAAAAAAAAAAAAAA", sealPrivateKey: a.identity.sealPrivateKey }),
    { ok: false, reason: "message-mismatch" },
  );
});

test("9. unopenable and malformed replies fail closed, never throw", () => {
  const a = machine("alice");
  const d = machine("dest");
  const carol = machine("carol");
  const dep = { destinationKeyId: d.keyId, messageId: MSG_ID, sealPrivateKey: a.identity.sealPrivateKey };

  // Sealed to carol's key (A cannot decrypt), signature valid → unopenable.
  const toCarol = sealRoutedResponse({ self: d.identity.publicKey, privateKey: d.identity.privateKey, responseSealKey: carol.identity.sealPublicKey, messageId: MSG_ID, body: { x: 1 } });
  assert.deepEqual(openRoutedResponse(toCarol, dep), { ok: false, reason: "unopenable" });

  // A flipped ciphertext byte (re-encoded canonically) breaks the signature → unopenable.
  const good = sealRoutedResponse({ self: d.identity.publicKey, privateKey: d.identity.privateKey, responseSealKey: a.identity.sealPublicKey, messageId: MSG_ID, body: { x: 1 } });
  const ctBytes = Buffer.from(good.ct, "base64");
  ctBytes[0] ^= 0xff;
  assert.deepEqual(openRoutedResponse({ ...good, ct: ctBytes.toString("base64") }, dep), { ok: false, reason: "unopenable" });

  // A block that names `from` but carries no signature cannot be opened → unopenable.
  assert.deepEqual(openRoutedResponse({ ...good, sig: undefined }, dep), { ok: false, reason: "unopenable" });

  // A truly unsigned block (no `from`) is caught at the sealer gate → wrong-sealer.
  const unsigned = seal(Buffer.from(JSON.stringify({ messageId: MSG_ID, body: 1 })), a.identity.sealPublicKey);
  assert.deepEqual(openRoutedResponse(unsigned, dep), { ok: false, reason: "wrong-sealer" });

  // Non-object carriers are malformed.
  for (const bad of ["nope", null, [1, 2, 3]]) {
    assert.deepEqual(openRoutedResponse(bad, dep), { ok: false, reason: "malformed" }, `${JSON.stringify(bad)} is malformed`);
  }

  // A valid seal whose plaintext is not the exact {messageId, body} envelope → malformed.
  const threeKey = sealRoutedResponse({ self: d.identity.publicKey, privateKey: d.identity.privateKey, responseSealKey: a.identity.sealPublicKey, messageId: MSG_ID, body: 1 });
  const threeKeyEnvelope = seal(Buffer.from(JSON.stringify({ messageId: MSG_ID, body: 1, extra: 2 })), a.identity.sealPublicKey, { signer: { publicKey: d.identity.publicKey, privateKey: d.identity.privateKey } });
  void threeKey;
  assert.deepEqual(openRoutedResponse(threeKeyEnvelope, dep), { ok: false, reason: "malformed" });
});

// --- Plugin: the sealed-response round-trip over a two-machine wire ---

/**
 * A→B wire where A seals to B (Tier-0 verified) and `tamper` may mutate B's response before A
 * sees it. `outer()` returns the genuine wire response B produced (snapshotted before tamper).
 */
const sealedWire = (a, b, { destOver = {}, aOver = {}, tamper = (r) => r } = {}) => {
  let pluginB;
  let outer;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => {
      const res = await pluginB.router.relay(envelope, a.identity.publicKey);
      outer = structuredClone(res?.response ?? null);
      return tamper(res);
    },
    tier0Seal: (dest) => (keyId(dest) === keyId(b.identity.publicKey) ? { state: "verified", key: b.identity.sealPublicKey } : { state: "unverified", key: null }),
    deliver: () => assert.fail("origin must not deliver a message addressed to bob"),
    ...aOver,
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, { neighbors: () => [a.identity.publicKey], sealPrivateKey: b.identity.sealPrivateKey, ...destOver }));
  return { pluginA, get pluginB() { return pluginB; }, outer: () => outer };
};

/** A delivery response with the record and receipt stripped, for exact-shape checks. */
const responseBody = (response) => {
  if (!response || typeof response !== "object") return response;
  const { [ROUTED_RECORD_FIELD]: _r, [ROUTED_RECEIPT_FIELD]: _c, ...rest } = response;
  return rest;
};

test("10. a sealed request gets a sealed reply; the origin opens it, no clear content on the wire", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const { pluginA, outer } = sealedWire(a, b, { destOver: { deliver: (body) => ({ echo: body, secret: MARKER }) } });

  const result = await pluginA.send(b.identity.publicKey, { hi: 1 });
  const o = outer();
  assert.ok(o[ROUTED_SEALED_RESPONSE_FIELD], "the reply is sealed");
  assert.ok(o[ROUTED_RECORD_FIELD], "the clear signed record rides beside it");
  assert.ok(o[ROUTED_RECEIPT_FIELD], "the clear signed receipt rides beside it");
  assert.ok(!JSON.stringify(o).includes(MARKER), "the consumer's secret is not on the wire");

  assert.equal(result.delivered, true);
  assert.deepEqual(result.responseSeal, { expected: true, state: "sealed" });
  assert.deepEqual(responseBody(result.response), { echo: { hi: 1 }, secret: MARKER });
  assert.deepEqual(result.receipt, { present: true, verified: true, outcome: "delivered", reason: "" });
  // The sealed reply still carries B's clear discovery record, so A re-learns it at Tier 1 as
  // pending — but Tier 0 governs the send and a pending key is never usable for sealing.
  assert.equal(pluginA.router.routedSealKey(b.identity.publicKey), null, "a pending Tier-1 key is not usable; Tier 0 wins");
});

test("11. a stripped (clear) reply where sealed was expected is WITHHELD", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const { pluginA } = sealedWire(a, b, {
    destOver: { deliver: () => ({ echo: 1, secret: MARKER }) },
    tamper: (r) => {
      const resp = r.response;
      r.response = { received: true, secret: "planted", [ROUTED_RECEIPT_FIELD]: resp[ROUTED_RECEIPT_FIELD], [ROUTED_RECORD_FIELD]: resp[ROUTED_RECORD_FIELD] };
      return r;
    },
  });

  const result = await pluginA.send(b.identity.publicKey, { hi: 1 });
  assert.deepEqual(result.responseSeal, { expected: true, state: "withheld", reason: "clear" });
  assert.equal(result.response.received, undefined, "no relay-planted content is handed up");
  assert.equal(result.response.secret, undefined);
  assert.ok(result.response[ROUTED_RECORD_FIELD], "the clear signed attachments survive");
  assert.ok(result.response[ROUTED_RECEIPT_FIELD]);
  assert.deepEqual(result.receipt, { present: true, verified: true, outcome: "delivered", reason: "" });
  assert.equal(result.delivered, true, "delivery still happened; only the unsealed body is refused");
});

test("12. a reply sealed by a non-target is WITHHELD (wrong-sealer)", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const mallory = machine("mallory");
  const aResponseKey = createPublicKey(createPrivateKey(a.identity.sealPrivateKey)).export({ type: "spki", format: "pem" }).toString();
  const { pluginA } = sealedWire(a, b, {
    destOver: { deliver: () => ({ echo: 1 }) },
    tamper: (r) => {
      r.response[ROUTED_SEALED_RESPONSE_FIELD] = sealRoutedResponse({ self: mallory.identity.publicKey, privateKey: mallory.identity.privateKey, responseSealKey: aResponseKey, messageId: MSG_ID, body: { evil: MARKER } });
      return r;
    },
  });

  const result = await pluginA.send(b.identity.publicKey, { hi: 1 });
  assert.deepEqual(result.responseSeal, { expected: true, state: "withheld", reason: "wrong-sealer" });
  assert.equal(result.response.evil, undefined);
  assert.ok(!JSON.stringify(result.response).includes(MARKER), "the forged reply's content is not handed up");
});

test("13. a replayed earlier reply is WITHHELD (message-mismatch)", async () => {
  const a = machine("alice");
  const b = machine("bob");
  let firstSealed = null;
  let sends = 0;
  const wire = sealedWire(a, b, {
    destOver: { deliver: () => ({ ok: 1 }) },
    tamper: (r) => {
      sends += 1;
      if (sends === 1) firstSealed = r.response[ROUTED_SEALED_RESPONSE_FIELD];
      else if (sends === 2 && firstSealed) r.response[ROUTED_SEALED_RESPONSE_FIELD] = firstSealed;
      return r;
    },
  });

  await wire.pluginA.send(b.identity.publicKey, { n: 1 });
  const second = await wire.pluginA.send(b.identity.publicKey, { n: 2 });
  assert.deepEqual(second.responseSeal, { expected: true, state: "withheld", reason: "message-mismatch" });
});

test("14. a legacy origin (no header) has its reply body WITHHELD at the destination", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const wrapper = wrapRoutedMessage({
    self: a.record,
    privateKey: a.identity.privateKey,
    destinationKeyId: keyId(b.identity.publicKey),
    body: { q: 1 },
    messageId: randomBytes(16).toString("base64url"),
    now: Date.now(),
    validityMs: 60_000,
    sealTo: { recipientKey: b.identity.sealPublicKey }, // sealed request, but NO responseSealKey
  });
  const pluginB = createRoutePlugin(cryptoDeps(b, { sealPrivateKey: b.identity.sealPrivateKey, deliver: () => ({ secret: MARKER }) }));

  const res = await pluginB.router.relay({ dest: b.identity.publicKey, ttl: 4, budget: 8, visited: [], payload: wrapper }, a.identity.publicKey);
  assert.ok(res.response[ROUTED_RECORD_FIELD], "the clear record still rides");
  assert.ok(res.response[ROUTED_RECEIPT_FIELD], "the delivery receipt still rides");
  assert.equal(res.response[ROUTED_SEALED_RESPONSE_FIELD], undefined, "no response key → no sealed reply");
  assert.ok(!JSON.stringify(res.response).includes(MARKER), "the body is withheld, never sent clear");
});

test("15. a clear (public) request keeps a clear reply; a stray sealed field is dropped unopened", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const { pluginA } = sealedWire(a, b, { destOver: { deliver: (body) => ({ echo: body }) } });
  const res = await pluginA.send(b.identity.publicKey, { hi: 1 }, { public: true });
  assert.deepEqual(responseBody(res.response), { echo: { hi: 1 } });
  assert.deepEqual(res.responseSeal, { expected: false, state: "clear" });

  const wire2 = sealedWire(a, b, {
    destOver: { deliver: () => ({ echo: 1 }) },
    tamper: (r) => { r.response[ROUTED_SEALED_RESPONSE_FIELD] = { bogus: true }; return r; },
  });
  const res2 = await wire2.pluginA.send(b.identity.publicKey, { hi: 1 }, { public: true });
  assert.equal(res2.response[ROUTED_SEALED_RESPONSE_FIELD], undefined, "a stray sealed field on a clear reply is dropped");
  assert.deepEqual(res2.responseSeal, { expected: false, state: "clear" });
});

test("16. a confidential send from an origin with no response key refuses locally", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    sealPrivateKey: undefined, // A cannot receive confidentially
    neighbors: () => [b.identity.publicKey],
    forward: async () => assert.fail("a send refused for no response key must not forward"),
    tier0Seal: (dest) => (keyId(dest) === keyId(b.identity.publicKey) ? { state: "verified", key: b.identity.sealPublicKey } : { state: "unverified", key: null }),
  }));
  assert.deepEqual(await pluginA.send(b.identity.publicKey, { secret: "s" }), {
    delivered: false,
    reason: "seal-refused:no-response-key",
    spent: 0,
    seal: { decision: "refuse", tier: 0, state: "no-response-key" },
  });
});

test("17. a refused sealed send yields responseSeal none (no body to protect)", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const { pluginA } = sealedWire(a, b, { destOver: { authorizeOrigin: () => false } });
  const res = await pluginA.send(b.identity.publicKey, { secret: "s" });
  assert.equal(res.refused, true);
  assert.deepEqual(res.receipt, { present: true, verified: true, outcome: "refused", reason: "origin-unauthorized" });
  assert.deepEqual(res.responseSeal, { expected: true, state: "none" });
});

test("18. multi-hop A→B→D: B relays only ciphertext back, A opens D's sealed reply", async () => {
  const a = machine("alice");
  const b = machine("bridge");
  const d = machine("destination");
  let pluginB;
  let pluginD;
  let backToA = null;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => { const r = await pluginB.router.relay(envelope, a.identity.publicKey); backToA = r?.response; return r; },
    tier0Seal: (dest) => (keyId(dest) === keyId(d.identity.publicKey) ? { state: "verified", key: d.identity.sealPublicKey } : { state: "unverified", key: null }),
    deliver: () => assert.fail("A must not deliver"),
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, {
    neighbors: () => [d.identity.publicKey],
    forward: async (_peer, envelope) => pluginD.router.relay(envelope, b.identity.publicKey),
    deliver: () => assert.fail("B must not deliver a message addressed to D"),
  }));
  pluginD = createRoutePlugin(cryptoDeps(d, { sealPrivateKey: d.identity.sealPrivateKey, deliver: (body) => ({ echo: body, secret: MARKER }) }));

  const res = await pluginA.send(d.identity.publicKey, { hi: 1 });
  assert.ok(backToA[ROUTED_SEALED_RESPONSE_FIELD], "B relayed D's sealed reply");
  assert.ok(!JSON.stringify(backToA).includes(MARKER), "no clear content crossed B");
  assert.deepEqual(res.responseSeal, { expected: true, state: "sealed" });
  assert.deepEqual(responseBody(res.response), { echo: { hi: 1 }, secret: MARKER });
});

test("19. an approved Tier-1 key survives the sealed round-trip, with a verifiable receipt", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const store = createRoutedKeyStore();
  const bKeyId = keyId(b.identity.publicKey);
  store.observe(bKeyId, recordOf(b));
  assert.equal(store.approve(bKeyId).ok, true);

  let pluginB;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => pluginB.router.relay(envelope, a.identity.publicKey),
    routedKeyStore: store,
    tier0Seal: () => ({ state: "unverified", key: null }), // no walk to B; Tier 1 in play
    deliver: () => assert.fail("origin must not deliver"),
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, { neighbors: () => [a.identity.publicKey], sealPrivateKey: b.identity.sealPrivateKey, deliver: (body) => ({ echo: body }) }));

  const res = await pluginA.send(b.identity.publicKey, { hi: 1 });
  assert.equal(res.delivered, true);
  assert.equal(res.seal.decision, "seal");
  assert.deepEqual(res.responseSeal, { expected: true, state: "sealed" });
  assert.deepEqual(responseBody(res.response), { echo: { hi: 1 } });
  assert.deepEqual(res.receipt, { present: true, verified: true, outcome: "delivered", reason: "" });
  assert.equal(pluginA.router.routedSealState(b.identity.publicKey), "record-approved", "the approved Tier-1 key survives");
});
