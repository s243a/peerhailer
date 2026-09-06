/**
 * The route plugin's per-caller rate limit — one receipt can trigger up to `fanout`
 * outbound callPeers, so an unbounded relay rate is an amplification lever.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  createRoutePlugin,
  MAX_IN_FLIGHT_PER_CALLER,
  MAX_IN_FLIGHT_RELAYS,
  MAX_RELAYS_PER_WINDOW,
  RELAY_WINDOW_MS,
  ROUTED_RECORD_FIELD,
  ROUTED_RECEIPT_FIELD,
} from "../src/builtin/routePlugin.js";
import { generateIdentity, normalizeKey } from "../src/identity.js";
import { signRecord } from "../src/peerRecord.js";
import { createRoutedKeyStore } from "../src/routedKeyStore.js";
import { createRoutedObservationStore } from "../src/routedObservation.js";
import { REFUSE } from "../src/plugins.js";
import { buildManifest, keyId, payloadDigest, signManifest } from "../src/routeManifest.js";
import { createRouteReplayGuard } from "../src/routeReplayGuard.js";
import { wrapRoutedMessage } from "../src/routedMessage.js";
import { seal } from "../src/sealing.js";
import { verifyReceipt } from "../src/routeReceipt.js";
import { randomBytes } from "node:crypto";

/** A signed key-only record for `m` advertising `sealPublicKey` (default its own). */
const recordOf = (m, sealPublicKey = m.identity.sealPublicKey) =>
  signRecord({ name: m.name, publicKey: m.identity.publicKey, sealPublicKey, addresses: [], lastSeen: null }, m.identity.privateKey);

const T = 1_700_000_000_000;
const machine = (name) => {
  const identity = generateIdentity();
  return {
    name,
    identity,
    record: { name, publicKey: identity.publicKey, sealPublicKey: identity.sealPublicKey, addresses: [] },
  };
};

/** A delivery response with the M2 discovery record and signed receipt stripped, for
 * exact-shape checks (dedicated tests cover both wire fields). */
const responseBody = (response) => {
  if (!response || typeof response !== "object") return response;
  const { [ROUTED_RECORD_FIELD]: _record, [ROUTED_RECEIPT_FIELD]: _receipt, ...rest } = response;
  return rest;
};

const cryptoDeps = (self, over = {}) => ({
  self: self.identity.publicKey,
  privateKey: self.identity.privateKey,
  selfRecord: () => self.record,
  authorizeOrigin: () => true,
  neighbors: () => [],
  forward: async () => ({ delivered: false, spent: 0 }),
  deliver: () => ({ received: true }),
  // The origin needs its own X25519 key to originate a confidential send (it carries a response
  // key for the destination to seal the reply to); the daemon always has one.
  sealPrivateKey: self.identity.sealPrivateKey,
  ...over,
});

test("a caller is refused past MAX_RELAYS_PER_WINDOW, and the window resets", async () => {
  let clock = 1_000_000;
  const self = machine("self");
  const plugin = createRoutePlugin(cryptoDeps(self, {
    now: () => clock,
  }));
  const relay = plugin.routes[0].handler;
  const caller = { publicKey: "peer-1" };
  const env = { dest: "somewhere", ttl: 4, budget: 8, visited: [], payload: "x" };

  for (let i = 0; i < MAX_RELAYS_PER_WINDOW; i++) {
    const r = await relay({ body: env, caller });
    assert.notEqual(r[REFUSE], true, `relay ${i} within the limit is allowed`);
  }
  const over = await relay({ body: env, caller });
  assert.equal(over[REFUSE], true, "one past the limit is refused");
  assert.match(over.reason, /too fast/);

  // A different caller is unaffected (per-caller bucket).
  const other = await relay({ body: env, caller: { publicKey: "peer-2" } });
  assert.notEqual(other[REFUSE], true, "the limit is per caller");

  // After the window passes, peer-1 is allowed again.
  clock += RELAY_WINDOW_MS + 1;
  const again = await relay({ body: env, caller });
  assert.notEqual(again[REFUSE], true, "the window resets");
});

test("send wraps once, relays opaquely, and delivers only the authenticated origin", async () => {
  const a = machine("alice");
  const b = machine("bob");
  let pluginB;
  let wire;
  let delivered;

  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => {
      wire = structuredClone(envelope);
      return pluginB.router.relay(envelope, a.identity.publicKey);
    },
    deliver: () => assert.fail("origin must not deliver a message addressed to bob"),
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, {
    neighbors: () => [a.identity.publicKey],
    deliver: (body, meta) => {
      delivered = { body, meta };
      return { received: true, echo: body };
    },
  }));

  const result = await pluginA.send(b.identity.publicKey, { hello: "graph" }, { public: true });
  assert.equal(result.delivered, true);
  assert.deepEqual(responseBody(result.response), { received: true, echo: { hello: "graph" } });
  assert.deepEqual(delivered.body, { hello: "graph" });
  assert.equal(delivered.meta.originKeyId, keyId(a.identity.publicKey));
  assert.equal(delivered.meta.origin, delivered.meta.originKeyId, "the unsigned outer origin is replaced");
  assert.equal(wire.id, null, "the unsigned M0 cache is bypassed");
  assert.match(wire.payload.manifest.messageId, /^[A-Za-z0-9_-]{22}$/, "16 random bytes, base64url");
  assert.equal(typeof wire.payload.payload, "string", "the engine carries the signed wrapper opaquely");

  const local = await pluginB.send(b.identity.publicKey, { hello: "self" }, { public: true });
  assert.equal(local.delivered, true, "self-send passes through the same wrap/open gates");
  assert.equal(delivered.meta.originKeyId, keyId(b.identity.publicKey));
});

test("the origin learns the destination's Tier-1 sealing key from its piggybacked record", async () => {
  const a = machine("alice");
  const b = machine("bob");
  let pluginB;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => pluginB.router.relay(envelope, a.identity.publicKey),
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, { neighbors: () => [a.identity.publicKey] }));

  // Before any exchange, alice holds no routed sealing key for bob.
  assert.equal(pluginA.router.routedSealState(b.identity.publicKey), "none");

  const result = await pluginA.send(b.identity.publicKey, { hello: "graph" }, { public: true });
  assert.equal(result.delivered, true);
  assert.ok(result.response[ROUTED_RECORD_FIELD], "bob piggybacked his signed record");

  // Alice now holds bob's advertised sealing key at Tier 1, PENDING approval: its
  // fingerprint is visible, but it is not usable for sealing (recordSealKey) until approved.
  assert.equal(pluginA.router.routedSealState(b.identity.publicKey), "record-carried");
  assert.equal(pluginA.router.routedSealKey(b.identity.publicKey), null, "a pending key is not usable yet");
  assert.equal(pluginA.router.routedSealDetail(b.identity.publicKey)?.sealKey, normalizeKey(b.identity.sealPublicKey));
  assert.equal(pluginA.router.routedSealDetail(b.identity.publicKey)?.name, "bob");
});

test("a relay that swaps in an older record of the destination causes a Tier-1 conflict, not a wrong key", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const bStale = generateIdentity(); // bob's retired sealing key
  let pluginB;
  let trips = 0;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => {
      const result = await pluginB.router.relay(envelope, a.identity.publicKey);
      // On the second round-trip a dishonest relay substitutes an older record it
      // captured — signed by bob's identity, but advertising a since-retired sealing
      // key. It cannot forge a record for a different identity, only replay this one.
      if ((trips += 1) === 2 && result?.response?.[ROUTED_RECORD_FIELD]) {
        result.response[ROUTED_RECORD_FIELD] = signRecord(
          { name: "bob", publicKey: b.identity.publicKey, sealPublicKey: bStale.sealPublicKey, addresses: [] },
          b.identity.privateKey,
        );
      }
      return result;
    },
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, { neighbors: () => [a.identity.publicKey] }));

  await pluginA.send(b.identity.publicKey, { n: 1 }, { public: true }); // honest: learns bob's real key
  assert.equal(pluginA.router.routedSealDetail(b.identity.publicKey)?.sealKey, normalizeKey(b.identity.sealPublicKey));
  await pluginA.send(b.identity.publicKey, { n: 2 }, { public: true }); // tampered: a second, different key
  assert.equal(pluginA.router.routedSealState(b.identity.publicKey), "record-conflict");
  assert.equal(pluginA.router.routedSealKey(b.identity.publicKey), null, "a disputed target seals to nothing");
});

test("a relay substituting its own valid record teaches the origin nothing about the destination", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const relay = machine("relay");
  let pluginB;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => {
      const result = await pluginB.router.relay(envelope, a.identity.publicKey);
      // The relay swaps in ITS OWN correctly-signed record — a different identity.
      if (result?.response?.[ROUTED_RECORD_FIELD]) {
        result.response[ROUTED_RECORD_FIELD] = signRecord(
          { name: "relay", publicKey: relay.identity.publicKey, sealPublicKey: relay.identity.sealPublicKey, addresses: [], lastSeen: null },
          relay.identity.privateKey,
        );
      }
      return result;
    },
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, { neighbors: () => [a.identity.publicKey] }));

  await pluginA.send(b.identity.publicKey, { n: 1 }, { public: true });
  // The foreign record is filed under bob's target key and rejected as not-target.
  assert.equal(pluginA.router.routedSealState(b.identity.publicKey), "none");
  assert.equal(pluginA.router.routedSealKey(b.identity.publicKey), null);
});

test("a non-plain-object response is delivered intact and carries no discovery record", async () => {
  const a = machine("alice");
  const b = machine("bob");
  let pluginB;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => pluginB.router.relay(envelope, a.identity.publicKey),
  }));
  // An array (a Buffer or class instance takes the same isPlainObject branch): the
  // discovery attach must pass it through untouched, never spread it into an object.
  pluginB = createRoutePlugin(cryptoDeps(b, { neighbors: () => [a.identity.publicKey], deliver: () => [1, 2, 3] }));

  const result = await pluginA.send(b.identity.publicKey, { n: 1 }, { public: true });
  assert.deepEqual(result.response, [1, 2, 3], "the array response is intact, not flattened to indexed keys");
  assert.equal(pluginA.router.routedSealState(b.identity.publicKey), "none", "no record rode a non-object response");
});

test("a refused delivery carries no discovery record", async () => {
  const a = machine("alice");
  const b = machine("bob");
  let pluginB;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => pluginB.router.relay(envelope, a.identity.publicKey),
  }));
  // Bob authenticates the origin but refuses it: open returns a refusal before any
  // record is attached, so the origin learns nothing from a rejected delivery.
  pluginB = createRoutePlugin(cryptoDeps(b, { neighbors: () => [a.identity.publicKey], authorizeOrigin: () => false }));

  const result = await pluginA.send(b.identity.publicKey, { n: 1 }, { public: true });
  assert.equal(result.refused, true);
  assert.equal(result.response?.reason, "origin-unauthorized");
  assert.equal(result.response?.[ROUTED_RECORD_FIELD], undefined, "a refusal attaches no record");
  assert.equal(pluginA.router.routedSealState(b.identity.publicKey), "none");
});

test("an unsigned outer-id pre-injection cannot poison M1; changed-id replay still opens once", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const carrier = machine("carrier");
  let deliveries = 0;
  let authenticatedOrigin;
  const guard = createRouteReplayGuard({ now: () => T });
  const plugin = createRoutePlugin(cryptoDeps(b, {
    now: () => T,
    replayGuard: guard,
    deliver: (_body, meta) => {
      deliveries += 1;
      authenticatedOrigin = meta.originKeyId;
      return { received: true };
    },
  }));
  const wrapper = wrapRoutedMessage({
    self: a.record,
    privateKey: a.identity.privateKey,
    destinationKeyId: keyId(b.identity.publicKey),
    body: { one: 1 },
    messageId: "AAAAAAAAAAAAAAAAAAAAAA",
    now: T,
    validityMs: 60_000,
  });
  const base = {
    dest: b.identity.publicKey,
    ttl: 4,
    budget: 8,
    visited: [],
    origin: "spoofed-outer-origin",
    id: "unsigned-shared-id",
  };
  const relay = plugin.routes[0].handler;

  const poison = await relay({ body: { ...base, payload: {} }, caller: { publicKey: carrier.identity.publicKey } });
  assert.equal(poison.refused, true, "junk reaches the target but is refused");
  assert.equal(deliveries, 0);

  const good = await relay({ body: { ...base, payload: wrapper }, caller: { publicKey: carrier.identity.publicKey } });
  assert.equal(good.delivered, true, "the unsigned id was not reserved by the poison");
  assert.deepEqual(responseBody(good.response), { received: true });
  assert.equal(deliveries, 1);
  assert.equal(authenticatedOrigin, keyId(a.identity.publicKey), "outer origin spoof is ignored");

  const replay = await relay({
    body: { ...base, id: "relay-reminted-id", payload: wrapper },
    caller: { publicKey: carrier.identity.publicKey },
  });
  assert.equal(replay.response.duplicate, true, "signed inner id catches a reminted outer id");
  assert.equal(replay.response.reason, "replay:duplicate");
  assert.equal(deliveries, 1);
});

test("legacy raw payloads fail closed and the exposed router has no raw-send bypass", async () => {
  const a = machine("alice");
  const b = machine("bob");
  let pluginB;
  let deliveries = 0;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: (_peer, envelope) => pluginB.router.relay(envelope, a.identity.publicKey),
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, {
    deliver: () => {
      deliveries += 1;
      return { received: true };
    },
  }));

  const legacy = await pluginB.router.relay({
    dest: b.identity.publicKey,
    ttl: 1,
    budget: 1,
    visited: [],
    payload: "old clear payload",
    id: "legacy",
  });
  assert.equal(legacy.refused, true);
  assert.equal(deliveries, 0);

  assert.equal((await pluginA.send("not a public key", {})).reason, "invalid destination identity key");
  const throughFacade = await pluginA.router.send(b.identity.publicKey, { secure: true }, { public: true });
  assert.equal(throughFacade.delivered, true);
  assert.equal(deliveries, 1, "router.send is the secure facade, not the raw engine");
});

test("an injected replay guard preserves reservations across a route-plugin rebuild", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const guard = createRouteReplayGuard({ now: () => T });
  let deliveries = 0;
  const build = () => createRoutePlugin(cryptoDeps(b, {
    now: () => T,
    replayGuard: guard,
    deliver: () => {
      deliveries += 1;
      return { received: true };
    },
  }));
  const wrapper = wrapRoutedMessage({
    self: a.record,
    privateKey: a.identity.privateKey,
    destinationKeyId: keyId(b.identity.publicKey),
    body: { after: "reload" },
    messageId: "BBBBBBBBBBBBBBBBBBBBBA",
    now: T,
    validityMs: 60_000,
  });
  const envelope = { dest: b.identity.publicKey, ttl: 1, budget: 1, visited: [], payload: wrapper };

  assert.equal((await build().router.relay({ ...envelope, id: "before" })).delivered, true);
  const replay = await build().router.relay({ ...envelope, id: "after" });
  assert.equal(replay.response.duplicate, true);
  assert.equal(deliveries, 1, "rebuilding the plugin did not reopen the signed envelope");
});

test("multi-hop refusal and duplicate status survive every pure-engine hop", async () => {
  const a = machine("alice");
  const b = machine("bridge");
  const d = machine("destination");
  let pluginB;
  let pluginD;
  let firstEnvelope;

  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: (_peer, envelope) => {
      firstEnvelope ??= structuredClone(envelope);
      return pluginB.router.relay(envelope, a.identity.publicKey);
    },
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, {
    neighbors: () => [d.identity.publicKey],
    forward: (_peer, envelope) => pluginD.router.relay(envelope, b.identity.publicKey),
  }));
  pluginD = createRoutePlugin(cryptoDeps(d, {
    authorizeOrigin: () => false,
  }));

  const refused = await pluginA.send(d.identity.publicKey, { action: "denied" }, { public: true });
  assert.equal(refused.delivered, true, "the destination was reached, so search is terminal");
  assert.equal(refused.refused, true, "the public sender sees refusal at top level");
  assert.equal(refused.response.reason, "origin-unauthorized");

  // Rebuild only the destination with an accepting policy, deliver the already-
  // signed wrapper once, then re-inject it through both A and B.
  let deliveries = 0;
  pluginD = createRoutePlugin(cryptoDeps(d, {
    deliver: () => { deliveries += 1; return { received: true }; },
  }));
  const envelope = { dest: d.identity.publicKey, ttl: 4, budget: 8, visited: [], payload: firstEnvelope.payload };
  assert.equal((await pluginA.router.relay(envelope)).delivered, true);
  const replay = await pluginA.router.relay({ ...envelope, id: "reminted" });
  assert.equal(replay.refused, true);
  assert.equal(replay.duplicate, true);
  assert.equal(replay.response.reason, "replay:duplicate");
  assert.equal(deliveries, 1);
});

test("simultaneous copies reserve before an asynchronous consumer and deliver once", async () => {
  const a = machine("alice");
  const b = machine("bob");
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  let deliveries = 0;
  const plugin = createRoutePlugin(cryptoDeps(b, {
    deliver: async () => { deliveries += 1; await gate; return { received: true }; },
  }));
  const wrapper = wrapRoutedMessage({
    self: a.record,
    privateKey: a.identity.privateKey,
    destinationKeyId: keyId(b.identity.publicKey),
    body: { concurrent: true },
    messageId: Buffer.alloc(16, 4).toString("base64url"),
    now: Date.now(),
    validityMs: 60_000,
  });
  const envelope = { dest: b.identity.publicKey, ttl: 1, budget: 1, visited: [], payload: wrapper };
  const first = plugin.router.relay(envelope);
  const second = plugin.router.relay({ ...envelope, id: "changed" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(deliveries, 1, "the first copy reserved before awaiting its consumer");
  release();
  const results = await Promise.all([first, second]);
  assert.equal(results.filter((result) => result.response?.received === true).length, 1);
  assert.equal(results.filter((result) => result.duplicate === true).length, 1);
});

test("recursive route searches have per-caller and global in-flight ceilings", async () => {
  const self = machine("self");
  const neighbor = machine("neighbor");
  const destination = machine("destination");
  const envelope = { dest: destination.identity.publicKey, ttl: 2, budget: 2, visited: [], payload: {} };

  const buildBlocked = () => {
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    let started = 0;
    const plugin = createRoutePlugin(cryptoDeps(self, {
      neighbors: () => [neighbor.identity.publicKey],
      forward: async () => { started += 1; await gate; return { delivered: false, spent: 0 }; },
    }));
    return { plugin, handler: plugin.routes[0].handler, release, started: () => started };
  };

  const perCaller = buildBlocked();
  const held = Array.from({ length: MAX_IN_FLIGHT_PER_CALLER }, () =>
    perCaller.handler({ body: envelope, caller: { publicKey: "same-caller" } }));
  assert.equal(perCaller.started(), MAX_IN_FLIGHT_PER_CALLER);
  const callerOverflow = await perCaller.handler({ body: envelope, caller: { publicKey: "same-caller" } });
  assert.equal(callerOverflow[REFUSE], true);
  assert.match(callerOverflow.reason, /in flight/);
  perCaller.release();
  await Promise.all(held);

  const global = buildBlocked();
  const allHeld = Array.from({ length: MAX_IN_FLIGHT_RELAYS }, (_, i) =>
    global.handler({ body: envelope, caller: { publicKey: `caller-${i}` } }));
  assert.equal(global.started(), MAX_IN_FLIGHT_RELAYS);
  const globalOverflow = await global.handler({ body: envelope, caller: { publicKey: "one-more" } });
  assert.equal(globalOverflow[REFUSE], true);
  assert.match(globalOverflow.reason, /in flight/);
  global.release();
  await Promise.all(allHeld);

  const host = buildBlocked();
  const hostHeld = Array.from({ length: MAX_IN_FLIGHT_RELAYS }, (_, i) =>
    host.plugin.send(destination.identity.publicKey, { host: i }, { public: true }));
  assert.equal(host.started(), MAX_IN_FLIGHT_RELAYS, "host sends share the plugin-wide ceiling");
  const hostOverflow = await host.plugin.send(destination.identity.publicKey, { host: "overflow" }, { public: true });
  assert.equal(hostOverflow.delivered, false);
  assert.match(hostOverflow.reason, /in flight/);
  host.release();
  await Promise.all(hostHeld);

  const afterRelease = await host.plugin.send(destination.identity.publicKey, { host: "after" }, { public: true });
  assert.doesNotMatch(afterRelease.reason ?? "", /in flight/, "finally releases capacity after work settles");
});

test("send seals to a Tier-0 verified key and the destination decrypts it", async () => {
  const a = machine("alice");
  const b = machine("bob");
  let pluginB;
  let deliveredBody;
  let forwarded;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => {
      forwarded = envelope;
      return pluginB.router.relay(envelope, a.identity.publicKey);
    },
    // A holds a walk-verified Tier-0 sealing key for bob.
    tier0Seal: (dest) =>
      keyId(dest) === keyId(b.identity.publicKey)
        ? { state: "verified", key: b.identity.sealPublicKey }
        : { state: "unverified", key: null },
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, {
    neighbors: () => [a.identity.publicKey],
    sealPrivateKey: b.identity.sealPrivateKey,
    deliver: (body) => { deliveredBody = body; return { received: true }; },
  }));

  const res = await pluginA.send(b.identity.publicKey, { secret: "s" });
  assert.equal(res.delivered, true);
  assert.deepEqual(deliveredBody, { secret: "s" }, "bob decrypted the sealed body");
  assert.equal(forwarded.payload.manifest.payloadMode, "sealed", "the wrapper on the wire was sealed");
});

test("a Tier-1 conflict refuses the send rather than falling back to cleartext", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const stale = generateIdentity();
  const store = createRoutedKeyStore();
  const bKeyId = keyId(b.identity.publicKey);
  store.observe(bKeyId, recordOf(b)); // bob's real key
  store.observe(bKeyId, recordOf(b, stale.sealPublicKey)); // a second, different key -> conflict
  assert.equal(store.recordState(bKeyId), "record-conflict");

  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async () => assert.fail("a refused send must not forward"),
    routedKeyStore: store,
    tier0Seal: () => ({ state: "unverified", key: null }), // no walk to bob; Tier 1 in play
  }));
  assert.deepEqual(await pluginA.send(b.identity.publicKey, { x: 1 }), {
    delivered: false,
    reason: "seal-refused:tier1-conflict",
    spent: 0,
    seal: { decision: "refuse", tier: null, state: "tier1-conflict" },
  });
});

test("the destination floor refuses a clear routed delivery", async () => {
  const a = machine("alice");
  const b = machine("bob");
  let pluginB;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => pluginB.router.relay(envelope, a.identity.publicKey),
  }));
  // Bob requires sealing; A has no key for bob, so the send is clear and bob refuses it.
  pluginB = createRoutePlugin(cryptoDeps(b, {
    neighbors: () => [a.identity.publicKey],
    sealPrivateKey: b.identity.sealPrivateKey,
    requireSealed: true,
  }));

  const res = await pluginA.send(b.identity.publicKey, { x: 1 }, { public: true });
  assert.equal(res.refused, true);
  assert.equal(res.response.reason, "cleartext-refused");
});

test("a misconfigured (non-X25519) sealPrivateKey is rejected at construction", () => {
  const a = machine("alice");
  assert.throws(
    () => createRoutePlugin(cryptoDeps(a, { sealPrivateKey: a.identity.privateKey })), // Ed25519, not X25519
    /X25519/,
  );
});

test("a floored destination teaches its key on a public probe; after approval the origin can seal", async () => {
  const a = machine("alice");
  const b = machine("bob");
  let pluginB;
  let deliveredBody;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => pluginB.router.relay(envelope, a.identity.publicKey),
    tier0Seal: () => ({ state: "unverified", key: null }), // A never walked B
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, {
    neighbors: () => [a.identity.publicKey],
    sealPrivateKey: b.identity.sealPrivateKey,
    requireSealed: true, // the floor: B refuses cleartext
    deliver: (body) => { deliveredBody = body; return { received: true }; },
  }));

  // A confidential send would refuse locally (no key); an explicit PUBLIC probe goes clear,
  // B refuses it under the floor, but the refusal still carries B's key-only record — so a
  // routed origin can discover the key even behind a floor.
  const refused = await pluginA.send(b.identity.publicKey, { probe: 1 }, { public: true });
  assert.equal(refused.refused, true);
  assert.equal(refused.response.reason, "cleartext-refused");
  assert.equal(pluginA.router.routedSealState(b.identity.publicKey), "record-carried", "A discovered B's key (pending)");

  // A pending key is not yet usable — a confidential send still refuses until approval.
  const stillRefused = await pluginA.send(b.identity.publicKey, { secret: "no" });
  assert.equal(stillRefused.reason, "seal-refused:tier1-pending");

  // The operator approves the discovered key; now the confidential send seals and B accepts.
  assert.equal(pluginA.router.approveRoutedSeal(b.identity.publicKey).ok, true);
  const sealed = await pluginA.send(b.identity.publicKey, { secret: "ok" });
  assert.equal(sealed.delivered, true, `sealed retry delivered (${sealed.reason ?? ""})`);
  assert.deepEqual(deliveredBody, { secret: "ok" });
});

// --- Signed delivery receipts: the origin can tell a real delivery/refusal (signed by the
// routing target) from a relay forgery or a grayhole (docs/routing-security-roadmap.md). ---

/** A two-machine wire where `relay` may tamper with bob's response before alice sees it. */
const receiptWire = (a, b, { destOver = {}, tamper = (r) => r } = {}) => {
  let pluginB;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => tamper(await pluginB.router.relay(envelope, a.identity.publicKey)),
    deliver: () => assert.fail("origin must not deliver a message addressed to bob"),
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, { neighbors: () => [a.identity.publicKey], ...destOver }));
  return pluginA;
};

test("a delivered send returns a receipt the origin verifies against the routing target", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const pluginA = receiptWire(a, b, { destOver: { deliver: (body) => ({ received: true, echo: body }) } });

  const result = await pluginA.send(b.identity.publicKey, { hello: "graph" }, { public: true });
  assert.equal(result.delivered, true);
  assert.deepEqual(result.receipt, { present: true, verified: true, outcome: "delivered", reason: "" });
  // The wire field carries bob's signature; the verdict is the origin's, keyed to this send.
  assert.ok(result.response[ROUTED_RECEIPT_FIELD]?.signature, "bob signed a delivery receipt");
});

test("a refusal the destination authenticated returns a signed `refused` receipt with the reason", async () => {
  const a = machine("alice");
  const b = machine("bob");
  // Bob authenticates the origin, then declines it: an authenticated refusal is receiptable.
  const pluginA = receiptWire(a, b, { destOver: { authorizeOrigin: () => false } });

  const result = await pluginA.send(b.identity.publicKey, { hello: "graph" }, { public: true });
  assert.equal(result.refused, true);
  assert.deepEqual(result.receipt, { present: true, verified: true, outcome: "refused", reason: "origin-unauthorized" });
});

test("a relay that drops the receipt leaves the origin with no proof (a possible grayhole)", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const pluginA = receiptWire(a, b, {
    destOver: { deliver: () => ({ received: true }) },
    tamper: (r) => {
      if (r?.response?.[ROUTED_RECEIPT_FIELD]) delete r.response[ROUTED_RECEIPT_FIELD];
      return r;
    },
  });

  const result = await pluginA.send(b.identity.publicKey, { hello: "graph" }, { public: true });
  assert.equal(result.delivered, true, "the response still arrives; only the proof is gone");
  assert.deepEqual(result.receipt, { present: false, verified: false });
});

test("a relay that forges the receipt outcome fails verification (present but not verified)", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const pluginA = receiptWire(a, b, {
    destOver: { authorizeOrigin: () => false }, // a `refused` receipt bob really signed
    tamper: (r) => {
      const carried = r?.response?.[ROUTED_RECEIPT_FIELD];
      if (carried) carried.receipt = { ...carried.receipt, outcome: "delivered", reason: "" }; // flip to a fake ack
      return r;
    },
  });

  const result = await pluginA.send(b.identity.publicKey, { hello: "graph" }, { public: true });
  assert.deepEqual(result.receipt, { present: true, verified: false }, "the tampered outcome breaks bob's signature");
});

test("T1: a floored destination's clear refusal carries BOTH its key record and a verified receipt", async () => {
  const a = machine("alice");
  const b = machine("bob");
  let pluginB;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => pluginB.router.relay(envelope, a.identity.publicKey),
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, {
    neighbors: () => [a.identity.publicKey],
    sealPrivateKey: b.identity.sealPrivateKey,
    requireSealed: true, // the floor: B refuses cleartext
  }));

  const res = await pluginA.send(b.identity.publicKey, { x: 1 }, { public: true });
  assert.equal(res.refused, true);
  assert.equal(res.response.reason, "cleartext-refused");
  // The two wire fields ride together on the same refusal object: the discovery record
  // (so a routed origin can still learn B's key behind the floor) AND the signed receipt.
  assert.ok(res.response[ROUTED_RECORD_FIELD], "the floor refusal still teaches B's key-only record");
  assert.ok(res.response[ROUTED_RECEIPT_FIELD]?.signature, "and carries B's signed refusal receipt");
  // The origin's verdict verifies it against the routing target and this send.
  assert.deepEqual(res.receipt, { present: true, verified: true, outcome: "refused", reason: "cleartext-refused" });
});

test("T2: a pre-authentication refusal (relay-mangled manifest) carries NO receipt", async () => {
  const a = machine("alice");
  const b = machine("bob");
  let pluginB;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => {
      // A relay mutates the signed manifest: verifyManifest now fails, so B refuses at
      // "manifest" — before any authenticated origin exists, so it can sign no receipt.
      const mangled = structuredClone(envelope);
      mangled.payload.manifest.messageId = "AAAAAAAAAAAAAAAAAAAAAA"; // valid shape, breaks the signature
      return pluginB.router.relay(mangled, a.identity.publicKey);
    },
    deliver: () => assert.fail("a mangled manifest must not deliver"),
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, { neighbors: () => [a.identity.publicKey] }));

  const res = await pluginA.send(b.identity.publicKey, { x: 1 }, { public: true });
  assert.equal(res.refused, true);
  assert.equal(res.response.reason, "manifest");
  assert.equal(res.response[ROUTED_RECEIPT_FIELD], undefined, "no receipt is signed over relay-tampered garbage");
  assert.deepEqual(res.receipt, { present: false, verified: false });
});

test("Q4: one messageId can yield two genuine receipts — a refused presentation and a delivered one", async () => {
  const a = machine("alice");
  const b = machine("bob");
  let pluginB;
  let refusedReceipt;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => {
      // A forking relay presents a payload-mangled copy first: it authenticates (manifest
      // intact) but fails the digest — refused BEFORE guard.admit, so nothing is reserved.
      const mangled = structuredClone(envelope);
      const bytes = Buffer.from(mangled.payload.payload, "base64");
      bytes[0] ^= 0xff;
      mangled.payload.payload = bytes.toString("base64");
      const refused = await pluginB.router.relay(mangled, a.identity.publicKey);
      refusedReceipt = refused?.response?.[ROUTED_RECEIPT_FIELD];
      // ...then forwards the real wrapper, which delivers (the mangled copy reserved nothing).
      return pluginB.router.relay(envelope, a.identity.publicKey);
    },
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, {
    neighbors: () => [a.identity.publicKey],
    deliver: () => ({ received: true }),
  }));

  const res = await pluginA.send(b.identity.publicKey, { x: 1 }, { public: true });
  // The real wrapper delivered, with a verified delivered receipt.
  assert.deepEqual(res.receipt, { present: true, verified: true, outcome: "delivered", reason: "" });
  const deliveredMsgId = res.response[ROUTED_RECEIPT_FIELD].receipt.messageId;
  // The mangled presentation produced a SEPARATE, genuine refused receipt for the SAME id:
  // both verify against B's key — the per-presentation limitation the roadmap documents.
  assert.ok(refusedReceipt, "the mangled presentation was itself receipted");
  assert.equal(verifyReceipt(refusedReceipt.receipt, refusedReceipt.signature, b.identity.publicKey), true);
  assert.equal(refusedReceipt.receipt.outcome, "refused");
  assert.equal(refusedReceipt.receipt.reason, "payload-digest");
  assert.equal(refusedReceipt.receipt.messageId, deliveredMsgId, "two true receipts bind one (origin, messageId)");
});

// --- M3a observation seam: a sealed delivery records a durable per-origin requireSealFrom
// marker; the enforcement floor (off by default) refuses a clear downgrade when armed. ---

test("M3a: a sealed delivery records a requireSealFrom observation against the authenticated origin", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const observed = [];
  let pluginB;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => pluginB.router.relay(envelope, a.identity.publicKey),
    // A Tier-0 verified key makes the send seal.
    tier0Seal: () => ({ state: "verified", key: normalizeKey(b.identity.sealPublicKey) }),
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, {
    neighbors: () => [a.identity.publicKey],
    sealPrivateKey: b.identity.sealPrivateKey,
    observeSealed: (proof) => observed.push(proof.originKeyId),
    deliver: () => ({ received: true }),
  }));

  const res = await pluginA.send(b.identity.publicKey, { secret: "s" });
  assert.equal(res.delivered, true);
  assert.equal(res.seal.decision, "seal", "the send was sealed (Tier-0 verified)");
  assert.deepEqual(observed, [keyId(a.identity.publicKey)], "bob recorded that this origin seals to him");
});

test("M3a: a clear (public) delivery records no observation", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const observed = [];
  let pluginB;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => pluginB.router.relay(envelope, a.identity.publicKey),
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, {
    neighbors: () => [a.identity.publicKey],
    sealPrivateKey: b.identity.sealPrivateKey,
    observeSealed: (proof) => observed.push(proof.originKeyId),
    deliver: () => ({ received: true }),
  }));

  const res = await pluginA.send(b.identity.publicKey, { x: 1 }, { public: true });
  assert.equal(res.delivered, true);
  assert.deepEqual(observed, [], "a clear delivery teaches no downgrade marker");
});

test("M3a: with requireSealFrom armed, a clear message from a known-sealing origin is refused", async () => {
  const a = machine("alice");
  const b = machine("bob");
  let pluginB;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => pluginB.router.relay(envelope, a.identity.publicKey),
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, {
    neighbors: () => [a.identity.publicKey],
    sealPrivateKey: b.identity.sealPrivateKey,
    requireSealFrom: (k) => k === keyId(a.identity.publicKey),
    deliver: () => ({ received: true }),
  }));

  const res = await pluginA.send(b.identity.publicKey, { x: 1 }, { public: true });
  assert.equal(res.refused, true);
  assert.equal(res.response.reason, "downgrade-refused", "the per-origin floor refuses the clear downgrade");
  // The downgrade refusal teaches B's current key, so an origin whose Tier-1 key went stale
  // (a relay-forced conflict, or B rotating its sealing key) recovers instead of deadlocking.
  assert.ok(res.response[ROUTED_RECORD_FIELD], "a downgrade refusal carries the discovery record");
});

// --- M3a ARMED: the per-origin downgrade floor is now wired to a live observation store, not
// a stub — the first sealed delivery arms it, a later clear is refused with the key taught back,
// a rotation is diagnosed via a `seal` refusal, and an operator clears a sticky conflict. ---

/**
 * Build an A→B pair whose destination B is armed by a REAL observation store: opening a sealed
 * body records a `requireSealFrom` marker, and the enforcement floor reads that same store — so
 * the tests exercise the wiring end to end, not a hand-written policy predicate.
 * @returns {{ pluginA: any, pluginB: any, obs: any, deliveredBody: () => any }}
 */
const armedPair = (a, b, { obs = createRoutedObservationStore(), tier0, sealPrivateKey = b.identity.sealPrivateKey, selfRecordB } = {}) => {
  let pluginB;
  let lastBody;
  const pluginA = createRoutePlugin(cryptoDeps(a, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => pluginB.router.relay(envelope, a.identity.publicKey),
    routedKeyStore: a.store,
    ...(tier0 ? { tier0Seal: tier0 } : { tier0Seal: () => ({ state: "unverified", key: null }) }),
  }));
  pluginB = createRoutePlugin(cryptoDeps(b, {
    neighbors: () => [a.identity.publicKey],
    sealPrivateKey,
    ...(selfRecordB ? { selfRecord: selfRecordB } : {}),
    observeSealed: (proof) => obs.observe(proof, "requireSealFrom"),
    requireSealFrom: (k) => obs.has(k, "requireSealFrom"),
    deliver: (body) => { lastBody = body; return { received: true }; },
  }));
  return { pluginA, get pluginB() { return pluginB; }, obs, deliveredBody: () => lastBody };
};

test("M3a armed (store-backed): the first seal arms the floor, and a later clear is refused with record + verified receipt", async () => {
  const a = machine("alice");
  const b = machine("bob");
  a.store = createRoutedKeyStore();
  // A holds a walk-verified Tier-0 key for B, so its first send seals.
  const { pluginA, obs } = armedPair(a, b, {
    tier0: () => ({ state: "verified", key: normalizeKey(b.identity.sealPublicKey) }),
  });

  const sealed = await pluginA.send(b.identity.publicKey, { secret: "s" });
  assert.equal(sealed.delivered, true, "the sealing send delivered");
  assert.equal(obs.has(keyId(a.identity.publicKey), "requireSealFrom"), true, "opening the seal armed the floor");

  // A now (mistakenly, or deliberately) sends clear: the armed floor refuses it, through the
  // real store, and the refusal carries B's key-only record and a receipt A can verify.
  const clear = await pluginA.send(b.identity.publicKey, { oops: 1 }, { public: true });
  assert.equal(clear.refused, true);
  assert.equal(clear.response.reason, "downgrade-refused", "the store-backed floor refuses the clear downgrade");
  assert.ok(clear.response[ROUTED_RECORD_FIELD], "the armed refusal still teaches B's key");
  assert.deepEqual(clear.receipt, { present: true, verified: true, outcome: "refused", reason: "downgrade-refused" });
});

test("M3a armed: the FIRST sealed delivery arms the floor (order-sensitive) and it survives a store restart", async () => {
  const a = machine("alice");
  const b = machine("bob");
  a.store = createRoutedKeyStore();
  const obs = createRoutedObservationStore();
  const tier0 = () => ({ state: "verified", key: normalizeKey(b.identity.sealPublicKey) });
  const first = armedPair(a, b, { obs, tier0 });

  // Clear BEFORE any seal: no marker yet, so it delivers.
  const before = await first.pluginA.send(b.identity.publicKey, { x: 1 }, { public: true });
  assert.equal(before.delivered, true, "a clear before the first seal delivers (nothing armed)");
  assert.equal(before.refused ?? false, false);

  // Seal once — this arms the floor — then a clear AFTER is refused.
  await first.pluginA.send(b.identity.publicKey, { secret: "s" });
  const after = await first.pluginA.send(b.identity.publicKey, { x: 2 }, { public: true });
  assert.equal(after.response.reason, "downgrade-refused", "a clear after the first seal is refused");

  // Restart the observation store from its persisted snapshot and rebuild B against it: the
  // durable marker still refuses, so arming is not session state.
  a.store = createRoutedKeyStore();
  const restored = createRoutedObservationStore({ initial: obs.snapshot() });
  const second = armedPair(a, b, { obs: restored, tier0 });
  const afterRestart = await second.pluginA.send(b.identity.publicKey, { x: 3 }, { public: true });
  assert.equal(afterRestart.response.reason, "downgrade-refused", "the marker survives a store restart");
});

test("M3a rotation: a stale sealed send is refused `seal`, teaches the current key, and flips the origin to a sticky conflict", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const rotated = generateIdentity(); // B's NEW sealing keypair
  a.store = createRoutedKeyStore();
  // A approves B's OLD sealing key, as a prior discovery+approval would have left it.
  const bKeyId = keyId(b.identity.publicKey);
  a.store.observe(bKeyId, recordOf(b, b.identity.sealPublicKey));
  assert.equal(a.store.approve(bKeyId).ok, true);

  // B has rotated: it advertises and holds the NEW key. Its identity (Ed25519) is unchanged.
  const { pluginA } = armedPair(a, b, {
    sealPrivateKey: rotated.sealPrivateKey,
    selfRecordB: () => ({ name: b.name, publicKey: b.identity.publicKey, sealPublicKey: rotated.sealPublicKey, addresses: [] }),
  });

  const res = await pluginA.send(b.identity.publicKey, { secret: "stale" });
  assert.equal(res.refused, true);
  assert.equal(res.response.reason, "seal", "sealing to the retired key cannot be opened -> `seal`");
  assert.ok(res.response[ROUTED_RECORD_FIELD], "the `seal` refusal now teaches B's CURRENT key");
  // Observing that current key against the still-approved old one is the rotation signal: a
  // sticky local conflict, so all further sends refuse locally instead of spraying the network.
  assert.equal(pluginA.router.routedSealState(b.identity.publicKey), "record-conflict", "the origin flips to a sticky conflict");
});

test("M3a rotation: a `seal-origin-mismatch` or a malformed sealed body is refused but teaches NO record", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const c = machine("carol"); // a third identity, to forge a seal by a non-origin
  const pluginB = createRoutePlugin(cryptoDeps(b, {
    neighbors: () => [a.identity.publicKey],
    sealPrivateKey: b.identity.sealPrivateKey,
  }));
  const nowT = Date.now();
  const msgId = () => randomBytes(16).toString("base64url");
  /** Forge a sealed wrapper: manifest signed by `origin`, carrying arbitrary transported bytes. */
  const forge = (origin, transported) => {
    const manifest = buildManifest({
      originKeyId: keyId(origin.identity.publicKey),
      destinationKeyId: keyId(b.identity.publicKey),
      messageId: msgId(),
      issuedAt: nowT,
      expiresAt: nowT + 60_000,
      payloadMode: "sealed",
      payloadDigest: payloadDigest(transported),
    });
    return {
      manifest,
      manifestSignature: signManifest(manifest, origin.identity.privateKey),
      originRecord: signRecord({ name: origin.name, publicKey: origin.identity.publicKey, sealPublicKey: origin.identity.sealPublicKey, addresses: [], lastSeen: null }, origin.identity.privateKey),
      payload: transported.toString("base64"),
    };
  };
  const feed = (wrapper) =>
    pluginB.router.relay({ dest: b.identity.publicKey, ttl: 4, budget: 8, visited: [], payload: wrapper, id: null }, a.identity.publicKey);

  // A block A signs the manifest over, but that CAROL sealed — the sealer is not the origin.
  const crossSealed = Buffer.from(JSON.stringify(seal(Buffer.from(JSON.stringify({ x: 1 })), b.identity.sealPublicKey, { signer: { publicKey: c.identity.publicKey, privateKey: c.identity.privateKey } })), "utf8");
  const mismatch = await feed(forge(a, crossSealed));
  assert.equal(mismatch.response.reason, "seal-origin-mismatch", "an attack indicator, not rotation");
  assert.equal(mismatch.response[ROUTED_RECORD_FIELD], undefined, "seal-origin-mismatch must NOT reward the sealer with a key");
  assert.ok(mismatch.response[ROUTED_RECEIPT_FIELD], "the authenticated refusal is still receipted");

  // Committed bytes that are not even a JSON object -> `sealed` (malformed), not rotation.
  const malformed = await feed(forge(a, Buffer.from("not-a-sealed-object", "utf8")));
  assert.equal(malformed.response.reason, "sealed");
  assert.equal(malformed.response[ROUTED_RECORD_FIELD], undefined, "a malformed sealed body teaches nothing");
});

test("M3a recovery: discard clears a sticky conflict so re-discover + pinned approve reseals end to end", async () => {
  const a = machine("alice");
  const b = machine("bob");
  const persists = [];
  a.store = createRoutedKeyStore({ persist: (_entries, meta) => persists.push(meta ?? {}) });
  const { pluginA, obs, deliveredBody } = armedPair(a, b);
  const bKeyId = keyId(b.identity.publicKey);
  const aKeyId = keyId(a.identity.publicKey);

  // Arm B via an approved Tier-1 key: A seals a first delivery, so B records A as a sealer.
  a.store.observe(bKeyId, recordOf(b, b.identity.sealPublicKey));
  assert.equal(a.store.approve(bKeyId).ok, true);
  const armed = await pluginA.send(b.identity.publicKey, { hi: 1 });
  assert.equal(armed.delivered, true);
  assert.equal(obs.has(aKeyId, "requireSealFrom"), true, "B is now armed for A");

  // Manufacture the origin-side conflict (a relay replaying a differing record would do this).
  a.store.observe(bKeyId, recordOf(b, generateIdentity().sealPublicKey));
  assert.equal(pluginA.router.routedSealState(b.identity.publicKey), "record-conflict");
  // Sends now refuse LOCALLY — no clear leak, no network spray.
  const stuck = await pluginA.send(b.identity.publicKey, { x: 1 });
  assert.equal(stuck.reason, "seal-refused:tier1-conflict");

  // The operator discards. It reports the prior state and persists a RESTRICTING write.
  const discarded = pluginA.router.discardRoutedSeal(b.identity.publicKey);
  assert.deepEqual(discarded, { ok: true, was: "record-conflict" });
  assert.equal(pluginA.router.routedSealState(b.identity.publicKey), "none", "discard leaves the destination at none");
  assert.equal(persists.at(-1)?.restricting, true, "discard persists as a key-voiding (restricting) write");
  // Discard of an unknown destination reports unknown, changing nothing.
  assert.deepEqual(pluginA.router.discardRoutedSeal(generateIdentity().publicKey), { ok: false, reason: "unknown" });

  // Re-discover against the ARMED destination: the clear probe is refused downgrade-refused but
  // still teaches B's current key, so the origin relearns it (pending) without a clear ever landing.
  const probe = await pluginA.send(b.identity.publicKey, { probe: 1 }, { public: true });
  assert.equal(probe.response.reason, "downgrade-refused", "the probe is refused by the armed floor");
  assert.equal(pluginA.router.routedSealState(b.identity.publicKey), "record-carried", "yet it re-learned B's key (pending)");

  // Approve pinned to the fingerprint the operator verified out of band, then the next send seals.
  assert.equal(pluginA.router.approveRoutedSeal(b.identity.publicKey, b.identity.sealPublicKey).ok, true);
  const resealed = await pluginA.send(b.identity.publicKey, { secret: "recovered" });
  assert.equal(resealed.delivered, true, `the resend seals and delivers (${resealed.reason ?? ""})`);
  assert.equal(resealed.seal.decision, "seal");
  assert.deepEqual(resealed.receipt, { present: true, verified: true, outcome: "delivered", reason: "" });
  assert.deepEqual(deliveredBody(), { secret: "recovered" });
});

test("M3a armed: a never-sealing origin's clear still delivers under the floor", async () => {
  const a = machine("alice"); // will seal, arming the floor for itself
  const c = machine("carol"); // never seals
  const b = machine("bob");
  a.store = createRoutedKeyStore();
  const wire = armedPair(a, b, {
    tier0: () => ({ state: "verified", key: normalizeKey(b.identity.sealPublicKey) }),
  });
  const { obs, deliveredBody } = wire;
  // C shares the same armed destination B, over its own wire.
  const pluginC = createRoutePlugin(cryptoDeps(c, {
    neighbors: () => [b.identity.publicKey],
    forward: async (_peer, envelope) => wire.pluginB.router.relay(envelope, c.identity.publicKey),
  }));

  await wire.pluginA.send(b.identity.publicKey, { secret: "s" }); // arms the floor for A only
  assert.equal(obs.has(keyId(a.identity.publicKey), "requireSealFrom"), true);
  assert.equal(obs.has(keyId(c.identity.publicKey), "requireSealFrom"), false, "C never sealed, so it has no marker");

  const clearFromC = await pluginC.send(b.identity.publicKey, { hello: "clear" }, { public: true });
  assert.equal(clearFromC.delivered, true, "the floor is per-origin: C's clear is unaffected");
  assert.deepEqual(deliveredBody(), { hello: "clear" });
});
