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
} from "../src/builtin/routePlugin.js";
import { generateIdentity } from "../src/identity.js";
import { REFUSE } from "../src/plugins.js";
import { keyId } from "../src/routeManifest.js";
import { createRouteReplayGuard } from "../src/routeReplayGuard.js";
import { wrapRoutedMessage } from "../src/routedMessage.js";

const T = 1_700_000_000_000;
const machine = (name) => {
  const identity = generateIdentity();
  return { name, identity, record: { name, publicKey: identity.publicKey, addresses: [] } };
};

const cryptoDeps = (self, over = {}) => ({
  self: self.identity.publicKey,
  privateKey: self.identity.privateKey,
  selfRecord: () => self.record,
  authorizeOrigin: () => true,
  neighbors: () => [],
  forward: async () => ({ delivered: false, spent: 0 }),
  deliver: () => ({ received: true }),
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

  const result = await pluginA.send(b.identity.publicKey, { hello: "graph" });
  assert.equal(result.delivered, true);
  assert.deepEqual(result.response, { received: true, echo: { hello: "graph" } });
  assert.deepEqual(delivered.body, { hello: "graph" });
  assert.equal(delivered.meta.originKeyId, keyId(a.identity.publicKey));
  assert.equal(delivered.meta.origin, delivered.meta.originKeyId, "the unsigned outer origin is replaced");
  assert.equal(wire.id, null, "the unsigned M0 cache is bypassed");
  assert.match(wire.payload.manifest.messageId, /^[A-Za-z0-9_-]{22}$/, "16 random bytes, base64url");
  assert.equal(typeof wire.payload.payload, "string", "the engine carries the signed wrapper opaquely");

  const local = await pluginB.send(b.identity.publicKey, { hello: "self" });
  assert.equal(local.delivered, true, "self-send passes through the same wrap/open gates");
  assert.equal(delivered.meta.originKeyId, keyId(b.identity.publicKey));
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
  assert.deepEqual(good.response, { received: true });
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
  const throughFacade = await pluginA.router.send(b.identity.publicKey, { secure: true });
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

  const refused = await pluginA.send(d.identity.publicKey, { action: "denied" });
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
    host.plugin.send(destination.identity.publicKey, { host: i }));
  assert.equal(host.started(), MAX_IN_FLIGHT_RELAYS, "host sends share the plugin-wide ceiling");
  const hostOverflow = await host.plugin.send(destination.identity.publicKey, { host: "overflow" });
  assert.equal(hostOverflow.delivered, false);
  assert.match(hostOverflow.reason, /in flight/);
  host.release();
  await Promise.all(hostHeld);

  const afterRelease = await host.plugin.send(destination.identity.publicKey, { host: "after" });
  assert.doesNotMatch(afterRelease.reason ?? "", /in flight/, "finally releases capacity after work settles");
});
