/** The loopback route-origin endpoint classifies caller mistakes without hiding faults. */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createRoutePlugin } from "../src/builtin/routePlugin.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import { MAX_ROUTED_BODY_BYTES } from "../src/routedMessage.js";
import { createDaemon } from "../src/server.js";

const post = (port, body) =>
  fetch(`http://127.0.0.1:${port}/api/route/send`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  }).then(async (response) => ({ status: response.status, json: await response.json() }));

test("route/send returns 400 only for routed input errors; internal failures stay generic 500s", async (t) => {
  const identity = generateIdentity();
  const directory = createDirectory({ self: { name: "self", publicKey: identity.publicKey } });
  const route = createRoutePlugin({
    self: identity.publicKey,
    privateKey: identity.privateKey,
    selfRecord: () => directory.self,
    authorizeOrigin: () => true,
    neighbors: () => [],
    forward: async () => ({ delivered: false, spent: 0 }),
    deliver: (body) => {
      if (body?.boom) throw new Error("sensitive internal failure");
      return { received: true };
    },
  });
  const logs = [];
  const daemon = createDaemon({ directory, identity, plugins: [route], log: (line) => logs.push(line) });
  const { port } = await daemon.listen({ port: 0 });
  t.after(() => daemon.close());

  const invalidDestination = await post(port, { dest: "not a key", payload: null });
  assert.equal(invalidDestination.status, 400);
  assert.match(invalidDestination.json.error, /invalid destination/);

  // The control request itself is below 1 MB, but JSON string quotes put the routed
  // body one byte beyond its 700,000-byte serialized ceiling.
  const oversized = await post(port, {
    dest: identity.publicKey,
    payload: "x".repeat(MAX_ROUTED_BODY_BYTES - 1),
    public: true,
  });
  assert.equal(oversized.status, 400);
  assert.match(oversized.json.error, /byte limit/);

  const valid = await post(port, { dest: identity.publicKey, payload: { ok: true }, public: true });
  assert.equal(valid.status, 200);
  assert.equal(valid.json.response.received, true);

  const internal = await post(port, { dest: identity.publicKey, payload: { boom: true }, public: true });
  assert.equal(internal.status, 500);
  assert.deepEqual(internal.json, { error: "internal error" }, "implementation details are not exposed");
  assert.ok(logs.some((line) => line.includes("sensitive internal failure")), "the operator still gets the cause");
});

test("route seal-approve / seal endpoints gate a discovered Tier-1 key behind manual approval", async (t) => {
  const { keyId } = await import("../src/routeManifest.js");
  const { signRecord } = await import("../src/peerRecord.js");
  const { createRoutedKeyStore } = await import("../src/routedKeyStore.js");
  const { normalizeKey } = await import("../src/identity.js");

  const self = generateIdentity();
  const peer = generateIdentity();
  const store = createRoutedKeyStore();
  const peerId = keyId(peer.publicKey);
  // A discovered (pending) key for the peer, as a data-free probe would have learned.
  store.observe(peerId, signRecord(
    { name: "peer", publicKey: peer.publicKey, sealPublicKey: peer.sealPublicKey, addresses: [], lastSeen: null },
    peer.privateKey,
  ));

  const directory = createDirectory({ self: { name: "self", publicKey: self.publicKey } });
  const route = createRoutePlugin({
    self: self.publicKey,
    privateKey: self.privateKey,
    selfRecord: () => directory.self,
    authorizeOrigin: () => true,
    neighbors: () => [],
    forward: async () => ({ delivered: false, spent: 0 }),
    deliver: () => ({ received: true }),
    routedKeyStore: store,
    tier0Seal: () => ({ state: "unverified", key: null }),
  });
  const daemon = createDaemon({ directory, identity: self, plugins: [route] });
  const { port } = await daemon.listen({ port: 0 });
  t.after(() => daemon.close());

  const seal = (path, dest, extra = {}) =>
    fetch(`http://127.0.0.1:${port}/api/route/${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ dest, ...extra }),
    }).then(async (r) => ({ status: r.status, json: await r.json() }));

  // Pending before approval: a fingerprint is visible, but it is not yet approved.
  const before = await seal("seal", peer.publicKey);
  assert.equal(before.json.state, "record-carried");
  assert.equal(before.json.detail.approved, false);

  // A mismatched fingerprint is refused (409).
  const wrong = await seal("seal-approve", peer.publicKey, { sealKey: normalizeKey(generateIdentity().sealPublicKey) });
  assert.equal(wrong.status, 409);
  assert.equal(wrong.json.reason, "mismatch");

  // The right fingerprint approves it.
  const ok = await seal("seal-approve", peer.publicKey, { sealKey: normalizeKey(peer.sealPublicKey) });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.ok, true);
  const after = await seal("seal", peer.publicKey);
  assert.equal(after.json.state, "record-approved");
  assert.equal(after.json.detail.approved, true);
});
