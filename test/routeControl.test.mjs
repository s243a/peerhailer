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
  });
  assert.equal(oversized.status, 400);
  assert.match(oversized.json.error, /byte limit/);

  const valid = await post(port, { dest: identity.publicKey, payload: { ok: true } });
  assert.equal(valid.status, 200);
  assert.equal(valid.json.response.received, true);

  const internal = await post(port, { dest: identity.publicKey, payload: { boom: true } });
  assert.equal(internal.status, 500);
  assert.deepEqual(internal.json, { error: "internal error" }, "implementation details are not exposed");
  assert.ok(logs.some((line) => line.includes("sensitive internal failure")), "the operator still gets the cause");
});
