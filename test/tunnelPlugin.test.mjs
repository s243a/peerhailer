/**
 * A tunnel carries bytes to a service this machine already runs.
 *
 * The tests that matter are the refusals: a peer reaching an endpoint nobody
 * declared, a peer holding one endpoint's capability reaching another, and a
 * peer using a tunnel it did not open. The carrying itself is the easy part.
 */
import assert from "node:assert/strict";
import { createServer } from "node:net";
import { test } from "node:test";

import { capabilityFor, createTunnelPlugin } from "../src/builtin/tunnelPlugin.js";
import { collectRoutes, REFUSE } from "../src/plugins.js";

/** A local service to tunnel to: echoes what it is given, in upper case. */
function shoutingService() {
  /** @type {Set<import("node:net").Socket>} */
  const live = new Set();
  const server = createServer((socket) => {
    live.add(socket);
    socket.on("close", () => live.delete(socket));
    socket.on("error", () => {});
    socket.on("data", (chunk) => socket.write(chunk.toString().toUpperCase()));
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = /** @type {import("node:net").AddressInfo} */ (server.address());
      resolve({
        port,
        // Destroying rather than waiting: `close` waits for open connections to
        // end, and a tunnel's socket is open by design — so a test that forgot
        // to close one would hang instead of failing.
        close: () =>
          new Promise((done) => {
            for (const socket of live) socket.destroy();
            server.close(() => done(undefined));
          }),
      });
    });
  });
}

const settle = (ms = 60) => new Promise((resolve) => setTimeout(resolve, ms));
const call = (routes, path, input) => routes.get(`POST ${path}`).handler({ log: () => {}, ...input });

test("a peer reaches a declared endpoint, and gets what it says back", async () => {
  const service = await shoutingService();
  const plugin = createTunnelPlugin({ endpoints: { echo: `127.0.0.1:${service.port}` } });
  const routes = collectRoutes([plugin], { log: () => {} });
  const caller = { name: "sol", publicKey: "KEY-SOL" };

  try {
    const { id } = await call(routes, "/tunnel/echo/open", { caller });
    assert.ok(id, "a tunnel has an id");
    await settle();

    await call(routes, "/tunnel/echo/send", { caller, body: { id, data: Buffer.from("hello").toString("base64") } });
    await settle();

    const polled = await call(routes, "/tunnel/echo/poll", { caller, body: { id } });
    assert.equal(Buffer.from(polled.data, "base64").toString(), "HELLO");
    assert.equal(polled.closed, false);

    await call(routes, "/tunnel/echo/close", { caller, body: { id } });
  } finally {
    await service.close();
  }
});

test("an endpoint nobody declared has no route at all", () => {
  const plugin = createTunnelPlugin({ endpoints: { echo: "127.0.0.1:1" } });
  const routes = collectRoutes([plugin], { log: () => {} });

  // Not refused at the door — absent. A caller cannot name an address, only a
  // name somebody wrote down, so there is nothing to aim anywhere else.
  assert.ok(routes.has("POST /tunnel/echo/open"));
  assert.equal(routes.has("POST /tunnel/database/open"), undefined || false);
  assert.equal(routes.get("POST /tunnel/database/open"), undefined);
});

test("each endpoint carries its own capability", () => {
  const plugin = createTunnelPlugin({ endpoints: { echo: "127.0.0.1:1", other: "127.0.0.1:2" } });
  const routes = collectRoutes([plugin], { log: () => {} });

  assert.equal(routes.get("POST /tunnel/echo/open").capability, "tunnel:echo");
  assert.equal(routes.get("POST /tunnel/other/open").capability, "tunnel:other");
  assert.notEqual(
    routes.get("POST /tunnel/echo/open").capability,
    routes.get("POST /tunnel/other/open").capability,
    "holding one endpoint says nothing about another",
  );
  assert.deepEqual(plugin.capabilities.sort(), [capabilityFor("echo"), capabilityFor("other")].sort());
});

test("a tunnel belongs to the peer that opened it", async () => {
  const service = await shoutingService();
  const plugin = createTunnelPlugin({ endpoints: { echo: `127.0.0.1:${service.port}` } });
  const routes = collectRoutes([plugin], { log: () => {} });
  const owner = { name: "sol", publicKey: "KEY-SOL" };
  const other = { name: "mars", publicKey: "KEY-MARS" };

  try {
    const { id } = await call(routes, "/tunnel/echo/open", { caller: owner });
    await settle();

    // Knowing the id is not a way in: ownership is by key, because a tunnel is
    // a live connection into a local service.
    for (const path of ["/tunnel/echo/send", "/tunnel/echo/poll", "/tunnel/echo/close"]) {
      const refused = await call(routes, path, { caller: other, body: { id, data: "" } });
      assert.equal(refused[REFUSE], true, `${path} must refuse a peer that does not own it`);
    }

    // And the owner is unaffected by the attempt.
    const polled = await call(routes, "/tunnel/echo/poll", { caller: owner, body: { id } });
    assert.equal(polled.closed, false, "the tunnel was not disturbed");
    await call(routes, "/tunnel/echo/close", { caller: owner, body: { id } });
  } finally {
    await service.close();
  }
});

test("a caller with no key cannot own anything", async () => {
  const plugin = createTunnelPlugin({ endpoints: { echo: "127.0.0.1:1" } });
  const routes = collectRoutes([plugin], { log: () => {} });
  const refused = await call(routes, "/tunnel/echo/open", { caller: { name: "anon" } });
  assert.equal(refused[REFUSE], true);
});

test("a dead endpoint is reported, not hung on", async () => {
  // Nothing listens on port 1.
  const plugin = createTunnelPlugin({ endpoints: { nowhere: "127.0.0.1:1" } });
  const routes = collectRoutes([plugin], { log: () => {} });
  const caller = { name: "sol", publicKey: "KEY-SOL" };

  const { id } = await call(routes, "/tunnel/nowhere/open", { caller });
  await settle(120);
  const polled = await call(routes, "/tunnel/nowhere/poll", { caller, body: { id } });
  assert.equal(polled.closed, true);
  assert.ok(polled.error, "and says why");
});

test("the fabric decides who reaches an endpoint, not the tunnel", async () => {
  const { createDaemon } = await import("../src/server.js");
  const { createDirectory } = await import("../src/directory.js");
  const { generateIdentity, signPayload } = await import("../src/identity.js");

  const service = await shoutingService();
  const me = generateIdentity();
  const allowed = generateIdentity();
  const refused = generateIdentity();

  const directory = createDirectory({ self: { name: "me", publicKey: me.publicKey } });
  // The capability has to be granted deliberately: nothing built in carries it,
  // so reaching an agent is never something a peer inherits by being trusted.
  directory.useProfiles({ driver: { name: "driver", allows: ["hail", "tunnel:echo"] } });
  directory.admit({ name: "driver-peer", publicKey: allowed.publicKey, profile: "driver" });
  directory.admit({ name: "ordinary", publicKey: refused.publicKey, profile: "trusted" });

  const plugin = createTunnelPlugin({ endpoints: { echo: `127.0.0.1:${service.port}` } });
  const daemon = createDaemon({ directory, identity: me, plugins: [plugin] });
  const { port } = await daemon.listen({ port: 0 });

  const open = async (name, identity) => {
    const from = { name, at: Date.now() };
    const response = await fetch(`http://127.0.0.1:${port}/tunnel/echo/open`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ from, signature: signPayload(from, identity.privateKey) }),
    }).catch(() => null);
    return response;
  };

  try {
    const yes = await open("driver-peer", allowed);
    assert.equal(yes?.status, 200, "a peer holding tunnel:echo gets through");
    const { id } = await yes.json();
    assert.ok(id);

    // `trusted` is your own machines, and driving a local service is a
    // different order of thing — so it is refused despite being trusted.
    const no = await open("ordinary", refused);
    assert.notEqual(no?.status, 200, "trusted is not the same as may reach an endpoint");
  } finally {
    await daemon.close();
    await service.close();
  }
});
