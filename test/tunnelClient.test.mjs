/**
 * The caller side of a tunnel: open a byte pipe to a peer's declared endpoint,
 * push bytes in, read bytes out — and pump a live stream through it end to end.
 *
 * The low-level calls are checked against a fake `call`; the pump is proven over
 * a real daemon, a real tunnel, and a real echo socket, because the whole point
 * is that bytes cross both ways under the request/poll transport.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { PassThrough } from "node:stream";
import { createServer as netServer } from "node:net";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import { callPeer } from "../src/hail.js";
import hailPlugin from "../src/builtin/hailPlugin.js";
import { createTunnelPlugin } from "../src/builtin/tunnelPlugin.js";
import { openTunnel, sendTunnel, pollTunnel, closeTunnel, pipeTunnel } from "../src/tunnelClient.js";

// ---- unit: the four calls map to the right routes and shapes ----

test("open/send/poll/close speak the tunnel routes", async () => {
  const seen = [];
  const call = async (path, body) => {
    seen.push([path, body]);
    return { ok: true, response: { id: "T1" } };
  };
  await openTunnel(call, "acp");
  await sendTunnel(call, "acp", "T1", "hi");
  await pollTunnel(call, "acp", "T1");
  await closeTunnel(call, "acp", "T1");

  assert.deepEqual(seen[0], ["/tunnel/acp/open", {}]);
  assert.deepEqual(seen[1], ["/tunnel/acp/send", { id: "T1", data: Buffer.from("hi").toString("base64") }]);
  assert.deepEqual(seen[2], ["/tunnel/acp/poll", { id: "T1" }]);
  assert.deepEqual(seen[3], ["/tunnel/acp/close", { id: "T1" }]);
});

// ---- integration harness ----

/** An upper-casing echo, so we can tell what crossed the tunnel from what didn't. */
function shoutingEcho() {
  const server = netServer((socket) => socket.on("data", (b) => socket.write(b.toString().toUpperCase())));
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = /** @type {import("node:net").AddressInfo} */ (server.address());
      resolve({ port, close: () => new Promise((r) => server.close(() => r(undefined))) });
    });
  });
}

/** A daemon offering `tunnel:echo` to `caller`, and a `call` bound to it. */
async function bootTunnelDaemon() {
  const me = generateIdentity();
  const caller = generateIdentity();
  const echo = await shoutingEcho();
  const directory = createDirectory({ self: { name: "target", publicKey: me.publicKey } });
  directory.useProfiles({ piped: { name: "piped", allows: ["hail", "tunnel:echo"] } });
  directory.admit({ name: "caller", publicKey: caller.publicKey, profile: "piped" });
  const plugin = createTunnelPlugin({ endpoints: { echo: `127.0.0.1:${echo.port}` } });
  const daemon = createDaemon({ directory, identity: me, plugins: [hailPlugin, plugin] });
  const { port } = await daemon.listen({ port: 0 }); // control-loopback: encrypted+mutual, serves the tunnel
  const record = { name: "target", addresses: [{ value: `http://127.0.0.1:${port}` }], publicKey: me.publicKey };
  const as = { name: "caller", privateKey: caller.privateKey };
  const call = (path, body) => callPeer(record, path, body, { as });
  return { daemon, plugin, echo, call };
}

// ---- integration: bytes cross, both ways, low level ----

test("bytes pushed in come back transformed by the endpoint", async () => {
  const { daemon, plugin, echo, call } = await bootTunnelDaemon();
  try {
    const opened = await openTunnel(call, "echo");
    assert.equal(opened.ok, true, opened.error);
    const id = opened.response.id;

    await sendTunnel(call, "echo", id, "hello-tunnel");
    // Poll until the echo comes back (a loop or two under the transport).
    let out = "";
    for (let i = 0; i < 40 && !out.includes("HELLO-TUNNEL"); i += 1) {
      const polled = await pollTunnel(call, "echo", id);
      if (polled.response?.data) out += Buffer.from(polled.response.data, "base64").toString();
      if (!out.includes("HELLO-TUNNEL")) await new Promise((r) => setTimeout(r, 20));
    }
    assert.match(out, /HELLO-TUNNEL/, "the endpoint's response crossed back through the tunnel");
    await closeTunnel(call, "echo", id);
  } finally {
    plugin.stop();
    await echo.close();
    await daemon.close();
  }
});

// ---- integration: the pump ----

test("pipeTunnel pumps a live stream through to the endpoint and back", async () => {
  const { daemon, plugin, echo, call } = await bootTunnelDaemon();
  const input = new PassThrough();
  const output = new PassThrough();
  let received = "";
  output.on("data", (b) => (received += b.toString()));
  try {
    // Run the pump in the background; it ends when `input` ends.
    const pump = pipeTunnel(call, "echo", { input, output }, { pollMs: 10 });

    input.write("first\n");
    for (let i = 0; i < 60 && !received.includes("FIRST"); i += 1) await new Promise((r) => setTimeout(r, 20));
    assert.match(received, /FIRST/, "a chunk written to input came back uppercased on output");

    // A second write proves the pipe stays open across messages (the ACP case).
    input.write("second\n");
    for (let i = 0; i < 60 && !received.includes("SECOND"); i += 1) await new Promise((r) => setTimeout(r, 20));
    assert.match(received, /SECOND/, "the pipe carried a second message on the same session");

    input.end(); // ends the pump
    const result = await pump;
    assert.equal(result.ok, true, "the pump closed cleanly when the local stream ended");
  } finally {
    plugin.stop();
    await echo.close();
    await daemon.close();
  }
});

test("pipeTunnel reports a refusal instead of hanging when the capability is missing", async () => {
  const me = generateIdentity();
  const caller = generateIdentity();
  const echo = await shoutingEcho();
  const directory = createDirectory({ self: { name: "target", publicKey: me.publicKey } });
  // Admit the caller but do NOT grant tunnel:echo.
  directory.useProfiles({ bare: { name: "bare", allows: ["hail"] } });
  directory.admit({ name: "caller", publicKey: caller.publicKey, profile: "bare" });
  const plugin = createTunnelPlugin({ endpoints: { echo: `127.0.0.1:${echo.port}` } });
  const daemon = createDaemon({ directory, identity: me, plugins: [hailPlugin, plugin] });
  const { port } = await daemon.listen({ port: 0 });
  const call = (path, body) =>
    callPeer({ name: "target", addresses: [{ value: `http://127.0.0.1:${port}` }], publicKey: me.publicKey }, path, body, {
      as: { name: "caller", privateKey: caller.privateKey },
    });
  try {
    const result = await pipeTunnel(call, "echo", { input: new PassThrough(), output: new PassThrough() }, { pollMs: 10 });
    assert.equal(result.ok, false, "a caller without tunnel:echo cannot open the pipe");
  } finally {
    plugin.stop();
    await echo.close();
    await daemon.close();
  }
});
