/**
 * `forwardTunnel` exposes a peer's tunnel endpoint as a local TCP port. Here a
 * loopback echo sits behind a real pinned-mutual-TLS daemon's tunnel; the forward
 * gives a local port, and a socket to it round-trips through the tunnel to the
 * echo. This is how the composer hands a remote HTTP-MCP supervisor seat to a
 * local Claude Code.
 *
 *   node test/live-tunnel-forward.mjs
 */
import assert from "node:assert/strict";
import net from "node:net";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import hailPlugin from "../src/builtin/hailPlugin.js";
import { createTunnelPlugin } from "../src/builtin/tunnelPlugin.js";
import { callPeer } from "../src/hail.js";
import { forwardTunnel } from "../src/tunnelClient.js";

const echo = net.createServer((socket) => socket.pipe(socket));
const echoPort = await new Promise((resolve) => echo.listen(0, "127.0.0.1", () => resolve(echo.address().port)));

const me = generateIdentity();
const caller = generateIdentity();
const directory = createDirectory({ self: { name: "home", publicKey: me.publicKey } });
directory.useProfiles({ p: { name: "p", allows: ["hail", "tunnel:echo"] } });
directory.admit({ name: "caller", publicKey: caller.publicKey }, { profile: "p" });
const daemon = createDaemon({
  directory,
  identity: me,
  plugins: [hailPlugin, createTunnelPlugin({ endpoints: { echo: "127.0.0.1:" + echoPort } })],
});
const bound = await daemon.listenHail({ port: 0, hosts: ["127.0.0.1"], tls: true });
const record = { name: "home", addresses: [{ value: `https://127.0.0.1:${bound[0].port}` }], publicKey: me.publicKey };
const as = { name: "caller", publicKey: caller.publicKey, privateKey: caller.privateKey };
const call = (path, body) => callPeer(record, path, body, { as });

const fwd = await forwardTunnel(call, "echo", { port: 0 });
assert.ok(fwd.port > 0, "forward bound a local port");

const echoed = await new Promise((resolve, reject) => {
  const client = net.connect(fwd.port, "127.0.0.1");
  let buf = "";
  client.on("data", (d) => {
    buf += d;
    if (buf.includes("PING")) {
      client.end();
      resolve(buf.trim());
    }
  });
  client.on("error", reject);
  client.on("connect", () => client.write("PING\n"));
  setTimeout(() => reject(new Error("no echo in 6s")), 6000);
});
assert.equal(echoed, "PING", "bytes round-tripped through the tunnel to the echo");

await fwd.close();
await daemon.close();
echo.close();
console.log("PASS — forwardTunnel exposed a local port that reaches the tunneled endpoint");
process.exit(0);
