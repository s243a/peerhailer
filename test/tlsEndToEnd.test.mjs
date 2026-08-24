/**
 * Pinned TLS, end to end.
 *
 * The point of TLS in this project: a shell (or tunnel) runs on a plaintext
 * LAN because the handshake makes the arrival encrypted, and the caller knows it
 * reached the real peer because it pins the server's key. Both proven here over
 * a real TLS listener — including that a server presenting the wrong key is
 * refused before the signed hail leaves.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import hailPlugin from "../src/builtin/hailPlugin.js";
import { createShellPlugin } from "../src/builtin/shellPlugin.js";
import { callPeer } from "../src/hail.js";
import { execShell } from "../src/shellClient.js";

test("a shell serves over pinned TLS, and the caller pins the server it holds", async () => {
  const me = generateIdentity();
  const caller = generateIdentity();
  const directory = createDirectory({ self: { name: "target", publicKey: me.publicKey } });
  directory.useProfiles({ sysadmin: { name: "sysadmin", allows: ["hail", "shell:sh"] } });
  directory.admit({ name: "caller", publicKey: caller.publicKey, profile: "sysadmin" });

  const shell = createShellPlugin({ shells: { sh: "sh" } });
  const daemon = createDaemon({ directory, identity: me, plugins: [hailPlugin, shell] });
  const bound = await daemon.listenHail({ port: 0, hosts: ["127.0.0.1"], tls: true });
  try {
    // A plaintext loopback that TLS made an encrypted arrival, dialed over https.
    const record = { name: "target", addresses: [{ value: `https://127.0.0.1:${bound[0].port}` }], publicKey: me.publicKey };
    const as = { name: "caller", privateKey: caller.privateKey };
    const result = await execShell((path, body) => callPeer(record, path, body, { as }), "sh", "echo tls-works");
    assert.equal(result.ok, true, result.ok ? "" : result.error);
    assert.match(result.output, /tls-works/, "a real shell ran over the pinned TLS channel");
  } finally {
    shell.stop();
    await daemon.close();
  }
});

test("the caller refuses a server whose key it does not hold — before the hail leaves", async () => {
  const me = generateIdentity();
  const impostor = generateIdentity();
  const directory = createDirectory({ self: { name: "target", publicKey: me.publicKey } });
  const daemon = createDaemon({ directory, identity: me, plugins: [hailPlugin] });
  const bound = await daemon.listenHail({ port: 0, hosts: ["127.0.0.1"], tls: true });
  try {
    // The record pins `impostor`, but the server presents `me`'s cert. The pin
    // must fail during the handshake, so the signed body is never sent.
    const record = { name: "target", addresses: [{ value: `https://127.0.0.1:${bound[0].port}` }], publicKey: impostor.publicKey };
    const r = await callPeer(record, "/hail", {}, { as: { name: "x", privateKey: generateIdentity().privateKey } });
    assert.equal(r.ok, false, "a server presenting the wrong key is refused");
    assert.match(r.error, /pin failed|no address answered/i);
  } finally {
    await daemon.close();
  }
});

test("callPeer refuses a TLS address for a peer it holds no key to pin", async () => {
  // No publicKey in the record → nothing to pin → the signed hail is not sent.
  const r = await callPeer(
    { name: "target", addresses: [{ value: "https://127.0.0.1:1" }] },
    "/hail",
    {},
    { as: { name: "x", privateKey: generateIdentity().privateKey } },
  );
  assert.equal(r.ok, false);
  assert.match(r.error, /no key held to pin/i);
});
