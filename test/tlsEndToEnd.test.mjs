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
import tls from "node:tls";
import { request as httpsRequest } from "node:https";
import { X509Certificate } from "node:crypto";
import { selfSignedCert } from "../src/cert.js";
import { signPayload } from "../src/identity.js";

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
    const as = { name: "caller", publicKey: caller.publicKey, privateKey: caller.privateKey };
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

test("mutual TLS is required: a caller presenting no client cert is refused", async () => {
  const me = generateIdentity();
  const caller = generateIdentity();
  const directory = createDirectory({ self: { name: "target", publicKey: me.publicKey } });
  directory.useProfiles({ sysadmin: { name: "sysadmin", allows: ["hail", "shell:sh"] } });
  directory.admit({ name: "caller", publicKey: caller.publicKey, profile: "sysadmin" });
  const shell = createShellPlugin({ shells: { sh: "sh" } });
  const daemon = createDaemon({ directory, identity: me, plugins: [hailPlugin, shell] });
  const bound = await daemon.listenHail({ port: 0, hosts: ["127.0.0.1"], tls: true });
  try {
    const record = { name: "target", addresses: [{ value: `https://127.0.0.1:${bound[0].port}` }], publicKey: me.publicKey };
    // `as` omits publicKey, so callPeer sends a valid signed hail but NO client
    // cert. The server pins the server side fine, but requires the client cert.
    const opened = await callPeer(record, "/shell/sh/open", {}, { as: { name: "caller", privateKey: caller.privateKey } });
    assert.equal(opened.ok, false, "a valid hail over TLS without the client cert is refused");
  } finally {
    shell.stop();
    await daemon.close();
  }
});

test("a provided cert is served, and mutual TLS is off for it (CA/browser clients)", async () => {
  const me = generateIdentity();
  const caller = generateIdentity();
  // The "provided" cert (a real / Let's Encrypt one in practice) — here a
  // separate self-signed cert standing in for one a CA issued.
  const provided = selfSignedCert(generateIdentity(), { cn: "example.com" });
  const directory = createDirectory({ self: { name: "target", publicKey: me.publicKey } });
  directory.useProfiles({ p: { name: "p", allows: ["hail"] } });
  directory.admit({ name: "caller", publicKey: caller.publicKey, profile: "p" });
  const daemon = createDaemon({ directory, identity: me, plugins: [hailPlugin] });
  const bound = await daemon.listenHail({ port: 0, hosts: ["127.0.0.1"], tls: true, cert: provided.cert, key: provided.key });
  try {
    // 1. The listener serves the *provided* cert, not the identity's self-signed one.
    const served = await new Promise((resolve, reject) => {
      const c = tls.connect({ host: "127.0.0.1", port: bound[0].port, rejectUnauthorized: false });
      c.once("secureConnect", () => { resolve(c.getPeerCertificate(true).raw.toString("base64")); c.destroy(); });
      c.once("error", reject);
    });
    assert.equal(served, new X509Certificate(provided.cert).raw.toString("base64"), "the provided cert is served");

    // 2. mTLS is off: a signed hail with NO client cert is accepted (a browser could not present one).
    const from = { name: "caller", at: Date.now() };
    const payload = JSON.stringify({ from, signature: signPayload(from, caller.privateKey) });
    const status = await new Promise((resolve, reject) => {
      const req = httpsRequest(
        { hostname: "127.0.0.1", port: bound[0].port, path: "/hail", method: "POST", headers: { "content-type": "application/json" }, rejectUnauthorized: false, agent: false },
        (r) => { r.resume(); resolve(r.statusCode); },
      );
      req.on("error", reject);
      req.end(payload);
    });
    assert.equal(status, 200, "an authenticated hail without a client cert is accepted — no mutual TLS on a provided-cert listener");
  } finally {
    await daemon.close();
  }
});
