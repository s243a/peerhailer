/**
 * The arrival door must survive a request-target that Node's HTTP parser accepts
 * but `new URL` rejects. Building the URL outside the handler's try turned such a
 * line into an unhandled rejection that crashed the whole daemon — an
 * unauthenticated remote crash reachable by anyone who can open a socket to a
 * hail (or --hail-on) listener. This drives a raw malformed line and asserts the
 * daemon answers it and stays up for the next request.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";

const raw = (port, requestLine) =>
  new Promise((resolve, reject) => {
    const s = net.connect(port, "127.0.0.1", () => s.write(requestLine + "\r\nHost: x\r\nConnection: close\r\n\r\n"));
    let buf = "";
    s.on("data", (d) => { buf += d; });
    s.on("end", () => resolve(buf));
    s.on("error", reject);
  });

/**
 * POST a raw body, optionally over-declaring its length (to trip the size guard).
 * `Host: 127.0.0.1` + `application/json` is what a same-origin page sends, so the
 * control API's cross-origin guard lets it through to the route under test.
 */
const rawPost = (port, path, body, { contentLength } = {}) =>
  new Promise((resolve, reject) => {
    const len = contentLength ?? Buffer.byteLength(body);
    const head = `POST ${path} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nContent-Type: application/json\r\nContent-Length: ${len}\r\nConnection: close\r\n\r\n`;
    const s = net.connect(port, "127.0.0.1", () => s.write(head + body));
    let buf = "";
    s.on("data", (d) => { buf += d; });
    s.on("end", () => resolve(buf));
    s.on("error", reject);
  });

test("a malformed request-target is answered, and the daemon stays up", async (t) => {
  const daemon = createDaemon({ directory: createDirectory({ self: { name: "a" } }), identity: generateIdentity(), plugins: [] });
  const { port } = await daemon.listen({ port: 0 });
  t.after(async () => { await daemon.close(); });

  // `new URL("//[", "http://localhost")` throws "Invalid URL"; before the fix this
  // crashed the process (an unhandled rejection). It must now get an HTTP reply.
  const bad = await raw(port, "GET //[ HTTP/1.1");
  assert.match(bad, /^HTTP\/1\.1 \d\d\d/, "the malformed request still gets an HTTP response");

  // The daemon survived: a following request is answered normally.
  const next = await raw(port, "GET /nope HTTP/1.1");
  assert.match(next, /^HTTP\/1\.1 \d\d\d/, "the server answers the next request");
});

test("the control API answers a malformed JSON body with 400 (not a blank 404)", async (t) => {
  const daemon = createDaemon({ directory: createDirectory({ self: { name: "a" } }), identity: generateIdentity(), plugins: [] });
  const { port } = await daemon.listen({ port: 0 });
  t.after(async () => { await daemon.close(); });

  // A script that sends broken JSON to a control endpoint used to get the same
  // blank 404 as a missing route — indistinguishable from "wrong URL".
  const res = await rawPost(port, "/api/block", "{ not json");
  assert.match(res, /^HTTP\/1\.1 400/, "malformed JSON is a 400");
  assert.match(res, /valid JSON/, "and the body says why");
});

test("the control API answers an over-declared body with 413", async (t) => {
  const daemon = createDaemon({ directory: createDirectory({ self: { name: "a" } }), identity: generateIdentity(), plugins: [] });
  const { port } = await daemon.listen({ port: 0 });
  t.after(async () => { await daemon.close(); });

  // Content-Length past the cap is refused before a byte is read — and answered,
  // not dropped, so the caller learns the limit exists.
  const res = await rawPost(port, "/api/block", "{}", { contentLength: 2_000_000 });
  assert.match(res, /^HTTP\/1\.1 413/, "an oversized body is a 413");
});

test("a peer-facing plugin route conceals a malformed body (404, not 400)", async (t) => {
  // requiresEncryptedArrival:false so the route is reached on a plaintext hail
  // listener; the malformed body is then refused *by concealment*, revealing no
  // more than an unmatched route would — the deliberate hail-scope posture.
  const echo = {
    name: "echo",
    routes: [{ method: "POST", path: "/echo", capability: "hail", requiresEncryptedArrival: false, handler: () => ({ ok: true }) }],
  };
  const daemon = createDaemon({ directory: createDirectory({ self: { name: "a" } }), identity: generateIdentity(), plugins: [echo] });
  const [{ port }] = await daemon.listenHail({ port: 0, hosts: ["127.0.0.1"], tls: false });
  t.after(async () => { await daemon.close(); });

  const res = await rawPost(port, "/echo", "{ not json");
  assert.doesNotMatch(res, /^HTTP\/1\.1 400/, "a hail plugin route does not leak a 400 for a bad body");
  assert.match(res, /^HTTP\/1\.1 404/, "it is answered like an unmatched route");
});
