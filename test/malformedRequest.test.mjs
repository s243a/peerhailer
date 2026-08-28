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
