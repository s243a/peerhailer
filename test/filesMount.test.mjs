/**
 * The WebDAV mount bridge, driven with real WebDAV verbs over fetch against a real
 * local share (the `call` proxies straight to the files plugin, no daemon needed).
 * Proves an external tool or the OS could mount it: OPTIONS advertises DAV,
 * PROPFIND lists, GET reads, PUT writes, and the refusals stay refusals.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createFilesPlugin } from "../src/builtin/filesPlugin.js";
import { mountShare } from "../src/filesMount.js";
import { collectRoutes, REFUSE } from "../src/plugins.js";

function share(writable) {
  const root = mkdtempSync(join(tmpdir(), "mount-share-"));
  writeFileSync(join(root, "hello.txt"), "hi there");
  mkdirSync(join(root, "sub"));
  writeFileSync(join(root, "sub", "nested.txt"), "deep");
  const routes = collectRoutes([createFilesPlugin({ shares: { docs: { backend: "local", root, writable } } })], { log: () => {} });
  const call = async (path, body) => {
    const r = routes.get("POST " + path);
    if (!r) return { ok: false, error: "no route" };
    const out = await r.handler({ log: () => {}, caller: { publicKey: "K" }, body });
    if (out && out[REFUSE]) return { ok: false, error: out.reason };
    return { ok: true, response: out };
  };
  return { call, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

const dav = (url, method, opts = {}) => fetch(url, { method, ...opts, headers: { connection: "close", ...(opts.headers || {}) } });

test("OPTIONS advertises DAV; PROPFIND lists; GET reads; PUT writes back", async (t) => {
  const { call, cleanup } = share(true);
  const mount = await mountShare({ call, share: "docs" });
  t.after(async () => { await mount.close(); cleanup(); });

  const opt = await dav(mount.url, "OPTIONS");
  assert.equal(opt.status, 200);
  assert.match(opt.headers.get("dav") ?? "", /1/, "advertises DAV: 1");

  const pf = await dav(mount.url, "PROPFIND", { headers: { depth: "1" } });
  assert.equal(pf.status, 207);
  const xml = await pf.text();
  assert.match(xml, /multistatus/, "a WebDAV multistatus");
  assert.match(xml, /hello\.txt/, "lists the file");
  assert.match(xml, /sub/, "lists the subdirectory");
  assert.match(xml, /<D:collection\/>/, "the dir is a collection");

  const get = await dav(mount.url + "hello.txt", "GET");
  assert.equal(get.status, 200);
  assert.equal(await get.text(), "hi there");

  const put = await dav(mount.url + "made.txt", "PUT", { body: "written over dav" });
  assert.equal(put.status, 201, "PUT creates the file");
  const back = await dav(mount.url + "made.txt", "GET");
  assert.equal(await back.text(), "written over dav");

  // PROPFIND Depth 0 on a file carries its length.
  const pf0 = await dav(mount.url + "hello.txt", "PROPFIND", { headers: { depth: "0" } });
  assert.match(await pf0.text(), /<D:getcontentlength>8<\/D:getcontentlength>/);
});

test("a read-only share refuses PUT with 403; unsupported verbs say 501", async (t) => {
  const { call, cleanup } = share(false);
  const mount = await mountShare({ call, share: "docs" });
  t.after(async () => { await mount.close(); cleanup(); });

  const put = await dav(mount.url + "nope.txt", "PUT", { body: "x" });
  assert.equal(put.status, 403, "read-only share refuses the write");

  const del = await dav(mount.url + "hello.txt", "DELETE");
  assert.equal(del.status, 501, "DELETE is honestly unsupported");

  // A traversal is refused upstream and surfaces, not served.
  const escape = await dav(mount.url + "../etc/passwd", "GET");
  assert.notEqual(escape.status, 200);
});

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import hailPlugin from "../src/builtin/hailPlugin.js";

test("the page mounts a peer's share and WebDAV works on the returned URL", async (t) => {
  const root = mkdtempSync(join(tmpdir(), "mount-e2e-"));
  writeFileSync(join(root, "shared.txt"), "over the fabric, over dav");
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const B = generateIdentity();
  const dirB = createDirectory({ self: { name: "bob", publicKey: B.publicKey } });
  dirB.useProfiles({ f: { name: "f", allows: ["hail", "files:docs"] } });
  const daemonB = createDaemon({ directory: dirB, identity: B, plugins: [hailPlugin, createFilesPlugin({ shares: { docs: { backend: "local", root } } })] });
  const hailB = await daemonB.listenHail({ port: 0, hosts: ["127.0.0.1"], tls: true });

  const A = generateIdentity();
  const dirA = createDirectory({ self: { name: "alice", publicKey: A.publicKey } });
  dirA.admit({ name: "bob", publicKey: B.publicKey, addresses: [{ value: `https://127.0.0.1:${hailB[0].port}` }] });
  dirB.admit({ name: "alice", publicKey: A.publicKey }, { profile: "f" });
  const daemonA = createDaemon({ directory: dirA, identity: A, plugins: [hailPlugin] });
  const ctrlA = await daemonA.listen({ port: 0 });
  t.after(async () => { await daemonA.close(); await daemonB.close(); });

  const started = await fetch(`http://127.0.0.1:${ctrlA.port}/api/files/mount`, {
    method: "POST", headers: { "content-type": "application/json", connection: "close" }, body: JSON.stringify({ peer: "bob", share: "docs" }),
  }).then((r) => r.json());
  assert.match(started.url ?? "", /^http:\/\/127\.0\.0\.1:\d+\/$/, "a loopback mount URL");

  const got = await fetch(started.url + "shared.txt", { headers: { connection: "close" } });
  assert.equal(await got.text(), "over the fabric, over dav", "reading the peer's file through the WebDAV mount");

  const listed = await fetch(`http://127.0.0.1:${ctrlA.port}/api/files/mounts`, { headers: { connection: "close" } }).then((r) => r.json());
  assert.equal(listed.mounts.length, 1);

  const stopped = await fetch(`http://127.0.0.1:${ctrlA.port}/api/files/mount/stop`, {
    method: "POST", headers: { "content-type": "application/json", connection: "close" }, body: JSON.stringify({ mountId: started.mountId }),
  }).then((r) => r.json());
  assert.equal(stopped.stopped, true, "the mount is torn down");
});
