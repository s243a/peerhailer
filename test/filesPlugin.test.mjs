/**
 * The files plugin. The tests that matter are the refusals: a path that climbs
 * out of the share, a symlink that points out of it, a write to a read-only
 * share. The carrying is the easy part; the containment is the point.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createFilesPlugin, safeSegments, MAX_FILE } from "../src/builtin/filesPlugin.js";
import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import hailPlugin from "../src/builtin/hailPlugin.js";
import { callPeer } from "../src/hail.js";
import { listFiles, getFile, putFile } from "../src/filesClient.js";
import { collectRoutes, REFUSE } from "../src/plugins.js";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "files-share-"));
  writeFileSync(join(root, "hello.txt"), "hi there");
  mkdirSync(join(root, "sub"));
  writeFileSync(join(root, "sub", "nested.txt"), "deep");
  const outside = mkdtempSync(join(tmpdir(), "files-outside-"));
  writeFileSync(join(outside, "secret.txt"), "SECRET");
  symlinkSync(outside, join(root, "escape")); // a symlink pointing out of the share
  return { root, outside, cleanup: () => { rmSync(root, { recursive: true, force: true }); rmSync(outside, { recursive: true, force: true }); } };
}

const caller = { name: "sol", publicKey: "KEY-SOL" };
const hit = (routes, path, body) => routes.get(`POST ${path}`).handler({ log: () => {}, caller, body });

test("safeSegments refuses climbing, drive letters and ~; keeps clean relatives", () => {
  assert.equal(safeSegments("../etc"), null);
  assert.equal(safeSegments("a/../../b"), null);
  assert.equal(safeSegments("C:/win"), null);
  assert.equal(safeSegments("~/x"), null);
  assert.deepEqual(safeSegments("sub/nested.txt"), ["sub", "nested.txt"]);
  assert.deepEqual(safeSegments("/etc/passwd"), ["etc", "passwd"]); // neutralised to root-relative
  assert.deepEqual(safeSegments(""), []);
});

test("local share lists, reads, and stats within the root", async () => {
  const { root, cleanup } = fixture();
  const routes = collectRoutes([createFilesPlugin({ shares: { docs: { backend: "local", root } } })], { log: () => {} });
  try {
    const { entries } = await hit(routes, "/files/docs/list", { path: "" });
    const names = entries.map((e) => e.name).sort();
    assert.ok(names.includes("hello.txt") && names.includes("sub"), "lists the share contents");
    const hello = entries.find((e) => e.name === "hello.txt");
    assert.equal(hello.type, "file");
    assert.equal(hello.size, 8);

    const got = await hit(routes, "/files/docs/get", { path: "hello.txt" });
    assert.equal(Buffer.from(got.data, "base64").toString(), "hi there");

    const nested = await hit(routes, "/files/docs/get", { path: "sub/nested.txt" });
    assert.equal(Buffer.from(nested.data, "base64").toString(), "deep");

    const st = await hit(routes, "/files/docs/stat", { path: "sub" });
    assert.equal(st.type, "dir");
  } finally { cleanup(); }
});

test("a path that climbs out of the root is refused, not served", async () => {
  const { root, outside, cleanup } = fixture();
  const routes = collectRoutes([createFilesPlugin({ shares: { docs: { backend: "local", root } } })], { log: () => {} });
  try {
    const climb = await hit(routes, "/files/docs/get", { path: "../" + outside.split("/").pop() + "/secret.txt" });
    assert.equal(climb[REFUSE], true, "a ../ path is refused");
  } finally { cleanup(); }
});

test("a symlink pointing out of the root cannot be read through", async () => {
  const { root, cleanup } = fixture();
  const routes = collectRoutes([createFilesPlugin({ shares: { docs: { backend: "local", root } } })], { log: () => {} });
  try {
    const through = await hit(routes, "/files/docs/get", { path: "escape/secret.txt" });
    assert.equal(through[REFUSE], true, "reading through an escaping symlink is refused");
  } finally { cleanup(); }
});

test("read-only by default; writable shares accept a put that then reads back", async () => {
  const { root, cleanup } = fixture();
  const ro = collectRoutes([createFilesPlugin({ shares: { docs: { backend: "local", root } } })], { log: () => {} });
  const rw = collectRoutes([createFilesPlugin({ shares: { drop: { backend: "local", root, writable: true } } })], { log: () => {} });
  try {
    const refused = await hit(ro, "/files/docs/put", { path: "new.txt", data: Buffer.from("nope").toString("base64") });
    assert.equal(refused[REFUSE], true, "put to a read-only share is refused");

    const put = await hit(rw, "/files/drop/put", { path: "made/here.txt", data: Buffer.from("written").toString("base64") });
    assert.equal(put.written, 7);
    const back = await hit(rw, "/files/drop/get", { path: "made/here.txt" });
    assert.equal(Buffer.from(back.data, "base64").toString(), "written");

    const escapePut = await hit(rw, "/files/drop/put", { path: "../pwned.txt", data: Buffer.from("x").toString("base64") });
    assert.equal(escapePut[REFUSE], true, "a write cannot escape the root either");
  } finally { cleanup(); }
});

test("put over the size cap is refused before touching disk", async () => {
  const { root, cleanup } = fixture();
  const routes = collectRoutes([createFilesPlugin({ shares: { drop: { backend: "local", root, writable: true } } })], { log: () => {} });
  try {
    const big = Buffer.alloc(MAX_FILE + 1).toString("base64");
    const res = await hit(routes, "/files/drop/put", { path: "big.bin", data: big });
    assert.match(res.error ?? "", /larger than/, "oversize put is rejected");
  } finally { cleanup(); }
});

test("http backend supports get but refuses list cleanly", async () => {
  const routes = collectRoutes([createFilesPlugin({ shares: { web: { backend: "http", base: "http://127.0.0.1:1/" } } })], { log: () => {} });
  const res = await hit(routes, "/files/web/list", { path: "" });
  assert.match(res.error ?? "", /does not support list/);
});

test("end to end: two daemons transfer a file through a writable share", async (t) => {
  const { root, cleanup } = fixture();
  t.after(cleanup);

  const B = generateIdentity();
  const dirB = createDirectory({ self: { name: "bob", publicKey: B.publicKey } });
  dirB.useProfiles({ f: { name: "f", allows: ["hail", "files:drop"] } });
  const daemonB = createDaemon({ directory: dirB, identity: B, plugins: [hailPlugin, createFilesPlugin({ shares: { drop: { backend: "local", root, writable: true } } })] });
  const hailB = await daemonB.listenHail({ port: 0, hosts: ["127.0.0.1"], tls: true });

  const A = generateIdentity();
  dirB.admit({ name: "alice", publicKey: A.publicKey }, { profile: "f" });
  const record = { name: "bob", addresses: [{ value: `https://127.0.0.1:${hailB[0].port}` }], publicKey: B.publicKey };
  const as = { name: "alice", publicKey: A.publicKey, privateKey: A.privateKey };
  const call = (path, body) => callPeer(record, path, body, { as });
  t.after(() => daemonB.close());

  const put = await putFile(call, "drop", "from-alice.txt", "hello over the fabric");
  assert.equal(put.ok, true, `put ok (${put.error ?? ""})`);
  assert.equal(put.written, 21);

  const listed = await listFiles(call, "drop", "");
  assert.ok((listed.response?.entries ?? []).some((e) => e.name === "from-alice.txt"), "the new file shows in a list");

  const got = await getFile(call, "drop", "from-alice.txt");
  assert.equal(got.ok, true, `get ok (${got.error ?? ""})`);
  assert.equal(got.buffer.toString(), "hello over the fabric");
});

test("the page's /api/files/browse proxies list/put/get to a peer's share", async (t) => {
  const { root, cleanup } = fixture();
  t.after(cleanup);

  // Bob serves a writable share; Alice runs a control door that proxies to him.
  const B = generateIdentity();
  const dirB = createDirectory({ self: { name: "bob", publicKey: B.publicKey } });
  dirB.useProfiles({ f: { name: "f", allows: ["hail", "files:drop"] } });
  const daemonB = createDaemon({ directory: dirB, identity: B, plugins: [hailPlugin, createFilesPlugin({ shares: { drop: { backend: "local", root, writable: true } } })] });
  const hailB = await daemonB.listenHail({ port: 0, hosts: ["127.0.0.1"], tls: true });

  const A = generateIdentity();
  const dirA = createDirectory({ self: { name: "alice", publicKey: A.publicKey } });
  dirA.admit({ name: "bob", publicKey: B.publicKey, addresses: [{ value: `https://127.0.0.1:${hailB[0].port}` }] });
  dirB.admit({ name: "alice", publicKey: A.publicKey }, { profile: "f" });
  const daemonA = createDaemon({ directory: dirA, identity: A, plugins: [hailPlugin] });
  const ctrlA = await daemonA.listen({ port: 0 });
  t.after(() => { daemonA.close(); daemonB.close(); });

  const browse = (body) =>
    fetch(`http://127.0.0.1:${ctrlA.port}/api/files/browse`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    }).then(async (r) => ({ status: r.status, json: await r.json() }));

  // Upload through the page, then it shows in a list, then download it back.
  const put = await browse({ peer: "bob", share: "drop", op: "put", path: "via-page.txt", data: Buffer.from("through the page").toString("base64") });
  assert.equal(put.status, 200, JSON.stringify(put.json));
  assert.equal(put.json.written, 16);

  const list = await browse({ peer: "bob", share: "drop", op: "list", path: "" });
  assert.ok(list.json.entries.some((e) => e.name === "via-page.txt"), "the upload appears in the listing");

  const get = await browse({ peer: "bob", share: "drop", op: "get", path: "via-page.txt" });
  assert.equal(Buffer.from(get.json.data, "base64").toString(), "through the page");

  // A bad share name is refused before it can become a route path.
  assert.equal((await browse({ peer: "bob", share: "../evil", op: "list" })).status, 400);
  // A traversal path is refused by bob's plugin and surfaces as a peer refusal.
  assert.equal((await browse({ peer: "bob", share: "drop", op: "get", path: "../../etc/passwd" })).status, 502);
});
