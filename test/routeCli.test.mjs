/**
 * `hail route` subcommands, run as a person runs them, against a live daemon. Unlike
 * `hail seal` (Tier-0, in the state file), a routed destination's Tier-1 key lives in the
 * running daemon's memory, so these commands POST to its control API. This drives the real
 * CLI process (bin/hail.js) against an in-process daemon: status → approve → status.
 */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import { keyId } from "../src/routeManifest.js";
import { signRecord } from "../src/peerRecord.js";
import { createRoutedKeyStore } from "../src/routedKeyStore.js";
import { createRoutePlugin } from "../src/builtin/routePlugin.js";

const run = promisify(execFile);
const CLI = fileURLToPath(new URL("../bin/hail.js", import.meta.url));

test("hail route status/approve drive the live daemon's routed key store", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "peerhailer-route-cli-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const state = join(dir, "directory.json");

  // A daemon holding a PENDING discovered key for `peer`, as a probe would have learned.
  const self = generateIdentity();
  const peer = generateIdentity();
  const store = createRoutedKeyStore();
  store.observe(keyId(peer.publicKey), signRecord(
    { name: "peer", publicKey: peer.publicKey, sealPublicKey: peer.sealPublicKey, addresses: [], lastSeen: null },
    peer.privateKey,
  ));
  const directory = createDirectory({ self: { name: "self", publicKey: self.publicKey } });
  const route = createRoutePlugin({
    self: self.publicKey, privateKey: self.privateKey, selfRecord: () => directory.self,
    authorizeOrigin: () => true, neighbors: () => [], forward: async () => ({ delivered: false, spent: 0 }),
    deliver: () => ({ received: true }), routedKeyStore: store, tier0Seal: () => ({ state: "unverified", key: null }),
  });
  const daemon = createDaemon({ directory, identity: self, plugins: [route] });
  const { port } = await daemon.listen({ port: 0 });
  t.after(() => daemon.close());

  const destFile = join(dir, "peer.pem");
  writeFileSync(destFile, peer.publicKey);
  const control = `http://127.0.0.1:${port}`;
  const hail = (args) => run(process.execPath, [CLI, "--state", state, "route", ...args, "--dest-file", destFile, "--control", control])
    .then((r) => r.stdout + r.stderr, (e) => `${e.stdout ?? ""}${e.stderr ?? ""}`);

  // Pending before approval.
  assert.match(await hail(["status"]), /record-carried.*pending/s);
  // Approve, then it reads as approved.
  assert.match(await hail(["approve"]), /approved routed sealing key/);
  assert.match(await hail(["status"]), /record-approved.*APPROVED/s);
});

test("hail route discard clears a conflict and prints the recovery next-steps; usage lists it", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "peerhailer-route-discard-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const state = join(dir, "directory.json");

  // A daemon holding a sticky CONFLICT for `peer` (two differing sealing keys seen).
  const self = generateIdentity();
  const peer = generateIdentity();
  const store = createRoutedKeyStore();
  const peerId = keyId(peer.publicKey);
  const rec = (sealPublicKey) => signRecord(
    { name: "peer", publicKey: peer.publicKey, sealPublicKey, addresses: [], lastSeen: null },
    peer.privateKey,
  );
  store.observe(peerId, rec(peer.sealPublicKey));
  store.observe(peerId, rec(generateIdentity().sealPublicKey));
  assert.equal(store.recordState(peerId), "record-conflict");

  const directory = createDirectory({ self: { name: "self", publicKey: self.publicKey } });
  const route = createRoutePlugin({
    self: self.publicKey, privateKey: self.privateKey, selfRecord: () => directory.self,
    authorizeOrigin: () => true, neighbors: () => [], forward: async () => ({ delivered: false, spent: 0 }),
    deliver: () => ({ received: true }), routedKeyStore: store, tier0Seal: () => ({ state: "unverified", key: null }),
  });
  const daemon = createDaemon({ directory, identity: self, plugins: [route] });
  const { port } = await daemon.listen({ port: 0 });
  t.after(() => daemon.close());

  const destFile = join(dir, "peer.pem");
  writeFileSync(destFile, peer.publicKey);
  const control = `http://127.0.0.1:${port}`;
  const hail = (args) => run(process.execPath, [CLI, "--state", state, "route", ...args, "--dest-file", destFile, "--control", control])
    .then((r) => r.stdout + r.stderr, (e) => `${e.stdout ?? ""}${e.stderr ?? ""}`);

  // A conflict refuses to seal; discard clears it and spells out the recovery script.
  assert.match(await hail(["status"]), /record-conflict.*CONFLICT/s);
  const out = await hail(["discard"]);
  assert.match(out, /discarded \(record-conflict\)/);
  assert.match(out, /hail route discover/);
  assert.match(out, /verify the fingerprint/);
  assert.match(out, /hail route approve/);
  assert.equal(store.recordState(peerId), "none", "the daemon's store was cleared");
  // The usage string advertises discard alongside the other route actions.
  assert.match(await hail(["bogus"]), /discover\|status\|approve\|discard\|send/);
});

test("hail route reports a clear error when the daemon control API is unreachable", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "peerhailer-route-cli-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const state = join(dir, "directory.json");
  const destFile = join(dir, "peer.pem");
  writeFileSync(destFile, generateIdentity().publicKey);

  // Nothing listening on this port: a clean, actionable message, not a stack trace.
  const out = await run(process.execPath, [CLI, "--state", state, "route", "status", "--dest-file", destFile, "--control", "http://127.0.0.1:9"])
    .then((r) => r.stdout + r.stderr, (e) => `${e.stdout ?? ""}${e.stderr ?? ""}`);
  assert.match(out, /could not reach the daemon control API/);
  assert.match(out, /--ui/);
});

test("hail forget writes a durable identity tombstone into directory.json (F1)", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "peerhailer-forget-tombstone-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const state = join(dir, "directory.json");

  // Admit a peer with a real key, no daemon in sight — the pure CLI path.
  const peer = generateIdentity();
  const keyFile = join(dir, "peer.pem");
  writeFileSync(keyFile, peer.publicKey);
  const cli = (...args) => run(process.execPath, [CLI, "--state", state, ...args]).then((r) => r.stdout + r.stderr);
  await cli("add", "peer", "--key-file", keyFile);
  await cli("forget", "peer");

  const stored = JSON.parse(readFileSync(state, "utf8"));
  assert.ok(Array.isArray(stored.tombstones), "directory.json carries a tombstones array");
  assert.equal(stored.tombstones.length, 1);
  assert.equal(stored.tombstones[0].keyId, keyId(peer.publicKey), "the forgotten identity's keyId is tombstoned");
  assert.equal(stored.tombstones[0].reason, "forget");
});
