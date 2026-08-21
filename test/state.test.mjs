/**
 * Two writers, one file.
 *
 * The daemon persists what the page did; a person persists what they typed.
 * Both write the whole directory, so the failure to prevent is the quiet one:
 * a change that lands and then disappears with nothing to say where it went.
 */
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { createDirectory } from "../src/directory.js";
import { MAX_ADDRESSES } from "../src/peerRecord.js";
import { defaultStatePath, loadState, saveState, updateState, withStateLock } from "../src/state.js";

const scratch = () => join(mkdtempSync(join(tmpdir(), "ph-state-")), "dir.json");

test("a change is applied to what is on disk now", () => {
  const path = scratch();
  saveState({ admitted: [{ name: "alpha" }], plugins: ["./p.js"] }, path);

  // Somebody else writes between our load and our save.
  const stale = loadState(path);
  saveState({ ...stale, admitted: [{ name: "alpha" }, { name: "beta" }] }, path);

  updateState(path, (onDisk) => ({
    ...onDisk,
    admitted: [...onDisk.admitted, { name: "gamma" }],
  }));

  const names = loadState(path).admitted.map((peer) => peer.name);
  assert.deepEqual(names, ["alpha", "beta", "gamma"], "beta must survive");
});

test("keys nobody touched are left alone", () => {
  const path = scratch();
  saveState({ admitted: [], plugins: ["./tunnel.js"], trust: { model: "direct" } }, path);

  updateState(path, (onDisk) => ({ ...onDisk, admitted: [{ name: "sol" }] }));

  const after = loadState(path);
  assert.deepEqual(after.plugins, ["./tunnel.js"]);
  assert.equal(after.trust.model, "direct");
});

test("the lock is released even when a change throws", () => {
  const path = scratch();
  saveState({ admitted: [] }, path);

  assert.throws(() => withStateLock(path, () => { throw new Error("boom"); }), /boom/);
  // A lock held by a dead change would wedge every later write.
  let ran = false;
  withStateLock(path, () => { ran = true; });
  assert.equal(ran, true);
});

test("a stale lock is broken rather than waited on forever", () => {
  const path = scratch();
  saveState({ admitted: [] }, path);
  // A process that died holding the lock must not leave the tool broken until
  // somebody finds a file they have never heard of.
  writeFileSync(`${path}.lock`, "");
  const oldTime = new Date(Date.now() - 60_000);
  utimesSync(`${path}.lock`, oldTime, oldTime);

  let ran = false;
  withStateLock(path, () => { ran = true; });
  assert.equal(ran, true);
});

test("an unreadable file costs the directory, not the write", () => {
  const path = scratch();
  writeFileSync(path, "{ not json", "utf8");

  updateState(path, (onDisk) => ({ ...onDisk, admitted: [{ name: "sol" }] }));
  assert.deepEqual(loadState(path).admitted.map((p) => p.name), ["sol"]);
});

test("a write leaves no partial file behind", () => {
  const path = scratch();
  saveState({ admitted: [{ name: "sol" }] }, path);
  // Written through a temporary and renamed, so a reader never sees half of it.
  assert.doesNotThrow(() => JSON.parse(readFileSync(path, "utf8")));
});

test("the state path follows each platform's convention", () => {
  // Windows keeps per-user application data in APPDATA; a dotted directory in
  // the profile root works and is not where anyone on that system would look.
  assert.match(defaultStatePath({ APPDATA: "C:/Users/sam/AppData/Roaming" }), /AppData/);
  assert.match(defaultStatePath({ XDG_CONFIG_HOME: "/home/sam/.config" }), /^\/home\/sam\/\.config\//);
  assert.match(defaultStatePath({ HOME: "/home/sam" }), /^\/home\/sam\/\.config\//);
  // An explicit override outranks all of it, which is how somebody puts the
  // key somewhere with an ACL they chose.
  assert.match(defaultStatePath({ PEERHAILER_HOME: "/srv/ph", APPDATA: "C:/x" }), /^\/srv\/ph\//);
});

test("addresses do not accumulate without bound", () => {
  // A laptop that joins many networks would otherwise keep one route per
  // network forever, and every one is tried before a peer is called
  // unreachable — an unbounded list turns a dead peer into a long wait.
  const directory = createDirectory({ self: { name: "here" }, now: () => 500 });
  directory.admit({ name: "laptop", addresses: [{ transport: "lan", value: "http://works:8787" }] });
  directory.markReachable("laptop", { transport: "lan", value: "http://works:8787" });

  for (let i = 0; i < 40; i += 1) {
    directory.admit({ name: "laptop", addresses: [{ transport: "lan", value: `http://10.0.${i}.5:8787` }] });
  }

  const peer = directory.get("laptop");
  assert.ok(peer.addresses.length <= MAX_ADDRESSES);
  // What has worked is never dropped for something that never has.
  assert.equal(peer.addresses[0].value, "http://works:8787");
});
