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

import { loadState, saveState, updateState, withStateLock } from "../src/state.js";

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
