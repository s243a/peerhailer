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
import { MAX_ADDRESSES, orderForDialing, presumedLifetime } from "../src/peerRecord.js";
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

test("a durable write is fsync'd, renamed, and readable (R3)", () => {
  // The restricting path (a conflict void, a forget's startup reconcile) writes with
  // `durable: true` so the contents survive power loss and are not reordered against a later
  // write. The observable contract here is simply: it writes, renames atomically, and reads back.
  const path = scratch();
  const payload = { entries: [{ id: "x", gen: 7 }], routeGenApplied: 7 };
  assert.equal(saveState(payload, path, { durable: true }), path);
  assert.deepEqual(loadState(path), payload, "the durable write is readable after fsync+rename");
  // The temp file must not linger — rename consumed it.
  assert.throws(() => readFileSync(`${path}.tmp-${process.pid}`), /ENOENT/);
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

test("eviction keeps diversity, not just recency", () => {
  // A machine that moves between networks is reachable at each, alternately
  // and indefinitely. Evicting the route it is not using right now guarantees a
  // slow rediscovery every time it moves back — and an overlay address is the
  // one that must survive, since it is how the peer is reached from elsewhere.
  const directory = createDirectory({ self: { name: "here" }, now: () => 500 });
  directory.admit({
    name: "laptop",
    addresses: [{ transport: "tailscale", value: "http://100.64.1.9:8787" }],
  });
  directory.markReachable("laptop", { transport: "tailscale", value: "http://100.64.1.9:8787" });

  for (let i = 0; i < 40; i += 1) {
    directory.admit({ name: "laptop", addresses: [{ transport: "lan", value: `http://10.0.${i}.5:8787` }] });
  }

  const held = directory.get("laptop").addresses;
  assert.ok(
    held.some((address) => address.transport === "tailscale"),
    "a busy network must not crowd out the only route from elsewhere",
  );
  const lanCount = held.filter((address) => address.transport === "lan").length;
  assert.ok(lanCount <= 3, "and one transport cannot fill the list");
});

test("an address's presumed lifetime follows what it is, not what it is labelled", () => {
  const day = 24 * 60 * 60_000;
  // DHCP lives in RFC1918, so those turn over daily.
  assert.equal(presumedLifetime({ transport: "lan", value: "http://192.168.1.5:8787" }), day);
  // Tailscale's 100.64/10 looks public and is assigned per node, so a mislabelled
  // one is still recognised — the shape is better evidence than the label.
  assert.equal(presumedLifetime({ transport: "lan", value: "http://100.64.1.9:8787" }), 30 * day);
  assert.equal(presumedLifetime({ transport: "tailscale", value: "http://x:1" }), 30 * day);
  // And a peer that knows its own network is believed, since it can only
  // mislead us into trying a route in the wrong order.
  assert.equal(presumedLifetime({ transport: "lan", value: "http://203.0.113.5:1", stability: "stable" }), 30 * day);
});

test("after a machine moves, today's report is dialled before last week's success", () => {
  const now = Date.now();
  const day = 24 * 60 * 60_000;
  const ordered = orderForDialing(
    [
      { transport: "lan", value: "http://old-home:8787", lastOk: now - 5 * day, learnedAt: null },
      { transport: "lan", value: "http://reported-today:8787", lastOk: null, learnedAt: now - 3_600_000 },
    ],
    now,
  );
  assert.equal(ordered[0].value, "http://reported-today:8787");
});

test("but storage keeps the route that worked, whatever is reported", () => {
  // Dialing order and eviction order are different questions. A burst of fresh
  // reports must not evict the one address known to reach this peer.
  const directory = createDirectory({ self: { name: "here" }, now: () => Date.now() });
  directory.admit({ name: "laptop", addresses: [{ transport: "lan", value: "http://works:8787" }] });
  directory.markReachable("laptop", { transport: "lan", value: "http://works:8787" });

  for (let i = 0; i < 20; i += 1) {
    directory.admit({ name: "laptop", addresses: [{ transport: "lan", value: `http://fresh-${i}:8787` }] });
  }

  const held = directory.get("laptop").addresses;
  assert.equal(held[0].value, "http://works:8787", "what has worked is never evicted for what has not");
});

test("a change made while a daemon runs is not undone when it exits", () => {
  const dir = mkdtempSync(join(tmpdir(), "peerhailer-daemon-"));
  const statePath = join(dir, "directory.json");
  writeFileSync(statePath, JSON.stringify({ self: { name: "host-a" }, admitted: [] }));

  // The picture a daemon holds from startup.
  const asDaemonStarted = JSON.parse(readFileSync(statePath, "utf8"));

  // A second terminal admits a peer while it runs.
  updateState(statePath, (onDisk) => ({
    ...onDisk,
    admitted: [{ name: "late-peer", publicKey: null, addresses: [], lastSeen: null, profile: "trusted" }],
  }));

  // What the old shutdown did: write that startup picture back over it. The
  // lock made the write atomic, which is not the same as making it correct.
  const afterNaiveShutdown = updateState(statePath, (onDisk) => ({ ...onDisk, ...asDaemonStarted }));
  assert.equal(afterNaiveShutdown.admitted.length, 0, "which is why the daemon no longer persists on exit");
});

test("loadState coerces a non-object file to {} so a caller's field access cannot throw", () => {
  // A corrupt or hand-edited state/sidecar file might parse to a non-object. Each must load
  // as an empty object, never a value whose `.field` access throws at daemon startup.
  for (const raw of ["null", "[]", '"a string"', "42", "not json{"]) {
    const path = scratch();
    writeFileSync(path, raw, "utf8");
    const state = loadState(path);
    assert.deepEqual(state, {}, `"${raw}" loads as {}`);
    assert.equal(state.entries, undefined, `"${raw}".entries is a safe undefined, not a throw`);
  }
});
