/**
 * Plugin resource lifecycle. `close()` must stop the plugins — shell/service/tunnel
 * hold child processes and tunnels that were otherwise orphaned on shutdown — after
 * the listeners are down, best-effort so one throwing stop() can't block the rest.
 * `reload()` must build the replacement route table before swapping, and stop the
 * replaced plugins only after the swap.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";

const daemonWith = (plugins) => {
  const id = generateIdentity();
  return createDaemon({ directory: createDirectory({ self: { name: "me", publicKey: id.publicKey } }), identity: id, plugins });
};
const tick = () => new Promise((r) => setImmediate(r));

test("close() stops the plugins (after the listeners), so their resources are not orphaned", async () => {
  const stopped = [];
  const daemon = daemonWith([{ name: "svc", routes: [], stop: () => stopped.push("svc") }]);
  await daemon.listen({ port: 0 });
  await daemon.close();
  assert.deepEqual(stopped, ["svc"], "the plugin's stop() ran on close");
});

test("close() is best-effort: a throwing stop() does not block the others", async () => {
  const stopped = [];
  const daemon = daemonWith([
    { name: "bad", routes: [], stop: () => { throw new Error("boom"); } },
    { name: "good", routes: [], stop: () => stopped.push("good") },
  ]);
  await daemon.listen({ port: 0 });
  await daemon.close(); // must resolve despite bad.stop throwing
  assert.deepEqual(stopped, ["good"], "the throwing stop() did not prevent the good one");
});

test("reload() swaps to the new plugins and stops the replaced ones", async () => {
  const stopped = [];
  const daemon = daemonWith([{ name: "old", routes: [], stop: () => stopped.push("old") }]);
  await daemon.listen({ port: 0 });
  const result = daemon.reload({ plugins: [{ name: "new", routes: [] }] });
  assert.ok(result, "reload returned");
  await tick(); // the teardown is fire-and-forget after the synchronous swap
  assert.deepEqual(stopped, ["old"], "the replaced plugin was stopped after the swap");
  await daemon.close();
});

test("reload() stops only retired plugins — an instance carried into the new set keeps serving", async () => {
  const stopped = [];
  const shared = { name: "shared", routes: [], stop: () => stopped.push("shared") };
  const daemon = daemonWith([shared, { name: "old", routes: [], stop: () => stopped.push("old") }]);
  await daemon.listen({ port: 0 });
  daemon.reload({ plugins: [shared, { name: "new", routes: [] }] }); // shared carried over
  await tick();
  assert.deepEqual(stopped, ["old"], "the retired plugin is stopped; the carried-over instance is not");
  await daemon.close(); // now shared IS stopped (it's the current set)
  assert.ok(stopped.includes("shared"), "the carried-over instance stops on close, once");
});
