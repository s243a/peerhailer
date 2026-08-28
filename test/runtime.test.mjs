/**
 * `buildRuntime` is the single builder for the daemon's runtime (plugins +
 * merged profiles) from state. Startup and reload both call it, so these pin the
 * invariants that keep the two from drifting — the divergence a prior review
 * found (different plugin order after the first reload; command-history dropped).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { buildRuntime } from "../src/runtime.js";
import { generateIdentity } from "../src/identity.js";
import { createDiagnostics } from "../src/diagnostics.js";

const deps = () => ({ identity: generateIdentity(), diagnostics: createDiagnostics(), port: 8787, routeDeps: () => ({}), flags: {}, log: () => {} });
const names = (rt) => rt.plugins.map((p) => p.name);

test("deterministic: the same state yields the same plugin names in the same order", async () => {
  const state = { tunnels: { t1: "addr" }, commands: { c1: {} }, shares: { s1: "/tmp" } };
  const d = deps();
  const a = await buildRuntime(state, d);
  const b = await buildRuntime(state, d);
  assert.deepEqual(names(a), names(b), "no order or membership drift between two builds");
  // The canonical (startup) order: hail, diagnostics, tunnel, ..., command last of the bundled.
  assert.equal(names(a)[0], "hail");
  assert.ok(names(a).indexOf("tunnel") < names(a).indexOf("command"), "tunnel before command (startup order)");
});

test("profiles: plugin suggestions overlaid by stored profiles (operator wins)", async () => {
  const state = { profiles: { operator: { name: "operator", allows: ["hail"] } } };
  const rt = await buildRuntime(state, deps());
  // diagnostics suggests `operator`; the stored override wins.
  assert.deepEqual(rt.profiles.operator.allows, ["hail"], "stored profile overrides the plugin suggestion");
});

test("flags can only enable: --chat with no state.chat still builds the chat plugin", async () => {
  const withFlag = await buildRuntime({}, { ...deps(), flags: { chat: true } });
  assert.ok(withFlag.plugins.some((p) => p.name === "chat"), "flag enables chat even when state doesn't");
  const fromState = await buildRuntime({ chat: true }, deps());
  assert.ok(fromState.plugins.some((p) => p.name === "chat"), "state enables chat even without the flag");
  const neither = await buildRuntime({}, deps());
  assert.ok(!neither.plugins.some((p) => p.name === "chat"), "off when neither says so");
});

test("a plugin-changing state changes the built set", async () => {
  const d = deps();
  const before = names(await buildRuntime({}, d));
  const after = names(await buildRuntime({ tunnels: { t1: "addr" } }, d));
  assert.ok(!before.includes("tunnel") && after.includes("tunnel"), "adding a tunnel adds the tunnel plugin");
});
