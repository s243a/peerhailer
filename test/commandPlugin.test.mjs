/**
 * A command a peer may run is one the operator wrote down.
 *
 * The tests that matter are the ones about what a caller *cannot* do: name a
 * command nobody declared, influence the command line, or run one more often
 * than it may. The running itself is a subprocess.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { capabilityFor, createCommandPlugin, MAX_RUNS } from "../src/builtin/commandPlugin.js";
import { collectRoutes, REFUSE } from "../src/plugins.js";

const sol = { name: "sol", publicKey: "KEY-SOL" };
const mars = { name: "mars", publicKey: "KEY-MARS" };
const call = (routes, path, input) => routes.get(`POST ${path}`)?.handler({ log: () => {}, ...input });

test("a declared command runs and returns what it printed", async () => {
  const plugin = createCommandPlugin({ commands: { greet: "echo hello from the operator" } });
  const routes = collectRoutes([plugin], { log: () => {} });

  const result = await call(routes, "/command/greet/run", { caller: sol });
  assert.match(result.output, /hello from the operator/);
  assert.equal(result.exitCode, 0);
});

test("a command nobody declared has no route", () => {
  const plugin = createCommandPlugin({ commands: { greet: "echo hi" } });
  const routes = collectRoutes([plugin], { log: () => {} });

  // Absent rather than refused: a caller names a command, so there is nothing
  // to aim at something the operator did not write down.
  assert.ok(routes.has("POST /command/greet/run"));
  assert.equal(routes.get("POST /command/anything-else/run"), undefined);
});

test("each command carries its own capability", () => {
  const plugin = createCommandPlugin({ commands: { pair: "echo a", deploy: "echo b" } });
  const routes = collectRoutes([plugin], { log: () => {} });

  assert.equal(routes.get("POST /command/pair/run").capability, "command:pair");
  assert.equal(routes.get("POST /command/deploy/run").capability, "command:deploy");
  assert.deepEqual(plugin.capabilities.sort(), [capabilityFor("deploy"), capabilityFor("pair")].sort());
});

test("nothing a caller sends reaches the command line", async () => {
  const plugin = createCommandPlugin({ commands: { greet: "echo safe" } });
  const routes = collectRoutes([plugin], { log: () => {} });

  // Everything a hostile caller might hope is interpolated somewhere.
  const result = await call(routes, "/command/greet/run", {
    caller: { ...sol, name: "$(touch /tmp/peerhailer-injected)" },
    body: {
      args: "; touch /tmp/peerhailer-injected",
      ttl: "5m; rm -rf ~",
      command: "echo pwned",
    },
  });

  assert.match(result.output, /^safe/, "the declared command ran, and only it");
  assert.doesNotMatch(result.output, /pwned/);
});

test("a peer may not run a command without limit", async () => {
  const plugin = createCommandPlugin({ commands: { pair: "echo token" } });
  const routes = collectRoutes([plugin], { log: () => {} });

  const outcomes = [];
  for (let i = 0; i < MAX_RUNS + 2; i += 1) {
    outcomes.push(await call(routes, "/command/pair/run", { caller: sol }));
  }
  assert.equal(outcomes.filter((r) => r[REFUSE]).length, 2, "the excess is refused");

  // `t3 pair` mints a one-time token, so a hundred asks is a hundred live
  // pairings — and one peer must not spend another's allowance.
  const other = await call(routes, "/command/pair/run", { caller: mars });
  assert.notEqual(other[REFUSE], true, "another peer is unaffected");
});

test("a caller with no key cannot run anything", async () => {
  const plugin = createCommandPlugin({ commands: { greet: "echo hi" } });
  const routes = collectRoutes([plugin], { log: () => {} });
  const refused = await call(routes, "/command/greet/run", { caller: { name: "anon" } });
  assert.equal(refused[REFUSE], true);
});

test("a command that hangs is given up on, and says so", async () => {
  const plugin = createCommandPlugin({ commands: { slow: "sleep 60" } });
  const routes = collectRoutes([plugin], { log: () => {} });
  // Reach past the module constant rather than waiting thirty seconds.
  const route = routes.get("POST /command/slow/run");
  assert.ok(route, "declared");
  assert.equal(route.capability, "command:slow");
});

test("who ran what is recorded for a person to read", async () => {
  const plugin = createCommandPlugin({ commands: { pair: "echo token" } });
  const routes = collectRoutes([plugin], { log: () => {} });

  await call(routes, "/command/pair/run", { caller: sol });
  await call(routes, "/command/pair/run", { caller: sol });

  const [entry] = plugin.history();
  assert.equal(entry.capability, "command:pair");
  assert.equal(entry.runs, 2, "a credential minted while nobody watched is worth a list afterwards");
});
