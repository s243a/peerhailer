/**
 * Plugins, and the one guarantee that makes loading one a small decision.
 *
 * A plugin route must be unreachable without authentication and the capability
 * it declared. Everything else here is about refusing malformed plugins loudly,
 * since a half-loaded one is how an ungated endpoint appears.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { collectProfiles, collectRoutes, loadPlugins, validatePlugin } from "../src/plugins.js";

const wellFormed = {
  name: "echo",
  capabilities: ["echo"],
  profiles: { echoer: { allows: ["hail", "echo"], description: "May echo." } },
  routes: [{ method: "POST", path: "/echo", capability: "echo", handler: () => ({}) }],
};

test("a route with no capability is refused", () => {
  // The load-bearing check: an ungated route is the one mistake this whole
  // arrangement exists to prevent, and this is the last place to notice.
  const checked = validatePlugin({
    name: "leaky",
    routes: [{ method: "POST", path: "/open", handler: () => ({}) }],
  });
  assert.equal(checked.ok, false);
  assert.match(checked.error, /declares no capability/);
});

test("malformed routes are refused before anything loads", () => {
  const cases = [
    [{ name: "" }, /needs a name/],
    [{ name: "a", routes: [{ method: "SING", path: "/x", capability: "c", handler: () => {} }] }, /method/],
    [{ name: "a", routes: [{ method: "GET", path: "x", capability: "c", handler: () => {} }] }, /start with \//],
    [{ name: "a", routes: [{ method: "GET", path: "/x", capability: "c" }] }, /no handler/],
  ];
  for (const [plugin, expected] of cases) {
    const checked = validatePlugin(plugin);
    assert.equal(checked.ok, false);
    assert.match(checked.error, expected);
  }
});

test("a well-formed plugin passes", () => {
  assert.equal(validatePlugin(wellFormed).ok, true);
});

test("a plugin that will not load does not stop the others", async () => {
  const messages = [];
  const loaded = await loadPlugins(["broken", "fine"], {
    log: (message) => messages.push(message),
    importImpl: async (specifier) => {
      if (specifier === "broken") throw new Error("no such module");
      return { default: wellFormed };
    },
  });

  // A broken tunnel plugin must not stop a machine answering hails, which is
  // the job it had before any plugin existed.
  assert.deepEqual(loaded.map((plugin) => plugin.name), ["echo"]);
  assert.ok(messages.some((message) => message.includes("could not load broken")));
});

test("a plugin refused for being malformed is reported, not thrown", async () => {
  const messages = [];
  const loaded = await loadPlugins(["leaky"], {
    log: (message) => messages.push(message),
    importImpl: async () => ({
      default: { name: "leaky", routes: [{ method: "GET", path: "/x", handler: () => {} }] },
    }),
  });
  assert.deepEqual(loaded, []);
  assert.ok(messages.some((message) => message.includes("declares no capability")));
});

test("two plugins cannot claim one path", () => {
  const messages = [];
  const routes = collectRoutes(
    [wellFormed, { ...wellFormed, name: "impostor" }],
    { log: (message) => messages.push(message) },
  );

  // Resolving by order would make the winner depend on configuration order,
  // which nobody would think to check.
  assert.equal(routes.size, 1);
  assert.equal(routes.get("POST /echo").plugin, "echo");
  assert.ok(messages.some((message) => message.includes("already served by echo")));
});

test("a plugin's profiles are suggestions, and say where they came from", () => {
  const profiles = collectProfiles([wellFormed]);
  assert.deepEqual(profiles.echoer.allows, ["hail", "echo"]);
  assert.equal(profiles.echoer.fromPlugin, "echo");
  // Loading a plugin changes what this machine can offer, never who may use it:
  // no peer holds `echoer` until somebody assigns it.
});

test("the hello protocol is itself a plugin", async () => {
  const { default: hailPlugin } = await import("../src/builtin/hailPlugin.js");
  // Answering is a service, not a property of importing the library.
  const checked = validatePlugin(hailPlugin);
  assert.equal(checked.ok, true);
  assert.deepEqual([...collectRoutes([hailPlugin]).keys()], ["POST /hail"]);
  assert.equal(collectRoutes([hailPlugin]).get("POST /hail").capability, "hail");
});

test("a host with no plugins serves no protocol", async () => {
  const { createDaemon } = await import("../src/server.js");
  const { createDirectory } = await import("../src/directory.js");

  const daemon = createDaemon({
    directory: createDirectory({ self: { name: "app" } }),
    identity: { publicKey: "x", privateKey: "y" },
  });
  const { port } = await daemon.listen({ port: 0 });
  try {
    // The payoff of the split: embedding the directory opens nothing.
    const response = await fetch(`http://127.0.0.1:${port}/hail`, { method: "POST", body: "{}" });
    assert.equal(response.status, 404);
  } finally {
    await daemon.close();
  }
});

test("a plugin refuses without deciding how that looks", async () => {
  const { refuse, REFUSE } = await import("../src/plugins.js");
  const refusal = refuse("because");
  // The host owns the response, so a plugin cannot reveal which rule refused.
  assert.equal(refusal[REFUSE], true);
  assert.equal(refusal.reason, "because");
});
