import { test } from "node:test";
import assert from "node:assert/strict";

import { createOffersPlugin, OFFERS } from "../src/builtin/offersPlugin.js";

test("advertises only launchable service+tunnel pairs; never the command", () => {
  const plugin = createOffersPlugin({
    services: {
      "agy-worker": {
        command: "node bridge.js --agent agy --listen 9102",
        agent: "agy",
        role: "worker",
        label: "Gemini worker",
        tunnel: "agy-worker",
      },
      "codex-worker": { command: "node bridge.js --agent codex-mcp --listen 9103", agent: "codex-mcp" }, // no matching tunnel
      plain: "some daemon {port}", // a bare command string — no metadata
    },
    tunnels: { "agy-worker": "127.0.0.1:9102" },
  });

  assert.deepEqual(plugin.capabilities, [OFFERS]);
  const route = plugin.routes[0];
  assert.equal(route.method, "POST");
  assert.equal(route.path, "/offers");
  assert.equal(route.capability, OFFERS);
  assert.equal(plugin.requiresEncryptedArrival, true);

  const { offers } = route.handler({ log: () => {} });
  assert.equal(offers.length, 1, "only the pair whose tunnel exists is advertised");
  assert.deepEqual(offers[0], {
    service: "agy-worker",
    label: "Gemini worker",
    agent: "agy",
    role: "worker",
    tunnel: "agy-worker",
  });
  assert.equal("command" in offers[0], false, "the command line is never advertised");
});

test("tunnel defaults to the service name; role defaults to worker", () => {
  const plugin = createOffersPlugin({
    services: { w: { command: "x", agent: "codex-mcp" } },
    tunnels: { w: "127.0.0.1:9000" },
  });
  const { offers } = plugin.routes[0].handler({ log: () => {} });
  assert.equal(offers[0].tunnel, "w");
  assert.equal(offers[0].role, "worker");
});

test("no services / no tunnels → no offers", () => {
  assert.equal(createOffersPlugin({}).routes[0].handler({}).offers.length, 0);
  assert.equal(
    createOffersPlugin({ services: { w: { command: "x", agent: "codex" } }, tunnels: {} }).routes[0].handler({}).offers.length,
    0,
    "a startable-but-unreachable service is not an offer",
  );
});
