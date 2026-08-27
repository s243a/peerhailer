/**
 * The route plugin's per-caller rate limit — one receipt can trigger up to `fanout`
 * outbound callPeers, so an unbounded relay rate is an amplification lever.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createRoutePlugin, MAX_RELAYS_PER_WINDOW, RELAY_WINDOW_MS } from "../src/builtin/routePlugin.js";
import { REFUSE } from "../src/plugins.js";

test("a caller is refused past MAX_RELAYS_PER_WINDOW, and the window resets", async () => {
  let clock = 1_000_000;
  const plugin = createRoutePlugin({
    self: "me",
    neighbors: () => [],
    forward: async () => ({ delivered: false, spent: 0 }),
    deliver: () => ({ received: true }),
    now: () => clock,
  });
  const relay = plugin.routes[0].handler;
  const caller = { publicKey: "peer-1" };
  const env = { dest: "somewhere", ttl: 4, budget: 8, visited: [], payload: "x" };

  for (let i = 0; i < MAX_RELAYS_PER_WINDOW; i++) {
    const r = await relay({ body: env, caller });
    assert.notEqual(r[REFUSE], true, `relay ${i} within the limit is allowed`);
  }
  const over = await relay({ body: env, caller });
  assert.equal(over[REFUSE], true, "one past the limit is refused");
  assert.match(over.reason, /too fast/);

  // A different caller is unaffected (per-caller bucket).
  const other = await relay({ body: env, caller: { publicKey: "peer-2" } });
  assert.notEqual(other[REFUSE], true, "the limit is per caller");

  // After the window passes, peer-1 is allowed again.
  clock += RELAY_WINDOW_MS + 1;
  const again = await relay({ body: env, caller });
  assert.notEqual(again[REFUSE], true, "the window resets");
});
