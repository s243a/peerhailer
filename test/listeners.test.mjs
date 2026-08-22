/**
 * Two doors, so a firewall rule admits what it says it admits.
 *
 * The page and `/api/*` hold no authentication; their boundary is that they
 * answer on loopback and nowhere else. Plugin routes authenticate every caller
 * and are the only thing safe to expose. Separating them by listener rather
 * than by a check inside one handler means the control API is not listening on
 * the external interface at all — there is nothing to reach, and no conditional
 * to get wrong.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import hailPlugin from "../src/builtin/hailPlugin.js";

test("the control API answers on loopback and not on a hail listener", async () => {
  const identity = generateIdentity();
  const directory = createDirectory({ self: { name: "me", publicKey: identity.publicKey } });
  directory.admit({ name: "sol", profile: "trusted" });

  const daemon = createDaemon({ directory, identity, plugins: [hailPlugin] });
  const control = await daemon.listen({ port: 0 });
  // Loopback stands in for "another interface": a second listener on the same
  // address, serving the hail scope only.
  const [hail] = await daemon.listenHail({ port: 0, hosts: ["127.0.0.1"] });

  try {
    assert.notEqual(hail.port, control.port, "two listeners, two ports");

    for (const path of ["/api/peers", "/api/profiles", "/"]) {
      const onControl = await fetch(`http://127.0.0.1:${control.port}${path}`);
      assert.equal(onControl.status, 200, `${path} is served on the control door`);

      const onHail = await fetch(`http://127.0.0.1:${hail.port}${path}`);
      assert.equal(onHail.status, 404, `${path} must not exist on a hail listener`);
    }

    // And a plugin route is reachable there — refused, because nothing proved
    // who it was, which is the gate working rather than the route missing.
    const hailed = await fetch(`http://127.0.0.1:${hail.port}/hail`, { method: "POST", body: "{}" })
      .then((r) => r.status)
      .catch(() => "dropped");
    assert.notEqual(hailed, 404, "the hail route exists on the hail door");
  } finally {
    await daemon.close();
  }
});

test("an address that cannot be bound is skipped, not fatal", async () => {
  const identity = generateIdentity();
  const directory = createDirectory({ self: { name: "me", publicKey: identity.publicKey } });
  const daemon = createDaemon({ directory, identity, plugins: [hailPlugin] });

  try {
    // A laptop whose wifi is not up yet should still answer on its tailnet.
    const bound = await daemon.listenHail({ port: 0, hosts: ["203.0.113.7", "127.0.0.1"] });
    assert.equal(bound.length, 1, "the reachable one is bound");
    assert.equal(bound[0].host, "127.0.0.1");
  } finally {
    await daemon.close();
  }
});
