/**
 * How this machine refuses, and what that tells a stranger.
 *
 * The style of a refusal is a channel. It used to be chosen from the name in
 * the request — before any signature was checked — so anyone could ask "is this
 * name blocked here?" and read the answer off the connection. These tests pin
 * the property that closed it: refusals depend on what was proved, never on
 * what was claimed.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import hailPlugin from "../src/builtin/hailPlugin.js";

/** Ask the daemon something, unauthenticated, claiming to be `name`. */
async function probe(url, name) {
  try {
    const response = await fetch(`${url}/hail`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ from: { name, at: Date.now() }, signature: "not-a-signature" }),
    });
    return { outcome: "answered", status: response.status };
  } catch {
    // A destroyed socket surfaces as a fetch failure, which is the point of it.
    return { outcome: "dropped" };
  }
}

test("an unauthenticated caller cannot tell a blocked name from any other", async () => {
  const identity = generateIdentity();
  const directory = createDirectory({ self: { name: "me", publicKey: identity.publicKey } });
  directory.admit({ name: "sol", profile: "trusted" });
  directory.admit({ name: "luna", profile: "trusted" });
  directory.block({ name: "luna" });

  // Without the hail plugin nothing serves /hail, and three identical 404s
  // would pass this test for entirely the wrong reason.
  const daemon = createDaemon({ directory, identity, plugins: [hailPlugin] });
  const { port } = await daemon.listen({ port: 0 });
  const url = `http://127.0.0.1:${port}`;

  try {
    const results = await Promise.all(
      ["luna", "sol", "never-heard-of-this-one"].map((name) => probe(url, name)),
    );
    const [blocked, admittedPeer, stranger] = results;

    assert.deepEqual(blocked, admittedPeer, "a blocked name must not answer differently");
    assert.deepEqual(blocked, stranger, "nor differently from a name we never knew");
    assert.equal(blocked.outcome, "dropped", "proving nothing earns silence, not a reply");
  } finally {
    await daemon.close();
  }
});
