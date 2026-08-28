/**
 * A profile removed at another terminal must reach a running daemon everywhere —
 * not only resolution (the directory), but the page's offered/validated set. The
 * server reads the profile set from the directory (single source), so a
 * `useProfiles` refresh (what applyChange/reload apply) is reflected immediately.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";

const call = (port, path, body) =>
  fetch(`http://127.0.0.1:${port}${path}`, body
    ? { method: "POST", headers: { "content-type": "application/json", connection: "close" }, body: JSON.stringify(body) }
    : { headers: { connection: "close" } }).then(async (r) => ({ status: r.status, json: await r.json() }));

test("the page's profile listing and validation track the live directory set", async (t) => {
  const id = generateIdentity();
  const custom = { lp: { name: "lp", allows: ["hail"], description: "restricted" } };
  const dir = createDirectory({ self: { name: "me", publicKey: id.publicKey }, profiles: custom });
  dir.useProfiles(custom);
  const daemon = createDaemon({ directory: dir, identity: id, plugins: [], profiles: dir.currentProfiles() });
  const { port } = await daemon.listen({ port: 0 });
  t.after(async () => { await daemon.close(); });

  // While lp exists: it's listed and assignable.
  assert.ok((await call(port, "/api/profiles")).json.some((p) => p.name === "lp"));
  assert.equal((await call(port, "/api/peers", { name: "a", profile: "lp" })).status, 200);

  // Remove it from the directory (what a profiles-remove reaching the daemon does).
  dir.useProfiles({});

  // The page no longer offers it, and no longer accepts admitting a peer into it.
  assert.ok(!(await call(port, "/api/profiles")).json.some((p) => p.name === "lp"), "listing drops the removed profile");
  assert.equal((await call(port, "/api/peers", { name: "b", profile: "lp" })).status, 400, "validation refuses the removed profile");
});
