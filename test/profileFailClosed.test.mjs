/**
 * A named profile that does not resolve must fail closed (grant nothing), never
 * open to `trusted` — a config edit or a typo must not silently invert an
 * operator's restricted grant into full trust. Assignment is validated at the
 * door (CLI/API); the resolver is the backstop for the paths validation cannot
 * cover (hand-edited state, removed/renamed profiles, config-sourced names).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { resolveProfile, isAssignableProfile } from "../src/profiles.js";
import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";

test("resolveProfile fails closed for a named-but-missing profile, open only for no name", () => {
  assert.equal(resolveProfile("typo").name, "unknown");
  assert.deepEqual(resolveProfile("typo").allows, [], "grants nothing");
  assert.equal(resolveProfile(undefined).name, "trusted", "absence is the trusted default");
  assert.equal(resolveProfile("").name, "trusted", "empty string == no name (legacy records)");
  // The config-sourced backstop: a hand-edited trust.unknownProfile of a bogus
  // name is resolved through the same function, so strangers get nothing, not trust.
  assert.deepEqual(resolveProfile("trustd-typo").allows, []);
});

test("a non-string profile is not stored verbatim — a candidate lands on its fallback, not trusted", () => {
  const bob = generateIdentity();
  const dir = createDirectory({ self: { name: "me" } });
  dir.learnFrom("introducer", [{ name: "cand", publicKey: bob.publicKey, addresses: [{ value: "https://127.0.0.1:9" }] }]);
  // Promote as a candidate (no new address) with a falsy non-string profile. A
  // bare `??` would keep `0` and resolve it down the no-name branch to trusted;
  // it must instead be ignored so the candidate fallback (`known`) applies.
  const admitted = dir.admit({ name: "cand", profile: 0 });
  assert.equal(typeof admitted.profile, "string", "a non-string profile is never stored");
  assert.equal(admitted.profile, "known", "candidate fallback, not the trusted no-name default");
});

test("isAssignableProfile: real names yes, unknown names no, `blocked` never", () => {
  assert.equal(isAssignableProfile("trusted"), true);
  assert.equal(isAssignableProfile("known"), true);
  assert.equal(isAssignableProfile("nosuch"), false);
  assert.equal(isAssignableProfile("blocked"), false, "blocked is produced by the blocklist, not assigned");
  assert.equal(isAssignableProfile(""), false);
  assert.equal(isAssignableProfile("mine", { mine: { name: "mine", allows: ["hail"] } }), true, "custom names count");
});

test("POST /api/peers rejects an unknown or `blocked` profile at the door", async (t) => {
  const id = generateIdentity();
  const daemon = createDaemon({ directory: createDirectory({ self: { name: "me", publicKey: id.publicKey } }), identity: id, plugins: [] });
  const { port } = await daemon.listen({ port: 0 });
  t.after(async () => { await daemon.close(); });
  const post = (body) =>
    fetch(`http://127.0.0.1:${port}/api/peers`, { method: "POST", headers: { "content-type": "application/json", connection: "close" }, body: JSON.stringify(body) })
      .then(async (r) => ({ status: r.status, json: await r.json() }));

  assert.equal((await post({ name: "bob", profile: "trustd" })).status, 400, "a typo'd profile is refused, not silently trusted");
  const blocked = await post({ name: "bob", profile: "blocked" });
  assert.equal(blocked.status, 400);
  assert.match(blocked.json.error, /block/, "points at the block control");
  assert.equal((await post({ name: "bob", profile: "known" })).status, 200, "a real profile is admitted");
});
