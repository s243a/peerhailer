/**
 * Blocking must be key-first even for a peer we only heard of. A candidate carries
 * a gossiped key; blocking it by name alone lets it rename its way back in — the
 * bypass `block` exists to deny. `recordFor` resolves admitted *or* candidate, so
 * block gets the key. Symmetric with `unblock`, which already consults candidates.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createDirectory } from "../src/directory.js";
import { generateIdentity, sameKey } from "../src/identity.js";

test("blocking a candidate uses its gossiped key, not just its name", () => {
  const bob = generateIdentity();
  const dir = createDirectory({ self: { name: "me" } });
  dir.learnFrom("introducer", [{ name: "bob", publicKey: bob.publicKey, addresses: [{ value: "https://127.0.0.1:9" }] }]);

  const peer = dir.recordFor("bob");
  assert.ok(peer?.publicKey, "the candidate carries the gossiped key");
  const list = dir.block(peer);
  assert.ok(list.keys.some((k) => sameKey(k, bob.publicKey)), "blocked by key");
  assert.ok(!list.names.includes("bob"), "not merely by name — a rename can't get it back in");
});

test("a name-only candidate (no gossiped key) is blocked by name", () => {
  const dir = createDirectory({ self: { name: "me" } });
  dir.learnFrom("introducer", [{ name: "ghost" }]); // no key
  const list = dir.block(dir.recordFor("ghost") ?? { name: "ghost" });
  assert.ok(list.names.includes("ghost"), "no key to block by, so by name");
  assert.equal(list.keys.length, 0);
});

test("recordFor prefers an admitted record, falls back to a candidate", () => {
  const bob = generateIdentity();
  const dir = createDirectory({ self: { name: "me" } });
  assert.equal(dir.recordFor("bob"), null, "unknown name");
  dir.learnFrom("introducer", [{ name: "bob", publicKey: bob.publicKey, addresses: [{ value: "https://127.0.0.1:9" }] }]);
  assert.ok(sameKey(dir.recordFor("bob").publicKey, bob.publicKey), "resolves the candidate");
  dir.admit({ name: "bob", publicKey: bob.publicKey, addresses: [{ value: "https://127.0.0.1:9" }] });
  assert.ok(sameKey(dir.recordFor("bob").publicKey, bob.publicKey), "resolves the admitted record once admitted");
});
