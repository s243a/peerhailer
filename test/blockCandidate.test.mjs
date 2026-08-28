/**
 * Blocking is key-first only for a key we can trust. An *admitted* peer's key was
 * bound by us, so it is blocked key-first — a stable identity a rename can't shed.
 * A *candidate*'s key is hearsay: a gossiper asserting `name → key` is evidence of
 * a claim, not that the key is that name. So a candidate blocks by name (it lands
 * on the intended target, even if a rename can later evade) and its reported key is
 * blocked only when the operator explicitly confirms it — never inferred from the
 * mere presence of a key. Otherwise a false gossiped binding would silently block
 * an innocent third party who holds that key while leaving the real peer free.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createDirectory } from "../src/directory.js";
import { generateIdentity, sameKey, fingerprint } from "../src/identity.js";

const addr = [{ value: "https://127.0.0.1:9" }];

/** A directory with `name` known only as a gossiped candidate carrying `key`. */
function withCandidate(name, key, heardFrom = "introducer") {
  const dir = createDirectory({ self: { name: "me" } });
  dir.learnFrom(heardFrom, [{ name, publicKey: key, addresses: addr }]);
  return dir;
}

test("a candidate blocks by name by default; its hearsay key is left alone", () => {
  const bob = generateIdentity();
  const dir = withCandidate("bob", bob.publicKey);

  const out = dir.blockPeer("bob");
  assert.equal(out.mode, "candidate-name");
  assert.ok(out.blocklist.names.includes("bob"), "the intended target is name-blocked");
  assert.equal(out.blocklist.keys.length, 0, "the unverified key is NOT blocked");
  // The key is reported (for disclosure), with its provenance — never asserted as blocked.
  assert.ok(sameKey(out.reportedKey, bob.publicKey));
  assert.equal(out.fingerprint, fingerprint(bob.publicKey));
  assert.deepEqual(out.heardFrom, ["introducer"]);
});

test("false gossip: blocking a candidate does not block the innocent key it named", () => {
  // A hostile/stale gossiper asserts bob -> innocentM's key. Blocking bob must not
  // deny innocentM, who never met us.
  const innocentM = generateIdentity();
  const dir = withCandidate("bob", innocentM.publicKey, "hostile");

  const out = dir.blockPeer("bob");
  assert.ok(out.blocklist.names.includes("bob"));
  assert.ok(
    !out.blocklist.keys.some((k) => sameKey(k, innocentM.publicKey)),
    "innocentM's key is untouched — the binding was never verified",
  );
});

test("a candidate's key IS blocked when the operator explicitly confirms it", () => {
  const bob = generateIdentity();
  const dir = withCandidate("bob", bob.publicKey);

  const out = dir.blockPeer("bob", { includeKey: true });
  assert.equal(out.mode, "candidate-name+key");
  assert.ok(out.blocklist.names.includes("bob"), "still name-blocked (lands on the target)");
  assert.ok(out.blocklist.keys.some((k) => sameKey(k, bob.publicKey)), "and now key-blocked (rename-proof)");
  assert.ok(sameKey(out.blockedKey, bob.publicKey));
  assert.deepEqual(out.heardFrom, ["introducer"]);
});

test("an admitted peer is blocked key-first; its name stays reusable", () => {
  const bob = generateIdentity();
  const dir = createDirectory({ self: { name: "me" } });
  dir.admit({ name: "bob", publicKey: bob.publicKey, addresses: addr });

  const out = dir.blockPeer("bob");
  assert.equal(out.mode, "verified-key");
  assert.ok(out.blocklist.keys.some((k) => sameKey(k, bob.publicKey)), "blocked by the key we bound");
  assert.ok(!out.blocklist.names.includes("bob"), "name not added — a different identity may reuse it");
  assert.ok(sameKey(out.blockedKey, bob.publicKey));
});

test("an unknown name (no record anywhere) blocks by name", () => {
  const dir = createDirectory({ self: { name: "me" } });
  const out = dir.blockPeer("ghost");
  assert.equal(out.mode, "name");
  assert.deepEqual(out.blocklist.names, ["ghost"]);
  assert.equal(out.blocklist.keys.length, 0);
  assert.equal(out.fingerprint, null);
});

test("a confirmed candidate block round-trips: unblock by name clears both entries", () => {
  const bob = generateIdentity();
  const dir = withCandidate("bob", bob.publicKey);

  dir.blockPeer("bob", { includeKey: true });
  const after = dir.unblock("bob");
  assert.ok(!after.names.includes("bob"), "name cleared");
  assert.ok(!after.keys.some((k) => sameKey(k, bob.publicKey)), "key cleared while the candidate still resolves it");
});

test("unblockKey lifts a key that outlived its record — by PEM and by fingerprint", () => {
  const bob = generateIdentity();

  // By PEM, after the candidate is forgotten so unblock(name) can't resolve the key.
  const byPem = withCandidate("bob", bob.publicKey);
  byPem.blockPeer("bob", { includeKey: true });
  byPem.forget("bob");
  assert.ok(byPem.blocklist().keys.some((k) => sameKey(k, bob.publicKey)), "key is stuck after forget");
  const pemResult = byPem.unblockKey(bob.publicKey);
  assert.equal(pemResult.removed, 1);
  assert.equal(byPem.blocklist().keys.length, 0);

  // By fingerprint — the form an operator can actually read off a screen.
  const byFp = withCandidate("bob", bob.publicKey);
  byFp.blockPeer("bob", { includeKey: true });
  byFp.forget("bob");
  const fpResult = byFp.unblockKey(fingerprint(bob.publicKey));
  assert.equal(fpResult.removed, 1);
  assert.equal(byFp.blocklist().keys.length, 0);

  // A miss removes nothing.
  assert.equal(byFp.unblockKey("not-a-real-key").removed, 0);
});
