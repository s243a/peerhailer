/**
 * The per-record causal merge (`mergeRecord` via `mergeByRevision`/`reconcilePersist`).
 *
 * Under peerhailer's single write lock each record's committed history is linear, so
 * concurrency is exactly "one uncommitted CLI branch vs. the committed line" and the
 * branch knows its fork point (the baseline). The merge therefore needs no vector
 * clock: `rev` movement against the baseline detects who advanced, and a per-field
 * 3-way content diff against the baseline decides which fields survive. These cover
 * the non-security lost-update fix (concurrent different-field edits both survive; a
 * stale higher-`rev` writer cannot clobber a concurrent edit), the deterministic
 * same-field resolution to the committed side, the elevation triple / addresses /
 * conflicts field rules, and the new "two concurrent rotations to different
 * identities fail closed and are visible" case. The security-critical High-1
 * properties live in `sealPersistence.test.mjs` and are unchanged.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createDirectory, mergeByRevision, reconcilePersist } from "../src/directory.js";
import { generateIdentity, sameKey } from "../src/identity.js";
import { publicRecord } from "../src/peerRecord.js";

const bob = generateIdentity();
const bob2 = generateIdentity();
const bob3 = generateIdentity();

/** Drive the real write path: baseline is the fork point, onDisk the committed line,
 * current this writer's snapshot. Returns the merged record for `k`. */
function merge(base, disk, mine) {
  const baseline = { admitted: [base] };
  const onDisk = { admitted: [disk] };
  const current = { admitted: [mine] };
  return reconcilePersist(onDisk, baseline, current).admitted.find((p) => p.name === "k");
}

test("concurrent different-field edits both survive", () => {
  const base = { name: "k", publicKey: bob.publicKey, note: "a", profile: "trusted", rev: 1 };
  const disk = { name: "k", publicKey: bob.publicKey, note: "a", profile: "lan", rev: 2 }; // daemon changed profile
  const mine = { name: "k", publicKey: bob.publicKey, note: "b", profile: "trusted", rev: 4 }; // walk changed note
  const merged = merge(base, disk, mine);
  assert.equal(merged.profile, "lan", "disk's profile edit survives");
  assert.equal(merged.note, "b", "this writer's note edit survives");
  assert.equal(merged.rev, 4, "rev floors to the max");
});

test("a stale higher-rev writer cannot clobber a concurrent edit (the residual)", () => {
  const base = { name: "k", publicKey: bob.publicKey, note: "a", profile: "trusted", rev: 1 };
  // Disk changed profile; this writer bumped rev many times but left profile untouched.
  const disk = { name: "k", publicKey: bob.publicKey, note: "a", profile: "lan", rev: 2 };
  const mine = { name: "k", publicKey: bob.publicKey, note: "a", profile: "trusted", rev: 9 };
  assert.equal(merge(base, disk, mine).profile, "lan", "the stale high-rev snapshot did not clobber disk's profile");

  // Mirror: this writer changed note; disk is a stale-but-high-rev unrelated edit.
  const base2 = { name: "k", publicKey: bob.publicKey, note: "a", profile: "trusted", rev: 1 };
  const disk2 = { name: "k", publicKey: bob.publicKey, note: "a", profile: "trusted", rev: 9 };
  const mine2 = { name: "k", publicKey: bob.publicKey, note: "b", profile: "trusted", rev: 2 };
  assert.equal(merge(base2, disk2, mine2).note, "b", "this writer's note edit lands despite disk's higher rev");
});

test("concurrent same-field edits resolve deterministically to disk (rev is not consulted)", () => {
  const base = { name: "k", publicKey: bob.publicKey, note: "base", rev: 1 };
  // Disk lower rev than mine — still wins the same-field conflict.
  assert.equal(
    merge(base, { name: "k", publicKey: bob.publicKey, note: "disk", rev: 2 }, { name: "k", publicKey: bob.publicKey, note: "mine", rev: 5 }).note,
    "disk",
    "same-field conflict resolves to the committed side even when disk out-revs lower",
  );
  // Swap the revs — the answer must not change.
  assert.equal(
    merge(base, { name: "k", publicKey: bob.publicKey, note: "disk", rev: 5 }, { name: "k", publicKey: bob.publicKey, note: "mine", rev: 2 }).note,
    "disk",
    "the same-field resolution is rev-independent",
  );
  assert.equal(merge(base, { name: "k", publicKey: bob.publicKey, note: "disk", rev: 2 }, { name: "k", publicKey: bob.publicKey, note: "mine", rev: 5 }).rev, 5, "rev still floors to max");
});

test("the elevation triple moves as a single unit", () => {
  const base = { name: "k", publicKey: bob.publicKey, profile: "trusted", rev: 1 };
  const disk = { name: "k", publicKey: bob.publicKey, profile: "admin", profileUntil: 999, profileAfter: "trusted", rev: 2 };
  const mine = { name: "k", publicKey: bob.publicKey, profile: "lan", rev: 4 };
  const merged = merge(base, disk, mine);
  assert.equal(merged.profile, "admin", "disk's elevated profile wins");
  assert.equal(merged.profileUntil, 999, "the window rode along");
  assert.equal(merged.profileAfter, "trusted", "the fallback rode along");
  assert.ok(!("profileUntil" in mine), "sanity: mine never carried a window to leak");
});

test("addresses union; conflicts union by key", () => {
  const base = {
    name: "k",
    publicKey: bob.publicKey,
    addresses: [{ transport: "lan", value: "http://base:1", lastOk: 1 }],
    rev: 1,
  };
  const disk = {
    name: "k",
    publicKey: bob.publicKey,
    addresses: [
      { transport: "lan", value: "http://base:1", lastOk: 1 },
      { transport: "lan", value: "http://disk:2", lastOk: 5 },
    ],
    conflicts: [{ key: bob2.publicKey, firstSeen: 10, lastSeen: 10, count: 1 }],
    rev: 2,
  };
  const mine = {
    name: "k",
    publicKey: bob.publicKey,
    addresses: [
      { transport: "lan", value: "http://base:1", lastOk: 1 },
      { transport: "relay", value: "http://mine:3", lastOk: 7 },
    ],
    conflicts: [{ key: bob2.publicKey, firstSeen: 4, lastSeen: 12, count: 2 }],
    rev: 4,
  };
  const merged = merge(base, disk, mine);
  const values = merged.addresses.map((a) => a.value);
  assert.ok(values.includes("http://disk:2"), "disk's new address survives");
  assert.ok(values.includes("http://mine:3"), "this writer's new address survives");
  assert.equal(merged.conflicts.length, 1, "the same conflict key is unioned, not duplicated");
  assert.equal(merged.conflicts[0].count, 2, "count = max across both sides");
  assert.equal(merged.conflicts[0].lastSeen, 12, "lastSeen = max");
  assert.equal(merged.conflicts[0].firstSeen, 4, "firstSeen = min");
});

test("conflicts follow a rotation (a rotate clears them)", () => {
  const base = { name: "k", publicKey: bob.publicKey, rev: 1 };
  // Disk rotated to a new identity, clearing conflicts.
  const disk = { name: "k", publicKey: bob2.publicKey, sealRequired: true, rev: 2 };
  // This writer noted a conflict on the OLD identity.
  const mine = { name: "k", publicKey: bob.publicKey, conflicts: [{ key: bob3.publicKey, firstSeen: 1, lastSeen: 1, count: 1 }], rev: 3 };
  const merged = merge(base, disk, mine);
  assert.ok(sameKey(merged.publicKey, bob2.publicKey), "disk's rotation held");
  assert.ok(!merged.conflicts || merged.conflicts.length === 0, "conflicts on the retired identity did not survive the rotation");
});

test("two concurrent rotations to DIFFERENT identities fail closed to disk and list the loser", () => {
  const base = { name: "k", publicKey: bob.publicKey, sealPublicKey: bob.sealPublicKey, sealSeen: true, sealRequired: true, rev: 1 };
  const disk = { name: "k", publicKey: bob2.publicKey, sealRequired: true, rev: 2 }; // rotated to bob2
  const mine = { name: "k", publicKey: bob3.publicKey, sealRequired: true, rev: 2 }; // concurrently rotated to bob3
  const merged = merge(base, disk, mine);
  assert.ok(sameKey(merged.publicKey, bob2.publicKey), "identity fails closed to disk (first committed under the lock)");
  assert.ok(!sameKey(merged.publicKey, bob.publicKey), "no resurrection of the retired identity");
  assert.ok(!merged.sealPublicKey, "no live seal key after the rotation (reverify posture)");
  assert.equal(merged.sealRequired, true, "sealRequired floor is preserved → sends fail closed");
  assert.ok(merged.conflicts?.some((c) => sameKey(c.key, bob3.publicKey)), "the competing identity is surfaced in conflicts");

  // Swapping the sides keeps the disk identity winning.
  const swapped = merge(base, { name: "k", publicKey: bob3.publicKey, sealRequired: true, rev: 2 }, { name: "k", publicKey: bob2.publicKey, sealRequired: true, rev: 2 });
  assert.ok(sameKey(swapped.publicKey, bob3.publicKey), "still the disk identity after the swap");
  assert.ok(swapped.conflicts?.some((c) => sameKey(c.key, bob2.publicKey)), "the other competing key is surfaced");
});

test("back-compat: direct mergeByRevision (no baseline) keeps legacy rev behaviour", () => {
  // Higher rev wins, either direction.
  const fresh = { name: "bob", publicKey: bob2.publicKey, rev: 5 };
  const stale = { name: "bob", publicKey: bob.publicKey, rev: 2 };
  assert.equal(mergeByRevision([fresh], [stale])[0].rev, 5, "on-disk newer wins");
  assert.equal(mergeByRevision([stale], [fresh])[0].rev, 5, "snapshot newer wins");
  assert.ok(sameKey(mergeByRevision([fresh], [stale])[0].publicKey, bob2.publicKey), "identity follows the winner");
  // A tie resolves to disk.
  const disk = { name: "bob", publicKey: bob.publicKey, note: "committed", rev: 4 };
  const snap = { name: "bob", publicKey: bob.publicKey, note: "stale", rev: 4 };
  assert.equal(mergeByRevision([disk], [snap])[0].note, "committed", "a tie goes to disk");
});

test("back-compat: with a baseline, classification is by baseline movement, not by raw rev", () => {
  // Disk did not move from the baseline; this writer did (and changed the note). The
  // legacy "higher rev wins" would have taken disk (rev 7 > 3); the causal merge keeps
  // this writer's note because only it advanced past the fork point.
  const base = { name: "k", publicKey: bob.publicKey, note: "base", rev: 7 };
  const disk = { name: "k", publicKey: bob.publicKey, note: "base", rev: 7 };
  const mine = { name: "k", publicKey: bob.publicKey, note: "mine", rev: 8 };
  assert.equal(merge(base, disk, mine).note, "mine", "only the side that advanced past the baseline wins the field");
});

test("neither vc nor rev leaves the machine: publicRecord/hailResponse strip internal fields", () => {
  const dir = createDirectory({ self: { name: "me", publicKey: generateIdentity().publicKey } });
  dir.admit({ name: "bob", publicKey: bob.publicKey, addresses: [{ transport: "lan", value: "http://bob:1" }] });
  const pub = publicRecord(dir.get("bob"));
  assert.ok(!("rev" in pub), "rev is not gossiped");
  assert.ok(!("vc" in pub), "no vector clock is gossiped (there is none)");
  assert.ok(!("conflicts" in pub), "conflicts are local-only");
  const peer = dir.hailResponse().peers[0];
  assert.ok(!("rev" in peer), "rev is stripped from the hail response");
  assert.ok(!("vc" in peer), "no vector clock in the hail response");
});
