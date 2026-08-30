/**
 * The sealing key's trust must survive the write path and rotation, not just the
 * happy load path. These cover the per-record revision merge (a stale writer must
 * not roll back newer trust, and must not open a cleartext window), the four-state
 * seal gate, the walk's TOCTOU guard, operator conflict resolution, and a real
 * walk binding the key from a signed record.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createDirectory, mergeByRevision, reconcileBaseline, reconcilePersist } from "../src/directory.js";
import { generateIdentity, sameKey } from "../src/identity.js";
import { walk } from "../src/hail.js";
import { makePeerRecord, signRecord } from "../src/peerRecord.js";

const bob = generateIdentity();
const bob2 = generateIdentity();

/** A directory with bob admitted (with his identity key) and a verified sealing key. */
function withVerifiedBob() {
  const dir = createDirectory({ self: { name: "me", publicKey: generateIdentity().publicKey } });
  dir.admit({ name: "bob", publicKey: bob.publicKey, addresses: [{ value: "https://127.0.0.1:9" }] });
  dir.bindSealKey("bob", bob.sealPublicKey, bob.publicKey);
  return dir;
}

test("mergeByRevision: higher revision wins, so a stale writer cannot roll a peer back", () => {
  const fresh = { name: "bob", publicKey: bob2.publicKey, sealPublicKey: bob2.sealPublicKey, sealSeen: true, sealRequired: true, rev: 5 };
  const stale = { name: "bob", publicKey: bob.publicKey, rev: 2 };
  assert.equal(mergeByRevision([fresh], [stale])[0].rev, 5, "on-disk newer wins over stale snapshot");
  assert.equal(mergeByRevision([stale], [fresh])[0].rev, 5, "snapshot newer wins over stale disk");
  assert.ok(sameKey(mergeByRevision([fresh], [stale])[0].publicKey, bob2.publicKey));
});

test("reconcilePersist: a stale writer's higher-rev walk cannot undo a concurrent identity rotation", () => {
  // This writer loaded peer K at rev 1 with the OLD identity + a verified old sealing key.
  const baseline = { admitted: [{ name: "k", publicKey: bob.publicKey, sealPublicKey: bob.sealPublicKey, sealSeen: true, sealRequired: true, rev: 1 }] };
  // Meanwhile another process ROTATED K to a new identity (rev 2), dropping the seal.
  const onDisk = { admitted: [{ name: "k", publicKey: bob2.publicKey, sealRequired: true, rev: 2 }] };
  // This stale writer, unaware of the rotation, made several walks on its old view -> rev 4.
  const current = { admitted: [{ name: "k", publicKey: bob.publicKey, sealPublicKey: bob.sealPublicKey, sealSeen: true, sealRequired: true, rev: 4 }] };

  const merged = reconcilePersist(onDisk, baseline, current).admitted[0];
  assert.ok(sameKey(merged.publicKey, bob2.publicKey), "the rotation held; the retired identity was not restored");
  assert.ok(!merged.sealPublicKey, "the retired sealing key did not come back with the old identity");
});

test("reconcilePersist: a higher-rev edit on the SAME identity still wins (no over-correction)", () => {
  const baseline = { admitted: [{ name: "k", publicKey: bob.publicKey, rev: 1 }] };
  const onDisk = { admitted: [{ name: "k", publicKey: bob.publicKey, rev: 2, note: "disk" }] };
  const current = { admitted: [{ name: "k", publicKey: bob.publicKey, rev: 4, note: "mine" }] };
  assert.equal(reconcilePersist(onDisk, baseline, current).admitted[0].rev, 4, "same-identity higher rev still wins");
});

test("reconcilePersist: a stale writer's higher-rev walk cannot restore a retired seal key on one identity", () => {
  const sNew = generateIdentity();
  // Baseline: peer K, identity bob, the OLD seal key, rev 1.
  const baseline = { admitted: [{ name: "k", publicKey: bob.publicKey, sealPublicKey: bob.sealPublicKey, sealSeen: true, sealRequired: true, rev: 1 }] };
  // Disk: a concurrent accept rotated the SEAL to sNew (same identity), rev 2.
  const onDisk = { admitted: [{ name: "k", publicKey: bob.publicKey, sealPublicKey: sNew.sealPublicKey, sealSeen: true, sealRequired: true, rev: 2 }] };
  // Stale writer: several walks still holding the OLD seal, rev 4.
  const current = { admitted: [{ name: "k", publicKey: bob.publicKey, sealPublicKey: bob.sealPublicKey, sealSeen: true, sealRequired: true, rev: 4 }] };

  const merged = reconcilePersist(onDisk, baseline, current).admitted[0];
  assert.ok(sameKey(merged.sealPublicKey, sNew.sealPublicKey), "the newer seal key held; the retired one was not restored");
});

test("reconcilePersist: concurrent DIFFERENT seal keys on one identity fail closed to a conflict", () => {
  const s1 = generateIdentity();
  const s2 = generateIdentity();
  const baseline = { admitted: [{ name: "k", publicKey: bob.publicKey, rev: 1 }] };
  const onDisk = { admitted: [{ name: "k", publicKey: bob.publicKey, sealPublicKey: s1.sealPublicKey, sealSeen: true, rev: 2 }] };
  const current = { admitted: [{ name: "k", publicKey: bob.publicKey, sealPublicKey: s2.sealPublicKey, sealSeen: true, rev: 4 }] };

  const merged = reconcilePersist(onDisk, baseline, current).admitted[0];
  assert.ok(merged.sealConflict, "disagreeing concurrent seal keys produce a conflict, not a silent pick");
});

test("mergeByRevision: sealRequired is a floor that never regresses, even if it loses the revision", () => {
  const onDisk = [{ name: "bob", publicKey: bob.publicKey, sealRequired: true, rev: 1 }];
  // A higher-rev snapshot that (defensively) lacks the floor must not clear it.
  const snap = [{ name: "bob", publicKey: bob.publicKey, rev: 9 }];
  assert.equal(mergeByRevision(onDisk, snap)[0].sealRequired, true, "seal-required floor held");
});

test("mergeByRevision: a peer present on only one side is kept, not dropped", () => {
  const onDisk = [{ name: "carol", publicKey: bob.publicKey, sealRequired: true, rev: 3 }];
  const snap = [{ name: "bob", publicKey: bob2.publicKey, rev: 1 }];
  const names = mergeByRevision(onDisk, snap).map((p) => p.name).sort();
  assert.deepEqual(names, ["bob", "carol"], "neither the on-disk-only nor the snapshot-only peer is lost");
});

test("reconcilePersist: `forget` actually deletes through the write path (tombstone, not absence)", () => {
  const baseline = { admitted: [{ name: "bob", publicKey: bob.publicKey, rev: 3 }], blocklist: { names: [], keys: [] } };
  const onDisk = { admitted: [{ name: "bob", publicKey: bob.publicKey, rev: 3 }], blocklist: { names: [], keys: [] } };
  const current = { admitted: [], blocklist: { names: [], keys: [] } }; // this command forgot bob
  assert.deepEqual(reconcilePersist(onDisk, baseline, current).admitted, [], "forget is honoured against current disk");
});

test("reconcilePersist: a slow writer does not resurrect a peer another writer forgot", () => {
  const baseline = { admitted: [{ name: "bob", publicKey: bob.publicKey, rev: 3 }] };
  const current = { admitted: [{ name: "bob", publicKey: bob.publicKey, rev: 3 }] }; // this walk still has bob
  const onDisk = { admitted: [] }; // someone forgot bob meanwhile
  assert.deepEqual(reconcilePersist(onDisk, baseline, current).admitted, [], "the forgotten peer stays gone");
});

test("reconcilePersist: a stale writer does not revert a concurrent block it never saw", () => {
  const baseline = { admitted: [], blocklist: { names: [], keys: [] } };
  const current = { admitted: [], blocklist: { names: [], keys: [] } }; // this command touched neither
  const onDisk = { admitted: [], blocklist: { names: ["mallory"], keys: [] } }; // a concurrent `block`
  assert.deepEqual(reconcilePersist(onDisk, baseline, current).blocklist.names, ["mallory"], "concurrent block preserved");
});

test("reconcilePersist: this command's own config change IS written", () => {
  const baseline = { admitted: [], blocklist: { names: [], keys: [] } };
  const current = { admitted: [], blocklist: { names: ["spammer"], keys: [] } }; // THIS command blocked
  const onDisk = { admitted: [], blocklist: { names: [], keys: [] } };
  assert.deepEqual(reconcilePersist(onDisk, baseline, current).blocklist.names, ["spammer"], "the command's block lands");
});

test("reconcilePersist: removing a config key that was null still counts as a change", () => {
  const onDisk = { blocklist: { names: ["later"], keys: [] } }; // a concurrent block
  const baseline = { blocklist: null };
  const current = {}; // this command removed the key
  // Presence-aware: absent != null, so the removal is honoured over the disk value.
  assert.equal("blocklist" in reconcilePersist(onDisk, baseline, current), false, "the removal wins");
});

test("reconcilePersist: an empty state round-trips unchanged (no spurious admitted [])", () => {
  assert.deepEqual(reconcilePersist({}, {}, {}), {}, "no key is materialised for a no-op write");
});

test("setTrust changes the snapshot, so a trust change actually persists", () => {
  const dir = createDirectory({ self: { name: "me" }, trust: { model: "direct" } });
  const baseline = { trust: { ...dir.trust() } };
  dir.setTrust({ model: "web-of-trust" });
  assert.equal(dir.snapshot().trust.model, "web-of-trust", "the directory reflects the change");
  const current = { trust: dir.snapshot().trust };
  const written = reconcilePersist({ trust: { model: "direct" } }, baseline, current);
  assert.equal(written.trust.model, "web-of-trust", "the change lands on disk, not diffed away");
});

test("reconcileBaseline: default-materialised trust on a legacy file does not clobber a concurrent trust edit", () => {
  // A legacy state file predating the trust policy: no `trust` key at all. The
  // constructor materialises a full default trust, but this command changed nothing.
  const stored = { self: { name: "me" }, admitted: [] };
  const dir = createDirectory({ ...stored, self: { ...stored.self, publicKey: "PK" } });
  const baseline = reconcileBaseline(stored, dir.snapshot());
  const current = { ...stored, ...dir.snapshot() };
  // Meanwhile another writer set a trust model on disk, which this process never saw.
  const onDisk = { self: stored.self, admitted: [], trust: { model: "web-of-trust", settings: {}, unknownProfile: "unknown" } };
  assert.equal(reconcilePersist(onDisk, baseline, current).trust.model, "web-of-trust", "the concurrent trust edit survives");

  // Documents the bug: the old raw baseline (no trust) made materialisation look
  // like a change, so the default clobbered the concurrent edit.
  const rawBaseline = JSON.parse(JSON.stringify(stored));
  assert.equal(reconcilePersist(onDisk, rawBaseline, current).trust.model, "direct", "the pre-fix baseline would have clobbered it");
});

test("reconcileBaseline: a materialised empty blocklist does not clobber a concurrent block", () => {
  const stored = { self: { name: "me" }, admitted: [] }; // no blocklist key (legacy)
  const dir = createDirectory({ ...stored, self: { ...stored.self, publicKey: "PK" } });
  const baseline = reconcileBaseline(stored, dir.snapshot());
  const current = { ...stored, ...dir.snapshot() }; // this command blocked nobody
  const onDisk = { self: stored.self, admitted: [], blocklist: { names: ["mallory"], keys: [] } };
  assert.deepEqual(reconcilePersist(onDisk, baseline, current).blocklist.names, ["mallory"], "concurrent block survives");
});

test("reconcileBaseline: identity stamping is still a change — the first-sight write is preserved", () => {
  // self is the deliberate exception: normalising it away would stop a machine
  // ever saving its freshly-stamped identity.
  const legacy = { self: { name: "me" } }; // legacy self, no keys yet
  const dir = createDirectory({ ...legacy, self: { ...legacy.self, publicKey: "PK", sealPublicKey: "SK" } });
  const stamped = reconcilePersist({ self: legacy.self }, reconcileBaseline(legacy, dir.snapshot()), { ...legacy, ...dir.snapshot() });
  assert.ok(stamped.self.publicKey, "the stamped identity is written, not diffed away");

  // And a brand-new machine with no stored self at all still persists its identity.
  const fresh = createDirectory({ self: { name: "host", publicKey: "PK", sealPublicKey: "SK" } });
  const written = reconcilePersist({}, reconcileBaseline({}, fresh.snapshot()), { ...fresh.snapshot() });
  assert.ok(written.self?.publicKey, "identity is written on first sight");
});

test("mergeByRevision: a revision tie resolves to disk (a stale writer does not overwrite)", () => {
  const disk = { name: "bob", publicKey: bob.publicKey, note: "committed", rev: 4 };
  const snap = { name: "bob", publicKey: bob.publicKey, note: "stale", rev: 4 };
  assert.equal(mergeByRevision([disk], [snap])[0].note, "committed", "tie goes to disk");
});

test("four-state gate: unverified → verified → conflict, sealKeyFor/sealState agree", () => {
  const dir = withVerifiedBob();
  assert.equal(dir.sealState("bob"), "verified");
  assert.ok(sameKey(dir.sealKeyFor("bob"), bob.sealPublicKey));

  // A different verified key raises a conflict; the key is withheld.
  dir.bindSealKey("bob", bob2.sealPublicKey, bob.publicKey);
  assert.equal(dir.sealState("bob"), "conflict");
  assert.equal(dir.sealKeyFor("bob"), null);
});

test("a conflict is NOT auto-resolved by re-walking the held key (replay defence)", () => {
  const dir = withVerifiedBob();
  dir.bindSealKey("bob", bob2.sealPublicKey, bob.publicKey); // conflict
  // An attacker replays bob's old, still-valid signed record with the held key.
  dir.bindSealKey("bob", bob.sealPublicKey, bob.publicKey);
  assert.equal(dir.sealState("bob"), "conflict", "a replayable re-walk does not clear a conflict");
});

test("acceptSealKey resolves a conflict deliberately, to the accepted key", () => {
  const dir = withVerifiedBob();
  dir.bindSealKey("bob", bob2.sealPublicKey, bob.publicKey); // conflict, presenting bob2's key
  dir.acceptSealKey("bob"); // accept the conflicting key
  assert.equal(dir.sealState("bob"), "verified");
  assert.ok(sameKey(dir.sealKeyFor("bob"), bob2.sealPublicKey));
});

test("rotateKey drops the key but keeps sealRequired → reverify, which fails sends closed", () => {
  const dir = withVerifiedBob();
  dir.rotateKey("bob", bob2.publicKey);
  assert.equal(dir.sealState("bob"), "reverify", "a peer we have sealed to does not fall back to cleartext after rotation");
  assert.equal(dir.sealKeyFor("bob"), null);
  // Re-verifying against the new identity restores sealing.
  dir.bindSealKey("bob", bob2.sealPublicKey, bob2.publicKey);
  assert.equal(dir.sealState("bob"), "verified");
});

test("a reverify wedge is liftable by accepting an explicit key (not only by re-walking)", () => {
  const dir = withVerifiedBob();
  dir.rotateKey("bob", bob2.publicKey); // reverify, no pending key to default to
  assert.equal(dir.sealState("bob"), "reverify");
  dir.acceptSealKey("bob", bob2.sealPublicKey); // operator provides the new key explicitly
  assert.equal(dir.sealState("bob"), "verified");
  assert.ok(sameKey(dir.sealKeyFor("bob"), bob2.sealPublicKey));
});

test("a conflict keeps the first-seen pending key; a later different key cannot flip it", () => {
  const dir = withVerifiedBob();
  const first = generateIdentity();
  const second = generateIdentity();
  dir.bindSealKey("bob", first.sealPublicKey, bob.publicKey); // conflict, pending = first
  dir.bindSealKey("bob", second.sealPublicKey, bob.publicKey); // attacker alternates
  dir.acceptSealKey("bob"); // accepts the pending (first-seen) key
  assert.ok(sameKey(dir.sealKeyFor("bob"), first.sealPublicKey), "the first disagreeing key is what gets accepted, not a later swap");
});

test("bindSealKey refuses when the identity changed under it (walk TOCTOU), including to keyless", () => {
  const dir = createDirectory({ self: { name: "me", publicKey: generateIdentity().publicKey } });
  dir.admit({ name: "bob", publicKey: bob.publicKey, addresses: [{ value: "https://127.0.0.1:9" }] });
  dir.bindSealKey("bob", bob.sealPublicKey, bob2.publicKey); // proof was for a different identity
  assert.equal(dir.sealState("bob"), "unverified", "proof for a different identity is refused");

  // ABA: the record went keyless under a concurrent adoption; a null current
  // identity must also be refused when an expected identity was supplied.
  const dir2 = createDirectory({ self: { name: "me", publicKey: generateIdentity().publicKey } });
  dir2.admit({ name: "bob", addresses: [{ value: "https://127.0.0.1:9" }] }); // no identity key
  dir2.bindSealKey("bob", bob.sealPublicKey, bob.publicKey);
  assert.equal(dir2.sealState("bob"), "unverified", "a keyless record is not bound against an expected identity");
});

test("seal trust round-trips through serialize → reload intact", () => {
  const dir = withVerifiedBob();
  dir.bindSealKey("bob", bob2.sealPublicKey, bob.publicKey); // conflict
  const reloaded = createDirectory({ self: dir.self, admitted: dir.snapshot().admitted });
  assert.equal(reloaded.sealState("bob"), "conflict", "a conflict a person must resolve survives a restart");

  const clean = withVerifiedBob();
  const back = createDirectory({ self: clean.self, admitted: clean.snapshot().admitted });
  assert.equal(back.sealState("bob"), "verified", "a verified key survives a restart");
  assert.ok(sameKey(back.sealKeyFor("bob"), bob.sealPublicKey));
});

test("a real walk binds the sealing key from the peer's signed record", async () => {
  const dir = createDirectory({ self: { name: "here", publicKey: generateIdentity().publicKey } });
  dir.admit({ name: "bob", publicKey: bob.publicKey, addresses: [{ transport: "lan", value: "http://bob:8787" }] });
  assert.equal(dir.sealKeyFor("bob"), null, "not sealed to before any walk");

  const signed = signRecord(makePeerRecord({ name: "bob", publicKey: bob.publicKey, sealPublicKey: bob.sealPublicKey }), bob.privateKey);
  const fetchImpl = async (url) => {
    if (url.replace(/\/hail$/, "") !== "http://bob:8787") throw new Error("ECONNREFUSED");
    return { ok: true, json: async () => ({ self: { name: "bob" }, peers: [], signed }) };
  };

  const result = await walk(dir, { fetchImpl });
  assert.deepEqual(result.reached.map((p) => p.name), ["bob"]);
  assert.equal(dir.sealState("bob"), "verified", "the walk bound the sealing key");
  assert.ok(sameKey(dir.sealKeyFor("bob"), bob.sealPublicKey));
});
