/**
 * The sealing key's trust must survive the write path and rotation, not just the
 * happy load path. These cover the per-record revision merge (a stale writer must
 * not roll back newer trust, and must not open a cleartext window), the four-state
 * seal gate, the walk's TOCTOU guard, operator conflict resolution, and a real
 * walk binding the key from a signed record.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createDirectory, mergeByRevision, reconcilePersist } from "../src/directory.js";
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
