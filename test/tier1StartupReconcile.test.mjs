/**
 * Durable Tier-1 invalidation at COLD START (Sol findings F1 + F2).
 *
 * A `hail forget`/`hail rotate` or a conflict done while the daemon is DOWN has no live
 * seal-posture listener to fire. F1 makes those survive a restart with directory tombstones
 * plus a startup reconcile; F2 makes a swallowed restricting persist heal (a directory
 * tombstone for a forget, a flagged retry for a conflict). The security property under test:
 * after a restart, a retired/approved key is REFUSED, never sealed to.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { createDirectory } from "../src/directory.js";
import { generateIdentity, normalizeKey } from "../src/identity.js";
import { keyId } from "../src/routeManifest.js";
import { signRecord } from "../src/peerRecord.js";
import { createRoutedKeyStore } from "../src/routedKeyStore.js";
import { resolveRoutedSeal } from "../src/routedSealResolver.js";

const recordOf = (id, sealPublicKey = id.sealPublicKey) =>
  signRecord({ name: "peer", publicKey: id.publicKey, sealPublicKey, addresses: [], lastSeen: null }, id.privateKey);

/** The daemon's cold-start reconcile (bin/hail.js), replicated so its two steps can be
 * driven in isolation: apply the directory's tombstones, then sweep any Tier-1 entry a
 * Tier-0 posture supersedes. Returns what each step touched. */
const reconcile = (store, directory) => {
  const dropped = store.applyTombstones(directory.tombstones());
  let swept = 0;
  for (const record of directory.listAdmitted()) {
    try {
      if (directory.sealForIdentity(record.publicKey).state !== "unverified") {
        const kid = keyId(record.publicKey);
        if (store.recordState(kid) !== "none") {
          store.forget(kid);
          swept += 1;
        }
      }
    } catch {
      /* a non-Ed25519 key can hold no routed entry */
    }
  }
  return { dropped, swept };
};

/** Whether a send to `kid` would be REFUSED given a forgotten (unverified Tier-0) identity —
 * the exact resolver call the send path makes, so a "none" Tier-1 state proves confidentiality. */
const wouldRefuse = (store, kid) => {
  const decision = resolveRoutedSeal({
    tier0: { state: "unverified", key: null },
    tier1: { state: store.recordState(kid), key: store.recordSealKey(kid) },
  });
  return decision.decision === "refuse";
};

// ---------------------------------------------------------------------------------------
// F1 — durable identity tombstones + startup reconcile
// ---------------------------------------------------------------------------------------

test("F1 kill shot: an offline forget refuses to seal to the stale approved key after a restart", () => {
  const alice = generateIdentity();
  const kid = keyId(alice.publicKey);

  // A daemon that discovered and approved alice's Tier-1 key, then persisted.
  const before = createRoutedKeyStore();
  before.observe(kid, recordOf(alice));
  before.approve(kid);
  const persisted = before.snapshot();

  // Before the fix, restarting into that snapshot would seal to the stale key:
  const naive = createRoutedKeyStore({ initial: persisted });
  assert.equal(naive.recordState(kid), "record-approved");
  assert.ok(!wouldRefuse(naive, kid), "the pre-reconcile store would still seal — the bug");

  // Offline forget: no daemon, so route-keys.json is untouched, but directory.json gains a
  // tombstone (its own write is fail-loud).
  const directory = createDirectory({ self: { name: "me" } });
  directory.admit({ name: "alice", publicKey: alice.publicKey });
  directory.forget("alice");

  // Restart: rehydrate the STALE sidecar, then run the reconcile.
  const restarted = createRoutedKeyStore({ initial: persisted });
  const { dropped } = reconcile(restarted, directory);
  assert.deepEqual(dropped, [kid], "the tombstone dropped the retired key");
  assert.equal(restarted.recordState(kid), "none");
  assert.ok(wouldRefuse(restarted, kid), "the send now REFUSES instead of sealing to the stale key");
});

test("F1 kill shot: an offline rotate retires the old identity; the new identity is ungoverned by the tombstone", () => {
  const oldId = generateIdentity();
  const newId = generateIdentity();
  const oldKid = keyId(oldId.publicKey);
  const newKid = keyId(newId.publicKey);

  const before = createRoutedKeyStore();
  before.observe(oldKid, recordOf(oldId));
  before.approve(oldKid);
  // A separate, legitimate Tier-1 approval for what will become the new identity.
  before.observe(newKid, recordOf(newId));
  before.approve(newKid);
  const persisted = before.snapshot();

  const directory = createDirectory({ self: { name: "me" } });
  directory.admit({ name: "peer", publicKey: oldId.publicKey });
  directory.rotateKey("peer", newId.publicKey);

  const restarted = createRoutedKeyStore({ initial: persisted });
  reconcile(restarted, directory);
  assert.equal(restarted.recordState(oldKid), "none", "the retired identity's key is gone");
  assert.equal(restarted.recordState(newKid), "record-approved", "the new identity's key is untouched by the rotate tombstone");
});

test("a deliberate re-approval AFTER a forget survives later restarts (newer `at` outranks the tombstone)", () => {
  const alice = generateIdentity();
  const kid = keyId(alice.publicKey);

  const directory = createDirectory({ self: { name: "me" }, now: () => 1000 });
  directory.admit({ name: "alice", publicKey: alice.publicKey });
  directory.forget("alice"); // tombstone at t=1000

  // Later, alice is re-discovered and DELIBERATELY re-approved — a newer claim.
  const store = createRoutedKeyStore();
  store.observe(kid, recordOf(alice)); // `at` = Date.now() (>> 1000)
  store.approve(kid);
  const persisted = store.snapshot();

  const restarted = createRoutedKeyStore({ initial: persisted });
  const { dropped } = reconcile(restarted, directory);
  assert.deepEqual(dropped, [], "the newer re-approval is not undone by the older tombstone");
  assert.equal(restarted.recordState(kid), "record-approved");
});

test("a legacy entry with no `at` is outranked by any tombstone (migration is fail-closed)", () => {
  const alice = generateIdentity();
  const kid = keyId(alice.publicKey);
  const genuine = recordOf(alice);

  // A pre-upgrade persisted entry carries no `at` (loads as 0).
  const legacy = [{ id: kid, sealKey: normalizeKey(alice.sealPublicKey), record: genuine, approved: true, conflict: false, name: "alice" }];
  const store = createRoutedKeyStore({ initial: legacy });
  assert.equal(store.recordState(kid), "record-approved");

  const dropped = store.applyTombstones([{ keyId: kid, at: 1, reason: "forget" }]);
  assert.deepEqual(dropped, [kid], "at=0 <= any tombstone -> forgotten");
  assert.equal(store.recordState(kid), "none");
});

test("a never-admitted, never-tombstoned approved entry survives the full reconcile", () => {
  // The whole trap avoided: absence-from-directory is NOT a forget signal.
  const stranger = generateIdentity();
  const kid = keyId(stranger.publicKey);
  const store = createRoutedKeyStore();
  store.observe(kid, recordOf(stranger));
  store.approve(kid);

  const directory = createDirectory({ self: { name: "me" } }); // stranger is not in it
  const { dropped, swept } = reconcile(store, directory);
  assert.deepEqual(dropped, [], "no tombstone touches it");
  assert.equal(swept, 0, "no Tier-0 posture touches it");
  assert.equal(store.recordState(kid), "record-approved", "a legitimate never-walked Tier-1 key survives");
});

test("posture sweep: a walked admitted peer's Tier-1 key is dropped; an unwalked peer's survives", () => {
  const walked = generateIdentity();
  const unwalked = generateIdentity();
  const walkedKid = keyId(walked.publicKey);
  const unwalkedKid = keyId(unwalked.publicKey);

  const store = createRoutedKeyStore();
  store.observe(walkedKid, recordOf(walked));
  store.approve(walkedKid);
  store.observe(unwalkedKid, recordOf(unwalked));
  store.approve(unwalkedKid);

  const directory = createDirectory({ self: { name: "me" } });
  // `walked` has a Tier-0 seal posture (a bound, ever-seen key); `unwalked` is admitted only.
  directory.adopt({
    admitted: [
      { name: "walked", publicKey: walked.publicKey, sealPublicKey: normalizeKey(walked.sealPublicKey), sealSeen: true, profile: "trusted" },
      { name: "unwalked", publicKey: unwalked.publicKey, profile: "trusted" },
    ],
  });
  // adopt's own notify would already have fired in this in-process directory; forget both
  // Tier-1 entries first is NOT what we want — re-seed after adopt to isolate the sweep.
  store.observe(walkedKid, recordOf(walked));
  store.approve(walkedKid);
  store.observe(unwalkedKid, recordOf(unwalked));
  store.approve(unwalkedKid);

  const { swept } = reconcile(store, directory);
  assert.equal(swept, 1, "only the walked peer's entry was swept");
  assert.equal(store.recordState(walkedKid), "none", "the walked peer's Tier-1 key is superseded by Tier 0");
  assert.equal(store.recordState(unwalkedKid), "record-approved", "the unwalked peer's approved key survives");
});

// ---------------------------------------------------------------------------------------
// F2 — restricting transitions become durable; the hot path stays best-effort
// ---------------------------------------------------------------------------------------

test("only a conflict and a forget flag the persist as restricting; observe/approve do not", () => {
  const calls = [];
  const store = createRoutedKeyStore({ persist: (_entries, meta) => calls.push(meta?.restricting === true) });
  const d = generateIdentity();
  const kid = keyId(d.publicKey);
  const stale = generateIdentity();

  store.observe(kid, recordOf(d)); // new discovery — additive
  store.approve(kid); // approval — additive
  assert.deepEqual(calls, [false, false], "the adding path is best-effort, not restricting");

  store.observe(kid, recordOf(d, normalizeKey(stale.sealPublicKey))); // conflict — restricting
  assert.equal(calls.at(-1), true, "the conflict transition flags restricting");

  store.forget(kid); // forget — restricting
  assert.equal(calls.at(-1), true, "a forget flags restricting");
});

test("F2 kill shot: a failed-then-retried conflict persist keeps the conflict across a restart", () => {
  const d = generateIdentity();
  const kid = keyId(d.publicKey);
  const stale = generateIdentity();

  const port = { mode: "ok", disk: null };
  const store = createRoutedKeyStore({
    persist: (entries) => {
      if (port.mode === "throw") throw new Error("disk full");
      port.disk = entries;
    },
  });
  store.observe(kid, recordOf(d));
  store.approve(kid); // disk now holds an APPROVED key for d

  // The conflict-voiding persist FAILS (full disk) and is swallowed: memory is conflicted,
  // but disk still holds the approved key — a restart here would resurrect it (the bug).
  port.mode = "throw";
  assert.equal(store.observe(kid, recordOf(d, normalizeKey(stale.sealPublicKey))), "record-conflict");
  assert.equal(createRoutedKeyStore({ initial: port.disk }).recordState(kid), "record-approved", "pre-retry disk would resurrect the voided key");

  // The daemon's bounded retry rewrites the store's CURRENT snapshot once a write can land.
  port.mode = "ok";
  port.disk = store.snapshot();

  // Restart from the retried disk: the conflict is durable and still refuses to pick.
  const restarted = createRoutedKeyStore({ initial: port.disk });
  assert.equal(restarted.recordState(kid), "record-conflict");
  assert.equal(restarted.recordSealKey(kid), null, "a restored conflict seals to nothing");
});

test("F2: a forget whose sidecar persist permanently fails still heals via the F1 tombstone", () => {
  const alice = generateIdentity();
  const kid = keyId(alice.publicKey);

  // A store whose persist ALWAYS fails: the sidecar can never record the forget.
  const stale = createRoutedKeyStore();
  stale.observe(kid, recordOf(alice));
  stale.approve(kid);
  const staleDisk = stale.snapshot(); // holds the approved key; a forget will never overwrite it

  // The operator forgets alice — the directory tombstone write is fail-loud and lands.
  const directory = createDirectory({ self: { name: "me" } });
  directory.admit({ name: "alice", publicKey: alice.publicKey });
  directory.forget("alice");

  // Restart from the stale sidecar (the forget's route-keys write was lost): the reconcile's
  // tombstone application heals the shed forget.
  const restarted = createRoutedKeyStore({ initial: staleDisk });
  const { dropped } = reconcile(restarted, directory);
  assert.deepEqual(dropped, [kid]);
  assert.equal(restarted.recordState(kid), "none", "the F1 machinery heals a forget the F2 sidecar could not persist");
});
