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
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { createDirectory, finalizeRouteGens, reconcileBaseline, reconcilePersist } from "../src/directory.js";
import { generateIdentity, normalizeKey } from "../src/identity.js";
import { keyId } from "../src/routeManifest.js";
import { signRecord } from "../src/peerRecord.js";
import { createRoutedKeyStore } from "../src/routedKeyStore.js";
import { resolveRoutedSeal } from "../src/routedSealResolver.js";
import { loadState, saveState, updateState } from "../src/state.js";

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

test("a deliberate re-approval AFTER a forget survives later restarts (a claim that saw the tombstone outranks it)", () => {
  const alice = generateIdentity();
  const kid = keyId(alice.publicKey);

  const directory = createDirectory({ self: { name: "me" }, now: () => 1000 });
  directory.admit({ name: "alice", publicKey: alice.publicKey });
  directory.forget("alice"); // provisional tombstone (at t=1000)
  // The forget is finalized under the state lock at write time; the running daemon then adopts
  // the written state, so its routeGen reflects the retirement (gen 1).
  directory.adopt(finalizeRouteGens({ ...directory.snapshot() }));
  assert.equal(directory.routeGen(), 1, "the finalized forget is gen 1");

  // Later, alice is re-discovered and DELIBERATELY re-approved — a claim made by a daemon that
  // has ADOPTED the tombstone, so it stamps gen == the tombstone's (a tie keeps). The gen
  // supplier mirrors the real daemon wiring (bin/hail.js); without it a gen-less re-approval
  // would (correctly, case 2) be forgotten against the gen-bearing tombstone.
  const store = createRoutedKeyStore({ gen: () => directory.routeGen() });
  store.observe(kid, recordOf(alice));
  store.approve(kid);
  const persisted = store.snapshot();

  const restarted = createRoutedKeyStore({ initial: persisted });
  const { dropped } = reconcile(restarted, directory);
  assert.deepEqual(dropped, [], "the re-approval that saw the forget is not undone by it");
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

// =======================================================================================
// R2 — logical generation: ordering is CAUSAL, never a wall clock
// =======================================================================================

test("R2 kill shot: a forget forgets a stale approval even when the wall clock inverts (entry.at > tombstone.at)", () => {
  const alice = generateIdentity();
  const kid = keyId(alice.publicKey);

  // A daemon whose clock is far AHEAD approves alice (entry `at` huge, gen 5).
  const store = createRoutedKeyStore({ gen: () => 5 });
  store.observe(kid, recordOf(alice));
  store.approve(kid);
  const persisted = store.snapshot();
  assert.ok(persisted[0].at > 1000, "the approval's wall clock is ahead of the forget's");
  assert.equal(persisted[0].gen, 5, "the approval stamped gen 5");

  // The clock is corrected BACKWARD before a later offline forget: tombstone at t=1000, but
  // gen 6 (a retirement bumps routeGen first). The old `at <= at` rule KEPT the retired key
  // here (entry.at > 1000); the gen rule forgets it (5 < 6).
  const directory = createDirectory({ self: { name: "me" }, now: () => 1000, routeGen: 5 });
  directory.admit({ name: "alice", publicKey: alice.publicKey });
  directory.forget("alice");
  const finalized = finalizeRouteGens({ ...directory.snapshot() });
  assert.equal(finalized.tombstones[0].gen, 6, "finalization minted gen 6 (strictly above routeGen 5)");

  const restarted = createRoutedKeyStore({ initial: persisted });
  const dropped = restarted.applyTombstones(finalized.tombstones);
  assert.deepEqual(dropped, [kid], "forgotten by causal order despite the inverted wall clock");
  assert.equal(restarted.recordState(kid), "none");
});

test("R2: an approval made in IGNORANCE of a forget is forgotten; one made after adopting it survives", () => {
  const alice = generateIdentity();
  const kid = keyId(alice.publicKey);
  const tombstone = [{ keyId: kid, at: 5, reason: "forget", gen: 5 }];

  // Ignorance: approved at gen 4 (< 5) — the approver never saw the retirement.
  const ignorant = createRoutedKeyStore({ gen: () => 4 });
  ignorant.observe(kid, recordOf(alice));
  ignorant.approve(kid);
  assert.deepEqual(ignorant.applyTombstones(tombstone), [kid], "gen 4 < 5 -> forgotten (fail-closed)");

  // Knowledge: approved at gen 5 (== the tombstone's) — the approver had adopted it. Tie keeps.
  const aware = createRoutedKeyStore({ gen: () => 5 });
  aware.observe(kid, recordOf(alice));
  aware.approve(kid);
  assert.deepEqual(aware.applyTombstones(tombstone), [], "gen 5 == 5 -> kept (the approver saw it)");
});

test("R2: the four-case comparison matrix", () => {
  const id = generateIdentity();
  const kid = keyId(id.publicKey);
  const rec = recordOf(id);
  const mk = (gen) => {
    const s = createRoutedKeyStore(gen === undefined ? {} : { gen: () => gen });
    s.observe(kid, rec);
    s.approve(kid);
    return s;
  };

  // 1. both gen -> strict: 3 < 4 forgets; 4 vs 4 (tie) and 5 vs 4 keep.
  assert.deepEqual(mk(3).applyTombstones([{ keyId: kid, gen: 4 }]), [kid], "gen 3 < 4 forgets");
  assert.deepEqual(mk(4).applyTombstones([{ keyId: kid, gen: 4 }]), [], "gen tie keeps");
  assert.deepEqual(mk(5).applyTombstones([{ keyId: kid, gen: 4 }]), [], "gen 5 > 4 keeps");
  // 2. gen tombstone, gen-less entry -> forget.
  assert.deepEqual(mk(undefined).applyTombstones([{ keyId: kid, gen: 4 }]), [kid], "gen tombstone beats a gen-less entry");
  // 3. gen-less tombstone, gen entry -> keep.
  assert.deepEqual(mk(7).applyTombstones([{ keyId: kid, at: 9_999_999_999 }]), [], "a gen-less tombstone loses to a gen entry");
  // 4. both gen-less -> legacy at <= at. A rehydrated pre-upgrade entry carries at=0, no gen.
  const legacy = [{ id: kid, sealKey: normalizeKey(id.sealPublicKey), record: rec, approved: true, conflict: false, name: "x", at: 0 }];
  const s4 = createRoutedKeyStore({ initial: legacy });
  assert.deepEqual(s4.applyTombstones([{ keyId: kid, at: 1 }]), [kid], "both legacy: at 0 <= 1 forgets (fail-closed)");
});

// =======================================================================================
// R1 — cap safety: never evict, prune only by consumption
// =======================================================================================

test("R1 kill shot: 300 offline forgets all survive (no eviction) and the 1st still drops its key", () => {
  // The old cap was 256; the 1st retirement's tombstone used to be evicted at #257, resurrecting
  // its approved key at the next cold start. Now nothing is evicted.
  const victims = Array.from({ length: 300 }, () => generateIdentity());
  const firstKid = keyId(victims[0].publicKey);

  const directory = createDirectory({ self: { name: "me" } });
  // Approve the FIRST victim's Tier-1 key in a store wired to the directory's gen.
  const store = createRoutedKeyStore({ gen: () => directory.routeGen() });
  store.observe(firstKid, recordOf(victims[0]));
  store.approve(firstKid); // stamped at the pre-forget gen (0)

  for (const v of victims) {
    directory.admit({ name: `v-${keyId(v.publicKey).slice(0, 8)}`, publicKey: v.publicKey });
    directory.forget(`v-${keyId(v.publicKey).slice(0, 8)}`);
  }
  assert.equal(directory.tombstones().length, 300, "all 300 tombstones are retained — no cap eviction");

  const restarted = createRoutedKeyStore({ initial: store.snapshot() });
  const dropped = restarted.applyTombstones(directory.tombstones());
  assert.deepEqual(dropped, [firstKid], "the 1st retirement's tombstone still drops its key (gen 0 < its tombstone gen)");
  assert.equal(restarted.recordState(firstKid), "none");
});

test("R1: forged tombstones cannot crowd out a genuine one, and the genuine one still kills its entry", () => {
  const alice = generateIdentity();
  const kid = keyId(alice.publicKey);

  const directory = createDirectory({ self: { name: "me" } });
  const store = createRoutedKeyStore({ gen: () => directory.routeGen() });
  store.observe(kid, recordOf(alice));
  store.approve(kid); // gen 0

  directory.admit({ name: "alice", publicKey: alice.publicKey });
  directory.forget("alice"); // provisional; finalized to the genuine gen-1 tombstone
  const finalized = finalizeRouteGens({ ...directory.snapshot() });
  const genuine = finalized.tombstones[0];
  assert.equal(genuine.gen, 1, "the genuine tombstone is gen 1");

  // 300 shape-valid forged tombstones with huge `at`/gen, hand-injected alongside the genuine one.
  const forged = Array.from({ length: 300 }, (_, i) => ({ keyId: i.toString(36).padStart(43, "0"), at: 9e12, reason: "forget", gen: 9e9 + i }));
  const reloaded = createDirectory({ ...finalized, tombstones: [...forged, genuine] });
  assert.equal(reloaded.tombstones().length, 301, "the genuine tombstone survives load beside 300 forged ones");
  assert.ok(reloaded.tombstones().some((t) => t.keyId === kid), "the genuine tombstone is not crowded out");

  const restarted = createRoutedKeyStore({ initial: store.snapshot() });
  const dropped = restarted.applyTombstones(reloaded.tombstones());
  assert.ok(dropped.includes(kid), "the genuine tombstone still kills its entry");
});

test("R1: a hand-rolled-back routeGen self-heals via load-as-max over the tombstones' own gens", () => {
  const snap = { self: { name: "me" }, tombstones: [{ keyId: "a".repeat(43), at: 1, reason: "forget", gen: 42 }], routeGen: 0 };
  const dir = createDirectory(snap);
  assert.equal(dir.routeGen(), 42, "routeGen floored up to the evidence even though the field said 0");
});

// =======================================================================================
// R1 — consume-after-durable startup sequence (mirrors bin/hail.js, driven over real files)
// =======================================================================================

const scratch = () => {
  const dir = mkdtempSync(join(tmpdir(), "ph-t1-"));
  return { statePath: join(dir, "directory.json"), keysPath: join(dir, "route-keys.json") };
};

/** Mirror of the daemon's 4-step cold-start reconcile (bin/hail.js), driven over real state
 * files so the durable-before-consume ordering is exercised against the real state/directory.
 * `saveSidecar` stands in for the durable route-keys write and may throw to simulate a failure. */
const consumeAfterDurable = (store, directory, statePath, saveSidecar) => {
  const pending = directory.tombstones();
  const N = directory.routeGen();
  const dropped = store.applyTombstones(pending);
  const anyMatch = pending.some((t) => store.recordState(t.keyId) !== "none");
  let durable = true;
  if (dropped.length || anyMatch) {
    try {
      saveSidecar(store.snapshot());
    } catch {
      durable = false;
    }
  }
  if (durable && pending.length) {
    updateState(statePath, (onDisk) => {
      const applied = Math.max(Number(onDisk?.routeGenApplied) || 0, N);
      const processed = new Set(pending.map((t) => t.keyId));
      const keep = (t) => {
        if (!t || typeof t.keyId !== "string" || !processed.has(t.keyId)) return true;
        const consumable = typeof t.gen === "number" ? t.gen <= N : true;
        return !consumable;
      };
      return { ...onDisk, routeGenApplied: applied, tombstones: (Array.isArray(onDisk?.tombstones) ? onDisk.tombstones : []).filter(keep) };
    });
    directory.markTombstonesApplied(N);
  }
  return { dropped, durable };
};

test("R1 consume-after-durable: a failed durable persist SKIPS consumption; a healed retry consumes", () => {
  const { statePath } = scratch();
  const alice = generateIdentity();
  const kid = keyId(alice.publicKey);

  const directory = createDirectory({ self: { name: "me" } });
  directory.admit({ name: "alice", publicKey: alice.publicKey });
  directory.forget("alice"); // provisional; finalized to gen 1 at write
  saveState(finalizeRouteGens({ ...directory.snapshot() }), statePath); // the CLI's finalized directory.json on disk

  // A stale sidecar still holding the approved key.
  const seed = createRoutedKeyStore();
  seed.observe(kid, recordOf(alice));
  seed.approve(kid);
  const staleDisk = seed.snapshot();

  // Boot 1: reload the finalized directory from disk (as the daemon does); the durable sidecar
  // write THROWS, so consumption must be skipped.
  const dir1 = createDirectory(loadState(statePath));
  const boot1 = createRoutedKeyStore({ initial: staleDisk });
  const r1 = consumeAfterDurable(boot1, dir1, statePath, () => {
    throw new Error("disk full");
  });
  assert.deepEqual(r1.dropped, [kid], "the tombstone was applied in memory");
  assert.equal(r1.durable, false);
  assert.equal(loadState(statePath).tombstones.length, 1, "the tombstone stays pending — the forget was never durable");
  assert.ok(!loadState(statePath).routeGenApplied, "routeGenApplied was NOT advanced");

  // Boot 2: the persist heals. Now it consumes.
  let sidecarDisk = null;
  const dir2 = createDirectory(loadState(statePath)); // re-loads, tombstone still pending
  const boot2 = createRoutedKeyStore({ initial: staleDisk });
  const r2 = consumeAfterDurable(boot2, dir2, statePath, (snap) => {
    sidecarDisk = snap;
  });
  assert.deepEqual(r2.dropped, [kid]);
  assert.equal(r2.durable, true);
  assert.equal(createRoutedKeyStore({ initial: sidecarDisk }).recordState(kid), "none", "the durable sidecar no longer holds the key");
  assert.deepEqual(loadState(statePath).tombstones ?? [], [], "the tombstone is now consumed");
  assert.equal(loadState(statePath).routeGenApplied, 1, "routeGenApplied advanced to N");
});

test("R1 crash-window equivalence: a durable-persist-then-crash (consume never ran) re-applies idempotently next boot", () => {
  const { statePath } = scratch();
  const alice = generateIdentity();
  const kid = keyId(alice.publicKey);

  const directory = createDirectory({ self: { name: "me" } });
  directory.admit({ name: "alice", publicKey: alice.publicKey });
  directory.forget("alice");
  saveState(finalizeRouteGens({ ...directory.snapshot() }), statePath); // finalized: tombstone gen 1

  // The forget IS durably in the sidecar (step 2 succeeded), but the process crashed before
  // step 3 — so the tombstone is still on disk and the sidecar no longer holds alice.
  const sidecarAfterStep2 = createRoutedKeyStore().snapshot(); // empty: alice already removed

  const dir = createDirectory(loadState(statePath));
  const boot = createRoutedKeyStore({ initial: sidecarAfterStep2 });
  const { dropped, durable } = consumeAfterDurable(boot, dir, statePath, () => {});
  assert.deepEqual(dropped, [], "no entry to drop — idempotent");
  assert.equal(durable, true);
  assert.deepEqual(loadState(statePath).tombstones ?? [], [], "the moot tombstone is consumed this boot");
});

test("R1: a concurrent CLI forget (gen N+1) during consumption survives the filter", () => {
  const { statePath } = scratch();
  const alice = generateIdentity();
  const kid = keyId(alice.publicKey);

  const directory = createDirectory({ self: { name: "me" } });
  directory.admit({ name: "alice", publicKey: alice.publicKey });
  directory.forget("alice"); // provisional; finalized to gen 1 — this boot processes N=1
  saveState(finalizeRouteGens({ ...directory.snapshot() }), statePath);
  const booted = createDirectory(loadState(statePath)); // the daemon boots the finalized directory (routeGen 1)

  const seed = createRoutedKeyStore();
  seed.observe(kid, recordOf(alice));
  seed.approve(kid);
  const boot = createRoutedKeyStore({ initial: seed.snapshot() });

  // Between the sidecar write and the consume, a concurrent CLI re-forget lands a gen-2
  // tombstone for the SAME id on disk (simulated by editing statePath just before consume).
  saveState({ ...loadState(statePath), tombstones: [{ keyId: kid, at: 2, reason: "forget", gen: 2 }], routeGen: 2 }, statePath);

  consumeAfterDurable(boot, booted, statePath, () => {});
  const after = loadState(statePath).tombstones ?? [];
  assert.deepEqual(after, [{ keyId: kid, at: 2, reason: "forget", gen: 2 }], "the gen-2 concurrent forget survives (gen 2 > N=1)");
});

test("R1: reconcilePersist max-merges the counters and never resurrects a consumed tombstone", () => {
  const kid = "a".repeat(43);
  // onDisk already consumed the gen-5 tombstone (routeGenApplied 5, list empty); a stale writer's
  // baseline+current still carry it. The merge must not bring it back.
  const result = reconcilePersist(
    { tombstones: [], routeGen: 5, routeGenApplied: 5 },
    { tombstones: [{ keyId: kid, at: 1, reason: "forget", gen: 5 }], routeGen: 5, routeGenApplied: 0 },
    { tombstones: [{ keyId: kid, at: 1, reason: "forget", gen: 5 }], routeGen: 5, routeGenApplied: 0 },
  );
  assert.equal(result.routeGen, 5, "routeGen max-merged");
  assert.equal(result.routeGenApplied, 5, "routeGenApplied max-merged to the durable high-water mark");
  assert.ok(!result.tombstones || result.tombstones.length === 0, "the consumed tombstone is not resurrected");
});

// =======================================================================================
// R3 — durability: restricting writes are fsync'd
// =======================================================================================

test("R3: only a restricting store mutation maps to a durable sidecar write", () => {
  // The exact mapping the daemon uses: persistSidecar passes `durable: meta?.restricting === true`.
  const calls = [];
  const store = createRoutedKeyStore({ persist: (_entries, meta) => calls.push(meta?.restricting === true) });
  const d = generateIdentity();
  const kid = keyId(d.publicKey);
  const stale = generateIdentity();

  store.observe(kid, recordOf(d)); // additive -> not durable
  store.approve(kid); // additive -> not durable
  store.observe(kid, recordOf(d, normalizeKey(stale.sealPublicKey))); // conflict -> durable
  store.forget(kid); // forget -> durable
  assert.deepEqual(calls, [false, false, true, true], "restricting <-> durable exactly on the conflict and the forget");
});

test("R3: saveState durable mode writes a readable, renamed file", () => {
  const { keysPath } = scratch();
  const payload = { entries: [{ id: "x", gen: 3 }] };
  assert.equal(saveState(payload, keysPath, { durable: true }), keysPath);
  assert.deepEqual(loadState(keysPath), payload, "the durable write is readable after the fsync+rename");
});

test("routeGen load-as-max is floored by routeGenApplied — a rolled-back field cannot swallow a future forget (Sol F2/Fable F1)", () => {
  // After consumption a tombstone is gone and routeGenApplied is the only surviving evidence.
  // A hand-rolled-back routeGen field must still load at least routeGenApplied, or the next
  // genuine forget would mint a gen already <= applied and be pruned before it is ever applied.
  const directory = createDirectory({ self: { name: "me" }, routeGen: 0, routeGenApplied: 5 });
  assert.equal(directory.routeGen(), 5, "routeGen is floored by routeGenApplied on load");
});

// =======================================================================================
// gen-under-lock: generations are ALLOCATED under the state lock (Sol HIGH — concurrent
// retirements collide). tombstone() mints a PROVISIONAL (gen: null); finalizeRouteGens, run
// inside reconcilePersist (CLI) and applyChange (daemon) under withStateLock, allocates it
// strictly above on-disk truth. The two kill shots reproduce the exact CLI race.
// =======================================================================================

/** A stale CLI writer, the exact bin/hail.js shape: it reads state once at "startup" (its
 * `baseline`), mutates a long-lived directory, and persists via `reconcilePersist` under the
 * state lock — so a second writer that loaded the same stale snapshot rebases against whatever
 * the first committed. */
const staleWriter = (statePath) => {
  const stored = loadState(statePath);
  const dir = createDirectory(stored);
  const baseline = reconcileBaseline(stored, dir.snapshot());
  return {
    dir,
    persist: () => updateState(statePath, (onDisk) => reconcilePersist(onDisk, baseline, { ...stored, ...dir.snapshot() })),
  };
};

/** The boot consume (bin/hail.js step 3), driven directly: raise `routeGenApplied` to the
 * directory's routeGen and drop every tombstone with `gen <= that`. */
const bootConsume = (statePath) => {
  const N = createDirectory(loadState(statePath)).routeGen();
  updateState(statePath, (onDisk) => ({
    ...onDisk,
    routeGenApplied: Math.max(Number(onDisk?.routeGenApplied) || 0, N),
    tombstones: (Array.isArray(onDisk?.tombstones) ? onDisk.tombstones : []).filter((t) => !(typeof t?.gen === "number" && t.gen <= N)),
  }));
  return N;
};

test("gen-under-lock kill shot (repro 1): a stale second writer's retirement lands ABOVE routeGenApplied, not pruned-as-applied", () => {
  const { statePath } = scratch();
  const alice = generateIdentity();
  const bob = generateIdentity();
  const bobKid = keyId(bob.publicKey);

  // Seed: two admitted peers, routeGen N = 5.
  const seed = createDirectory({ self: { name: "me" }, routeGen: 5 });
  seed.admit({ name: "alice", publicKey: alice.publicKey });
  seed.admit({ name: "bob", publicKey: bob.publicKey });
  saveState(seed.snapshot(), statePath);

  // Writers A and B BOTH load the stale routeGen = 5.
  const a = staleWriter(statePath);
  const b = staleWriter(statePath);

  // A forgets alice and persists → tombstone finalized at gen 6; disk routeGen 6.
  a.dir.forget("alice");
  a.persist();
  // The daemon boots, applies + durably persists + consumes alice: routeGenApplied = 6.
  const applied = bootConsume(statePath);
  assert.equal(applied, 6, "the boot consumed through gen 6");
  assert.equal(loadState(statePath).routeGenApplied, 6);

  // B forgets bob from its STALE snapshot and persists. Pre-fix, B would mint gen 6 (5 + 1) and
  // reconcilePersist would prune it as `gen 6 <= routeGenApplied 6` — bob's retirement never
  // reaches disk, and its approved Tier-1 key resurrects. Post-fix, B's provisional is finalized
  // strictly above the on-disk max → gen 7 > routeGenApplied 6, so it survives.
  b.dir.forget("bob");
  b.persist();
  const onDisk = loadState(statePath);
  const bobTomb = (onDisk.tombstones ?? []).find((t) => t.keyId === bobKid);
  assert.ok(bobTomb, "bob's tombstone is on disk — NOT pruned as already-applied");
  assert.equal(bobTomb.gen, 7, "finalized to N+2, strictly above routeGenApplied");
  assert.ok(bobTomb.gen > onDisk.routeGenApplied, "the retirement is not consumable");

  // A store holding bob's approved key (stamped at or below N) is invalidated by the surviving tombstone.
  const store = createRoutedKeyStore({ gen: () => 5 });
  store.observe(bobKid, recordOf(bob));
  store.approve(bobKid);
  assert.deepEqual(store.applyTombstones(onDisk.tombstones), [bobKid], "the surviving tombstone drops the stale key");
  assert.equal(store.recordSealKey(bobKid), null, "the resurrected key is gone");
});

test("gen-under-lock kill shot (repro 2): a stale forget's finalized gen exceeds an earlier approval — no spurious tie", () => {
  const { statePath } = scratch();
  const bob = generateIdentity();
  const cpeer = generateIdentity();
  const bobKid = keyId(bob.publicKey);

  // Seed: routeGen N = 5, bob and cpeer admitted.
  const seed = createDirectory({ self: { name: "me" }, routeGen: 5 });
  seed.admit({ name: "bob", publicKey: bob.publicKey });
  seed.admit({ name: "cpeer", publicKey: cpeer.publicKey });
  saveState(seed.snapshot(), statePath);

  // The stale CLI writer loads at N = 5 (the sharp case) — BEFORE the daemon advances routeGen.
  const writer = staleWriter(statePath);

  // The daemon retires an UNRELATED key (cpeer), advancing routeGen to N+1 = 6, and approves
  // bob's Tier-1 key at that gen — WITHOUT having seen any retirement of bob.
  const daemonDir = createDirectory(loadState(statePath));
  daemonDir.forget("cpeer");
  const afterCpeer = finalizeRouteGens({ ...daemonDir.snapshot() });
  daemonDir.adopt(afterCpeer);
  saveState(afterCpeer, statePath);
  assert.equal(daemonDir.routeGen(), 6, "the unrelated retirement advanced routeGen to N+1");
  const store = createRoutedKeyStore({ gen: () => daemonDir.routeGen() });
  store.observe(bobKid, recordOf(bob));
  store.approve(bobKid); // entry gen 6 (== N+1)

  // The stale writer forgets bob. Pre-fix it would also stamp gen 6 (its stale 5 + 1) → a tie
  // with the approval → KEEP → the retired key survives. Post-fix its provisional is finalized
  // above the on-disk max (6) → gen 7 > 6 → strict-less forgets the approval.
  writer.dir.forget("bob");
  const written = writer.persist();
  const bobTomb = (written.tombstones ?? []).find((t) => t.keyId === bobKid);
  assert.equal(bobTomb.gen, 7, "the stale forget finalized strictly above the daemon's approval gen");
  assert.deepEqual(store.applyTombstones([bobTomb]), [bobKid], "the retired key is forgotten (7 > 6), no spurious tie");

  // Counter-test — the LEGITIMATE tie still keeps. The daemon adopts the written state: bob
  // disappears, the seal-posture diff drops the live entry, and routeGen reaches the tombstone's
  // gen. A deliberate post-retirement re-approval then stamps gen == the tombstone's → keep.
  daemonDir.setSealPostureListener((pk) => {
    try {
      store.forget(keyId(pk));
    } catch {
      /* non-Ed25519 keys hold no routed entry */
    }
  });
  daemonDir.adopt(written);
  assert.equal(store.recordState(bobKid), "none", "adopt's disappeared-identity diff dropped the live entry");
  assert.equal(daemonDir.routeGen(), 7, "the daemon adopted the tombstone's gen");
  store.observe(bobKid, recordOf(bob));
  store.approve(bobKid); // gen 7 == the tombstone's gen
  assert.deepEqual(store.applyTombstones(daemonDir.tombstones()), [], "a re-approval that saw the retirement (tie) is kept");
});

test("gen-under-lock: three interleaved stale writers get three strictly-increasing, unique gens", () => {
  const { statePath } = scratch();
  const peers = [generateIdentity(), generateIdentity(), generateIdentity()];
  const seed = createDirectory({ self: { name: "me" } });
  peers.forEach((p, i) => seed.admit({ name: `p${i}`, publicKey: p.publicKey }));
  saveState(seed.snapshot(), statePath);

  // All three load the same stale state (routeGen 0), then persist one after another.
  const writers = [staleWriter(statePath), staleWriter(statePath), staleWriter(statePath)];
  writers.forEach((w, i) => {
    w.dir.forget(`p${i}`);
    w.persist();
  });

  const onDisk = loadState(statePath);
  const gens = (onDisk.tombstones ?? []).map((t) => t.gen).sort((x, y) => x - y);
  assert.deepEqual(gens, [1, 2, 3], "each writer rebased above the last — unique, strictly increasing");
  assert.equal(new Set(gens).size, 3, "no two writers minted the same gen");
  assert.equal(onDisk.routeGen, 3, "routeGen equals the highest allocated");
});

test("gen-under-lock: tombstone() records a provisional and does NOT bump routeGen; reconcilePersist emits no null gens", () => {
  const p = generateIdentity();
  const dir = createDirectory({ self: { name: "me" }, now: () => 4242 });
  dir.admit({ name: "p", publicKey: p.publicKey });
  dir.forget("p");
  assert.equal(dir.routeGen(), 0, "routeGen is untouched pre-lock");
  assert.deepEqual(dir.tombstones(), [{ keyId: keyId(p.publicKey), at: 4242, reason: "forget", gen: null }], "a provisional tombstone, gen: null");

  // The provisional round-trips through snapshot() as JSON-serializable null…
  assert.equal(JSON.parse(JSON.stringify(dir.snapshot())).tombstones[0].gen, null);
  // …but reconcilePersist finalizes it — no null ever reaches the written state.
  const result = reconcilePersist({}, reconcileBaseline({}, createDirectory({ self: { name: "me" } }).snapshot()), { ...dir.snapshot() });
  assert.ok(result.tombstones.every((t) => typeof t.gen === "number"), "no provisional gen in the reconcilePersist output");
  assert.equal(result.tombstones[0].gen, 1);
});

test("gen-under-lock: a provisional supersedes a finalized same-keyId tombstone and is re-stamped higher (double-persist is benign)", () => {
  const kid = "a".repeat(43);
  // mergeTombstones: a provisional candidate outranks an on-disk finalized tombstone for the
  // same keyId; finalize then re-stamps it one above the file max.
  const result = reconcilePersist(
    { tombstones: [{ keyId: kid, at: 1, reason: "forget", gen: 5 }], routeGen: 5, routeGenApplied: 0 },
    { tombstones: [{ keyId: kid, at: 1, reason: "forget", gen: 5 }] },
    { tombstones: [{ keyId: kid, at: 9, reason: "forget", gen: null }], routeGen: 0 },
  );
  assert.equal(result.tombstones.length, 1, "the two collapse to one");
  assert.equal(result.tombstones[0].gen, 6, "the provisional superseded gen 5 and finalized to 6");

  // Double-persist by the same CLI process: its directory keeps the provisional after the first
  // persist (persist does not adopt back), so a second persist re-stamps one higher — benign,
  // over-forget-safe, still unique.
  const { statePath } = scratch();
  const p = generateIdentity();
  const seed = createDirectory({ self: { name: "me" } });
  seed.admit({ name: "p", publicKey: p.publicKey });
  saveState(seed.snapshot(), statePath);
  const w = staleWriter(statePath);
  w.dir.forget("p");
  assert.equal(w.persist().tombstones.find((t) => t.keyId === keyId(p.publicKey)).gen, 1, "first persist finalizes to gen 1");
  assert.equal(w.persist().tombstones.find((t) => t.keyId === keyId(p.publicKey)).gen, 2, "second persist re-stamps to gen 2 (benign re-forget)");
});

test("gen-under-lock: the applyChange path allocates above a fresher on-disk routeGen and adopt raises the live counter", () => {
  const { statePath } = scratch();
  const p = generateIdentity();
  const pKid = keyId(p.publicKey);

  // The live directory a stale daemon holds saw routeGen 0…
  const liveDir = createDirectory({ self: { name: "me" } });
  liveDir.admit({ name: "p", publicKey: p.publicKey });
  // …but disk has since advanced to routeGen 10 (another writer).
  const onDiskSeed = createDirectory({ self: { name: "me" }, routeGen: 10 });
  onDiskSeed.admit({ name: "p", publicKey: p.publicKey });
  saveState(onDiskSeed.snapshot(), statePath);

  // The daemon's applyChange (bin/hail.js): fresh from onDisk, mutate, finalize under the lock.
  const applyChange = (mutate) => {
    let result;
    const next = updateState(statePath, (onDisk) => {
      const fresh = createDirectory({ ...onDisk });
      result = mutate(fresh);
      return finalizeRouteGens({ ...onDisk, ...fresh.snapshot() });
    });
    liveDir.adopt(next);
    return { result, next };
  };

  const { next } = applyChange((dir) => dir.forget("p"));
  const tomb = (next.tombstones ?? []).find((t) => t.keyId === pKid);
  assert.equal(tomb.gen, 11, "allocated strictly above the fresher on-disk routeGen 10");
  assert.equal(next.routeGen, 11);
  assert.equal(liveDir.routeGen(), 11, "adopt raised the live counter to the finalized gen");
});

test("gen-under-lock: consumption stays a true prefix — prune drops only gens <= applied, keeps higher and finalizes provisionals above", () => {
  const kidLow = "a".repeat(43);
  const kidHigh = "b".repeat(43);
  const kidProv = "c".repeat(43);
  const result = reconcilePersist(
    {
      tombstones: [
        { keyId: kidLow, at: 1, reason: "forget", gen: 3 }, // gen 3 <= applied 5 -> consumed
        { keyId: kidHigh, at: 2, reason: "forget", gen: 7 }, // gen 7 > applied -> kept
      ],
      routeGen: 7,
      routeGenApplied: 5,
    },
    { tombstones: [] },
    { tombstones: [{ keyId: kidProv, at: 3, reason: "forget", gen: null }], routeGen: 0 }, // provisional -> finalized above, never consumed
  );
  const byId = Object.fromEntries(result.tombstones.map((t) => [t.keyId, t.gen]));
  assert.ok(!(kidLow in byId), "gen 3 <= routeGenApplied 5 was consumed");
  assert.equal(byId[kidHigh], 7, "gen 7 above the high-water survives");
  assert.equal(byId[kidProv], 8, "the provisional finalized to 8 (above the file max 7), never pruned");
  assert.ok(result.tombstones.every((t) => typeof t.gen === "number"), "no null gen in the output");
});

test("gen-under-lock defensive: a leaked provisional (gen: null) tombstone forgets a gen-bearing entry (fail closed)", () => {
  const alice = generateIdentity();
  const kid = keyId(alice.publicKey);
  const store = createRoutedKeyStore({ gen: () => 9 });
  store.observe(kid, recordOf(alice));
  store.approve(kid); // entry gen 9
  const dropped = store.applyTombstones([{ keyId: kid, at: 1, reason: "forget", gen: null }]);
  assert.deepEqual(dropped, [kid], "a provisional outranks anything — it must not degrade to the gen-less-tombstone-loses case");
  assert.equal(store.recordState(kid), "none");
});
