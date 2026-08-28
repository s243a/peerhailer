/**
 * Fail-closed profile resolution must be *visible*, not silent: a peer whose
 * assigned profile no longer resolves is "parked" (granted nothing), and that is
 * surfaced (profileStatus), its holders are findable before a removal (holdersOf),
 * and a removal can reassign them rather than stranding them.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";

const lowpriv = { lowpriv: { name: "lowpriv", allows: ["hail"], description: "restricted" } };
const withLowpriv = () => {
  const dir = createDirectory({ self: { name: "me" }, profiles: lowpriv });
  dir.useProfiles(lowpriv);
  return dir;
};
const addr = [{ value: "https://127.0.0.1:9" }];

test("profileStatus: a peer on a real profile is not parked; one whose profile was removed is", () => {
  const dir = withLowpriv();
  dir.admit({ name: "phone", publicKey: generateIdentity().publicKey, addresses: addr }, { profile: "lowpriv" });
  assert.deepEqual(dir.profileStatus("phone"), { assigned: "lowpriv", parked: false, effective: "lowpriv" });

  dir.useProfiles({}); // the profile is removed out from under the holder
  const st = dir.profileStatus("phone");
  assert.equal(st.parked, true);
  assert.equal(st.assigned, "lowpriv");
  assert.equal(st.effective, "unknown", "granted nothing until reassigned");
});

test("holdersOf lists exactly the peers assigned a profile", () => {
  const dir = withLowpriv();
  dir.admit({ name: "a", publicKey: generateIdentity().publicKey, addresses: addr }, { profile: "lowpriv" });
  dir.admit({ name: "b", publicKey: generateIdentity().publicKey, addresses: addr }, { profile: "trusted" });
  assert.deepEqual(dir.holdersOf("lowpriv").map((p) => p.name), ["a"]);
  assert.deepEqual(dir.holdersOf("trusted").map((p) => p.name), ["b"]);
});

test("reassigning holders (what `profiles remove --reassign` does) un-parks them", () => {
  const dir = withLowpriv();
  dir.admit({ name: "phone", publicKey: generateIdentity().publicKey, addresses: addr }, { profile: "lowpriv" });
  // Move the holder, then drop the profile — the mechanism the CLI wires together.
  for (const h of dir.holdersOf("lowpriv")) dir.admit({ name: h.name }, { profile: "known" });
  dir.useProfiles({});
  assert.equal(dir.profileStatus("phone").parked, false);
  assert.equal(dir.profileStatus("phone").effective, "known");
});

test("holdersOf catches a peer elevated AWAY from the profile (it would park at lapse)", () => {
  const dir = withLowpriv();
  const key = generateIdentity().publicKey;
  dir.admit({ name: "alice", publicKey: key, addresses: addr }, { profile: "lowpriv" });
  dir.admit({ name: "alice", publicKey: key, addresses: addr }, { profile: "trusted", until: Date.now() + 1_000_000 });
  // Effectively trusted now, but profileAfter === lowpriv → she reverts to it.
  assert.equal(dir.effectiveProfile("alice").profile, "trusted");
  assert.deepEqual(dir.holdersOf("lowpriv").map((p) => p.name), ["alice"], "the scheduled holder is not missed at removal time");
});

test("extending a live elevation keeps the original revert target, not the raised profile", () => {
  const dir = withLowpriv();
  const key = generateIdentity().publicKey;
  dir.admit({ name: "c", publicKey: key, addresses: addr }, { profile: "trusted" }); // base
  dir.admit({ name: "c", publicKey: key, addresses: addr }, { profile: "known", until: Date.now() + 1_000_000 }); // raise
  assert.equal(dir.get("c").profileAfter, "trusted", "first raise reverts to the base");
  // Extend the raise while it is still live — must NOT capture the raised profile.
  dir.admit({ name: "c", publicKey: key, addresses: addr }, { profile: "known", until: Date.now() + 2_000_000 });
  assert.equal(dir.get("c").profileAfter, "trusted", "extension keeps the base, so a temporary raise stays temporary");
});

test("an explicit permanent re-admit clears a live elevation (so --reassign is permanent)", () => {
  const dir = withLowpriv();
  const key = generateIdentity().publicKey;
  dir.admit({ name: "bob", publicKey: key, addresses: addr }, { profile: "lowpriv", until: Date.now() + 1_000_000 });
  assert.equal(dir.effectiveProfile("bob").profile, "lowpriv");
  assert.ok(dir.get("bob").profileUntil, "bob is elevated");
  dir.admit({ name: "bob" }, { profile: "known" }); // the reassign move
  assert.equal(dir.effectiveProfile("bob").profile, "known");
  assert.equal(dir.get("bob").profileUntil, undefined, "the elevation is cleared, so it can't resurrect the old profile");
});
