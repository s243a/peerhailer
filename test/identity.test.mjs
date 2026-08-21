/**
 * Identity, and what a signature is supposed to stop.
 *
 * The property under test is impersonation: a name is a claim anyone can make,
 * so what matters is that a record only counts when it was signed by the key
 * this machine already binds to that name.
 */
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  canonicalize,
  fingerprint,
  generateIdentity,
  loadIdentity,
  signPayload,
  verifyPayload,
} from "../src/identity.js";
import { makePeerRecord, signRecord, verifyRecord } from "../src/peerRecord.js";
import { allows, listProfiles, resolveProfile, setPinned } from "../src/profiles.js";

const scratch = () => join(mkdtempSync(join(tmpdir(), "ph-id-")), "identity.json");

test("a signature verifies with the matching key and fails with another", () => {
  const sol = generateIdentity();
  const mallory = generateIdentity();
  const payload = { name: "sol", at: 1 };

  const signature = signPayload(payload, sol.privateKey);
  assert.equal(verifyPayload(payload, signature, sol.publicKey), true);
  assert.equal(verifyPayload(payload, signature, mallory.publicKey), false);
});

test("altering the payload invalidates the signature", () => {
  const sol = generateIdentity();
  const signature = signPayload({ name: "sol", at: 1 }, sol.privateKey);
  // The whole point: addresses cannot be rewritten between here and there.
  assert.equal(verifyPayload({ name: "sol", at: 2 }, signature, sol.publicKey), false);
});

test("malformed input is a failed check, not a crash", () => {
  const sol = generateIdentity();
  assert.equal(verifyPayload({}, "not-base64!", sol.publicKey), false);
  assert.equal(verifyPayload({}, "", "not a key"), false);
});

test("canonical form does not depend on key order", () => {
  assert.equal(canonicalize({ a: 1, b: 2 }), canonicalize({ b: 2, a: 1 }));
  // Absent and undefined must agree, or a signature verifies on one machine only.
  assert.equal(canonicalize({ a: 1, b: undefined }), canonicalize({ a: 1 }));
});

test("fingerprints differ between keys", () => {
  // Every Ed25519 SPKI key shares an ASN.1 prefix, so a fingerprint taken from
  // the start of the key would compare equal for unrelated machines.
  const one = fingerprint(generateIdentity().publicKey);
  const two = fingerprint(generateIdentity().publicKey);
  assert.notEqual(one, two);
});

test("an identity is generated once and kept private", () => {
  const path = scratch();
  const first = loadIdentity(path);
  const second = loadIdentity(path);

  assert.equal(first.created, true);
  assert.equal(second.created, false);
  assert.equal(first.publicKey, second.publicKey, "the identity must survive a restart");
  if (process.platform !== "win32") {
    // Mode bits mean little on Windows, where the ACL decides; the module says
    // so rather than this asserting something the platform will not honour.
    assert.equal(statSync(path).mode & 0o077, 0, "no group or world access to a private key");
  }
  assert.ok(!readFileSync(path, "utf8").includes("BEGIN PUBLIC KEY\\nMCowBQ\\n"));
});

test("a signed record verifies against the key held for that name", () => {
  const sol = generateIdentity();
  const record = makePeerRecord({ name: "sol", publicKey: sol.publicKey, lastSeen: 5 });
  const envelope = signRecord(record, sol.privateKey);

  const good = verifyRecord(envelope, sol.publicKey);
  assert.equal(good.ok, true);
  assert.equal(good.record.name, "sol");
});

test("a record signed by a different key is rejected outright", () => {
  const sol = generateIdentity();
  const mallory = generateIdentity();

  // Mallory claims to be sol, signing with her own key and presenting it.
  const forged = signRecord(
    makePeerRecord({ name: "sol", publicKey: mallory.publicKey }),
    mallory.privateKey,
  );

  const checked = verifyRecord(forged, sol.publicKey);
  assert.equal(checked.ok, false);
  assert.match(checked.error, /different key/);
});

test("first contact accepts the record's own key, and is only that", () => {
  const sol = generateIdentity();
  const envelope = signRecord(makePeerRecord({ name: "sol", publicKey: sol.publicKey }), sol.privateKey);

  // Trust on first use: no stronger than the claim, which is why binding the
  // key to the name afterwards is what the rest depends on.
  assert.equal(verifyRecord(envelope, null).ok, true);
});

test("the default profile grants hailing, and 'known' grants nothing", () => {
  assert.equal(resolveProfile(undefined).name, "trusted");
  assert.equal(allows("trusted", "hail"), true);
  assert.equal(allows("known", "hail"), false);
  // Relaying spends this machine's bandwidth, so it is not inherited by being a peer.
  assert.equal(allows("trusted", "relay"), false);
  assert.equal(allows("carrier", "relay"), true);
});

test("an unknown profile name falls back rather than failing shut", () => {
  // A peer that silently stops working after a config edit looks exactly like a
  // network problem, which is the worst way for this to fail.
  assert.equal(resolveProfile("typo-profile").name, "trusted");
});

test("trusted is offered first out of the box", () => {
  const listed = listProfiles();
  assert.equal(listed[0].name, "trusted");
  assert.equal(listed[0].pinned, true);
  // The rest are alphabetical, so the order does not shift as profiles are
  // added. Asserted as a property rather than a list, or adding a profile
  // breaks a test that has nothing to do with it.
  const rest = listed.slice(1).map((profile) => profile.name);
  assert.deepEqual(rest, [...rest].sort());
});

test("a user can change what is offered first", () => {
  const custom = setPinned(setPinned({}, "known", true), "trusted", false);
  const listed = listProfiles(custom).map((profile) => profile.name);
  assert.equal(listed[0], "known", "the pinned profile leads");
  const rest = listed.slice(1);
  assert.deepEqual(rest, [...rest].sort());
  assert.ok(rest.includes("trusted"), "unpinning moves it down, not out");
});

test("repinning a built-in does not freeze what it grants", () => {
  // The override records the pin only, so a later version changing what
  // `trusted` allows still reaches someone who merely moved it up the list.
  const custom = setPinned({}, "trusted", false);
  const trusted = listProfiles(custom).find((p) => p.name === "trusted");
  assert.deepEqual(trusted.allows, ["hail", "directory"]);
  assert.notEqual(trusted.pinned, true);
});

test("a user-defined profile joins the list", () => {
  const listed = listProfiles({
    backup: { allows: ["hail"], description: "The backup box.", pinned: true },
  });
  assert.equal(listed[0].name, "backup");
  assert.deepEqual(listed.find((p) => p.name === "backup").allows, ["hail"]);
});
