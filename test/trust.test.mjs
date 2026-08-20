/**
 * Which profile a peer ends up with, and what beats what.
 *
 * The precedence is the security model, so it is pinned here rather than left
 * to be inferred: blocked, then assigned, then derived, then unknown. An
 * authorization order nobody can predict is one nobody can audit.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import { isBlocked, profileFor, resolveTrustModel } from "../src/trust.js";

const directoryStub = { allowsCapability: () => true };

test("blocking beats a profile someone assigned", () => {
  const decision = profileFor({
    peer: { name: "sol", profile: "trusted" },
    directory: directoryStub,
    blocklist: { names: ["sol"] },
  });
  assert.equal(decision.profile, "blocked");
  assert.equal(decision.reason, "blocked");
});

test("an assignment beats what a model would derive", () => {
  const decision = profileFor({
    peer: { name: "sol", profile: "known" },
    directory: directoryStub,
    model: "web-of-trust",
    vouchedBy: ["a", "b", "c"],
  });
  // A person decided; a heuristic does not get to overrule them quietly.
  assert.equal(decision.profile, "known");
  assert.equal(decision.reason, "assigned");
});

test("a peer nobody assigned gets nothing under the direct model", () => {
  const decision = profileFor({ peer: { name: "sol" }, directory: directoryStub });
  assert.equal(decision.profile, "unknown");
  assert.match(decision.reason, /no opinion/);
});

test("web-of-trust derives a profile once enough credible peers vouch", () => {
  const thin = profileFor({
    peer: { name: "luna" },
    directory: directoryStub,
    model: "web-of-trust",
    vouchedBy: ["sol"],
  });
  assert.equal(thin.profile, "unknown", "one voucher is not a web");

  const enough = profileFor({
    peer: { name: "luna" },
    directory: directoryStub,
    model: "web-of-trust",
    vouchedBy: ["sol", "mars"],
  });
  assert.equal(enough.profile, "known");
  assert.match(enough.reason, /web-of-trust/);
});

test("vouches from peers granted nothing do not count", () => {
  // A peer whose opinion we already decided not to act on cannot launder trust
  // by introducing someone.
  const decision = profileFor({
    peer: { name: "luna" },
    directory: { allowsCapability: () => false },
    model: "web-of-trust",
    vouchedBy: ["ignored", "also-ignored", "still-ignored"],
  });
  assert.equal(decision.profile, "unknown");
});

test("a vouched peer never inherits the voucher's profile", () => {
  const decision = profileFor({
    peer: { name: "luna" },
    directory: directoryStub,
    model: "web-of-trust",
    vouchedBy: ["sol", "mars"],
  });
  // Otherwise trust is transitive by arithmetic, which the design refuses.
  assert.notEqual(decision.profile, "trusted");
});

test("blocking matches the key, so renaming does not evade it", () => {
  const sol = generateIdentity();
  const blocklist = { keys: [sol.publicKey] };

  assert.equal(isBlocked(blocklist, { name: "sol", publicKey: sol.publicKey }), true);
  assert.equal(isBlocked(blocklist, { name: "renamed", publicKey: sol.publicKey }), true);
  assert.equal(isBlocked(blocklist, { name: "sol", publicKey: null }), false);
});

test("a blocked peer loses its capabilities in the directory", () => {
  const sol = generateIdentity();
  const directory = createDirectory({ self: { name: "here" } });
  directory.admit({ name: "sol", publicKey: sol.publicKey });

  assert.equal(directory.allowsCapability("sol", "hail"), true);
  directory.block(directory.get("sol"));
  assert.equal(directory.allowsCapability("sol", "hail"), false);
  assert.equal(directory.effectiveProfile("sol").profile, "blocked");
});

test("unblocking restores what was assigned", () => {
  const sol = generateIdentity();
  const directory = createDirectory({ self: { name: "here" } });
  directory.admit({ name: "sol", publicKey: sol.publicKey });

  directory.block(directory.get("sol"));
  directory.unblock("sol");
  assert.equal(directory.allowsCapability("sol", "hail"), true);
});

test("a blocked peer is not passed on to others", () => {
  const sol = generateIdentity();
  const directory = createDirectory({ self: { name: "here" } });
  directory.admit({ name: "sol", publicKey: sol.publicKey });
  directory.admit({ name: "luna" });
  directory.block(directory.get("sol"));

  // Telling a peer where to find a machine we refuse to answer would hand out a
  // reachability we deliberately withdrew.
  const named = directory.hailResponse().peers.map((peer) => peer.name);
  assert.ok(!named.includes("sol"));
  assert.ok(named.includes("luna"));
});

test("a caller we have never heard of gets the unknown profile", () => {
  const directory = createDirectory({ self: { name: "here" } });
  assert.equal(directory.allowsCapability("stranger", "hail"), false);

  const welcoming = createDirectory({
    self: { name: "here" },
    trust: { unknownProfile: "trusted" },
  });
  // Deliberately configurable: a fabric that wants to answer strangers can say
  // so, without the code growing a special case for it.
  assert.equal(welcoming.allowsCapability("stranger", "hail"), true);
});

test("an unknown model name falls back rather than failing shut", () => {
  assert.equal(resolveTrustModel("nonsense").name, "direct");
});
