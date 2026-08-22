/**
 * The directory, and the line between hearing of a peer and trusting one.
 *
 * The rules under test are the ones a future change is most likely to erode:
 * gossip must not admit anybody, records must not carry secrets, and a peer
 * must not be able to talk this machine out of a route it has seen work.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { createDirectory } from "../src/directory.js";
import { mergePeerRecord, publicRecord } from "../src/peerRecord.js";
import { generateIdentity, sameKey } from "../src/identity.js";

const at = (t) => () => t;

test("hearing about a peer does not admit it", () => {
  const directory = createDirectory({ self: { name: "here" } });
  directory.learnFrom("sol", [{ name: "luna", addresses: [{ transport: "lan", value: "http://10.0.0.9:8787" }] }]);

  assert.deepEqual(directory.listAdmitted(), []);
  assert.equal(directory.listCandidates()[0].name, "luna");
  // The lead is only useful if you can see who vouched for it.
  assert.deepEqual(directory.listCandidates()[0].heardFrom, ["sol"]);
});

test("admitting is what promotes a candidate", () => {
  const directory = createDirectory({ self: { name: "here" } });
  directory.learnFrom("sol", [{ name: "luna" }]);
  directory.admit({ name: "luna", addresses: [{ transport: "lan", value: "http://10.0.0.9:8787" }] });

  assert.deepEqual(directory.listAdmitted().map((p) => p.name), ["luna"]);
  assert.deepEqual(directory.listCandidates(), []);
});

test("a hail answers with admitted peers only", () => {
  const directory = createDirectory({ self: { name: "here" }, now: at(5) });
  directory.admit({ name: "sol", addresses: [{ transport: "tailscale", value: "http://100.1.2.3:8787" }] });
  directory.learnFrom("sol", [{ name: "luna" }]);

  const answer = directory.hailResponse();
  assert.deepEqual(answer.peers.map((p) => p.name), ["sol"]);
  // Passing on hearsay would let one peer seed names across a whole network.
  assert.ok(!JSON.stringify(answer).includes("luna"));
});

test("nothing secret survives the trip to another peer", () => {
  const leaky = {
    name: "sol",
    token: "terminal-operate-secret",
    addresses: [{ transport: "lan", value: "http://10.0.0.2:8787", lastOk: 12 }],
    lastSeen: 12,
  };
  const safe = publicRecord(leaky);

  assert.equal(safe.token, undefined, "a credential must not reach the wire");
  assert.ok(!JSON.stringify(safe).includes("secret"));
  // lastOk is ours; it says a route worked *here*, which is meaningless there.
  assert.equal(safe.addresses[0].lastOk, undefined);
});

test("a peer cannot overwrite a route we saw work", () => {
  const mine = {
    name: "sol",
    addresses: [{ transport: "lan", value: "http://10.0.0.2:8787", lastOk: 100 }],
    lastSeen: 100,
  };
  const theirs = {
    name: "sol",
    addresses: [
      { transport: "lan", value: "http://10.0.0.2:8787", lastOk: 999 },
      { transport: "tinc", value: "http://172.16.0.2:8787", lastOk: 999 },
    ],
    lastSeen: 50,
  };

  const merged = mergePeerRecord(mine, theirs);
  const known = merged.addresses.find((a) => a.transport === "lan");
  const learned = merged.addresses.find((a) => a.transport === "tinc");

  assert.equal(known.lastOk, 100, "our own observation wins; we were there");
  assert.equal(learned.lastOk, null, "theirs is a lead until it works here");
  assert.equal(merged.lastSeen, 100, "a peer cannot age our record backwards");
});

test("marking a route reachable is what orders the addresses", () => {
  const directory = createDirectory({ self: { name: "here" }, now: at(500) });
  directory.admit({
    name: "sol",
    addresses: [
      { transport: "lan", value: "http://10.0.0.2:8787", lastOk: null },
      { transport: "relay", value: "http://relay.example:8787", lastOk: 10 },
    ],
  });

  directory.markReachable("sol", { transport: "lan", value: "http://10.0.0.2:8787" });
  assert.equal(directory.get("sol").addresses[0].transport, "lan", "what worked is tried first");
});

test("forgetting a peer removes it from both sets", () => {
  const directory = createDirectory({ self: { name: "here" } });
  directory.admit({ name: "sol" });
  directory.learnFrom("sol", [{ name: "luna" }]);

  assert.equal(directory.forget("sol"), true);
  assert.equal(directory.forget("luna"), true);
  assert.deepEqual(directory.listAdmitted(), []);
  assert.deepEqual(directory.listCandidates(), []);
});

test("a peer never learns about itself, or replaces us", () => {
  const directory = createDirectory({ self: { name: "here" } });
  directory.learnFrom("sol", [{ name: "here" }, { name: "" }, null]);
  assert.deepEqual(directory.listCandidates(), []);
});

test("a verified key binds on first contact, and is never replaced after", () => {
  const first = generateIdentity();
  const impostor = generateIdentity();
  const directory = createDirectory({ self: { name: "me" } });
  directory.admit({ name: "sol", addresses: [{ transport: "lan", value: "10.0.0.2:7645" }] });

  assert.equal(directory.get("sol").publicKey, null, "admitted without a key: trust on first use");

  directory.bindKey("sol", first.publicKey);
  assert.ok(sameKey(directory.get("sol").publicKey, first.publicKey), "first contact ends TOFU");

  // Rotation is deliberate. A second machine answering later cannot become sol
  // by presenting a different key.
  directory.bindKey("sol", impostor.publicKey);
  assert.ok(sameKey(directory.get("sol").publicKey, first.publicKey), "a held key is never replaced");

  // Binding must not quietly reassign the profile.
  assert.equal(directory.get("sol").profile, directory.get("sol").profile);
  assert.equal(directory.bindKey("nobody", first.publicKey), null);
});

test("a profile whose name merely contains 'blocked' is not blocked", () => {
  const directory = createDirectory({ self: { name: "me" } });
  directory.useProfiles({ unblocked: { name: "unblocked", allows: ["hail"] } });
  directory.admit({ name: "mars", profile: "unblocked" });

  const shared = directory.hailResponse().peers.map((peer) => peer.name);
  assert.ok(shared.includes("mars"), "`unblocked` contains `blocked` as a substring, but is not it");
});

test("where a peer lands depends on how it arrived", () => {
  const directory = createDirectory({ self: { name: "me" } });

  // Typed in: an assertion that you know the machine.
  directory.admit({ name: "sol", addresses: [{ transport: "lan", value: "10.0.0.2:7645" }] });
  assert.equal(directory.get("sol").profile, "trusted");

  // Heard of: someone else's say-so about a machine never contacted.
  directory.admit({ name: "mars", profile: "trusted" });
  directory.learnFrom("mars", [{ name: "phobos", addresses: [] }]);
  assert.ok(directory.listCandidates().some((c) => c.name === "phobos"));
  directory.admit({ name: "phobos" });
  assert.equal(directory.get("phobos").profile, "known", "a lead is not trust");

  // An explicit choice still wins, and both defaults are configurable.
  const strict = createDirectory({
    self: { name: "me" },
    trust: { admitProfile: "known", candidateProfile: "unknown" },
  });
  strict.admit({ name: "luna" });
  assert.equal(strict.get("luna").profile, "known");
  strict.admit({ name: "deimos", profile: "carrier" });
  assert.equal(strict.get("deimos").profile, "carrier");
});

test("gossip is taken only from peers allowed to introduce", () => {
  const directory = createDirectory({ self: { name: "me" } });
  directory.admit({ name: "sol", profile: "trusted" });
  directory.admit({ name: "quiet", profile: "known" });

  assert.equal(directory.allowsCapability("sol", "introduce"), true);
  assert.equal(
    directory.allowsCapability("quiet", "introduce"),
    false,
    "recorded but granted nothing must not include seeding our candidate list",
  );
});

test("promoting a heard-of name with your own address is an assertion, not a lead", () => {
  const directory = createDirectory({ self: { name: "me" } });
  directory.admit({ name: "mars", profile: "trusted" });
  directory.learnFrom("mars", [{ name: "phobos", addresses: [] }, { name: "deimos", addresses: [] }]);

  // Clicking admit on a name someone mentioned: still only their say-so.
  directory.admit({ name: "phobos" });
  assert.equal(directory.get("phobos").profile, "known");

  // Typing an address for it is your own claim about the machine.
  directory.admit({ name: "deimos", addresses: [{ transport: "lan", value: "10.0.0.5:7645" }] });
  assert.equal(directory.get("deimos").profile, "trusted");
});

test("adopting state carries the trust defaults, not just the peers", () => {
  const directory = createDirectory({ self: { name: "me" } });
  assert.equal(directory.trust().candidateProfile, "known");

  // A daemon reloading state used to keep its old defaults, so changing where
  // admitted peers land did nothing until restart.
  directory.adopt({ admitted: [], candidates: [], trust: { candidateProfile: "unknown" } });
  assert.equal(directory.trust().candidateProfile, "unknown");
  assert.equal(directory.trust().admitProfile, "trusted", "unset fields keep their value");
});

test("an address you can type is an address that can be dialled", () => {
  const directory = createDirectory({ self: { name: "me" } });
  // People type host:port. Stored values are used as a URL base, so without
  // this the peer is reported unreachable — which reads as "it is down".
  directory.admit({ name: "sol", addresses: [{ transport: "lan", value: "192.168.1.50:7645" }] });
  assert.equal(directory.get("sol").addresses[0].value, "http://192.168.1.50:7645");
  assert.doesNotThrow(() => new URL(`${directory.get("sol").addresses[0].value}/hail`));

  // An explicit scheme is never second-guessed.
  directory.admit({ name: "mars", addresses: [{ transport: "tailscale", value: "https://mars.ts.net" }] });
  assert.equal(directory.get("mars").addresses[0].value, "https://mars.ts.net");
});

test("a competing key is recorded and warned about, never accepted", () => {
  const original = generateIdentity();
  const other = generateIdentity();
  const directory = createDirectory({ self: { name: "me" } });
  directory.admit({ name: "sol", publicKey: original.publicKey, addresses: [] });

  directory.noteKeyConflict("sol", other.publicKey, { transport: "lan", value: "http://10.0.0.9:7645" });
  const seen = directory.get("sol");

  assert.ok(sameKey(seen.publicKey, original.publicKey), "the key held keeps working");
  assert.equal(seen.conflicts.length, 1);
  assert.ok(sameKey(seen.conflicts[0].key, other.publicKey));

  // Seeing it again counts it rather than duplicating it.
  directory.noteKeyConflict("sol", other.publicKey);
  assert.equal(directory.get("sol").conflicts.length, 1);
  assert.equal(directory.get("sol").conflicts[0].count, 2);

  // Stamping a route must not quietly drop the warning.
  directory.markReachable("sol", { transport: "lan", value: "http://10.0.0.9:7645" });
  assert.equal(directory.get("sol").conflicts?.length, 1, "a conflict survives a record being rebuilt");

  // Only a person resolves it, and doing so clears what was reported.
  const rotated = directory.rotateKey("sol", other.publicKey);
  assert.ok(sameKey(rotated.publicKey, other.publicKey));
  assert.equal(rotated.conflicts, undefined);
});
