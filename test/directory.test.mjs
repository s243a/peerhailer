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
