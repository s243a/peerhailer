/**
 * Hailing, and what a walk is allowed to do with what it hears.
 *
 * Reachability is decided by connecting, so these drive a fake transport and
 * check the consequences: which address gets used, what a failure costs, and
 * that a walk never admits anyone.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { createDirectory } from "../src/directory.js";
import { hailPeer, walk } from "../src/hail.js";

/** A fetch that answers only for the URLs it was given. */
const fakeFetch = (routes) => {
  const calls = [];
  const impl = async (url) => {
    calls.push(url);
    const answer = routes[url.replace(/\/hail$/, "")];
    if (!answer) throw new Error("ECONNREFUSED");
    return { ok: true, json: async () => answer };
  };
  impl.calls = calls;
  return impl;
};

test("the first address that answers is the one used", async () => {
  const fetchImpl = fakeFetch({ "http://second:8787": { self: { name: "sol" }, peers: [] } });
  const result = await hailPeer(
    {
      name: "sol",
      addresses: [
        { transport: "lan", value: "http://first:8787", lastOk: null },
        { transport: "tinc", value: "http://second:8787", lastOk: null },
      ],
    },
    { fetchImpl },
  );

  assert.equal(result.ok, true);
  assert.equal(result.address.transport, "tinc");
  assert.equal(fetchImpl.calls.length, 2, "the dead address was tried first, then the live one");
});

test("a peer with no address is a name, not a destination", async () => {
  const result = await hailPeer({ name: "sol" }, { fetchImpl: fakeFetch({}) });
  assert.equal(result.ok, false);
  assert.match(result.error, /no known address/);
});

test("every address failing is reported with each reason", async () => {
  const result = await hailPeer(
    { name: "sol", addresses: [{ transport: "lan", value: "http://gone:8787" }] },
    { fetchImpl: fakeFetch({}) },
  );
  assert.equal(result.ok, false);
  assert.match(result.error, /ECONNREFUSED/);
});

test("a walk collects candidates and admits none of them", async () => {
  const directory = createDirectory({ self: { name: "here" } });
  directory.admit({ name: "sol", addresses: [{ transport: "lan", value: "http://sol:8787" }] });

  const fetchImpl = fakeFetch({
    "http://sol:8787": {
      self: { name: "sol" },
      peers: [{ name: "luna", addresses: [{ transport: "lan", value: "http://luna:8787" }] }],
    },
    "http://luna:8787": { self: { name: "luna" }, peers: [] },
  });

  const result = await walk(directory, { fetchImpl });

  assert.deepEqual(result.reached.map((p) => p.name), ["sol"]);
  assert.deepEqual(result.candidates.map((p) => p.name), ["luna"]);
  assert.deepEqual(directory.listAdmitted().map((p) => p.name), ["sol"]);
  // A candidate is a lead. Hailing it would be acting on the introduction.
  assert.ok(!fetchImpl.calls.some((url) => url.includes("luna")));
});

test("a walk reaches an admitted peer that another peer told us moved", async () => {
  const directory = createDirectory({ self: { name: "here" } });
  directory.admit({ name: "sol", addresses: [{ transport: "lan", value: "http://sol:8787" }] });
  directory.admit({ name: "luna", addresses: [] });

  const fetchImpl = fakeFetch({
    "http://sol:8787": {
      self: { name: "sol" },
      peers: [{ name: "luna", addresses: [{ transport: "tinc", value: "http://luna-new:8787" }] }],
    },
    "http://luna-new:8787": { self: { name: "luna" }, peers: [] },
  });

  const result = await walk(directory, { fetchImpl });
  assert.deepEqual(result.reached.map((p) => p.name).sort(), ["luna", "sol"]);
});

test("an unreachable peer costs the walk nothing else", async () => {
  const directory = createDirectory({ self: { name: "here" } });
  directory.admit({ name: "gone", addresses: [{ transport: "lan", value: "http://gone:8787" }] });
  directory.admit({ name: "sol", addresses: [{ transport: "lan", value: "http://sol:8787" }] });

  const result = await walk(directory, {
    fetchImpl: fakeFetch({ "http://sol:8787": { self: { name: "sol" }, peers: [] } }),
  });

  assert.deepEqual(result.reached.map((p) => p.name), ["sol"]);
  assert.deepEqual(result.unreachable.map((p) => p.name), ["gone"]);
});

test("each admitted peer is hailed exactly once", async () => {
  const directory = createDirectory({ self: { name: "here" } });
  directory.admit({ name: "a", addresses: [{ transport: "lan", value: "http://a:8787" }] });
  directory.admit({ name: "b", addresses: [{ transport: "lan", value: "http://b:8787" }] });

  // Each names the other, which would loop if a walk followed what it hears.
  const fetchImpl = fakeFetch({
    "http://a:8787": { self: { name: "a" }, peers: [{ name: "b" }] },
    "http://b:8787": { self: { name: "b" }, peers: [{ name: "a" }] },
  });

  const result = await walk(directory, { fetchImpl });
  assert.deepEqual(result.reached.map((p) => p.name).sort(), ["a", "b"]);
  assert.equal(fetchImpl.calls.length, 2, "one hail per peer, no loop");
});
