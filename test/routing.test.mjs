/**
 * The Stage 1 routing engine, exercised as a pure in-memory network — nodes wired
 * by a `forward` that just calls the target's `relay`. No daemons, no crypto: the
 * algorithm is the thing under test. The properties that matter are the refusals
 * and the bounds — loops never happen, ttl and budget are ceilings, a blocked key
 * is never a hop — because those are what a multi-hop protocol gets wrong.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createRouter, greedyPolicy, floodPolicy, xorDistanceOver } from "../src/routing.js";

/** Build a network from an adjacency map; returns the routers and a forward counter. */
function net(adjacency, { policy, ttlMax, budgetMax, blocked = new Set() } = {}) {
  const nodes = new Map();
  let forwards = 0;
  for (const key of Object.keys(adjacency)) {
    nodes.set(
      key,
      createRouter({
        self: key,
        neighbors: () => adjacency[key],
        forward: async (peer, env) => {
          forwards += 1;
          return nodes.get(peer).relay(env, key);
        },
        deliver: async (payload, meta) => ({ payload, at: key, via: meta.via, origin: meta.origin }),
        isBlocked: (k) => blocked.has(k),
        policy,
        ttlMax,
        budgetMax,
      }),
    );
  }
  return { nodes, forwards: () => forwards };
}

test("delivers across several hops and threads the response back to the origin", async () => {
  const { nodes } = net({ a: ["b"], b: ["a", "c"], c: ["b", "d"], d: ["c"] });
  const r = await nodes.get("a").send("d", "hello");
  assert.equal(r.delivered, true);
  assert.equal(r.response.at, "d", "delivered at the destination");
  assert.equal(r.response.payload, "hello", "the payload arrived");
  assert.equal(r.response.origin, "a", "the origin is carried");
  assert.deepEqual(r.via, ["a", "b", "c", "d"], "the via path is the route taken");
});

test("finds a route around a graph with cycles, without looping", async () => {
  // A diamond with back-edges everywhere — a naive relay would loop forever.
  const { nodes } = net({ a: ["b", "c"], b: ["a", "c", "d"], c: ["a", "b", "d"], d: ["b", "c"] });
  const r = await nodes.get("a").send("d", "x");
  assert.equal(r.delivered, true);
  assert.equal(r.via[0], "a");
  assert.equal(r.via.at(-1), "d");
  assert.equal(new Set(r.via).size, r.via.length, "no node appears twice on the path");
});

test("an unreachable destination fails cleanly (no route), and terminates", async () => {
  const { nodes } = net({ a: ["b", "c"], b: ["a", "c"], c: ["a", "b"], z: [] }); // z is disconnected
  const r = await nodes.get("a").send("z", "x");
  assert.equal(r.delivered, false);
  assert.equal(r.reason, "no route");
});

test("ttl is a hard depth ceiling", async () => {
  const { nodes } = net({ a: ["b"], b: ["a", "c"], c: ["b", "d"], d: ["c"] });
  const ok = await nodes.get("a").send("d", "x", { ttl: 3 });
  assert.equal(ok.delivered, true, "3 hops fit in ttl 3");
  const tooFar = await nodes.get("a").send("d", "x", { ttl: 2 });
  assert.equal(tooFar.delivered, false, "d is 3 hops away; ttl 2 cannot reach it");
});

test("budget is a hard ceiling on total forwards, so a search cannot flood", async () => {
  // a -> b -> (dead end e); a -> c -> d. Greedy tries b first (by order below).
  const order = (cands) => [...cands].sort(); // b before c before ...
  const { nodes, forwards } = net(
    { a: ["b", "c"], b: ["a", "e"], e: ["b"], c: ["a", "d"], d: ["c"] },
    { policy: { order } },
  );
  const starved = await nodes.get("a").send("d", "x", { budget: 2 });
  assert.equal(starved.delivered, false, "budget 2 is spent exploring the dead end before c is tried");
  assert.ok(forwards() <= 2, `no more than the budget of forwards happened (${forwards()})`);

  const { nodes: n2 } = net(
    { a: ["b", "c"], b: ["a", "e"], e: ["b"], c: ["a", "d"], d: ["c"] },
    { policy: { order } },
  );
  const fed = await n2.get("a").send("d", "x", { budget: 64 });
  assert.equal(fed.delivered, true, "with budget it backtracks past the dead end to c->d");
  assert.deepEqual(fed.via, ["a", "c", "d"]);
});

test("never routes through a blocked key", async () => {
  // Both b and c reach d; block b, so the only usable route is via c.
  const order = (cands) => [...cands].sort(); // would try b first if allowed
  const { nodes } = net(
    { a: ["b", "c"], b: ["a", "d"], c: ["a", "d"], d: ["b", "c"] },
    { policy: { order }, blocked: new Set(["b"]) },
  );
  const r = await nodes.get("a").send("d", "x");
  assert.equal(r.delivered, true);
  assert.ok(!r.via.includes("b"), "the blocked node is never on the path");
  assert.deepEqual(r.via, ["a", "c", "d"]);
});

test("greedy policy orders neighbours toward the destination by XOR distance", async () => {
  // Hex keys so xorDistanceOver(identity) is a real Kademlia metric.
  const dist = xorDistanceOver((k) => k);
  const policy = greedyPolicy({ distance: dist, fanout: 3 });
  // a's neighbours 8 and f; destination f. XOR(8,f)=7, XOR(f,f)=0 -> f is closer,
  // so greedy tries f first. Both reach d=f directly here (f is the dest).
  const { nodes } = net({ a: ["8", "f"], "8": ["a", "f"], f: ["a", "8"] }, { policy });
  const r = await nodes.get("a").send("f", "x");
  assert.equal(r.delivered, true);
  assert.deepEqual(r.via, ["a", "f"], "greedy stepped straight to the closer (destination) key");
});

test("flood policy tries every neighbour (bounded only by ttl/budget)", async () => {
  const { nodes } = net(
    { a: ["b", "c"], b: ["a"], c: ["a", "d"], d: ["c"] }, // b is a dead end; must try c
    { policy: floodPolicy() },
  );
  const r = await nodes.get("a").send("d", "x");
  assert.equal(r.delivered, true, "flood backtracks off the dead-end neighbour to the one that works");
  assert.deepEqual(r.via, ["a", "c", "d"]);
});

test("sending to self delivers locally without a hop", async () => {
  const { nodes, forwards } = net({ a: ["b"], b: ["a"] });
  const r = await nodes.get("a").send("a", "me");
  assert.equal(r.delivered, true);
  assert.deepEqual(r.via, ["a"]);
  assert.equal(forwards(), 0, "no network hop for a local delivery");
});

test("clamps ttl and budget on RECEIPT to local maxima — an oversized envelope can't over-search", async () => {
  // A line b-c-d-e-f; a peer hands b an envelope claiming ttl/budget of 99999.
  const { nodes, forwards } = net(
    { a: ["b"], b: ["a", "c"], c: ["b", "d"], d: ["c", "e"], e: ["d", "f"], f: ["e"] },
    { ttlMax: 3, budgetMax: 5 },
  );
  const r = await nodes.get("b").relay({ dest: "f", ttl: 99999, budget: 99999, visited: ["a"], payload: "x" }, "a");
  assert.equal(r.delivered, false, "ttl clamped to the local max cannot reach a node past it");
  assert.ok(forwards() <= 5, `total forwards bounded by the local budget max, not the claim (${forwards()})`);

  // Sanity: a reachable node within the clamped ttl still delivers.
  const { nodes: n2 } = net(
    { a: ["b"], b: ["a", "c"], c: ["b", "d"], d: ["c"] },
    { ttlMax: 3, budgetMax: 5 },
  );
  const ok = await n2.get("b").relay({ dest: "d", ttl: 99999, budget: 99999, visited: ["a"], payload: "x" }, "a");
  assert.equal(ok.delivered, true, "within the clamped bound it still works");
});
