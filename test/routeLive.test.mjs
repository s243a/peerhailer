/**
 * Stage 1 routing over real daemons: a line A—B—D where A has admitted only B and
 * cannot address D directly. A `send` from A to D must relay through B, deliver at
 * D, and thread D's response back to A — all over signed callPeer + the `route`
 * capability. Proves the plugin wiring (key->record, callPeer, deliver) on top of
 * the engine's algorithm (already unit-tested in routing.test.mjs).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity, normalizeKey } from "../src/identity.js";
import hailPlugin from "../src/builtin/hailPlugin.js";
import { createRoutePlugin } from "../src/builtin/routePlugin.js";
import { callPeer } from "../src/hail.js";
import { keyId } from "../src/routeManifest.js";
import { MAX_ROUTED_BODY_BYTES } from "../src/routedMessage.js";

const norm = (k) => normalizeKey(k) ?? k;

test("A reaches D through B: multi-hop relay + delivery + response, over real peers", async (t) => {
  // Identities and directories first.
  const id = { a: generateIdentity(), b: generateIdentity(), d: generateIdentity() };
  const dir = {
    a: createDirectory({ self: { name: "a", publicKey: id.a.publicKey, sealPublicKey: id.a.sealPublicKey } }),
    b: createDirectory({ self: { name: "b", publicKey: id.b.publicKey, sealPublicKey: id.b.sealPublicKey } }),
    d: createDirectory({ self: { name: "d", publicKey: id.d.publicKey, sealPublicKey: id.d.sealPublicKey } }),
  };
  for (const k of ["a", "b", "d"]) dir[k].useProfiles({ r: { name: "r", allows: ["hail", "route"] } });

  // Shared key->record map (filled after the hail listeners are up) and per-node inbox.
  const recordFor = new Map();
  const delivered = {};
  const plugin = {};
  for (const k of ["a", "b", "d"]) {
    const as = { name: k, publicKey: id[k].publicKey, privateKey: id[k].privateKey };
    plugin[k] = createRoutePlugin({
      self: id[k].publicKey,
      privateKey: id[k].privateKey,
      selfRecord: () => dir[k].self,
      normalize: norm,
      neighbors: () => dir[k].listAdmitted().map((p) => norm(p.publicKey)),
      isBlocked: () => false,
      // This demo endpoint only records receipt. Unknown routed origins are
      // explicitly allowed but remain unknown; a capability-bearing consumer
      // would classify the authenticated key against its own policy here.
      authorizeOrigin: () => true,
      forward: async (peerKey, env) => {
        const rec = recordFor.get(peerKey);
        if (!rec) return { delivered: false, reason: "unknown peer", spent: 0 };
        const r = await callPeer(rec, "/route/relay", env, { as });
        return r.ok ? r.response : { delivered: false, reason: r.error, spent: 0 };
      },
      deliver: (payload, meta) => {
        delivered[k] = { payload, via: meta.via, origin: meta.origin };
        return { received: true, at: k, echo: payload };
      },
    });
  }

  const daemon = {};
  const hail = {};
  for (const k of ["a", "b", "d"]) {
    daemon[k] = createDaemon({ directory: dir[k], identity: id[k], plugins: [hailPlugin, plugin[k]] });
    hail[k] = await daemon[k].listenHail({ port: 0, hosts: ["127.0.0.1"], tls: true });
  }
  t.after(async () => { for (const k of ["a", "b", "d"]) await daemon[k].close(); });

  // Records (normalized key -> reachable record).
  for (const k of ["a", "b", "d"]) {
    recordFor.set(norm(id[k].publicKey), { name: k, publicKey: id[k].publicKey, addresses: [{ value: `https://127.0.0.1:${hail[k][0].port}` }] });
  }

  // The line: A admits B; B admits A and D; D admits B. A does NOT know D.
  dir.a.admit({ name: "b", publicKey: id.b.publicKey, addresses: [{ value: `https://127.0.0.1:${hail.b[0].port}` }] }, { profile: "r" });
  dir.b.admit({ name: "a", publicKey: id.a.publicKey }, { profile: "r" });
  dir.b.admit({ name: "d", publicKey: id.d.publicKey, addresses: [{ value: `https://127.0.0.1:${hail.d[0].port}` }] }, { profile: "r" });
  dir.d.admit({ name: "b", publicKey: id.b.publicKey }, { profile: "r" });

  // A cannot reach D directly — B is A's only neighbour, and B knows D.
  const res = await plugin.a.send(norm(id.d.publicKey), "across the graph");
  assert.equal(res.delivered, true, `delivered (${res.reason ?? ""})`);
  assert.equal(res.response.at, "d", "delivered at D");
  assert.equal(res.response.echo, "across the graph", "D got the payload");
  assert.equal(delivered.d?.payload, "across the graph", "D's inbox recorded it");
  assert.equal(delivered.d?.origin, keyId(id.a.publicKey), "D attributes the signed origin, not last hop B");
  assert.deepEqual(res.via.map((k) => Object.keys(id).find((n) => norm(id[n].publicKey) === k)), ["a", "b", "d"], "route was A -> B -> D");

  // M2 Tier-1 discovery: D piggybacked its signed self-record on the response, so A —
  // which never walked to D — now holds D's advertised sealing key, record-carried.
  assert.equal(plugin.a.router.routedSealState(norm(id.d.publicKey)), "record-carried");
  assert.equal(plugin.a.router.routedSealKey(norm(id.d.publicKey)), norm(id.d.sealPublicKey), "A learned D's Tier-1 seal key");

  // The advertised maximum serialized body fits through the actual signed hail
  // request (whose own limit is 1 MB), not only through an in-memory wrapper.
  const emptyShapeBytes = Buffer.byteLength(JSON.stringify({ blob: "" }), "utf8");
  const nearLimit = { blob: "x".repeat(MAX_ROUTED_BODY_BYTES - emptyShapeBytes) };
  assert.equal(Buffer.byteLength(JSON.stringify(nearLimit), "utf8"), MAX_ROUTED_BODY_BYTES);
  const large = await plugin.a.send(norm(id.d.publicKey), nearLimit);
  assert.equal(large.delivered, true, `maximum-size body crossed A -> B -> D (${large.reason ?? ""})`);
  assert.equal(large.response.echo.blob.length, nearLimit.blob.length);

  // And a message to an unreachable key fails cleanly rather than looping.
  const gone = generateIdentity();
  const miss = await plugin.a.send(norm(gone.publicKey), "nowhere", { ttl: 5 });
  assert.equal(miss.delivered, false, "no route to an unknown key");
});
