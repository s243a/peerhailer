/**
 * Sealed routing over real daemons (M3b), the canonical Tier-1 path. A—B—D where A
 * has admitted only B and cannot walk to D — so A cannot hold a Tier-0 key for D. A
 * first routes a *clear* message and learns D's sealing key from the record D piggybacks
 * (M2 discovery); then, opting into Tier 1, A routes a *sealed* message to D. B relays
 * ciphertext it cannot read; D decrypts. Proves the send-resolve → seal → relay → open
 * wiring end to end, and that the plaintext never crosses the relay.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity, normalizeKey } from "../src/identity.js";
import hailPlugin from "../src/builtin/hailPlugin.js";
import { createRoutePlugin } from "../src/builtin/routePlugin.js";
import { callPeer } from "../src/hail.js";

const norm = (k) => normalizeKey(k) ?? k;

test("A seals a routed message to D through B; the relay carries only ciphertext", async (t) => {
  const id = { a: generateIdentity(), b: generateIdentity(), d: generateIdentity() };
  const dir = {
    a: createDirectory({ self: { name: "a", publicKey: id.a.publicKey, sealPublicKey: id.a.sealPublicKey } }),
    b: createDirectory({ self: { name: "b", publicKey: id.b.publicKey, sealPublicKey: id.b.sealPublicKey } }),
    d: createDirectory({ self: { name: "d", publicKey: id.d.publicKey, sealPublicKey: id.d.sealPublicKey } }),
  };
  for (const k of ["a", "b", "d"]) dir[k].useProfiles({ r: { name: "r", allows: ["hail", "route"] } });

  const recordFor = new Map();
  const delivered = {};
  let relayedToD = null; // the envelope B forwards to D on the sealed round
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
      authorizeOrigin: () => true,
      // D can open sealed blocks with its X25519 key.
      ...(k === "d" ? { sealPrivateKey: id.d.sealPrivateKey } : {}),
      // Tier-0 lookup by identity (none of these peers has walked D's sealing key).
      tier0Seal: (destKey) => {
        const peer = dir[k].getByKey?.(destKey);
        if (!peer) return { state: "unverified", key: null };
        return { state: dir[k].sealState(peer.name), key: dir[k].sealKeyFor(peer.name) };
      },
      forward: async (peerKey, env) => {
        const rec = recordFor.get(peerKey);
        if (!rec) return { delivered: false, reason: "unknown peer", spent: 0 };
        if (k === "b" && peerKey === norm(id.d.publicKey)) relayedToD = env;
        const r = await callPeer(rec, "/route/relay", env, { as });
        return r.ok ? r.response : { delivered: false, reason: r.error, spent: 0 };
      },
      deliver: (payload, meta) => {
        delivered[k] = { payload, origin: meta.origin };
        return { received: true, at: k };
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

  for (const k of ["a", "b", "d"]) {
    recordFor.set(norm(id[k].publicKey), { name: k, publicKey: id[k].publicKey, addresses: [{ value: `https://127.0.0.1:${hail[k][0].port}` }] });
  }
  dir.a.admit({ name: "b", publicKey: id.b.publicKey, addresses: [{ value: `https://127.0.0.1:${hail.b[0].port}` }] }, { profile: "r" });
  dir.b.admit({ name: "a", publicKey: id.a.publicKey }, { profile: "r" });
  dir.b.admit({ name: "d", publicKey: id.d.publicKey, addresses: [{ value: `https://127.0.0.1:${hail.d[0].port}` }] }, { profile: "r" });
  dir.d.admit({ name: "b", publicKey: id.b.publicKey }, { profile: "r" });

  // A confidential send would refuse (no key). An explicit PUBLIC, data-free probe carries
  // no application data and discovers D's sealing key from the record D piggybacks back.
  const probe = await plugin.a.send(norm(id.d.publicKey), null, { public: true });
  assert.equal(probe.delivered, true, `discovery probe delivered (${probe.reason ?? ""})`);
  assert.equal(plugin.a.router.routedSealState(norm(id.d.publicKey)), "record-carried", "A discovered D's key (pending)");

  // A confidential send still refuses until the operator approves the discovered key.
  assert.equal((await plugin.a.send(norm(id.d.publicKey), { secret: 1 })).reason, "seal-refused:tier1-pending");
  assert.equal(plugin.a.router.approveRoutedSeal(norm(id.d.publicKey)).ok, true, "operator approves D's key");

  // Round 2 (sealed): now that A holds an APPROVED key, the confidential send seals.
  const marker = "top-secret-plaintext-marker";
  relayedToD = null;
  const sealedRes = await plugin.a.send(norm(id.d.publicKey), { secret: marker });
  assert.equal(sealedRes.delivered, true, `sealed message delivered (${sealedRes.reason ?? ""})`);

  // D decrypted the body; the origin is attributed to A.
  assert.deepEqual(delivered.d.payload, { secret: marker }, "D decrypted the sealed body");

  // The relay B forwarded a sealed wrapper, and the plaintext marker is nowhere in what
  // it carried — B cannot read the message it relayed.
  assert.ok(relayedToD, "B forwarded the sealed message to D");
  assert.equal(relayedToD.payload.manifest.payloadMode, "sealed", "the routed wrapper was sealed");
  assert.ok(!JSON.stringify(relayedToD).includes(marker), "the plaintext never crossed the relay");
});
