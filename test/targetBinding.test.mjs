/**
 * Binding a hail to its target.
 *
 * A hail authenticates *who* is calling; on its own it does not say *whom the
 * caller meant to reach*, so the same signed bytes authenticate that caller at
 * any peerhailer holding their key — a bearer credential the caller never chose
 * to hand out. `to = fingerprint(target.publicKey)`, signed into `from`, fixes
 * that: a captured hail names its target and is inert if replayed anywhere else.
 *
 * These drive a real daemon over HTTP, because the check lives in `identify` and
 * the whole point is what a *replayed* signed body does at the wrong peer.
 *
 * See docs/hail-target-binding.md.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity, signPayload, fingerprint } from "../src/identity.js";
import { mintGrant } from "../src/grants.js";
import { callPeer, hailPeer } from "../src/hail.js";
import { makePeerRecord, mergePeerRecord, publicRecord, TARGET_BINDING_VERSION } from "../src/peerRecord.js";
import hailPlugin from "../src/builtin/hailPlugin.js";

/** Stand up a daemon that admits `caller` under a hail-able profile. */
async function daemonThatKnows(callerKey, { name = "caller", requireTargetBinding = false } = {}) {
  const me = generateIdentity();
  const directory = createDirectory({ self: { name: "me", publicKey: me.publicKey } });
  directory.useProfiles({ greeter: { name: "greeter", allows: ["hail"] } });
  if (callerKey) directory.admit({ name, publicKey: callerKey, profile: "greeter" });
  const daemon = createDaemon({ directory, identity: me, plugins: [hailPlugin], requireTargetBinding });
  const { port } = await daemon.listen({ port: 0 });
  return { me, directory, daemon, url: `http://127.0.0.1:${port}` };
}

/**
 * POST a hail body verbatim — the shape a replay would resend — and return the
 * HTTP status. A refused hail may come back two ways: a `deny` (an HTTP status)
 * or a `drop` (the socket closed with no reply), and target-binding refusals
 * take the `drop` path. A dropped connection *is* a refusal, so it maps to 0 —
 * never 200. `connection: close` keeps a dropped socket from poisoning the next
 * request through undici's keep-alive pool.
 */
async function post(url, body) {
  try {
    const response = await fetch(`${url}/hail`, {
      method: "POST",
      headers: { "content-type": "application/json", connection: "close" },
      body: JSON.stringify(body),
    });
    return response.status;
  } catch {
    return 0;
  }
}

/** A signed hail from `caller` to the peer whose key fingerprint is `to`. */
function hail(caller, name, to, extra = {}) {
  const from = { name, at: Date.now(), ...(to ? { to } : {}) };
  return { from, signature: signPayload(from, caller.privateKey), ...extra };
}

test("a hail addressed to us is answered; one addressed elsewhere is refused", async () => {
  const caller = generateIdentity();
  const { me, url, daemon } = await daemonThatKnows(caller.publicKey);
  try {
    assert.equal(await post(url, hail(caller, "caller", fingerprint(me.publicKey))), 200, "the right target answers");

    const elsewhere = fingerprint(generateIdentity().publicKey);
    assert.notEqual(await post(url, hail(caller, "caller", elsewhere)), 200, "a hail for another peer is refused");
  } finally {
    await daemon.close();
  }
});

test("the leak is closed: a hail captured at one peer is inert replayed at another", async () => {
  const caller = generateIdentity();
  // Two daemons that both hold the caller's key — the replay scenario exactly.
  const alice = await daemonThatKnows(caller.publicKey);
  const bob = await daemonThatKnows(caller.publicKey);
  try {
    // The caller genuinely hails Alice, binding the hail to Alice's key.
    const toAlice = hail(caller, "caller", fingerprint(alice.me.publicKey));
    assert.equal(await post(alice.url, toAlice), 200, "the honest call to Alice works");

    // An attacker captures those exact signed bytes and replays them at Bob.
    // Same signature, still fresh — and refused, because it names Alice.
    assert.notEqual(await post(bob.url, toAlice), 200, "the captured hail does not authenticate at Bob");
  } finally {
    await alice.daemon.close();
    await bob.daemon.close();
  }
});

test("a present `to` must match even during migration — no downgrade by keeping it", async () => {
  // The daemon does not know the caller binds (no walk yet), so it tolerates a
  // `to`-less hail. But a *present* `to` is always checked, so the moment a
  // caller signs `to`, cross-delivery is closed for that pair with no migration.
  const caller = generateIdentity();
  const { me, url, daemon } = await daemonThatKnows(caller.publicKey);
  try {
    assert.equal(await post(url, hail(caller, "caller", null)), 200, "a genuinely to-less hail is still tolerated");
    assert.equal(await post(url, hail(caller, "caller", fingerprint(me.publicKey))), 200, "the right to is fine");
    assert.notEqual(await post(url, hail(caller, "caller", "wrong-fingerprint")), 200, "a wrong to is always fatal");
  } finally {
    await daemon.close();
  }
});

test("a grant-bearing hail must name its target, from day one", async () => {
  const me = generateIdentity();
  const issuer = generateIdentity();
  const guest = generateIdentity();
  const directory = createDirectory({ self: { name: "me", publicKey: me.publicKey } });
  directory.useProfiles({ delegator: { name: "delegator", allows: ["hail", "delegate"] } });
  directory.admit({ name: "issuer", publicKey: issuer.publicKey, profile: "delegator" });
  const grant = mintGrant({
    issuer: "issuer",
    issuerKey: issuer.publicKey,
    privateKey: issuer.privateKey,
    subjectKey: guest.publicKey,
    capabilities: ["hail"],
  });
  const daemon = createDaemon({ directory, identity: me, plugins: [hailPlugin] });
  const { port } = await daemon.listen({ port: 0 });
  const url = `http://127.0.0.1:${port}`;
  try {
    // A grant-presenter carries no record for us to learn its support from, so
    // there is nothing to migrate: `to` is simply required whenever a grant rides.
    assert.notEqual(await post(url, hail(guest, "guest", null, { grant })), 200, "a to-less grant hail is refused");
    assert.equal(await post(url, hail(guest, "guest", fingerprint(me.publicKey), { grant })), 200, "with to, it is let in");
  } finally {
    await daemon.close();
  }
});

test("once a caller is known to bind, a to-less hail from it is refused (downgrade guard)", async () => {
  const caller = generateIdentity();
  const { me, directory, url, daemon } = await daemonThatKnows(caller.publicKey);
  try {
    // Before we know it binds, a to-less hail is tolerated.
    assert.equal(await post(url, hail(caller, "caller", null)), 200, "tolerated before any support signal");

    // We observe — through a signed record, the only place it is safe — that the
    // caller advertises v1. `noteBinding` records it, monotone.
    directory.noteBinding("caller", TARGET_BINDING_VERSION);

    // Now a replayed old-style (to-less) hail from that caller is refused: we
    // know it signs `to`, so a hail without one is a downgrade.
    assert.notEqual(await post(url, hail(caller, "caller", null)), 200, "to-less refused once known to bind");
    assert.equal(await post(url, hail(caller, "caller", fingerprint(me.publicKey))), 200, "with to it still works");
  } finally {
    await daemon.close();
  }
});

test("require-target-binding refuses every to-less hail — the fully-closed state", async () => {
  const caller = generateIdentity();
  const { me, url, daemon } = await daemonThatKnows(caller.publicKey, { requireTargetBinding: true });
  try {
    assert.notEqual(await post(url, hail(caller, "caller", null)), 200, "no to, no entry when the flag is on");
    assert.equal(await post(url, hail(caller, "caller", fingerprint(me.publicKey))), 200, "a bound hail is fine");
  } finally {
    await daemon.close();
  }
});

test("callPeer signs `to` from the record it dials, end to end", async () => {
  // The caller side computes `to = fingerprint(target key)` from the same record
  // the address came from. Drive a real hail through a real daemon.
  const caller = generateIdentity();
  const { me, url, daemon } = await daemonThatKnows(caller.publicKey);
  try {
    const record = { name: "me", publicKey: me.publicKey, addresses: [{ transport: "lan", value: url, lastOk: null }] };
    const result = await hailPeer(record, { as: { name: "caller", privateKey: caller.privateKey, publicKey: caller.publicKey } });
    assert.equal(result.ok, true, "the hail callPeer signed was accepted — it named the target");
    assert.ok(result.response?.self, "and got an answer");
  } finally {
    await daemon.close();
  }
});

test("a keyless target gets a to-less hail — the one path binding cannot cover", async () => {
  // No key held for the peer, so no fingerprint to sign. callPeer sends no `to`,
  // and a daemon that does not yet know the caller binds tolerates it.
  const caller = generateIdentity();
  const { url, daemon } = await daemonThatKnows(caller.publicKey);
  try {
    const record = { name: "me", addresses: [{ transport: "lan", value: url, lastOk: null }] }; // no publicKey
    const result = await callPeer(record, "/hail", {}, {
      as: { name: "caller", privateKey: caller.privateKey, publicKey: caller.publicKey },
    });
    assert.equal(result.ok, true, "a keyless dial still hails, to-less");
  } finally {
    await daemon.close();
  }
});

test("a routine address update does not clear the downgrade guard", async () => {
  // `hail add <known-peer> <new-address>` re-admits an existing peer. The sticky
  // support observation must survive it, or the guard silently reopens until the
  // next walk. (Kimi review, finding 2.)
  const caller = generateIdentity();
  const { directory, url, daemon } = await daemonThatKnows(caller.publicKey);
  try {
    directory.noteBinding("caller", TARGET_BINDING_VERSION);
    assert.equal(directory.get("caller").bindingSeen, TARGET_BINDING_VERSION, "known to bind");

    // Update the peer's route, exactly as an operator would after it moved.
    directory.admit({ name: "caller", publicKey: caller.publicKey, addresses: [{ transport: "lan", value: "http://moved:9" }] });
    assert.equal(directory.get("caller").bindingSeen, TARGET_BINDING_VERSION, "the guard survived the address update");

    // And it still bites: a to-less hail from that caller is refused.
    assert.notEqual(await post(url, hail(caller, "caller", null)), 200, "to-less still refused after re-admit");
  } finally {
    await daemon.close();
  }
});

test("a gossip merge keeps the advertised version, so support keeps propagating", async () => {
  // `mergePeerRecord` used to drop `v`, so the first `learnFrom` merge erased a
  // peer's support signal and this machine stopped gossiping it. (Kimi finding 2.)
  const mine = makePeerRecord({ name: "p", publicKey: generateIdentity().publicKey, v: 1 });
  const theirs = { name: "p", addresses: [{ transport: "lan", value: "http://x:1" }] }; // no v
  const merged = mergePeerRecord(mine, theirs);
  assert.equal(merged.v, 1, "our known version is not erased by a version-less gossip record");

  // And max wins when both carry one.
  const higher = mergePeerRecord(makePeerRecord({ name: "p", v: 1 }), { name: "p", v: 2 });
  assert.equal(higher.v, 2, "the higher advertised version wins the merge");
  // publicRecord then carries it back onto the wire.
  assert.equal(publicRecord(merged).v, 1, "and it survives back out through publicRecord");
});

test("the self record advertises the binding version, signed and sticky by max", async () => {
  const caller = generateIdentity();
  const { directory, daemon } = await daemonThatKnows(caller.publicKey);
  try {
    // What a peer would receive and verify: our self record carries `v`.
    const response = directory.hailResponse();
    assert.equal(response.self.v, TARGET_BINDING_VERSION, "we advertise the version in our own record");

    // Monotone: a lower/absent version never lowers what was seen.
    directory.noteBinding("caller", 2);
    directory.noteBinding("caller", 1); // a rollback attempt
    assert.equal(directory.get("caller").bindingSeen, 2, "max wins — a stale record cannot roll support back");
    directory.noteBinding("caller", undefined);
    assert.equal(directory.get("caller").bindingSeen, 2, "and an absent version leaves it untouched");
  } finally {
    await daemon.close();
  }
});
