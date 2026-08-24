/**
 * A grant is an accelerator, never an override.
 *
 * Precedence rule one is that blocked beats everything "whatever else says
 * otherwise". The grant path used to sit outside it: a peer that obtained a
 * valid grant while in good standing kept using it after being blocked, until
 * the TTL ran out. This drives that exact sequence through the daemon.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity, signPayload, fingerprint } from "../src/identity.js";
import { mintGrant } from "../src/grants.js";
import hailPlugin from "../src/builtin/hailPlugin.js";

/** A signed hail carrying a grant, as a peer nobody admitted would send it. */
async function hailWithGrant(url, { name, identity, grant, to }) {
  // `to` binds the hail to this daemon: a grant-bearing hail must name its
  // target, since a grant-presenter carries no record to advertise support.
  const from = { name, at: Date.now(), ...(to ? { to } : {}) };
  const response = await fetch(`${url}/hail`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ from, signature: signPayload(from, identity.privateKey), grant }),
  });
  return response.status;
}

test("blocking a peer stops a grant it already holds", async () => {
  const me = generateIdentity();
  const issuer = generateIdentity();
  const mallory = generateIdentity();

  const directory = createDirectory({ self: { name: "me", publicKey: me.publicKey } });
  // An issuer this machine trusts to delegate.
  directory.useProfiles({
    delegator: { name: "delegator", allows: ["hail", "directory", "delegate"] },
  });
  directory.admit({ name: "issuer", publicKey: issuer.publicKey, profile: "delegator" });

  // Minted while Mallory was in good standing, and still inside its TTL.
  const grant = mintGrant({
    issuer: "issuer",
    issuerKey: issuer.publicKey,
    privateKey: issuer.privateKey,
    subjectKey: mallory.publicKey,
    capabilities: ["hail"],
  });
  assert.ok(grant, "the grant itself is valid");

  const daemon = createDaemon({ directory, identity: me, plugins: [hailPlugin] });
  const { port } = await daemon.listen({ port: 0 });
  const url = `http://127.0.0.1:${port}`;

  try {
    const before = await hailWithGrant(url, { name: "mallory", identity: mallory, grant, to: fingerprint(me.publicKey) });
    assert.equal(before, 200, "a grant lets in a peer nobody admitted — that is what it is for");

    // The operator decides otherwise.
    directory.block({ name: "mallory", publicKey: mallory.publicKey });

    const after = await hailWithGrant(url, { name: "mallory", identity: mallory, grant, to: fingerprint(me.publicKey) });
    assert.notEqual(after, 200, "the same grant must stop working the moment its subject is blocked");
  } finally {
    await daemon.close();
  }
});

test("a grant carrying `directory` grants it, and one that does not does not", async () => {
  const me = generateIdentity();
  const issuer = generateIdentity();
  const guest = generateIdentity();

  const directory = createDirectory({ self: { name: "me", publicKey: me.publicKey } });
  directory.useProfiles({
    delegator: { name: "delegator", allows: ["hail", "directory", "delegate"] },
  });
  directory.admit({ name: "issuer", publicKey: issuer.publicKey, profile: "delegator" });
  directory.admit({ name: "someone", profile: "trusted" });

  const mint = (capabilities) =>
    mintGrant({
      issuer: "issuer",
      issuerKey: issuer.publicKey,
      privateKey: issuer.privateKey,
      subjectKey: guest.publicKey,
      capabilities,
    });

  const daemon = createDaemon({ directory, identity: me, plugins: [hailPlugin] });
  const { port } = await daemon.listen({ port: 0 });

  const ask = async (grant) => {
    const from = { name: "guest", at: Date.now(), to: fingerprint(me.publicKey) };
    const response = await fetch(`http://127.0.0.1:${port}/hail`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ from, signature: signPayload(from, guest.privateKey), grant }),
    });
    return response.ok ? response.json() : { status: response.status };
  };

  try {
    // Hail alone: answered, and told nothing about who this machine knows.
    const narrow = await ask(mint(["hail"]));
    assert.ok(narrow.self, "a grant for hail is answered");
    assert.deepEqual(narrow.peers, [], "and carries no directory");

    // A grant that says `directory` is an issuer saying so deliberately, in
    // something signed and expiring. Ignoring it made grants weaker than
    // assignments, which is backwards.
    const wide = await ask(mint(["hail", "directory"]));
    assert.equal(wide.peers.length, 2, "a grant for directory is honoured");
  } finally {
    await daemon.close();
  }
});

test("a grant confers nothing the issuer does not currently hold", async () => {
  const me = generateIdentity();
  const issuer = generateIdentity();
  const guest = generateIdentity();

  const directory = createDirectory({ self: { name: "me", publicKey: me.publicKey } });
  // May delegate, may hail — and may *not* see who this machine knows.
  directory.useProfiles({ weak: { name: "weak", allows: ["hail", "delegate"] } });
  directory.admit({ name: "issuer", publicKey: issuer.publicKey, profile: "weak" });
  directory.admit({ name: "someone", profile: "trusted" });

  // It mints a grant claiming `directory` anyway. Nothing stops it minting;
  // the check belongs at the point of use, where the issuer's standing is known.
  const grant = mintGrant({
    issuer: "issuer",
    issuerKey: issuer.publicKey,
    privateKey: issuer.privateKey,
    subjectKey: guest.publicKey,
    capabilities: ["hail", "directory"],
  });

  const daemon = createDaemon({ directory, identity: me, plugins: [hailPlugin] });
  const { port } = await daemon.listen({ port: 0 });

  try {
    const from = { name: "guest", at: Date.now(), to: fingerprint(me.publicKey) };
    const response = await fetch(`http://127.0.0.1:${port}/hail`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ from, signature: signPayload(from, guest.privateKey), grant }),
    });
    assert.equal(response.status, 200, "the grant is good for hail, which the issuer does hold");

    const body = await response.json();
    assert.deepEqual(body.peers, [], "delegating what you do not hold is escalation with extra steps");
  } finally {
    await daemon.close();
  }
});
