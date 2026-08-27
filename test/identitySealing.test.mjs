/**
 * Identities carry an X25519 sealing key beside the Ed25519 identity key, so a peer
 * can seal to them and a sealed block's authenticated `from` is the sender's identity
 * (the finding-5 binding). Existing identities gain a sealing key on load, once.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";

import { generateIdentity, loadIdentity } from "../src/identity.js";
import { seal, openSigned } from "../src/sealing.js";

test("a generated identity has a usable X25519 sealing key", () => {
  const id = generateIdentity();
  assert.match(id.sealPublicKey, /BEGIN PUBLIC KEY/);
  assert.match(id.sealPrivateKey, /BEGIN PRIVATE KEY/);
  // Round-trip a seal to it.
  const sealed = seal("for me", id.sealPublicKey);
  // (open, not openSigned — unsigned round-trip)
  assert.equal(seal && sealed.suite, "A");
});

test("sealing with the identity signing key makes `from` the sender's identity (finding 5)", () => {
  const alice = generateIdentity();
  const bob = generateIdentity();
  // Alice seals to Bob's sealing key, signing with her Ed25519 IDENTITY key.
  const sealed = seal("hi bob", bob.sealPublicKey, {
    signer: { publicKey: alice.publicKey, privateKey: alice.privateKey },
  });
  const { plaintext, from } = openSigned(sealed, bob.sealPrivateKey);
  assert.equal(plaintext.toString(), "hi bob");
  assert.equal(from, alice.publicKey, "the authenticated sender is Alice's identity key — mappable to her peer");
});

test("loadIdentity generates and persists a sealing key for a fresh identity", () => {
  const path = join(mkdtempSync(join(tmpdir(), "id-seal-")), "identity.json");
  const first = loadIdentity(path, { log: () => {} });
  assert.equal(first.created, true);
  assert.match(first.sealPublicKey, /BEGIN PUBLIC KEY/);
  // Re-load reads the same keys from disk (persisted).
  const again = loadIdentity(path, { log: () => {} });
  assert.equal(again.created, false);
  assert.equal(again.sealPublicKey, first.sealPublicKey);
  assert.equal(again.sealPrivateKey, first.sealPrivateKey);
});

test("a legacy identity (no sealing key) is migrated once, identity key untouched", () => {
  const path = join(mkdtempSync(join(tmpdir(), "id-legacy-")), "identity.json");
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const legacy = {
    publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
  writeFileSync(path, JSON.stringify(legacy, null, 2));

  const loaded = loadIdentity(path, { log: () => {} });
  assert.equal(loaded.publicKey, legacy.publicKey, "the Ed25519 identity key is unchanged");
  assert.equal(loaded.privateKey, legacy.privateKey);
  assert.match(loaded.sealPublicKey, /BEGIN PUBLIC KEY/, "a sealing key was added");

  // The migration is persisted to disk...
  const onDisk = JSON.parse(readFileSync(path, "utf8"));
  assert.equal(onDisk.sealPublicKey, loaded.sealPublicKey, "the added key was saved");
  // ...and a second load does not re-migrate (same key).
  const reloaded = loadIdentity(path, { log: () => {} });
  assert.equal(reloaded.sealPublicKey, loaded.sealPublicKey, "not regenerated on the next load");
});
