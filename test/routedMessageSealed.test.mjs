/**
 * Sealed routed payloads (M3b). What matters: a sealed wrapper round-trips so the
 * destination recovers the body while the plaintext never appears on the wire; the seal's
 * signer is bound to the authenticated manifest origin (a block sealed by another key is
 * refused); the recipient's key is required to open; the local floor refuses cleartext;
 * and every tamper/replay is a refusal, never a throw.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { generateIdentity } from "../src/identity.js";
import { buildManifest, keyId, payloadDigest, signManifest } from "../src/routeManifest.js";
import { signRecord } from "../src/peerRecord.js";
import { seal } from "../src/sealing.js";
import { createRouteReplayGuard } from "../src/routeReplayGuard.js";
import { wrapRoutedMessage, openRoutedMessage } from "../src/routedMessage.js";

const T = 1_700_000_000_000;
const MSG_ID = "_9_dyjXkLPnraDMak3Jg0w"; // 16 bytes, canonical base64url

/** A machine: identity (Ed25519), self-record, key id, and X25519 sealing keypair. */
const machine = (name) => {
  const id = generateIdentity();
  return {
    id,
    self: { name, publicKey: id.publicKey, addresses: [] },
    keyId: keyId(id.publicKey),
    sealPublicKey: id.sealPublicKey,
    sealPrivateKey: id.sealPrivateKey,
  };
};

const guardAt = (t = T) => createRouteReplayGuard({ now: () => t });

/** Wrap `body` sealed from `origin` to `dest`. */
const sealedWrap = (origin, dest, body, over = {}) =>
  wrapRoutedMessage({
    self: origin.self,
    privateKey: origin.id.privateKey,
    destinationKeyId: dest.keyId,
    body,
    messageId: MSG_ID,
    now: T,
    validityMs: 60_000,
    sealTo: { recipientKey: dest.sealPublicKey },
    ...over,
  });

/** Open at `dest`, supplying its sealing key by default. */
const openAt = (wrapper, dest, { guard = guardAt(), ...rest } = {}) =>
  openRoutedMessage(wrapper, {
    selfKeyId: dest.keyId,
    guard,
    authorizeOrigin: () => true,
    sealPrivateKey: dest.sealPrivateKey,
    ...rest,
  });

test("a sealed wrapper round-trips; the plaintext never appears on the wire", () => {
  const a = machine("alice");
  const b = machine("bob");
  const marker = "hunter2-plaintext-marker";
  const w = sealedWrap(a, b, { secret: marker });
  assert.equal(w.manifest.payloadMode, "sealed");
  const wire = Buffer.from(w.payload, "base64").toString("utf8");
  assert.ok(!wire.includes(marker), "the plaintext marker is not present in the transported bytes");
  assert.deepEqual(openAt(w, b), { ok: true, body: { secret: marker }, originKeyId: a.keyId });
});

test("a sealed wrapper cannot be opened without the recipient's sealing key", () => {
  const a = machine("alice");
  const b = machine("bob");
  const w = sealedWrap(a, b, { x: 1 });
  assert.deepEqual(
    openRoutedMessage(w, { selfKeyId: b.keyId, guard: guardAt(), authorizeOrigin: () => true }),
    { ok: false, reason: "unsupported-mode" },
  );
});

test("the confidentiality floor refuses a clear wrapper and admits a sealed one", () => {
  const a = machine("alice");
  const b = machine("bob");
  const clearW = wrapRoutedMessage({
    self: a.self,
    privateKey: a.id.privateKey,
    destinationKeyId: b.keyId,
    body: { x: 1 },
    messageId: MSG_ID,
    now: T,
    validityMs: 60_000,
  });
  assert.deepEqual(openAt(clearW, b, { requireSealed: true }), { ok: false, reason: "cleartext-refused" });
  assert.equal(openAt(sealedWrap(a, b, { x: 1 }), b, { requireSealed: true }).ok, true);
});

test("a block sealed by a different key than the manifest origin is refused", () => {
  const a = machine("alice");
  const b = machine("bob");
  const mallory = machine("mallory");
  const bytes = Buffer.from(JSON.stringify({ x: 1 }), "utf8");
  // Sealed to bob, but signed by mallory; alice signs a manifest over that ciphertext.
  const sealed = seal(bytes, b.sealPublicKey, { signer: { publicKey: mallory.id.publicKey, privateKey: mallory.id.privateKey } });
  const transported = Buffer.from(JSON.stringify(sealed), "utf8");
  const manifest = buildManifest({
    originKeyId: a.keyId,
    destinationKeyId: b.keyId,
    messageId: MSG_ID,
    issuedAt: T,
    expiresAt: T + 60_000,
    payloadMode: "sealed",
    payloadDigest: payloadDigest(transported),
  });
  const w = {
    manifest,
    manifestSignature: signManifest(manifest, a.id.privateKey),
    originRecord: signRecord(a.self, a.id.privateKey),
    payload: transported.toString("base64"),
  };
  assert.deepEqual(openAt(w, b), { ok: false, reason: "seal-origin-mismatch" });
});

test("a block sealed to a different key than the opener fails to decrypt", () => {
  const a = machine("alice");
  const b = machine("bob");
  const carol = machine("carol");
  const bytes = Buffer.from(JSON.stringify({ x: 1 }), "utf8");
  // Addressed to bob, but sealed to carol's key: bob can't decrypt it.
  const sealed = seal(bytes, carol.sealPublicKey, { signer: { publicKey: a.id.publicKey, privateKey: a.id.privateKey } });
  const transported = Buffer.from(JSON.stringify(sealed), "utf8");
  const manifest = buildManifest({
    originKeyId: a.keyId,
    destinationKeyId: b.keyId,
    messageId: MSG_ID,
    issuedAt: T,
    expiresAt: T + 60_000,
    payloadMode: "sealed",
    payloadDigest: payloadDigest(transported),
  });
  const w = {
    manifest,
    manifestSignature: signManifest(manifest, a.id.privateKey),
    originRecord: signRecord(a.self, a.id.privateKey),
    payload: transported.toString("base64"),
  };
  assert.deepEqual(openAt(w, b), { ok: false, reason: "seal" });
});

test("tampering the sealed ciphertext is caught by the manifest digest", () => {
  const a = machine("alice");
  const b = machine("bob");
  const w = sealedWrap(a, b, { x: 1 });
  const bytes = Buffer.from(w.payload, "base64");
  bytes[bytes.length - 5] ^= 0xff; // flip a byte, re-encode canonically
  assert.deepEqual(openAt({ ...w, payload: bytes.toString("base64") }, b), { ok: false, reason: "payload-digest" });
});

test("a sealed wrapper is delivered once; a replay is refused", () => {
  const a = machine("alice");
  const b = machine("bob");
  const w = sealedWrap(a, b, { x: 1 });
  const guard = guardAt();
  assert.equal(openAt(w, b, { guard }).ok, true);
  assert.deepEqual(openAt(w, b, { guard }), { ok: false, reason: "replay:duplicate" });
});
