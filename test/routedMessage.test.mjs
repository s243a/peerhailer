/**
 * The routed-message wrapper (M1 integration). What matters: a wrapper the origin
 * built for this destination round-trips exactly once; and every gate — a forged or
 * mismatched origin, a tampered manifest or payload, a wrong destination, a replay,
 * an out-of-window envelope, and any malformed input — is a refusal, never a throw.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { generateIdentity } from "../src/identity.js";
import { buildManifest, keyId, payloadDigest, signManifest } from "../src/routeManifest.js";
import { signRecord } from "../src/peerRecord.js";
import { createRouteReplayGuard } from "../src/routeReplayGuard.js";
import {
  MAX_ROUTED_BODY_BYTES,
  MAX_ROUTED_WRAPPER_BYTES,
  RoutedMessageInputError,
  wrapRoutedMessage,
  openRoutedMessage,
} from "../src/routedMessage.js";

const T = 1_700_000_000_000;

/** A machine: its identity, its self-record, and its key id. */
const machine = (name) => {
  const id = generateIdentity();
  return {
    id,
    self: { name, publicKey: id.publicKey, addresses: [] },
    keyId: keyId(id.publicKey),
  };
};

/** Wrap `body` from `origin` to `dest`, with sensible M1 defaults. */
const wrap = (origin, dest, body, over = {}) =>
  wrapRoutedMessage({
    self: origin.self,
    privateKey: origin.id.privateKey,
    destinationKeyId: dest.keyId,
    body,
    messageId: "_9_dyjXkLPnraDMak3Jg0w", // exactly 16 bytes, canonical base64url
    now: T,
    validityMs: 60_000,
    ...over,
  });

/** A guard pinned to T, so window checks are deterministic. */
const guardAt = (t = T) => createRouteReplayGuard({ now: () => t });
const open = (wrapper, destination, guard = guardAt(), authorizeOrigin = () => true) => {
  const r = openRoutedMessage(wrapper, { selfKeyId: destination.keyId, guard, authorizeOrigin });
  // Strip the receipt- and observation-support fields (messageId/blockIndex/sealed/proof on
  // ok; authenticated on refusal) so the exact-shape assertions here stay focused on open's
  // core result; dedicated tests cover those fields.
  if (r.ok) { const { messageId, blockIndex, sealed, proof, ...core } = r; return core; }
  const { authenticated, ...core } = r;
  return core;
};

/**
 * Hand-build a wrapper `origin` signs over arbitrary `bytes`, with manifest overrides
 * `wrap` would never emit (a non-clear mode, a multi-block count, non-JSON bytes) — to
 * probe the destination gates against a validly-signed-but-hostile manifest.
 */
const forge = (origin, dest, bytes, over = {}) => {
  const manifest = buildManifest({
    originKeyId: origin.keyId,
    destinationKeyId: dest.keyId,
    messageId: "_9_dyjXkLPnraDMak3Jg0w",
    issuedAt: T,
    expiresAt: T + 60_000,
    payloadMode: "clear",
    payloadDigest: payloadDigest(bytes),
    ...over,
  });
  return {
    manifest,
    manifestSignature: signManifest(manifest, origin.id.privateKey),
    originRecord: signRecord(origin.self, origin.id.privateKey),
    payload: bytes.toString("base64"),
  };
};

test("a wrapper built for this destination round-trips, exposing the body and origin", () => {
  const a = machine("alice");
  const b = machine("bob");
  const w = wrap(a, b, { hello: "world" });
  const opened = open(w, b);
  assert.deepEqual(opened, { ok: true, body: { hello: "world" }, originKeyId: a.keyId });
});

test("the same wrapper delivers once; a replay through a fresh open is refused", () => {
  const a = machine("alice");
  const b = machine("bob");
  const w = wrap(a, b, { n: 1 });
  const guard = guardAt();
  assert.equal(open(w, b, guard).ok, true);
  assert.deepEqual(open(w, b, guard), { ok: false, reason: "replay:duplicate" });
});

test("a wrapper addressed to someone else is refused by the destination self-check", () => {
  const a = machine("alice");
  const b = machine("bob");
  const c = machine("carol");
  const w = wrap(a, b, { for: "bob" });
  assert.deepEqual(open(w, c), { ok: false, reason: "not-for-me" });
});

test("a swapped payload breaks the digest binding", () => {
  const a = machine("alice");
  const b = machine("bob");
  const w = wrap(a, b, { amount: 1 });
  const tampered = { ...w, payload: Buffer.from(JSON.stringify({ amount: 1000 }), "utf8").toString("base64") };
  assert.deepEqual(open(tampered, b), { ok: false, reason: "payload-digest" });
});

test("any change to a signed manifest field breaks the signature", () => {
  const a = machine("alice");
  const b = machine("bob");
  const w = wrap(a, b, {});
  for (const [field, value] of [
    ["messageId", Buffer.alloc(16, 1).toString("base64url")],
    ["expiresAt", T + 120_000],
    ["issuedAt", T - 1000], // a valid-shaped but different timestamp
  ]) {
    const opened = open({ ...w, manifest: { ...w.manifest, [field]: value } }, b);
    assert.equal(opened.ok, false, `${field} tamper should be refused`);
  }
});

test("re-signing alice's manifest with a stranger's key still fails the origin binding", () => {
  const a = machine("alice");
  const b = machine("bob");
  const mallory = machine("mallory");
  // Mallory keeps the manifest claiming Alice as origin, signs it with Mallory's
  // private key, and supplies Mallory's record. The claimed/attached origins differ.
  const w = wrap(a, b, { secret: true });
  const forged = {
    ...w,
    manifestSignature: signManifest(w.manifest, mallory.id.privateKey),
    originRecord: signRecord(mallory.self, mallory.id.privateKey),
  };
  assert.deepEqual(open(forged, b), { ok: false, reason: "origin-mismatch" });
});

test("attaching a different peer's record than the manifest names is refused", () => {
  const a = machine("alice");
  const b = machine("bob");
  const mallory = machine("mallory");
  const w = wrap(a, b, {});
  // Keep alice's signed manifest, but swap in mallory's self-record.
  const swapped = { ...w, originRecord: wrap(mallory, b, {}).originRecord };
  assert.deepEqual(open(swapped, b), { ok: false, reason: "origin-mismatch" });
});

test("an out-of-window envelope is refused before it is reserved", () => {
  const a = machine("alice");
  const b = machine("bob");
  const w = wrap(a, b, {});
  // Open it far in the future — past expiry plus skew.
  const late = createRouteReplayGuard({ now: () => T + 10 * 60_000 });
  assert.deepEqual(open(w, b, late), { ok: false, reason: "replay:expired" });
});

test("a signed but non-clear payloadMode is refused, not reinterpreted as cleartext", () => {
  const a = machine("alice");
  const b = machine("bob");
  const bytes = Buffer.from(JSON.stringify({ x: 1 }), "utf8");
  const w = forge(a, b, bytes, { payloadMode: "sealed" });
  assert.deepEqual(open(w, b), { ok: false, reason: "unsupported-mode" });
});

test("a multi-block manifest is refused — a fragment is not delivered as a whole body", () => {
  const a = machine("alice");
  const b = machine("bob");
  const bytes = Buffer.from(JSON.stringify({ part: 1 }), "utf8");
  const w = forge(a, b, bytes, { blockCount: 2 });
  assert.deepEqual(open(w, b), { ok: false, reason: "multi-block" });
});

test("a body that fails to parse is refused and burns no replay reservation", () => {
  const a = machine("alice");
  const b = machine("bob");
  const bytes = Buffer.from("not-json{", "utf8"); // transported intact, but not JSON
  const w = forge(a, b, bytes);
  const guard = guardAt();
  assert.deepEqual(open(w, b, guard), { ok: false, reason: "body" });
  assert.equal(guard.size(), 0, "a parse failure must reserve nothing (guard freshness preserved)");
});

test("malformed wrappers are refusals, not throws", () => {
  const b = machine("bob");
  const g = guardAt();
  for (const bad of [null, undefined, 42, "x", {}, { manifest: {}, originRecord: null, payload: "" }]) {
    const opened = open(bad, b, g);
    assert.equal(opened.ok, false);
    assert.equal(typeof opened.reason, "string");
  }
});

test("origin policy runs before replay allocation and can fail closed", () => {
  const a = machine("alice");
  const b = machine("bob");
  const w = wrap(a, b, { action: "no" });
  const guard = guardAt();
  let classified;
  const opened = open(w, b, guard, ({ originKeyId }) => {
    classified = originKeyId;
    return false;
  });
  assert.deepEqual(opened, { ok: false, reason: "origin-unauthorized" });
  assert.equal(classified, a.keyId, "policy sees only the authenticated origin id");
  assert.equal(guard.size(), 0, "a rejected origin consumes no replay slot");

  const throwing = guardAt();
  assert.deepEqual(open(w, b, throwing, () => { throw new Error("policy failed"); }), {
    ok: false,
    reason: "origin-unauthorized",
  });
  assert.equal(throwing.size(), 0, "a policy exception also fails closed without reserving");
});

test("wrap rejects a mismatched keypair and every non-serialisable top-level body clearly", () => {
  const a = machine("alice");
  const b = machine("bob");
  const stranger = machine("stranger");
  assert.throws(() => wrap(a, b, {}, { privateKey: stranger.id.privateKey }), /does not match/);

  const cyclic = {};
  cyclic.self = cyclic;
  for (const body of [undefined, () => {}, Symbol("x"), 1n, cyclic]) {
    assert.throws(() => wrap(a, b, body), /routed body is not JSON-serialisable/);
  }
  const exact = wrap(a, b, "x".repeat(MAX_ROUTED_BODY_BYTES - 2));
  assert.equal(Buffer.byteLength(JSON.stringify(exact), "utf8") <= MAX_ROUTED_WRAPPER_BYTES, true);
  assert.throws(
    () => wrap(a, b, "x".repeat(MAX_ROUTED_BODY_BYTES - 1)),
    (error) => error instanceof RoutedMessageInputError && /byte limit/.test(error.message),
    "700,001 serialized bytes are refused while exactly 700,000 fit",
  );
  assert.deepEqual(open(wrap(a, b, null), b), { ok: true, body: null, originKeyId: a.keyId });
});

test("the total wrapper ceiling also bounds an unusually large signed self-record", () => {
  const a = machine("alice");
  const b = machine("bob");
  // The origin record is key-only, so a huge `note`/`addresses` are dropped — only the
  // required `name` can bloat it, and the wrapper ceiling still catches that.
  const oversizedRecord = { ...a.self, name: "n".repeat(MAX_ROUTED_WRAPPER_BYTES) };
  assert.throws(
    () => wrapRoutedMessage({
      self: oversizedRecord,
      privateKey: a.id.privateKey,
      destinationKeyId: b.keyId,
      body: null,
      messageId: Buffer.alloc(16, 3).toString("base64url"),
      now: T,
      validityMs: 60_000,
    }),
    /origin record exceeds/,
  );

  // Edge of the classifier: the record with an empty payload field still fits,
  // but no JSON body can encode to fewer than four base64 characters. That is a
  // host-record fault, not a caller body error/HTTP 400.
  const oneName = wrap(a, b, 0, { self: { ...a.self, name: "n" } });
  const oneNameBytes = Buffer.byteLength(JSON.stringify(oneName), "utf8");
  const justImpossibleNameLength = 1 + (MAX_ROUTED_WRAPPER_BYTES - oneNameBytes) + 1;
  assert.throws(
    () => wrap(a, b, 0, { self: { ...a.self, name: "n".repeat(justImpossibleNameLength) } }),
    (error) => !(error instanceof RoutedMessageInputError) && /origin record exceeds/.test(error.message),
  );

  const valid = wrap(a, b, null);
  const tooLargeOnReceive = {
    ...valid,
    originRecord: { ...valid.originRecord, record: { ...valid.originRecord.record, note: "n".repeat(MAX_ROUTED_WRAPPER_BYTES) } },
  };
  assert.deepEqual(open(tooLargeOnReceive, b), { ok: false, reason: "wrapper-too-large" });
});

test("non-canonical base64 in payload or either signature is refused", () => {
  const a = machine("alice");
  const b = machine("bob");
  const w = wrap(a, b, { x: 1 });

  assert.deepEqual(open({ ...w, payload: `${w.payload}!!!!` }, b), { ok: false, reason: "payload" });
  assert.deepEqual(open({ ...w, manifestSignature: `${w.manifestSignature}!!!!` }, b), { ok: false, reason: "manifest" });
  assert.deepEqual(
    open({ ...w, originRecord: { ...w.originRecord, signature: `${w.originRecord.signature}!!!!` } }, b),
    { ok: false, reason: "origin-record" },
  );

  // Change only unused pad bits: Node's lenient decoder produces the same bytes,
  // but this is not the one canonical spelling emitted by Buffer.toString("base64").
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const padAt = w.payload.indexOf("=");
  const at = padAt - 1;
  const oldIndex = alphabet.indexOf(w.payload[at]);
  const alias = `${w.payload.slice(0, at)}${alphabet[oldIndex ^ 1]}${w.payload.slice(at + 1)}`;
  assert.deepEqual(Buffer.from(alias, "base64"), Buffer.from(w.payload, "base64"), "test setup aliases the same bytes");
  assert.deepEqual(open({ ...w, payload: alias }, b), { ok: false, reason: "payload" });
});

test("signed bytes must be strict UTF-8 JSON with finite numeric values", () => {
  const a = machine("alice");
  const b = machine("bob");
  assert.deepEqual(open(forge(a, b, Buffer.from([0x22, 0xff, 0x22])), b), { ok: false, reason: "body" });
  assert.deepEqual(open(forge(a, b, Buffer.from("1e400", "utf8")), b), { ok: false, reason: "body" });
});

test("a stale signed manifest is rejected before a corrupt payload can burn state", () => {
  const a = machine("alice");
  const b = machine("bob");
  const w = wrap(a, b, { x: 1 });
  const late = createRouteReplayGuard({ now: () => T + 10 * 60_000 });
  const corrupt = { ...w, payload: Buffer.from("not the signed body", "utf8").toString("base64") };
  assert.deepEqual(open(corrupt, b, late), { ok: false, reason: "replay:expired" });
  assert.equal(late.size(), 0);
});

test("open surfaces the authenticated identity, for a delivery receipt", () => {
  const a = machine("alice");
  const b = machine("bob");
  const w = wrap(a, b, { x: 1 });
  // On delivery: the authenticated origin, message id, and block index are exposed.
  const ok = openRoutedMessage(w, { selfKeyId: b.keyId, guard: guardAt(), authorizeOrigin: () => true });
  assert.equal(ok.ok, true);
  assert.equal(ok.originKeyId, a.keyId);
  assert.equal(ok.messageId, "_9_dyjXkLPnraDMak3Jg0w");
  assert.equal(ok.blockIndex, 0);
  // A post-authentication refusal carries the same identity under `authenticated`.
  const refused = openRoutedMessage(w, { selfKeyId: b.keyId, guard: guardAt(), authorizeOrigin: () => false });
  assert.equal(refused.reason, "origin-unauthorized");
  assert.deepEqual(refused.authenticated, { originKeyId: a.keyId, messageId: "_9_dyjXkLPnraDMak3Jg0w", blockIndex: 0 });
  // A pre-authentication refusal (not addressed to us) has no authenticated identity.
  const notForMe = openRoutedMessage(w, { selfKeyId: machine("carol").keyId, guard: guardAt(), authorizeOrigin: () => true });
  assert.equal(notForMe.reason, "not-for-me");
  assert.equal(notForMe.authenticated, undefined);
});
