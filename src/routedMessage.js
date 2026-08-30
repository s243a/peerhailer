/**
 * The routed-message wrapper — the integration half of milestone M1
 * (`docs/routing-security-roadmap.md`): it ties the authenticated manifest, the
 * attached origin record, the payload-digest binding, the destination self-check,
 * and the replay guard into one origin-side `wrap` and one destination-side `open`.
 *
 * It rides *inside* the routing payload, opaque to the pure engine and to every
 * relay — a relay cannot forge the origin, redirect the message, or swap the body
 * (all of that is under the manifest signature) without the destination refusing it.
 * A **clear** body is signed but not private (relays read it); a **sealed** body (M3b,
 * `payloadMode:"sealed"`) is encrypted to the destination's X25519 key, and the manifest
 * commits to the ciphertext — so relays read nothing while the signature still lives
 * outside the seal (verify-before-decrypt). The signed `payloadMode` records which, so a
 * relay can neither reinterpret one as the other nor downgrade a sealed send.
 * Multi-block reassembly is later.
 *
 * Two limits worth stating precisely:
 *  - **The attached origin record is bound only by its *key*, not by this message.**
 *    The manifest commits to `originKeyId`, so a relay cannot substitute a record for
 *    a *different* key — but it could substitute an older self-signed record of the
 *    *same* origin (stale addresses, an older sealing key). `open` therefore exposes
 *    only `body` and `originKeyId`; a caller must not read address/seal fields out of
 *    the wrapper as if they were message-fresh.
 *  - **The body must be JSON-representable.** `wrap` serialises with `JSON.stringify`,
 *    so `-0`, `NaN`, `Date`, `undefined` properties, etc. are lost the usual way; the
 *    destination always receives the parse of exactly the bytes the origin signed.
 *
 * Trust note: `open` recovers the origin's key from the *self-certifying* attached
 * record (trust-on-first-use for its self-consistency) and binds it to the manifest.
 * That authenticates *which key* produced the message — not *which name* — so a
 * caller must treat an unknown origin as unknown-profile, never as admitted, and must
 * never bind a routed key to a name. Authenticated ≠ admitted.
 *
 * @module routedMessage
 */
import { createPrivateKey, createPublicKey } from "node:crypto";

import { buildManifest, keyId, manifestProblem, payloadDigest, signManifest, verifyManifest } from "./routeManifest.js";
import { signRecord, verifyRecord } from "./peerRecord.js";
import { seal, openSigned } from "./sealing.js";

/** Serialized body ceiling before base64 expansion. */
export const MAX_ROUTED_BODY_BYTES = 700_000;
/**
 * Total signed wrapper ceiling. The peer-facing request limit is 1 MB; keeping the
 * wrapper below 950 kB leaves room for the routing envelope, visited keys, and hail.
 */
export const MAX_ROUTED_WRAPPER_BYTES = 950_000;

/** A host/control caller supplied a body that cannot fit the routed wire contract. */
export class RoutedMessageInputError extends Error {
  /** @param {string} message @param {{cause?: unknown}} [options] */
  constructor(message, options) {
    super(message, options);
    this.name = "RoutedMessageInputError";
  }
}

const MAX_ROUTED_BODY_BASE64_LENGTH = 4 * Math.ceil(MAX_ROUTED_BODY_BYTES / 3);
const MIN_ROUTED_BODY_BASE64_LENGTH = 4; // JSON `0` is one byte -> `MA==`
const ED25519_SIGNATURE_BYTES = 64;
const ED25519_SIGNATURE_BASE64_LENGTH = 88;
const BASE64_SHAPE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const WRAPPER_FIELDS = /** @type {const} */ (["manifest", "manifestSignature", "originRecord", "payload"]);
const SIGNED_RECORD_FIELDS = /** @type {const} */ (["record", "signature"]);
const UTF8 = new TextDecoder("utf-8", { fatal: true });

/** @param {any} value @param {readonly string[]} fields */
const hasExactly = (value, fields) =>
  Boolean(
    value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.keys(value).length === fields.length &&
      fields.every((field) => Object.hasOwn(value, field)),
  );

/** A fixed-width Ed25519 signature in its one canonical standard-base64 spelling. */
/** @param {unknown} value */
const isCanonicalSignature = (value) => {
  if (typeof value !== "string" || value.length !== ED25519_SIGNATURE_BASE64_LENGTH || !BASE64_SHAPE.test(value)) {
    return false;
  }
  const bytes = Buffer.from(value, "base64");
  return bytes.length === ED25519_SIGNATURE_BYTES && bytes.toString("base64") === value;
};

/** JSON.parse can produce Infinity from `1e400`; refuse values JSON cannot represent. */
/** @param {any} value */
const containsNonFiniteNumber = (value) => {
  const pending = [value];
  while (pending.length > 0) {
    const next = pending.pop();
    if (typeof next === "number" && !Number.isFinite(next)) return true;
    if (next && typeof next === "object") {
      for (const child of Object.values(next)) pending.push(child);
    }
  }
  return false;
};

/**
 * Serialise a body to the exact bytes the manifest commits to. Done once at the origin.
 * Throws on a value JSON cannot represent — an origin-side programming error, not
 * network input, so it fails loudly rather than silently sending something else.
 * @param {any} body
 */
const bodyToBytes = (body) => {
  let json;
  try {
    json = JSON.stringify(body);
  } catch (cause) {
    throw new RoutedMessageInputError("routed body is not JSON-serialisable", { cause });
  }
  if (typeof json !== "string") throw new RoutedMessageInputError("routed body is not JSON-serialisable");
  const bytes = Buffer.from(json, "utf8");
  if (bytes.length > MAX_ROUTED_BODY_BYTES) {
    throw new RoutedMessageInputError(`routed body exceeds the ${MAX_ROUTED_BODY_BYTES}-byte limit`);
  }
  return bytes;
};

/**
 * Origin side: build the signed, self-describing wrapper for `body` addressed to the
 * destination key `destinationKeyId` (`keyId(destPublicKey)`). Single-block only.
 *
 * With `sealTo`, the body is **sealed** (M3b): the serialized bytes are encrypted to the
 * destination's X25519 key and signed by the origin's identity key (seal-then-sign), and
 * the manifest commits to the *ciphertext* — so a relay reads nothing, and the manifest
 * signature stays outside the seal (verify-before-decrypt). Without it, the body is
 * cleartext (signed, not private) as at M1/M2. The signed `payloadMode` records which.
 *
 * @param {{
 *   self: any,               // this machine's own record ({name, publicKey, ...})
 *   privateKey: string,      // its Ed25519 private key (PEM)
 *   destinationKeyId: string,
 *   body: any,               // must be JSON-representable
 *   messageId: string,       // exactly 16 random bytes as 22-char base64url
 *   now: number,
 *   validityMs: number,
 *   sealTo?: { recipientKey: string },  // the destination's X25519 sealing key; seals when present
 * }} input
 * @returns {{ manifest: any, manifestSignature: string, originRecord: any, payload: string }}
 */
export function wrapRoutedMessage({ self, privateKey, destinationKeyId, body, messageId, now, validityMs, sealTo }) {
  let originKeyId;
  let signingKeyId;
  try {
    originKeyId = keyId(self?.publicKey);
  } catch (cause) {
    throw new Error("cannot use the origin identity key", { cause });
  }
  try {
    signingKeyId = keyId(createPublicKey(createPrivateKey(privateKey)));
  } catch (cause) {
    throw new Error("cannot use the origin private key", { cause });
  }
  if (originKeyId !== signingKeyId) throw new Error("origin private key does not match self.publicKey");

  const originRecord = signRecord(self, privateKey);
  if (!originRecord) throw new Error("cannot sign the origin record");
  const bodyBytes = bodyToBytes(body);

  // The exact bytes the manifest commits to and the wire carries: the plaintext for a
  // clear send, or the serialized sealed object for a sealed one. The digest is over
  // these — the ciphertext at the sealed milestone, never the plaintext.
  let transported = bodyBytes;
  let payloadMode = /** @type {"clear" | "sealed"} */ ("clear");
  if (sealTo) {
    let sealed;
    try {
      // Sign with the origin *identity* key, so the sealed `from` equals the manifest
      // origin the destination already authenticated — the two are bound at open.
      sealed = seal(bodyBytes, sealTo.recipientKey, { signer: { publicKey: self.publicKey, privateKey } });
    } catch (cause) {
      throw new RoutedMessageInputError("cannot seal to the destination key", { cause });
    }
    transported = Buffer.from(JSON.stringify(sealed), "utf8");
    payloadMode = "sealed";
  }

  // The destination gates the *transported* bytes at MAX_ROUTED_BODY_BYTES, and sealing
  // expands the plaintext (~4/3, base64 ciphertext inside the sealed JSON). Enforce that
  // same ceiling on the transported form here so a body that would always be refused at
  // open fails loudly at *send* instead of wrapping successfully and never arriving.
  if (transported.length > MAX_ROUTED_BODY_BYTES) {
    throw new RoutedMessageInputError(`sealed payload exceeds the ${MAX_ROUTED_BODY_BYTES}-byte transported limit`);
  }

  const manifest = buildManifest({
    originKeyId,
    destinationKeyId,
    messageId,
    issuedAt: now,
    expiresAt: now + validityMs,
    payloadMode,
    payloadDigest: payloadDigest(transported),
  });
  const wrapper = {
    manifest,
    manifestSignature: signManifest(manifest, privateKey),
    originRecord,
    payload: transported.toString("base64"),
  };
  const wireBytes = Buffer.byteLength(JSON.stringify(wrapper), "utf8");
  if (wireBytes > MAX_ROUTED_WRAPPER_BYTES) {
    const fixedBytes = Buffer.byteLength(JSON.stringify({ ...wrapper, payload: "" }), "utf8");
    if (fixedBytes + MIN_ROUTED_BODY_BASE64_LENGTH > MAX_ROUTED_WRAPPER_BYTES) {
      throw new Error(`origin record exceeds the ${MAX_ROUTED_WRAPPER_BYTES}-byte routed-wrapper limit`);
    }
    throw new RoutedMessageInputError(`routed body exceeds the ${MAX_ROUTED_WRAPPER_BYTES}-byte wrapper limit after encoding`);
  }
  return wrapper;
}

/**
 * Destination side: verify a wrapper end to end and, if it is fresh, return the body.
 *
 * In order (each a fail-closed gate): cheap shape/size/destination checks →
 * recover and self-verify the origin record →
 * bind its key to the manifest's origin → verify the manifest signature → authorize
 * that authenticated key → preflight time/replay/capacity → confirm the payload
 * matches its signed digest and strict UTF-8 JSON → reserve in the replay guard.
 * Reservation stays last, so nothing an attacker can force to fail leaves one behind;
 * the non-reserving preflight still rejects stale/duplicate traffic before large-body
 * work. Any failure returns
 * `{ ok: false, reason }`; a malformed wrapper is a refusal, never a throw.
 *
 * A **sealed** wrapper (M3b) is decrypted after all the same gates: the ciphertext is
 * what the manifest committed to, so integrity/replay are checked first, then the block
 * is opened with `sealPrivateKey` and its signed sender is bound to the authenticated
 * manifest origin (the sealer must be the origin). Sealing requires `sealPrivateKey`; a
 * sealed wrapper without one is refused. `requireSealed` is the local confidentiality
 * floor: with it set, a *clear* wrapper is refused — a relay can suppress the record that
 * advertises the floor but cannot forge the origin's signature over a sealed mode+digest.
 *
 * @param {any} wrapper the `{ manifest, manifestSignature, originRecord, payload }` shape
 * @param {{
 *   selfKeyId: string,       // keyId(this machine's public key)
 *   guard: {
 *     check: (m: any) => { ok: true } | { ok: false, reason: string },
 *     admit: (m: any) => { ok: true } | { ok: false, reason: string },
 *   },
 *   authorizeOrigin: (origin: {originKeyId: string}) => boolean,
 *   sealPrivateKey?: string, // this machine's X25519 private key (PEM); required for sealed
 *   requireSealed?: boolean, // local floor: refuse a clear wrapper
 * }} deps
 * @returns {{ ok: true, body: any, originKeyId: string }
 *   | { ok: false, reason: string }}
 */
export function openRoutedMessage(wrapper, { selfKeyId, guard, authorizeOrigin, sealPrivateKey, requireSealed }) {
  if (!hasExactly(wrapper, WRAPPER_FIELDS)) return { ok: false, reason: "malformed" };
  const { manifest, manifestSignature, originRecord, payload } = wrapper;

  // The HTTP door already bounds network input, but direct embedders use this same
  // primitive. Enforce the protocol ceiling here too, before any signature work.
  try {
    if (Buffer.byteLength(JSON.stringify(wrapper), "utf8") > MAX_ROUTED_WRAPPER_BYTES) {
      return { ok: false, reason: "wrapper-too-large" };
    }
  } catch {
    return { ok: false, reason: "malformed" };
  }

  // 1. Shape/size and signed policy fields are safe to reject before crypto. None
  // can make a valid message for us pass; a relay that changes one earns refusal.
  if (manifestProblem(manifest) !== null) return { ok: false, reason: "manifest" };
  if (manifest.destinationKeyId !== selfKeyId) return { ok: false, reason: "not-for-me" };
  // Mode + local floor. `payloadMode` is a signed field, so these are safe pre-crypto
  // rejections a relay cannot leverage: it can neither downgrade sealed→clear nor
  // upgrade clear→sealed without breaking the manifest signature checked below.
  if (manifest.payloadMode === "clear") {
    if (requireSealed) return { ok: false, reason: "cleartext-refused" };
  } else if (manifest.payloadMode === "sealed") {
    if (!sealPrivateKey) return { ok: false, reason: "unsupported-mode" };
  } else {
    return { ok: false, reason: "unsupported-mode" };
  }
  if (manifest.blockCount !== 1) return { ok: false, reason: "multi-block" };
  if (typeof payload !== "string") return { ok: false, reason: "payload" };
  if (payload.length > MAX_ROUTED_BODY_BASE64_LENGTH) return { ok: false, reason: "payload-too-large" };
  if (!BASE64_SHAPE.test(payload)) return { ok: false, reason: "payload" };
  if (!isCanonicalSignature(manifestSignature)) return { ok: false, reason: "manifest" };
  if (!hasExactly(originRecord, SIGNED_RECORD_FIELDS) || !isCanonicalSignature(originRecord.signature)) {
    return { ok: false, reason: "origin-record" };
  }

  // 2. Parse only an Ed25519 identity key and bind the claimed record to the
  // manifest before spending a signature verification on it.
  let presentedKeyId;
  try {
    presentedKeyId = keyId(originRecord.record?.publicKey);
  } catch {
    return { ok: false, reason: "origin-record" };
  }
  if (presentedKeyId !== manifest.originKeyId) return { ok: false, reason: "origin-mismatch" };

  // 3. Recover the origin's key from the self-certifying record (TOFU: its own key).
  const rec = verifyRecord(originRecord, null);
  if (!rec.ok) return { ok: false, reason: "origin-record" };

  // 4. Re-check the normalized verified key, then verify the manifest under it.
  let recKeyId;
  try {
    recKeyId = keyId(rec.key);
  } catch {
    return { ok: false, reason: "origin-record" };
  }
  if (typeof manifest?.originKeyId !== "string" || recKeyId !== manifest.originKeyId) {
    return { ok: false, reason: "origin-mismatch" };
  }
  if (!verifyManifest(manifest, manifestSignature, rec.key)) return { ok: false, reason: "manifest" };

  // 5. Authentication is not admission. Give local policy the authenticated key
  // before either payload work or replay allocation; a rejected/Sybil key consumes
  // no global guard slot. Policy is synchronous and should be side-effect-free.
  let authorized = false;
  try {
    authorized = typeof authorizeOrigin === "function" && authorizeOrigin({ originKeyId: recKeyId }) === true;
  } catch {
    authorized = false;
  }
  if (!authorized) return { ok: false, reason: "origin-unauthorized" };

  // 6. Reject expiry, replay, and capacity before decoding/hashing a large body,
  // without reserving yet (a corrupt first copy must not poison a later good path).
  if (!guard || typeof guard.check !== "function" || typeof guard.admit !== "function") {
    return { ok: false, reason: "replay-guard" };
  }
  const checked = guard.check(manifest);
  if (!checked.ok) return { ok: false, reason: `replay:${checked.reason}` };

  // 7. The payload is the exact canonical base64 spelling of the committed bytes.
  const bytes = Buffer.from(payload, "base64");
  if (bytes.length > MAX_ROUTED_BODY_BYTES) return { ok: false, reason: "payload-too-large" };
  if (bytes.toString("base64") !== payload) return { ok: false, reason: "payload" };
  if (payloadDigest(bytes) !== manifest.payloadDigest) return { ok: false, reason: "payload-digest" };

  // Recover the body. Clear: strict-UTF-8 JSON of the committed bytes. Sealed: the
  // committed bytes are the sealed object; open it (verify-before-decrypt inside), then
  // bind its signed sender to the authenticated manifest origin — the sealer must be the
  // origin, not merely *some* key. Strict UTF-8 avoids replacement-character decoding;
  // JSON may still parse `1e400` to Infinity, so representability is enforced after.
  let body;
  if (manifest.payloadMode === "sealed") {
    let sealed;
    try {
      sealed = JSON.parse(UTF8.decode(bytes));
    } catch {
      return { ok: false, reason: "sealed" };
    }
    let opened;
    try {
      opened = openSigned(sealed, /** @type {string} */ (sealPrivateKey));
    } catch {
      return { ok: false, reason: "seal" };
    }
    let sealerKeyId;
    try {
      sealerKeyId = keyId(opened.from);
    } catch {
      return { ok: false, reason: "seal" };
    }
    if (sealerKeyId !== manifest.originKeyId) return { ok: false, reason: "seal-origin-mismatch" };
    try {
      body = JSON.parse(UTF8.decode(opened.plaintext));
    } catch {
      return { ok: false, reason: "body" };
    }
  } else {
    try {
      body = JSON.parse(UTF8.decode(bytes));
    } catch {
      return { ok: false, reason: "body" };
    }
  }
  if (containsNonFiniteNumber(body)) return { ok: false, reason: "body" };

  // 8. Reserve only after every gate that can reject the bytes has passed.
  const admitted = guard.admit(manifest);
  if (!admitted.ok) return { ok: false, reason: `replay:${admitted.reason}` };

  return { ok: true, body, originKeyId: recKeyId };
}
