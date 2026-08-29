/**
 * The authenticated route manifest — milestone M1 of `docs/routing-security-roadmap.md`.
 *
 * A relayed message carries a small header the *origin* signs with its identity key,
 * so a relay it passes through cannot forge the origin, strip or re-mint the message
 * id, alter the timing, or swap the payload. This module is only the primitive:
 * build a manifest, sign it, verify it. Binding it to an envelope, the destination's
 * self-check, the replay/dedup state, and confidentiality all live above this, in the
 * routing engine and its milestones — a manifest is *signed*, not *private*, so at M1
 * relays still read payloads.
 *
 * Two deliberate choices from the design review:
 *  - **Canonicalisation is a fixed-order JSON array**, not a generic sorted-object
 *    walk — easier to audit, and a relay cannot reorder or omit a field and still
 *    produce a verifying signature.
 *  - **Key ids are the SHA-256 of the canonical SPKI DER**, not PEM text or the short
 *    human fingerprint — DER is canonical, so the id is stable across PEM whitespace,
 *    and full-width so it is collision-resistant as an identifier.
 *
 * @module routeManifest
 */
import { createHash, createPublicKey } from "node:crypto";

import { signPayload, verifyPayload } from "./identity.js";

/** Prevents a signature made here from verifying as some other peerhailer message. */
export const MANIFEST_DOMAIN = "peerhailer/routed-block";
/** Bump only on an interpretation change; verification refuses an unknown version. */
export const MANIFEST_VERSION = 1;
/** The only digest bound today; carried in the manifest so it can change without ambiguity. */
export const PAYLOAD_DIGEST_ALGORITHM = "sha256";
/** What the committed payload bytes represent. */
export const PAYLOAD_MODES = /** @type {const} */ (["clear", "sealed"]);

// The signed set, in the exact order it is serialised. Order is part of the contract.
const FIELDS = /** @type {const} */ ([
  "domain",
  "version",
  "originKeyId",
  "destinationKeyId",
  "messageId",
  "blockIndex",
  "blockCount",
  "issuedAt",
  "expiresAt",
  "payloadMode",
  "payloadDigestAlgorithm",
  "payloadDigest",
]);

const B64URL = /^[A-Za-z0-9_-]+$/;
const SHA256_B64URL_LEN = 43; // 32 bytes, base64url, unpadded
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

/** @param {unknown} v */
const isSafeUint = (v) => typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= MAX_SAFE;
/** @param {unknown} v @param {number} min @param {number} max */
const isB64Url = (v, min, max) => typeof v === "string" && v.length >= min && v.length <= max && B64URL.test(v);

/**
 * The canonical, collision-resistant id of a public key: SHA-256 of its SPKI DER,
 * base64url. Accepts a PEM string or a `KeyObject`.
 *
 * @param {string | import("node:crypto").KeyObject} publicKey
 * @returns {string}
 */
export function keyId(publicKey) {
  const der = createPublicKey(publicKey).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("base64url");
}

/**
 * The digest a manifest commits to: SHA-256 of the *exact transported bytes*,
 * base64url. Hash the wire bytes — serialised-once cleartext, or the ciphertext at
 * the sealed milestone — never a re-stringified object.
 *
 * @param {Buffer | Uint8Array} bytes
 * @returns {string}
 */
export function payloadDigest(bytes) {
  return createHash("sha256").update(bytes).digest("base64url");
}

/**
 * Validate a manifest's shape and field ranges. Returns the reason it is invalid, or
 * `null` if it is well-formed. Time-window policy (clock skew, maximum validity) is a
 * *local* decision the verifier layers on top — this only checks internal consistency.
 *
 * @param {any} m
 * @returns {string | null}
 */
export function manifestProblem(m) {
  if (!m || typeof m !== "object") return "not an object";
  for (const f of FIELDS) if (!(f in m)) return `missing ${f}`;
  // Exactly the signed fields, no more: an unsigned extra property is not covered by
  // the signature, so a relay could attach one to a valid manifest. Refusing it here
  // means a verified manifest is guaranteed to be precisely what was signed.
  if (Object.keys(m).length !== FIELDS.length) return "unexpected fields";
  if (m.domain !== MANIFEST_DOMAIN) return "wrong domain";
  if (m.version !== MANIFEST_VERSION) return "unknown version";
  if (!isB64Url(m.originKeyId, SHA256_B64URL_LEN, SHA256_B64URL_LEN)) return "bad originKeyId";
  if (!isB64Url(m.destinationKeyId, SHA256_B64URL_LEN, SHA256_B64URL_LEN)) return "bad destinationKeyId";
  if (!isB64Url(m.messageId, 22, 64)) return "bad messageId"; // >= 128 bits of base64url
  if (!isSafeUint(m.blockIndex) || !isSafeUint(m.blockCount)) return "bad block index/count";
  if (m.blockCount < 1 || m.blockIndex >= m.blockCount) return "block index out of range";
  if (!isSafeUint(m.issuedAt) || !isSafeUint(m.expiresAt)) return "bad timestamps";
  if (m.expiresAt <= m.issuedAt) return "expiresAt not after issuedAt";
  if (!PAYLOAD_MODES.includes(m.payloadMode)) return "bad payloadMode";
  if (m.payloadDigestAlgorithm !== PAYLOAD_DIGEST_ALGORITHM) return "unknown digest algorithm";
  if (!isB64Url(m.payloadDigest, SHA256_B64URL_LEN, SHA256_B64URL_LEN)) return "bad payloadDigest";
  return null;
}

/**
 * The signed form: the manifest's fields as a fixed-order array. A relay cannot
 * reorder or drop a field without breaking the signature.
 *
 * @param {any} m
 * @returns {unknown[]}
 */
function toSignedArray(m) {
  return FIELDS.map((f) => m[f]);
}

/**
 * Assemble a manifest from parts, filling the constant fields. Throws on an invalid
 * result — building a malformed manifest is a programming error, not network input.
 *
 * @param {{
 *   originKeyId: string, destinationKeyId: string, messageId: string,
 *   issuedAt: number, expiresAt: number, payloadMode: "clear" | "sealed",
 *   payloadDigest: string, blockIndex?: number, blockCount?: number,
 * }} parts
 * @returns {Record<string, any>}
 */
export function buildManifest(parts) {
  const m = {
    domain: MANIFEST_DOMAIN,
    version: MANIFEST_VERSION,
    originKeyId: parts.originKeyId,
    destinationKeyId: parts.destinationKeyId,
    messageId: parts.messageId,
    blockIndex: parts.blockIndex ?? 0,
    blockCount: parts.blockCount ?? 1,
    issuedAt: parts.issuedAt,
    expiresAt: parts.expiresAt,
    payloadMode: parts.payloadMode,
    payloadDigestAlgorithm: PAYLOAD_DIGEST_ALGORITHM,
    payloadDigest: parts.payloadDigest,
  };
  const problem = manifestProblem(m);
  if (problem) throw new Error(`invalid manifest: ${problem}`);
  return m;
}

/**
 * Sign a manifest with the origin's identity private key. The signature covers the
 * fixed-order array of the (validated) fields.
 *
 * @param {any} manifest
 * @param {string} privateKey the origin's Ed25519 private key (PEM)
 * @returns {string} base64 signature
 */
export function signManifest(manifest, privateKey) {
  const problem = manifestProblem(manifest);
  if (problem) throw new Error(`invalid manifest: ${problem}`);
  return signPayload(toSignedArray(manifest), privateKey);
}

/**
 * Verify a manifest against a signature and the signer's public identity key.
 * Returns `true` only if the manifest is well-formed, the signature covers it, **and**
 * the signer's key is the one the manifest names as its origin (`keyId(publicKey) ===
 * manifest.originKeyId`) — so a relay cannot present a validly-signed manifest for a
 * different origin. A malformed manifest, key, or signature is a `false`, never a
 * throw: it arrives from the network, where malformed is ordinary.
 *
 * @param {any} manifest
 * @param {string} signature base64
 * @param {string} publicKey the signer's Ed25519 public key (PEM)
 * @returns {boolean}
 */
export function verifyManifest(manifest, signature, publicKey) {
  if (manifestProblem(manifest) !== null) return false;
  let signerId;
  try {
    signerId = keyId(publicKey);
  } catch {
    return false;
  }
  if (signerId !== manifest.originKeyId) return false;
  return verifyPayload(toSignedArray(manifest), signature, publicKey);
}
