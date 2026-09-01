/**
 * The signed delivery receipt — the destination's proof, to the origin, of what it did
 * with a routed message (`docs/routing-security-roadmap.md`).
 *
 * The routed *response* is otherwise unsigned: a relay can forge a "delivered" ack, alter
 * a refusal reason, or grayhole (drop silently while the origin waits). A receipt closes
 * that: the destination signs a small fixed header with its **identity key** — the same
 * key the origin routed to — binding the outcome to the exact `(origin, messageId,
 * blockIndex)`. The origin verifies it against the routing target it chose, so a relay can
 * neither forge a receipt for a key it does not hold, replay one for a different message,
 * nor manufacture a "delivered" it cannot sign. A *missing* receipt is itself the signal:
 * no proof, so treat it as a possible grayhole rather than a delivery.
 *
 * A receipt is signed, not private — it names key ids and an outcome, nothing secret. Its
 * canonicalisation is the same fixed-order array the manifest uses, for the same reason: a
 * relay cannot reorder or drop a field and still produce a verifying signature.
 *
 * @module routeReceipt
 */
import { signPayload, verifyPayload } from "./identity.js";
import { keyId } from "./routeManifest.js";

// The identity key id is the manifest's — imported, not re-derived, so the two copies of a
// security primitive cannot silently drift. Re-exported so receipt consumers and tests keep
// a single `keyId` source.
export { keyId };

/** Prevents a receipt signature from verifying as some other peerhailer message. */
export const RECEIPT_DOMAIN = "peerhailer/routed-receipt";
/** Bump only on an interpretation change; verification refuses an unknown version. */
export const RECEIPT_VERSION = 1;
/** What the destination did. `refused` carries the (bounded) reason; `delivered` is empty. */
export const RECEIPT_OUTCOMES = /** @type {const} */ (["delivered", "refused"]);

// The signed set, in the exact order it is serialised. Order is part of the contract.
const FIELDS = /** @type {const} */ ([
  "domain",
  "version",
  "originKeyId",
  "destinationKeyId",
  "messageId",
  "blockIndex",
  "outcome",
  "reason",
  "issuedAt",
]);
const FIELD_SET = new Set(/** @type {readonly string[]} */ (FIELDS));

const B64URL = /^[A-Za-z0-9_-]+$/;
const ED25519_SIGNATURE_BYTES = 64;
const ED25519_SIGNATURE_B64_LEN = 88; // 64 bytes, base64, padded — the one canonical spelling
const SHA256_B64URL_LEN = 43; // 32 bytes, base64url, unpadded
const MESSAGE_ID_B64URL_LEN = 22; // exactly 16 random bytes, base64url, unpadded
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const MAX_REASON_LEN = 64;
// A refusal reason is one of our own short slugs (e.g. `cleartext-refused`, `replay:duplicate`).
const REASON_RE = /^[a-z0-9:_-]*$/;

/** @param {unknown} v */
const isSafeUint = (v) => typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= MAX_SAFE && !Object.is(v, -0);
/** @param {unknown} v @param {number} min @param {number} max */
const isB64Url = (v, min, max) => typeof v === "string" && v.length >= min && v.length <= max && B64URL.test(v);
/** @param {unknown} v */
const isMessageId = (v) => {
  if (!isB64Url(v, MESSAGE_ID_B64URL_LEN, MESSAGE_ID_B64URL_LEN)) return false;
  const text = /** @type {string} */ (v);
  const bytes = Buffer.from(text, "base64url");
  return bytes.length === 16 && bytes.toString("base64url") === text;
};

/**
 * Validate a receipt's shape and field ranges. Returns the reason it is invalid, or `null`
 * if it is well-formed. Whether the receipt *matches this send* (right origin, right
 * message id, signed by the routing target) is the verifier's job, above this.
 *
 * @param {any} r
 * @returns {string | null}
 */
export function receiptProblem(r) {
  if (!r || typeof r !== "object") return "not an object";
  for (const f of FIELDS) if (!Object.hasOwn(r, f)) return `missing ${f}`;
  const keys = Object.keys(r);
  if (keys.length !== FIELDS.length || keys.some((field) => !FIELD_SET.has(field))) return "unexpected fields";
  if (r.domain !== RECEIPT_DOMAIN) return "wrong domain";
  if (r.version !== RECEIPT_VERSION) return "unknown version";
  if (!isB64Url(r.originKeyId, SHA256_B64URL_LEN, SHA256_B64URL_LEN)) return "bad originKeyId";
  if (!isB64Url(r.destinationKeyId, SHA256_B64URL_LEN, SHA256_B64URL_LEN)) return "bad destinationKeyId";
  if (!isMessageId(r.messageId)) return "bad messageId";
  if (!isSafeUint(r.blockIndex)) return "bad blockIndex";
  if (!RECEIPT_OUTCOMES.includes(r.outcome)) return "bad outcome";
  if (typeof r.reason !== "string" || r.reason.length > MAX_REASON_LEN || !REASON_RE.test(r.reason)) return "bad reason";
  if (r.outcome === "delivered" && r.reason !== "") return "delivered carries a reason";
  if (!isSafeUint(r.issuedAt)) return "bad issuedAt";
  return null;
}

/** The signed form: the receipt's fields as a fixed-order array. @param {any} r */
const toSignedArray = (r) => FIELDS.map((f) => r[f]);

/**
 * Assemble a receipt from parts, filling the constants. Throws on an invalid result —
 * building a malformed receipt is a programming error, not network input.
 *
 * @param {{ originKeyId: string, destinationKeyId: string, messageId: string,
 *   blockIndex?: number, outcome: "delivered" | "refused", reason?: string, issuedAt: number }} parts
 * @returns {Record<string, any>}
 */
export function buildReceipt(parts) {
  const r = {
    domain: RECEIPT_DOMAIN,
    version: RECEIPT_VERSION,
    originKeyId: parts.originKeyId,
    destinationKeyId: parts.destinationKeyId,
    messageId: parts.messageId,
    blockIndex: parts.blockIndex ?? 0,
    outcome: parts.outcome,
    reason: parts.outcome === "refused" ? (parts.reason ?? "") : "",
    issuedAt: parts.issuedAt,
  };
  const problem = receiptProblem(r);
  if (problem) throw new Error(`invalid receipt: ${problem}`);
  return r;
}

/**
 * Sign a receipt with the destination's identity private key (the key the origin routed
 * to). The signature covers the fixed-order array of the validated fields.
 *
 * @param {any} receipt
 * @param {string} privateKey the destination's Ed25519 private key (PEM)
 * @returns {string} base64 signature
 */
export function signReceipt(receipt, privateKey) {
  const problem = receiptProblem(receipt);
  if (problem) throw new Error(`invalid receipt: ${problem}`);
  return signPayload(toSignedArray(receipt), privateKey);
}

/**
 * Verify a receipt against a signature and the **destination's** public identity key.
 * Returns `true` only if the receipt is well-formed, the signature covers it, AND the
 * signer's key is the one the receipt names as its destination (`keyId(publicKey) ===
 * receipt.destinationKeyId`) — so a relay cannot present a receipt signed for a different
 * key. That the receipt's `originKeyId`/`messageId` match *this* send is the caller's
 * check (it holds those). A malformed receipt/key/signature is `false`, never a throw.
 *
 * @param {any} receipt
 * @param {string} signature base64
 * @param {string} publicKey the destination's Ed25519 public key (PEM)
 * @returns {boolean}
 */
export function verifyReceipt(receipt, signature, publicKey) {
  if (receiptProblem(receipt) !== null) return false;
  // Ed25519 signatures are fixed-width. Require the one canonical base64 spelling rather
  // than letting Buffer's lenient decoder ignore whitespace or junk — the same gate the
  // manifest uses, so a relay cannot re-spell the signature string on the wire and still verify.
  if (typeof signature !== "string" || signature.length !== ED25519_SIGNATURE_B64_LEN) return false;
  const signatureBytes = Buffer.from(signature, "base64");
  if (signatureBytes.length !== ED25519_SIGNATURE_BYTES || signatureBytes.toString("base64") !== signature) return false;
  let signerId;
  try {
    signerId = keyId(publicKey);
  } catch {
    return false;
  }
  if (signerId !== receipt.destinationKeyId) return false;
  return verifyPayload(toSignedArray(receipt), signature, publicKey);
}
