/**
 * Who this machine is, cryptographically.
 *
 * A name is a label a person chose; the **identity is the public key**. Two
 * machines may both call themselves `laptop`, and a peer may rename itself
 * tomorrow, but a key either signed something or did not. So names are for
 * humans and keys are for decisions.
 *
 * That is what makes a record's metadata worth anything. Addresses arrive from
 * the network and would otherwise be a stranger's suggestion about where to
 * find your machine — signed, they are a claim only the holder of that key
 * could make.
 *
 * Ed25519, from Node's own crypto: small keys, small signatures, no
 * dependencies, and no parameters to get wrong.
 *
 * The private key lives apart from the directory. The directory is meant to be
 * read, diffed and pasted into a bug report; a secret in a file people are
 * invited to `cat` is a secret with a short life.
 *
 * @module identity
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { defaultStatePath } from "./state.js";

/** @param {string} [statePath] */
export function defaultIdentityPath(statePath = defaultStatePath()) {
  return join(dirname(statePath), "identity.json");
}

/**
 * One spelling of a key, so comparisons mean what they look like.
 *
 * PEM text differs harmlessly between sources: a generated key ends with a
 * newline, one read from a file may not, and one pasted through a form may have
 * either. Comparing raw strings makes a key unequal to itself and surfaces as a
 * peer being refused for presenting "a different key" — true only of the
 * whitespace.
 *
 * @param {unknown} key
 * @returns {string | null}
 */
export function normalizeKey(key) {
  if (typeof key !== "string") return null;
  const trimmed = key.trim();
  return trimmed.length > 0 ? trimmed.replace(/\r\n/g, "\n") : null;
}

/**
 * @param {unknown} left
 * @param {unknown} right
 */
export function sameKey(left, right) {
  const a = normalizeKey(left);
  const b = normalizeKey(right);
  return a !== null && a === b;
}

/**
 * A stable, human-checkable short form of a public key.
 *
 * For reading down a phone line or comparing on a screen — the moment where a
 * person decides whether the machine answering is the one they meant.
 *
 * @param {string} publicKey
 */
export function fingerprint(publicKey) {
  // A hash, not a slice of the key: every Ed25519 SPKI key begins with the same
  // ASN.1 header, so the first characters are identical across all of them and
  // a fingerprint made from them would compare equal between different
  // machines — exactly backwards from the job.
  const digest = createHash("sha256")
    .update(normalizeKey(publicKey) ?? "")
    .digest("base64url")
    .slice(0, 20);
  return digest.match(/.{1,5}/g)?.join("-") ?? digest;
}

/** @returns {{publicKey: string, privateKey: string}} */
export function generateIdentity() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

/**
 * Load this machine's identity, generating one the first time.
 *
 * Generating on first use rather than asking: a key nobody has to think about
 * is a key that exists, and a setup step people skip protects nothing.
 *
 * @param {string} [path]
 * @param {{log?: (message: string) => void}} [options]
 * @returns {{publicKey: string, privateKey: string, created: boolean}}
 */
export function loadIdentity(path = defaultIdentityPath(), { log = () => {} } = {}) {
  try {
    const stored = JSON.parse(readFileSync(path, "utf8"));
    if (typeof stored?.publicKey === "string" && typeof stored?.privateKey === "string") {
      return { publicKey: stored.publicKey, privateKey: stored.privateKey, created: false };
    }
    log(`[identity] ${path} is unusable; keeping it and generating a new key`);
  } catch (cause) {
    const code = /** @type {NodeJS.ErrnoException} */ (cause)?.code;
    if (code !== "ENOENT") {
      // Never overwrite a key we merely failed to read: a transient error must
      // not become a new identity that every peer then rejects.
      throw cause;
    }
  }

  const identity = generateIdentity();
  saveIdentity(identity, path);
  log(`[identity] generated ${fingerprint(identity.publicKey)}`);
  return { ...identity, created: true };
}

/**
 * @param {{publicKey: string, privateKey: string}} identity
 * @param {string} [path]
 */
export function saveIdentity(identity, path = defaultIdentityPath()) {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}`;
  writeFileSync(temporary, `${JSON.stringify(identity, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  chmodSync(temporary, 0o600);
  renameSync(temporary, path);
  return path;
}

/**
 * Canonical bytes for a payload, so both sides sign the same thing.
 *
 * Key order and absent-versus-null are exactly the differences that make a
 * signature verify on one machine and fail on another, so neither is left to
 * `JSON.stringify`.
 *
 * @param {unknown} payload
 * @returns {string}
 */
export function canonicalize(payload) {
  if (payload === null || typeof payload !== "object") return JSON.stringify(payload) ?? "null";
  if (Array.isArray(payload)) return `[${payload.map(canonicalize).join(",")}]`;
  const entries = Object.entries(/** @type {Record<string, unknown>} */ (payload))
    .filter(([, value]) => value !== undefined)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  return `{${entries.map(([key, value]) => `${JSON.stringify(key)}:${canonicalize(value)}`).join(",")}}`;
}

/**
 * @param {unknown} payload
 * @param {string} privateKey
 * @returns {string} base64 signature
 */
export function signPayload(payload, privateKey) {
  return sign(null, Buffer.from(canonicalize(payload), "utf8"), createPrivateKey(privateKey)).toString(
    "base64",
  );
}

/**
 * @param {unknown} payload
 * @param {string} signature base64
 * @param {string} publicKey
 */
export function verifyPayload(payload, signature, publicKey) {
  if (typeof signature !== "string" || typeof publicKey !== "string") return false;
  try {
    return verify(
      null,
      Buffer.from(canonicalize(payload), "utf8"),
      createPublicKey(publicKey),
      Buffer.from(signature, "base64"),
    );
  } catch {
    // A malformed key or signature is a failed verification, not a crash: it
    // arrives from the network, where malformed is a thing that happens.
    return false;
  }
}
