/**
 * Seal a blob so only the intended recipient can read it — the fabric-level
 * confidentiality primitive from docs/sealing.md. Content is protected end to end:
 * a relay carries an opaque block it cannot open.
 *
 * This is **suite A**, the mandatory zero-dependency default: X25519 (Curve25519
 * ECDH) key agreement, HKDF-SHA256 to a key, AES-256-GCM for the seal, and an
 * Ed25519 signature over the *ciphertext* (seal-then-sign) so the recipient can
 * reject a forged or substituted block **before decrypting** it. Ephemeral-static
 * ECDH — a throwaway sender key against the recipient's static key — gives
 * per-message forward secrecy on the sender's side and works when the recipient is
 * offline (the ephemeral public key travels in the sealed object).
 *
 * All of it is `node:crypto`; no dependency. Keys are PEM, the same shape identities
 * already use. The `suite` tag and the ephemeral key are bound into the AEAD's
 * associated data, so neither can be rewritten (the hook a future negotiated-suite
 * framework needs to resist downgrade).
 *
 * What this does NOT do: it hides *content*, not metadata (size, timing, the
 * destination) — that is the anonymity work — and a valid signature proves only
 * that the holder of `from`'s key sealed it, never that `from` is a peer you trust.
 * The caller authorises `from`; this module only reports it.
 *
 * @module sealing
 */
import {
  generateKeyPairSync,
  createPublicKey,
  createPrivateKey,
  diffieHellman,
  hkdfSync,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  sign as edSign,
  verify as edVerify,
} from "node:crypto";

/** The suite id this module implements. Bound into the seal; checked on open. */
export const SUITE = "A";

const HKDF_INFO = Buffer.from("peerhailer/seal/A/aes-256-gcm");
const KEY_LEN = 32;
const NONCE_LEN = 12;

/** A fresh X25519 key pair (PEM), the sealing key an identity publishes under suite A. */
export function generateSealKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

/** ECDH → HKDF → 32-byte AES key. */
function deriveKey(/** @type {import("node:crypto").KeyObject} */ privateKey, /** @type {import("node:crypto").KeyObject} */ publicKey, /** @type {Buffer} */ salt) {
  const shared = diffieHellman({ privateKey, publicKey });
  return Buffer.from(hkdfSync("sha256", shared, salt, HKDF_INFO, KEY_LEN));
}

/** Associated data bound into the AEAD (and covered by the signature). */
function associatedData(/** @type {string} */ epkPem, /** @type {Buffer} */ salt, /** @type {Buffer} */ nonce, /** @type {string | undefined} */ from) {
  return Buffer.concat([
    Buffer.from(SUITE),
    Buffer.from("\0"),
    Buffer.from(epkPem),
    Buffer.from("\0"),
    salt,
    Buffer.from("\0"),
    nonce,
    Buffer.from("\0"),
    Buffer.from(from ?? ""),
  ]);
}

/**
 * Seal `plaintext` to `recipientPublicKeyPem` (the recipient's static X25519 key).
 * If `signer` (an Ed25519 key pair) is given, the ciphertext is signed so the
 * recipient can authenticate and reject before decrypting; without it the block is
 * confidential but unauthenticated (the caller must decide that is acceptable).
 *
 * @param {Buffer | string} plaintext
 * @param {string} recipientPublicKeyPem  the recipient's X25519 public key (PEM)
 * @param {{ signer?: { privateKey: string, publicKey: string } }} [opts]
 * @returns {{ suite: string, epk: string, salt: string, nonce: string, ct: string, from?: string, sig?: string }}
 */
export function seal(plaintext, recipientPublicKeyPem, { signer } = {}) {
  const pt = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext));
  const recipient = createPublicKey(recipientPublicKeyPem);
  // Ephemeral sender key: forward secrecy on our side, and no need for the
  // recipient to be online.
  const eph = generateKeyPairSync("x25519");
  const epkPem = eph.publicKey.export({ type: "spki", format: "pem" }).toString();
  const salt = randomBytes(16);
  const nonce = randomBytes(NONCE_LEN);
  const key = deriveKey(eph.privateKey, recipient, salt);

  const from = signer?.publicKey;
  const ad = associatedData(epkPem, salt, nonce, from);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(ad);
  const body = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();
  const ct = Buffer.concat([body, tag]); // tag appended

  /** @type {{ suite: string, epk: string, salt: string, nonce: string, ct: string, from?: string, sig?: string }} */
  const sealed = {
    suite: SUITE,
    epk: epkPem,
    salt: salt.toString("base64"),
    nonce: nonce.toString("base64"),
    ct: ct.toString("base64"),
  };
  if (signer) {
    // Seal-then-sign: sign the ciphertext (+ its bound context), so a relay cannot
    // substitute content and the recipient verifies without decrypting.
    sealed.from = signer.publicKey;
    const signed = Buffer.concat([Buffer.from(ct), ad]);
    sealed.sig = edSign(null, signed, createPrivateKey(signer.privateKey)).toString("base64");
  }
  return sealed;
}

/**
 * Open a sealed object with the recipient's static X25519 private key. If the block
 * is signed, the signature is verified **first** (before any decryption); a bad
 * signature throws. Returns the plaintext and the claimed sender `from` — which the
 * caller must still authorise; a valid signature only proves the holder of that key
 * produced it.
 *
 * @param {{ suite: string, epk: string, salt: string, nonce: string, ct: string, from?: string, sig?: string }} sealed
 * @param {string} recipientPrivateKeyPem  the recipient's X25519 private key (PEM)
 * @returns {{ plaintext: Buffer, from: string | null }}
 */
export function open(sealed, recipientPrivateKeyPem) {
  if (!sealed || sealed.suite !== SUITE) throw new Error(`seal: unsupported suite ${sealed?.suite}`);
  const nonce = Buffer.from(sealed.nonce, "base64");
  const ct = Buffer.from(sealed.ct, "base64");
  const salt = Buffer.from(sealed.salt, "base64");
  const ad = associatedData(sealed.epk, salt, nonce, sealed.from);

  // Verify the signature before decrypting — reject forged/substituted blocks
  // without spending decryption on attacker-chosen bytes.
  if (sealed.sig || sealed.from) {
    if (!sealed.sig || !sealed.from) throw new Error("seal: a signed block must carry both from and sig");
    const signed = Buffer.concat([ct, ad]);
    const okSig = edVerify(null, signed, createPublicKey(sealed.from), Buffer.from(sealed.sig, "base64"));
    if (!okSig) throw new Error("seal: signature does not verify");
  }

  const eph = createPublicKey(sealed.epk);
  const key = deriveKey(createPrivateKey(recipientPrivateKeyPem), eph, salt);
  if (ct.length < 16) throw new Error("seal: ciphertext too short");
  const tag = ct.subarray(ct.length - 16);
  const body = ct.subarray(0, ct.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(ad);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(body), decipher.final()]); // throws on tamper
  return { plaintext, from: sealed.from ?? null };
}
