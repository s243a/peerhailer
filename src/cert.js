/**
 * A self-signed Ed25519 certificate for a peer's identity key, and the pin that
 * verifies one on the far end of a TLS connection.
 *
 * This is the whole of the cryptography TLS adds, and it is deliberately small:
 * a *comparison*, not a construction. Node's `tls` (OpenSSL) does the handshake,
 * the cipher, the record layer. What lives here is only "is the key on the other
 * end the key I hold for this peer" — the same question `verifyRecord` already
 * answers for a hail, moved to the TLS layer.
 *
 * **The cert key is the identity key, in this version.** The design
 * (`docs/tls.md`) argues for a certified *subkey* to keep the identity out of
 * the TLS stack's blast radius; that is a hardening, and the cost is a vouching
 * statement to transmit and verify per connection. This first cut reuses the
 * identity key directly, so a client pins by comparing the presented cert's
 * public key against the identity key it already holds from the directory — no
 * statement to carry. The subkey is the documented next step; `spkiOf` and the
 * pin are written against a *key*, so swapping in a subkey changes what is
 * pinned, not how.
 *
 * The DER assembly below is serialization, not a cipher — the one cryptographic
 * operation is Node's `sign`, so this does not break the no-hand-rolled-crypto
 * rule the design rests on. Proven end to end by the spike in `docs/tls.md`.
 *
 * @module cert
 */
import { sign, createPrivateKey, createPublicKey, X509Certificate } from "node:crypto";

/**
 * DER tag-length-value. Length is short-form under 128, long-form above.
 * @param {number} tag @param {Buffer} body
 */
function tlv(tag, body) {
  let len;
  if (body.length < 0x80) len = Buffer.from([body.length]);
  else {
    const bytes = [];
    let n = body.length;
    while (n > 0) {
      bytes.unshift(n & 0xff);
      n >>= 8;
    }
    len = Buffer.from([0x80 | bytes.length, ...bytes]);
  }
  return Buffer.concat([Buffer.from([tag]), len, body]);
}
/** @param {...Buffer} c */
const SEQ = (...c) => tlv(0x30, Buffer.concat(c));
/** @param {...Buffer} c */
const SET = (...c) => tlv(0x31, Buffer.concat(c));
/** @param {number[]} bytes */
const OID = (bytes) => tlv(0x06, Buffer.from(bytes));
/** @param {string} s */
const UTF8 = (s) => tlv(0x0c, Buffer.from(s));
/** @param {string} s */
const UTCTIME = (s) => tlv(0x17, Buffer.from(s));
/** @param {Buffer} b */
const BITSTRING = (b) => tlv(0x03, Buffer.concat([Buffer.from([0]), b]));
/** @param {Buffer} c */
const CONTEXT0 = (c) => tlv(0xa0, c);
/** @param {number[]} b */
const INTEGER = (b) => tlv(0x02, Buffer.from(b));

/** The Ed25519 AlgorithmIdentifier (OID 1.3.101.112), used for both the key and the signature. */
const ED25519_ALG = SEQ(OID([0x2b, 0x65, 0x70]));

/** A minimal X.500 name with a single CN. */
const nameCN = (/** @type {string} */ cn) => SEQ(SET(SEQ(OID([0x55, 0x04, 0x03]), UTF8(cn))));

/** A UTCTime `YYMMDDHHMMSSZ` (valid 1950–2049; the ten-year window stays inside it). */
const utcTime = (/** @type {Date} */ date) => date.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z";

/** How long a generated cert is valid. It follows the identity, not a schedule. */
export const CERT_DAYS = 3650;

/**
 * A self-signed Ed25519 certificate for an identity key.
 *
 * @param {{publicKey: string, privateKey: string}} identity  PEM key pair.
 * @param {{ cn?: string, notBefore?: Date, notAfter?: Date }} [options]
 * @returns {{ cert: string, key: string }}  PEM cert and the key to serve it with.
 */
export function selfSignedCert(identity, { cn = "peerhailer", notBefore, notAfter } = {}) {
  const publicKey = createPublicKey(identity.publicKey);
  const privateKey = createPrivateKey(identity.privateKey);
  const spki = publicKey.export({ type: "spki", format: "der" });

  const start = notBefore ?? new Date();
  const end = notAfter ?? new Date(start.getTime() + CERT_DAYS * 86_400_000);

  const tbs = SEQ(
    CONTEXT0(INTEGER([0x02])), // version v3
    INTEGER([0x01]), // serial number
    ED25519_ALG, // signature algorithm
    nameCN(cn), // issuer
    SEQ(UTCTIME(utcTime(start)), UTCTIME(utcTime(end))), // validity
    nameCN(cn), // subject (self-signed)
    spki, // subjectPublicKeyInfo
  );
  // The one cryptographic step. Ed25519 signs the raw message, algorithm `null`.
  const signature = sign(null, tbs, privateKey);
  const certDer = SEQ(tbs, ED25519_ALG, BITSTRING(signature));
  const wrapped = (certDer.toString("base64").match(/.{1,64}/g) ?? []).join("\n");
  const cert = `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----\n`;

  return { cert, key: privateKey.export({ type: "pkcs8", format: "pem" }) };
}

/**
 * The SPKI (SubjectPublicKeyInfo) DER of a public key, the value the pin
 * compares. Accepts a PEM key or a raw certificate DER (a presented peer cert).
 *
 * @param {string | Buffer} keyOrCertDer
 * @returns {Buffer}
 */
export function spkiOf(keyOrCertDer) {
  if (Buffer.isBuffer(keyOrCertDer)) {
    return new X509Certificate(keyOrCertDer).publicKey.export({ type: "spki", format: "der" });
  }
  return createPublicKey(keyOrCertDer).export({ type: "spki", format: "der" });
}

/**
 * Does the certificate presented over TLS carry the key we hold for this peer?
 *
 * This is the pin. It is **total** by construction — a missing cert, an
 * unparseable one, or a key that does not match all return `false`, and the
 * caller destroys the socket on `false`. Nothing about it can return "accept" by
 * omission, which is the failure `checkServerIdentity` invited (see the doc).
 *
 * @param {{ raw?: Buffer } | null | undefined} presented  from `getPeerCertificate(true)`
 * @param {string | undefined} expectedKeyPem  the peer's identity key from the directory
 * @returns {boolean}
 */
export function certMatchesKey(presented, expectedKeyPem) {
  if (!presented || !presented.raw || typeof expectedKeyPem !== "string" || !expectedKeyPem) return false;
  try {
    return Buffer.compare(spkiOf(presented.raw), spkiOf(expectedKeyPem)) === 0;
  } catch {
    return false;
  }
}
