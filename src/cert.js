/**
 * A self-signed Ed25519 certificate for a *cert key* the identity vouches for,
 * and the pin that verifies that vouch on the far end of a TLS connection.
 *
 * This is the whole of the cryptography TLS adds, and it is deliberately small:
 * a *comparison and one signature check*, not a construction. Node's `tls`
 * (OpenSSL) does the handshake, the cipher, the record layer. What lives here is
 * only "does the identity I hold for this peer vouch for the key on the other
 * end" — the same question `verifyRecord` answers for a hail, at the TLS layer.
 *
 * **The cert key is a subkey, not the identity.** A daemon generates a fresh
 * Ed25519 key for TLS and has the identity sign a *vouch* — `{k: cert-key, u:
 * until}` — which rides in the certificate's Subject Alternative Name as a URI.
 * The identity key never enters the TLS stack, so an OpenSSL bug reading the
 * in-use key leaks a disposable subkey, not the identity; and the binding is one
 * revocable indirection away (regenerate the cert, re-sign the vouch). The
 * client reads the presented cert's key and the SAN vouch, and checks the vouch
 * against the identity key it already holds from the directory — nothing new is
 * exchanged, and the vouch is self-verifying, so a man-in-the-middle cannot
 * forge one for its own key.
 *
 * The SAN carries the vouch because Node exposes it as `subjectAltName` with no
 * ASN.1 parsing on the read side. The DER *assembly* below is serialization, not
 * a cipher — the one cryptographic operation is a signature — so this keeps the
 * no-hand-rolled-crypto rule the design rests on. Proven by the spike in
 * `docs/tls.md`.
 *
 * @module cert
 */
import { generateKeyPairSync, sign, createPublicKey, X509Certificate } from "node:crypto";

import { signPayload, verifyPayload } from "./identity.js";

/** DER tag-length-value. Length is short-form under 128, long-form above. */
function tlv(/** @type {number} */ tag, /** @type {Buffer} */ body) {
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
/** @param {number[]} b */
const OID = (b) => tlv(0x06, Buffer.from(b));
/** @param {string} s */
const UTF8 = (s) => tlv(0x0c, Buffer.from(s));
/** @param {string} s */
const UTCTIME = (s) => tlv(0x17, Buffer.from(s));
/** @param {Buffer} b */
const BITSTRING = (b) => tlv(0x03, Buffer.concat([Buffer.from([0]), b]));
/** @param {Buffer} b */
const OCTETSTRING = (b) => tlv(0x04, b);
/** @param {number} n @param {Buffer} b */
const CONTEXT = (n, b) => tlv(0xa0 | n, b);
/** @param {number[]} b */
const INTEGER = (b) => tlv(0x02, Buffer.from(b));
/** GeneralName [6] uniformResourceIdentifier (IA5String). @param {string} s */
const GN_URI = (s) => tlv(0x86, Buffer.from(s));

const ED25519_ALG = SEQ(OID([0x2b, 0x65, 0x70]));
const nameCN = (/** @type {string} */ cn) => SEQ(SET(SEQ(OID([0x55, 0x04, 0x03]), UTF8(cn))));
const utcTime = (/** @type {Date} */ date) => date.toISOString().replace(/[-:T]/g, "").slice(2, 14) + "Z";

/** The SAN URI scheme carrying the identity's vouch: `<scheme><until>.<base64 sig>`. */
export const VOUCH_SCHEME = "peerhailer-vouch:";

/** How long a generated cert (and its vouch) is valid. */
export const CERT_DAYS = 3650;

/**
 * A self-signed Ed25519 cert for a fresh subkey, carrying the identity's vouch
 * in its SAN. The returned `key` is the subkey's — it, not the identity, is what
 * TLS holds.
 *
 * @param {{publicKey: string, privateKey: string}} identity  the vouching identity
 * @param {{ cn?: string, days?: number, now?: number }} [options]
 * @returns {{ cert: string, key: string }}
 */
export function selfSignedCert(identity, { cn = "peerhailer", days = CERT_DAYS, now = Date.now() } = {}) {
  const { publicKey: certPub, privateKey: certPriv } = generateKeyPairSync("ed25519");
  const spki = certPub.export({ type: "spki", format: "der" });
  const until = now + days * 86_400_000;

  // The identity vouches for the cert key, once, here. `signPayload` is the same
  // canonical signing the hail uses, so the client verifies it with the same
  // `verifyPayload` and the identity key it already holds.
  const vouchSig = signPayload({ k: spki.toString("base64"), u: until }, identity.privateKey);
  const sanExtension = SEQ(
    OID([0x55, 0x1d, 0x11]), // subjectAltName (2.5.29.17)
    OCTETSTRING(SEQ(GN_URI(`${VOUCH_SCHEME}${until}.${vouchSig}`))),
  );

  const start = new Date(now);
  const end = new Date(until);
  const tbs = SEQ(
    CONTEXT(0, INTEGER([0x02])), // version v3
    INTEGER([0x01]), // serial
    ED25519_ALG,
    nameCN(cn), // issuer
    SEQ(UTCTIME(utcTime(start)), UTCTIME(utcTime(end))), // validity
    nameCN(cn), // subject (self-signed by the cert key)
    spki, // subjectPublicKeyInfo (the cert key)
    CONTEXT(3, SEQ(sanExtension)), // [3] extensions
  );
  // Self-signed *by the cert key*. The identity's role was the vouch above.
  const signature = sign(null, tbs, certPriv);
  const certDer = SEQ(tbs, ED25519_ALG, BITSTRING(signature));
  const wrapped = (certDer.toString("base64").match(/.{1,64}/g) ?? []).join("\n");
  const cert = `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----\n`;

  return { cert, key: certPriv.export({ type: "pkcs8", format: "pem" }) };
}

/** The SPKI (SubjectPublicKeyInfo) DER of a PEM public key. @param {string} keyPem */
export function spkiOf(keyPem) {
  return createPublicKey(keyPem).export({ type: "spki", format: "der" });
}

/**
 * Does the presented certificate carry a valid, unexpired vouch from the
 * identity we hold for this peer?
 *
 * This is the pin. It reads the cert's key and its SAN vouch, and checks that
 * the identity signed "this cert key speaks for me until then" and that *then*
 * is still ahead. **Total** by construction — a missing cert, a missing or
 * malformed vouch, an expired one, a bad signature all return `false`, and the
 * caller destroys the socket on `false`. Nothing accepts by omission, which is
 * the failure `checkServerIdentity` invited (see the doc).
 *
 * @param {{ raw?: Buffer } | null | undefined} presented  from `getPeerCertificate(true)`
 * @param {string | undefined} identityKeyPem  the peer's identity key from the directory
 * @param {number} [nowMs]
 * @returns {boolean}
 */
export function certVouchedBy(presented, identityKeyPem, nowMs = Date.now()) {
  if (!presented || !presented.raw || typeof identityKeyPem !== "string" || !identityKeyPem) return false;
  try {
    const x = new X509Certificate(presented.raw);
    const certKeySpki = x.publicKey.export({ type: "spki", format: "der" });
    const san = x.subjectAltName ?? "";
    const match = san.match(/URI:peerhailer-vouch:(\d+)\.([^,]+)/);
    if (!match) return false;
    const until = Number(match[1]);
    const vouchSig = match[2];
    if (!vouchSig || !(until > nowMs)) return false; // no signature, or the vouch has lapsed
    return verifyPayload({ k: certKeySpki.toString("base64"), u: until }, vouchSig, identityKeyPem);
  } catch {
    return false;
  }
}

/**
 * A client certificate for mutual TLS, one per identity, cached — building it is
 * a keypair generation and a signature, not worth repeating across the many
 * calls a session makes. The identity vouches for its own client subkey exactly
 * as a server does, so the far side pins it with the same `certVouchedBy`.
 *
 * @type {Map<string, { cert: string, key: string }>}
 */
const clientCerts = new Map();

/**
 * @param {{ publicKey: string, privateKey: string }} identity
 * @returns {{ cert: string, key: string }}
 */
export function clientCertFor(identity) {
  const cached = clientCerts.get(identity.publicKey);
  if (cached) return cached;
  const built = selfSignedCert(identity, { cn: "peerhailer-client" });
  clientCerts.set(identity.publicKey, built);
  return built;
}
