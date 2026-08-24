/**
 * The certified subkey and its pin.
 *
 * The cert key is a subkey; what makes it trustworthy is the identity's vouch
 * carried in the SAN. The tests that matter: the vouch pins to the vouching
 * identity and to nothing else, an expired vouch is refused, and it holds over a
 * real TLS handshake — so a peer vouched by a different identity is a MITM.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import tls from "node:tls";
import { X509Certificate } from "node:crypto";

import { selfSignedCert, certVouchedBy, spkiOf } from "../src/cert.js";
import { generateIdentity } from "../src/identity.js";

test("selfSignedCert makes an Ed25519 cert whose key is a subkey, not the identity", () => {
  const id = generateIdentity();
  const { cert, key } = selfSignedCert(id);
  const x = new X509Certificate(cert);
  assert.equal(x.publicKey.asymmetricKeyType, "ed25519", "a real RFC 8410 cert");
  assert.ok(key.includes("PRIVATE KEY"));
  const certKeySpki = x.publicKey.export({ type: "spki", format: "der" });
  assert.notEqual(Buffer.compare(certKeySpki, spkiOf(id.publicKey)), 0, "the cert key is not the identity key");
  assert.match(x.subjectAltName ?? "", /peerhailer-vouch:/, "and it carries the vouch");
});

test("the pin accepts the vouching identity and rejects any other", () => {
  const me = generateIdentity();
  const impostor = generateIdentity();
  const raw = new X509Certificate(selfSignedCert(me).cert).raw;

  assert.equal(certVouchedBy({ raw }, me.publicKey), true, "the identity that vouched matches");
  assert.equal(certVouchedBy({ raw }, impostor.publicKey), false, "an identity that did not vouch does not");
  assert.equal(certVouchedBy(null, me.publicKey), false, "no cert is not a match");
  assert.equal(certVouchedBy({ raw }, undefined), false, "no expected key is not a match");
  assert.equal(certVouchedBy({}, me.publicKey), false, "a cert with no bytes is not a match");
});

test("an expired vouch is refused", () => {
  const me = generateIdentity();
  const raw = new X509Certificate(selfSignedCert(me, { days: -1 }).cert).raw; // vouch already lapsed
  assert.equal(certVouchedBy({ raw }, me.publicKey), false, "a lapsed vouch does not pin");
});

test("over a real TLS handshake, the vouch identifies the peer", async () => {
  const id = generateIdentity();
  const { cert, key } = selfSignedCert(id);
  const server = tls.createServer({ key, cert }, (s) => s.end("hi"));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  try {
    const pinned = await new Promise((resolve, reject) => {
      const c = tls.connect({ host: "127.0.0.1", port, rejectUnauthorized: false });
      c.once("secureConnect", () => {
        resolve(certVouchedBy(c.getPeerCertificate(true), id.publicKey));
        c.destroy();
      });
      c.once("error", reject);
    });
    assert.equal(pinned, true, "the presented cert's vouch verifies against the held identity");
  } finally {
    server.close();
  }
});

test("a peer vouched by a different identity fails the pin (MITM)", async () => {
  const real = generateIdentity();
  const mallory = generateIdentity();
  // Mallory serves a perfectly valid cert — vouched by *Mallory's* identity.
  const { cert, key } = selfSignedCert(mallory);
  const server = tls.createServer({ key, cert }, (s) => s.end("gotcha"));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  try {
    const pinned = await new Promise((resolve, reject) => {
      const c = tls.connect({ host: "127.0.0.1", port, rejectUnauthorized: false });
      c.once("secureConnect", () => {
        resolve(certVouchedBy(c.getPeerCertificate(true), real.publicKey)); // we expected `real`
        c.destroy();
      });
      c.once("error", reject);
    });
    assert.equal(pinned, false, "a vouch from the wrong identity is not the peer we meant — destroy");
  } finally {
    server.close();
  }
});
