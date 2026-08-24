/**
 * The self-signed cert and its pin.
 *
 * The tests that matter: the cert is a real Ed25519 cert Node can serve, and the
 * pin is total — it accepts the key we hold and rejects everything else, over a
 * real TLS handshake, so a man-in-the-middle presenting its own cert is refused.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import tls from "node:tls";
import { X509Certificate } from "node:crypto";

import { selfSignedCert, certMatchesKey, spkiOf } from "../src/cert.js";
import { generateIdentity } from "../src/identity.js";

test("selfSignedCert produces an Ed25519 cert Node parses", () => {
  const id = generateIdentity();
  const { cert, key } = selfSignedCert(id);
  const x = new X509Certificate(cert);
  assert.equal(x.publicKey.asymmetricKeyType, "ed25519", "a real RFC 8410 cert");
  assert.ok(key.includes("PRIVATE KEY"), "and the key to serve it with");
  // Its key is the identity's key — that is what makes the identity pinnable.
  assert.equal(Buffer.compare(spkiOf(cert === cert ? new X509Certificate(cert).raw : cert), spkiOf(id.publicKey)), 0);
});

test("the pin accepts the held key and rejects any other", () => {
  const me = generateIdentity();
  const impostor = generateIdentity();
  const raw = new X509Certificate(selfSignedCert(me).cert).raw;

  assert.equal(certMatchesKey({ raw }, me.publicKey), true, "the key we hold matches");
  assert.equal(certMatchesKey({ raw }, impostor.publicKey), false, "a different key does not");
  assert.equal(certMatchesKey(null, me.publicKey), false, "no cert is not a match");
  assert.equal(certMatchesKey({ raw }, undefined), false, "no expected key is not a match");
  assert.equal(certMatchesKey({}, me.publicKey), false, "a cert with no bytes is not a match");
});

test("over a real TLS handshake, the pin identifies the peer by key", async () => {
  const id = generateIdentity();
  const { cert, key } = selfSignedCert(id);
  const server = tls.createServer({ key, cert }, (s) => s.end("hello"));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;

  try {
    const pinned = await new Promise((resolve, reject) => {
      // rejectUnauthorized:false — no CA; we pin ourselves in secureConnect.
      const c = tls.connect({ host: "127.0.0.1", port, rejectUnauthorized: false });
      c.once("secureConnect", () => {
        // checkServerIdentity never fires under rejectUnauthorized:false — the
        // pin has to be here, and it destroys on any failure.
        resolve(certMatchesKey(c.getPeerCertificate(true), id.publicKey));
        c.destroy();
      });
      c.once("error", reject);
    });
    assert.equal(pinned, true, "the real presented cert pins to the identity");
  } finally {
    server.close();
  }
});

test("a peer presenting a different cert fails the pin", async () => {
  const real = generateIdentity();
  const mallory = generateIdentity();
  // The server is Mallory, but the client holds `real`'s key.
  const { cert, key } = selfSignedCert(mallory);
  const server = tls.createServer({ key, cert }, (s) => s.end("gotcha"));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;

  try {
    const pinned = await new Promise((resolve, reject) => {
      const c = tls.connect({ host: "127.0.0.1", port, rejectUnauthorized: false });
      c.once("secureConnect", () => {
        resolve(certMatchesKey(c.getPeerCertificate(true), real.publicKey));
        c.destroy();
      });
      c.once("error", reject);
    });
    assert.equal(pinned, false, "Mallory's cert does not pin to the key we expected — destroy the socket");
  } finally {
    server.close();
  }
});
