# TLS, pinned to the peer's key

**Status: built.** `src/cert.js` (the pure-Node cert + the pin), `src/pinnedFetch.js`
(the client side), and `--hail-on-tls <iface>` on the daemon, which serves pinned
TLS on a LAN interface — the handshake makes the arrival encrypted, so a shell or
tunnel runs there off any tailnet. All three layers of the design are in place:

- **Certified subkey.** A fresh Ed25519 key does the TLS; the identity signs a
  *vouch* for it (`{k: cert-key, u: until}`) carried in the cert's SAN URI, and
  the client verifies that vouch against the identity key it holds. The identity
  key never enters the TLS stack.
- **Mutual pinning (mTLS).** The client pins the server's key before its signed
  hail leaves; the server, on a TLS arrival, requires the caller's own client
  cert to be vouched by the caller's identity — so a replayed hail over an
  attacker's socket, lacking that cert, is refused even though its signature is
  valid.
- **An optional provided cert.** `--tls-cert`/`--tls-key` serve a real (Let's
  Encrypt) cert for clients that validate against a CA — a browser — on which
  mutual pinning is off, since a browser cannot present a peerhailer client cert.
  Peers use the self-signed listener; this one is the browser case.

The spike that de-risked all of this is below.

## What it is for

Today an encrypted arrival means Tailscale, because WireGuard is the only
encryption in the stack. `network-trust.md` makes tunnels require an encrypted
arrival, so today tunnels run over the tailnet and nowhere else. TLS is what
extends "encrypted" to a **direct peer-to-peer link** — the household LAN, a
machine you did not enroll in a tailnet, someone else's peer — without a third
party's coordination server in the path.

It is not extra safety layered on what works. It is what makes the fabric work
where Tailscale is not.

## The one rule: no hand-rolled cipher

This is stated first because it is the constraint everything else obeys. An
ephemeral key exchange signed by the identity keys is the textbook shape and
entirely writable — and it would be the most dangerous code in a project whose
safety argument is that it is small enough to read. Reviews this month found
defects in far less subtle code, the same week it was written.

So: **Node's `tls` module, and nothing bespoke below it.** What this project
writes is the *pinning* — deciding whether the certificate on the other end
belongs to the peer we mean — which is a comparison, not a construction. The
cipher, the handshake, the record layer are Node's, which is OpenSSL's, which is
attacked continuously by people who do that for a living.

## The mechanism: a cert key the identity certifies

peerhailer identities are **Ed25519**, and X.509 certificates can be Ed25519
(RFC 8410). Node's `tls` both serves and verifies them. So:

- A daemon generates, once, a **self-signed certificate for a dedicated cert
  key, and has the identity key certify it** — a signed statement "cert key K
  speaks for identity I until time T", verified with the same `verifyPayload`
  machinery the hail already uses. The client pins by verifying that statement:
  the presented cert's key is vouched for by the identity key it holds. Stored
  beside the identity file.

  *Why not reuse the identity key as the cert key directly (the first draft's
  plan)?* Because one Ed25519 key signing both hail payloads and the TLS
  handshake is cross-protocol reuse, and its safety would rest entirely on
  OpenSSL's domain-separation prefix (`"TLS 1.3, server CertificateVerify"` +
  padding) keeping the two signature domains from colliding — a property enforced
  by a third party's framing constant, not by this project's own code, in a
  project whose safety argument is that it is small enough to read. Reuse also
  couples the blast radii: an OpenSSL memory-disclosure bug reading the in-use
  cert key would then leak the *identity*, unrecoverably, rather than a disposable
  subkey. And it buys nothing operationally — `hail rotate` rotates the identity,
  which forces cert regeneration anyway. A certified subkey costs one extra
  verification and keeps "the cert is the identity" one revocable indirection
  away.
- A client connecting over TLS does **not** use a CA. It sets
  `rejectUnauthorized: false` to stop Node applying the web PKI, and instead, in
  the TLS `checkServerIdentity` / on `secureConnect`, reads the peer's presented
  cert key *and* the accompanying certificate statement, and **verifies that
  statement against the identity key the directory holds** — the subkey speaks
  for the identity we pin to. A cert whose statement does not verify under the
  held identity key is refused.

That comparison is the security boundary against key impersonation, and it is the
same check the whole project already rests on: *is this the key I hold for this
name.* A certificate signed by any other key — a real CA, a different peer, a
man-in-the-middle — fails it, exactly as a hail signed by the wrong key fails
`verifyRecord`.

**But the pin only closes key-impersonation, not name-resolution.** The pin
proves "I am talking to the key I hold for X" — at whatever address X's name
currently resolves to. If the address came from one place (DNS on a LAN, an ARP
answer, a CLI argument) and the pinned key from another (the directory), an
attacker who can shift the *address* cannot forge the key, but can change the
question the pin answers: the client gets a pinned session to a peer who will
never answer there, and its traffic flows to a black hole, or to a relay holding
it for later replay. So the rule, stated as a rule: **the pinned key and the
address it dials must come from the same lookup — one directory record, read
once, both fields from it.** Never "resolve the name, then separately ask the
directory for its key." This is the live-read rule the doc already endorses for
rotation, extended from freshness to provenance.

### Why not a CA, and why not the web PKI

A CA answers "did someone in this trust store vouch for this name." This project
does not have names in that sense or a trust store; it has keys it holds for
peers. Pinning asks the question the fabric actually has an answer to. Turning on
the web PKI would *weaken* it — it would accept any cert a public CA issued for a
hostname, which is a wider set than "the key I hold."

### Self-signed is not trust-on-first-use here

The dangerous reading of "self-signed cert" is TOFU — accept whatever shows up
the first time. That is **not** this. The key is pinned *before* the connection,
from the directory, by the same out-of-band exchange that admitted the peer. A
cert whose key we do not already hold is refused, not remembered. There is no
first-use window because there is no first-use acceptance.

## How it composes

- **The encrypted-arrival rule gets a second satisfier.** `network-trust.md` says
  tunnels require an encrypted arrival, served today only over Tailscale. A TLS
  listener whose peer verified the pinned cert is now also an encrypted arrival —
  so `--hail-on` gains a `tls` sense, and the tunnel routes that were tailnet-only
  can run on a pinned-TLS LAN listener too.
- **It does not replace the two-listener split.** Recall `network-trust.md`'s
  refinement: serve tunnel routes only on the encrypted listener, so a plaintext
  arrival gets a 404 rather than a policy check. TLS *is* how a listener becomes
  encrypted without Tailscale under it — so a TLS hail listener serves tunnels, a
  plaintext one does not, and the check stays "which socket did this arrive on."
- **It is the missing half of the ACP tunnel.** `acp-tunnel.md` and the T3
  credential path both say the sealed/authenticated story is complete over
  Tailscale and needs TLS for a direct wire. This is that TLS.

## What it is not

**Not confidentiality against the peer.** TLS encrypts the wire; the peer at the
other end reads everything, as it must to act on it. This protects against
someone *between* the machines, not against the machine you are talking to.

**Not authentication on its own — pinning is.** Plain TLS with
`rejectUnauthorized: false` and no pin authenticates nothing; it encrypts to
whoever answered. The pin is the half that makes the encryption meaningful, so
the pin check is not optional and not skippable.

And here the spike changed the design: **`checkServerIdentity` is the wrong
hook.** Setting `rejectUnauthorized: false` — which we must, to stop Node
applying the web PKI — skips certificate verification *entirely*, and
`checkServerIdentity` is never called (confirmed: the callback did not fire). So
the pin cannot live there. It lives in the **`secureConnect` handler** (client)
and the **connection handler** (server, under `requestCert: true`): read the
presented cert with `getPeerCertificate(true)`, take its key
(`new X509Certificate(peer.raw).publicKey`), compare its SPKI to the key the
directory holds, and **`socket.destroy()` on any failure** before a single byte
of application data is read. That handler is total: a mismatch, a missing cert,
a parse error all destroy the socket; nothing falls through to "accepted". A pin
that can reach the request handler without matching is a pin that fails open.

**Not a new identity.** The cert key is a *subkey*, vouched for by the existing
Ed25519 identity. Nothing new is *exchanged* — a peer still holds only the
identity key, and verifies the subkey's certificate against it, so there is no
second key to distribute. The subkey is disposable and locally regenerable; the
identity, which `hail rotate` covers, remains the one thing peers pin to.

## Spike results (done)

The one thing to prove before building — that Node's stdlib does RFC 8410 the way
the design needs — was run on Node 22. All green, with one correction to the
design (above):

- **Node serves and reads Ed25519 certs.** A `tls` server with an Ed25519
  key/cert handshakes fine, and a client reads the peer's Ed25519 public key from
  `getPeerCertificate(true).raw` via `new X509Certificate(raw).publicKey`.
- **The cert is generatable in pure Node — no dependency.** A ~40-line DER builder
  (SEQUENCE/OID/BIT-STRING helpers) assembles the TBSCertificate, signs it with
  `crypto.sign(null, tbs, ed25519Key)`, and Node parses the result as a valid
  ed25519 cert. So the "generate once, self-signed" step needs no `openssl`
  subprocess and no library — peerhailer stays zero-dependency. The DER encoding
  is serialization, not cryptography, so it does not violate the no-hand-rolled-
  cipher rule: the one cryptographic operation is Node's `sign`.
- **mTLS mutual pinning works** (see the resolved Open item).
- **The `checkServerIdentity` correction** (see *What it is not*): the pin moves to
  the `secureConnect`/connection handler, because `rejectUnauthorized: false`
  skips `checkServerIdentity` entirely. A negative test — presenting a *different*
  cert — was rejected, confirming the pin actually discriminates.

The spike scripts are throwaway; what survives is this design, now accurate.

## When TLS is on, and when it is not

TLS is not a global switch; it is **what makes a listener's arrival count as
encrypted**, which is exactly the property the shell and tunnels already require
(`requiresEncryptedArrival`). So the default follows the wire, not a preference:

| Arrival      | Wire encryption          | peerhailer TLS |
| ------------ | ------------------------ | -------------- |
| **loopback** | none needed (local)      | off — already trusted |
| **tailnet**  | WireGuard already encrypts | off — TLS on top is redundant |
| **LAN / direct** | plaintext            | **on** — the only place it earns its keep |

A pinned-TLS LAN listener *becomes* an encrypted arrival, so the operator no
longer has to *assert* `--hail-on-encrypted` on a LAN NIC (the footgun the
enforcement warns against) — the handshake **proves** it. That is the whole point
of building this: it is what lets a shell or a tunnel run on a household LAN,
off any tailnet.

**Self-signed is right for the fabric; a CA cert is only for browsers.** The pin
is peerhailer verifying peerhailer — no browser, no CA, no Chrome rejection,
nothing published. The one case that needs a real (CA) certificate is a *browser*
connecting **directly** to a TLS endpoint — the web page over TLS, or a browser
reaching a `tunnel:devtools` endpoint itself — because a browser wants a trust
store, not a pin. That is a separate, opt-in concern, not the default, and on a
LAN it is barely available anyway: a bare LAN IP has no public DNS, so Let's
Encrypt cannot issue for it and the only options are a locally-trusted cert or a
non-browser path.

**Let's Encrypt via Tailscale does not expose you.** `tailscale serve` (what a
phone runs to front `127.0.0.1:7645`) uses a real Let's Encrypt cert for the
`<node>.<tailnet>.ts.net` name and serves it **tailnet-only** — the internet-
exposing command is the *different* `tailscale funnel`. So the tailnet already
has proper, browser-valid TLS for free, which is a second reason peerhailer does
nothing there. The only cost is that the hostname lands in public Certificate
Transparency logs — a fingerprinting leak, not an exposure, and the same tracking
concern noted below.

## Two doors, two replay postures — and the shell insists on the strong one

TLS gives a listener an *encrypted* arrival, but not always a *bound* one, and
the difference matters for the strongest routes. Three levels:

- **Mutual** — a self-signed TLS listener that pins the client back (mTLS), or a
  loopback bind where binding is moot because the arrival is local. The caller's
  identity is bound to the socket, so a captured hail cannot be replayed here: a
  replay over an attacker's socket lacks the vouched client cert.
- **Encrypted but unbound** — a provided-cert listener a browser reaches (no
  client cert), or a tailnet address bound directly (WireGuard encrypts the wire,
  but nothing binds the peerhailer identity to the socket). A hail captured
  elsewhere replays here within the freshness window. This is the *pre-TLS* replay
  posture, retained deliberately for browser reachability.
- **Plaintext** — refused for any route that requires encryption at all.

Because these now differ, the **shell** — the strongest capability — is marked
`requiresEncryptedArrival: "mutual"`, not merely `true`: it is served only on a
mutual or loopback arrival, and **404s on an encrypted-but-unbound door** as if
the route were absent. A browser can reach the page over a provided cert; it
cannot reach a remote shell there. Lighter routes (`hail`, the page) still serve
on the unbound door — the browser case they exist for. The general rule: the
listener decides the posture, the route decides how much posture it demands.

## Open

- **Rotation and the cert.** When `hail rotate` replaces a peer's key, the pinned
  cert check must follow the new key — trivial if pinning reads the directory
  live per connection rather than caching, which it should.
- **Which end presents a cert — resolved: both (mTLS).** The spike confirmed
  mutual pinning works with `requestCert: true` on the server: the client pins
  the server's key and the server pins the client's, each by the same
  `getPeerCertificate` read. So the TLS session is bound to *both* identities the
  fabric authenticates, closing the gap between "who opened this socket" and "who
  the hail said it was." Build it mutual.
- **The cert as a fingerprinting surface.** A stable identity cert presented on
  every TLS connection is a stable identifier, the same tracking concern the
  discovery beacon has. On a network you do not trust, that is the covert-mode
  question again; note it, defer it.
