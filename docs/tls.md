# TLS, pinned to the peer's key

**Status: designed, not built.** The thing that makes tunnels work off the
tailnet — and the one place this project uses cryptography it did not already
have, so the design is deliberately conservative.

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
the pin check is not optional and not skippable. And Node's API makes the skip
*easy* — `checkServerIdentity` returning `undefined` accepts — so the failure
shape must be explicit: **the pin callback is total.** Every branch returns a
verified key or throws; `getPeerCertificate()` returning empty (handshake
weirdness, post-handshake auth) throws, never falls through. A pin that can
return `undefined` is a pin that fails open.

**Not a new identity.** The cert key is a *subkey*, vouched for by the existing
Ed25519 identity. Nothing new is *exchanged* — a peer still holds only the
identity key, and verifies the subkey's certificate against it, so there is no
second key to distribute. The subkey is disposable and locally regenerable; the
identity, which `hail rotate` covers, remains the one thing peers pin to.

## Open

- **Rotation and the cert.** When `hail rotate` replaces a peer's key, the pinned
  cert check must follow the new key — trivial if pinning reads the directory
  live per connection rather than caching, which it should.
- **Which end presents a cert.** A tunnel is client→server; the server (the peer
  being reached) presents its identity cert and the client pins it. Whether the
  *client* also presents one — mutual TLS, so the server pins the caller too — is
  worth it: the fabric already authenticates the caller via the signed hail, but
  a mutual pin would bind the TLS session to that same identity rather than
  trusting a separate authentication step. Lean yes, because it closes the gap
  between "who opened this socket" and "who the fabric authenticated."
- **Verifying Node's Ed25519-cert support end to end.** RFC 8410 certs are
  supported, but the exact API path — generating the self-signed cert from an
  existing Ed25519 key without a new keypair, reading the peer cert's SPKI in
  `checkServerIdentity` — needs a spike before the design is called done. This is
  the one place "conservative" means "prove the stdlib does what the RFC says
  before relying on it."
- **The cert as a fingerprinting surface.** A stable identity cert presented on
  every TLS connection is a stable identifier, the same tracking concern the
  discovery beacon has. On a network you do not trust, that is the covert-mode
  question again; note it, defer it.
