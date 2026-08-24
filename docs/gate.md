# A password gate for a local web app

**Status: built.** `src/gate.js` is the door; `hail gate set-password` and
`hail gate serve` drive it.

A bastion in front of a web app you run locally — T3, a dashboard, anything with
a port — so a browser reaches it only after a password, over TLS, without the app
itself being exposed. It is the browser-facing counterpart to the peer-facing
`tunnel`: same instinct (an operator declares the local target, the caller never
names it), different door.

## Why it is not a plugin

Every peerhailer plugin route is reached only after a *signed hail* authenticates
the caller and a capability admits it — the invariant at the top of `plugins.js`,
*"a plugin never sees an unauthenticated request."* A browser can satisfy neither
half: it holds no Ed25519 key to sign with, and it needs cookies and a streamed
proxy the plugin contract never hands a handler. So the gate is its **own door**,
with its own auth model — a password and a signed session cookie — kept out of
the peer-authenticated core rather than punching a hole in the invariant that
makes loading a plugin safe.

## The shape

- A **login page** is served for any request without a valid session.
- The right password mints an **HMAC-signed, expiring session cookie**
  (`HttpOnly`, `Secure`, `SameSite=Strict`).
- Every other request is **reverse-proxied** to the locally-declared target —
  including **WebSocket upgrades**, which a modern app (T3 among them) needs to
  function at all. An upgrade without a valid session is dropped.

It is a reverse-proxy, not an iframe: the app is served *through* the gate at the
gate's own origin, so there is no `X-Frame-Options` / CSP `frame-ancestors`
refusal, no clickjacking surface, and no cross-origin cookie dance — the browser
sees one site.

## Using it

```bash
# 1. set a password (read from a prompt, a --password-file, or piped stdin —
#    never an argv, which `ps` and shell history would keep)
hail gate set-password

# 2. serve your local app behind it, over TLS
hail gate serve --target http://127.0.0.1:3000 --port 8443
```

The password is stored **scrypt-hashed** in the state file, never in the clear.
The cookie-signing secret is generated once and kept beside it, so live sessions
survive a restart (and a password change).

## Security posture, stated plainly

- **TLS is not optional.** A password on a plaintext link is no gate. `gate serve`
  always serves over https, and the handler refuses a cleartext arrival outright
  (`requireTls`), so a misconfiguration fails closed. The `Secure` cookie is only
  returned to the browser over TLS anyway.
- **Password at rest:** scrypt with a per-password random salt; verification is
  constant-time. The plaintext password never touches disk or argv.
- **Brute force:** failed logins are counted per source address and, past a
  threshold, locked out for a window — and a correct password is refused while
  the lockout stands. One caveat behind a **loopback-terminating proxy**
  (`tailscale serve`): every client then arrives from `127.0.0.1`, so the
  per-source lockout becomes one global bucket — an attacker's guesses can lock
  the operator out, and per-source accounting buys nothing. Pass
  `--trust-forwarded` there and the gate keys the lockout on the proxy's
  `X-Forwarded-For` (the real client) instead. Only set it behind a proxy that
  overwrites that header — on a direct connection it is client-supplied and must
  not be trusted.
- **Sessions:** a signed token carrying only an expiry (the gate has one
  principal — whoever holds the password — so there is no identity to carry). A
  tampered or expired cookie falls back to the login page and never reaches the
  app; `GET /__peerhailer_gate__/logout` clears it. Changing the password
  **revokes every live session** (the cookie-signing secret is rotated), which is
  the point of changing it — pass `--keep-sessions` to `set-password` only if you
  deliberately want existing sessions to survive.
- **CSRF:** the login POST carries no CSRF token, and does not need one — the
  cookie is `SameSite=Strict`, and a login-CSRF has no payoff on a one-principal
  gate whose session carries no identity. Stated so nobody "fixes" it into a
  regression later.
- **One principal.** This is a shared-password gate, not per-user accounts. It
  raises the bar in front of an app that has none of its own; it is not an
  identity system. If you need per-person access with revocation, that is the
  peer-key door (the capability model), not this.

## The cert question (the one browser reality)

A browser hitting a **self-signed** listener shows a warning and is fussy about
`Secure` cookies. `gate serve` uses the identity's self-signed cert by default
(fine for a quick reach, but it warns), and takes a **provided cert** for a clean
load:

```bash
hail gate serve --target http://127.0.0.1:3000 --port 8443 \
  --tls-cert /path/fullchain.pem --tls-key /path/privkey.pem
```

The clean path is a real cert — e.g. a Let's Encrypt one fronted by `tailscale
serve`, which terminates a valid `*.ts.net` cert into your loopback. That keeps
the app reachable by its tailnet name with no browser warning and without
exposing anything to the public internet. See [tls.md](tls.md) for how peerhailer
handles certs generally.

## What this is not

- **Not per-user auth.** One password, one principal. See above.
- **Not a relay.** It proxies to the **operator's declared target**, never one a
  caller supplies — a browser cannot name a destination. A local port is the
  intended use, and a non-local target is allowed but logs a note on startup
  (fronting an internal service on another host is an operator's call, the same
  "operator declares" trust the tunnel rests on). A *caller* still cannot reach a
  machine they could not otherwise reach; that boundary is
  [network-trust.md](network-trust.md)'s.
- **Not a substitute for the app's own auth** where the app has real accounts —
  it is a bar in front of an app that does not, or a second bar in front of one
  that does.
