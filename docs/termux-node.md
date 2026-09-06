# Running a Termux phone as a peerhailer node

A phone is a full peerhailer peer — it can be hailed, relay for others, and be a
routed destination — once Termux runs its own userspace `tailscaled` and fronts a
loopback daemon with `tailscale serve`. This is peerhailer's **Path B** (no kernel
TUN); see [deploy-minimal-linux.md](deploy-minimal-linux.md) for the Path A / Path B
split and [two-machines.md](two-machines.md#android-phones) for the deeper Serve and
diagnostics detail. This page is the reproducible bootstrap.

Order matters: **Tailscale first, then the node.** The daemon binds loopback and
`serve` publishes it, so nothing answers peers until both are up.

## Prerequisites

- Termux with Node ≥ 16 (`node -v`) — Ed25519 signing needs it.
- The peerhailer repo cloned. Zero runtime deps, so there is no install step —
  run the CLI as `node bin/hail.js …`.
- A one-time human step: the phone authenticates to your tailnet through a login
  URL in a browser. A persistent `tailscaled` statedir means it only happens once.

## 1. Userspace Tailscale

The Android Tailscale app and Termux do **not** share a `tailscaled`. A phone is a
full peer only when Termux runs its own userspace daemon, which registers as a
second tailnet node beside the app's.

```sh
termux-wake-lock                      # keep the phone from sleeping the daemon
mkdir -p "$HOME/.tailscale"
setsid sh -c 'exec tailscaled \
  --statedir="$HOME/.tailscale" \
  --socket="$HOME/.tailscale/tailscaled.sock" \
  --tun=userspace-networking \
  --socks5-server=127.0.0.1:1055 \
  --outbound-http-proxy-listen=127.0.0.1:1055 \
  > "$HOME/.tailscale/tailscaled.log" 2>&1 < /dev/null' &

tailscale --socket="$HOME/.tailscale/tailscaled.sock" up \
  --hostname=termux-phone --accept-dns=false
```

Pass `--socket=` on **every** `tailscale` call. `TS_SOCKET` is silently ignored on
some builds and falls back to a socket that does not exist, which then fails with
`tailscaled.sock: no such file` and looks like the daemon being down. If `up` prints
a login URL, open it and authenticate; later starts reconnect from the statedir
without it.

Confirm, and note the tailnet identity:

```sh
tailscale --socket="$HOME/.tailscale/tailscaled.sock" status --self
tailscale --socket="$HOME/.tailscale/tailscaled.sock" ip -4
```

## 2. The peerhailer node

Userspace networking creates no `tailscale0` to bind, so bind **loopback** and let
`serve` carry the tailnet to it. Two things matter here, and getting either wrong
leaves the node reachable by a browser but **not by peerhailer peers**:

- **The daemon does TLS itself** — `--hail-on-tls 127.0.0.1`, so it presents *its own*
  certificate (the one carrying the identity's `peerhailer-vouch` SAN that peers pin).
- **`serve` forwards raw TCP (passthrough), it does not terminate TLS.** A *terminating*
  `serve` (the default `serve --bg <port>`) presents its **own Let's Encrypt cert** for
  the MagicDNS name — no vouch — so every peerhailer peer fails the pin with
  `TLS pin failed: the peer's cert is not the key held for it`. Passthrough keeps the
  daemon's vouched cert end-to-end. (See "Terminating vs. passthrough" below.)

```sh
node bin/hail.js status 2>/dev/null || node bin/hail.js name phone
node bin/hail.js id > "$HOME/phone.pub"       # the key to hand to peers

setsid sh -c 'exec node bin/hail.js \
  daemon --hail-on-tls 127.0.0.1 --port 7645 --route \
  > "$HOME/hail-daemon.log" 2>&1 < /dev/null' &
sleep 2 && cat "$HOME/hail-daemon.log"         # expect: hails on https://127.0.0.1:7645 (pinned TLS, mutual)
```

Add `--ui` only if you need the page or the route control API *on the phone*; leave it
off for a node that is only a peer, relay, or destination.

Publish the loopback port as a **raw-TCP passthrough** on 443 (not the default HTTPS
reverse proxy):

```sh
tailscale --socket="$HOME/.tailscale/tailscaled.sock" serve reset
tailscale --socket="$HOME/.tailscale/tailscaled.sock" serve --bg --tcp 443 tcp://127.0.0.1:7645
tailscale --socket="$HOME/.tailscale/tailscaled.sock" serve status
```

`--tcp 443 tcp://127.0.0.1:7645` forwards raw TCP — the **daemon** terminates the TLS,
so its vouched cert reaches the caller. Do **not** use the bare-port HTTPS proxy
(`serve --bg 7645`) or `--tls-terminated-tcp`: both terminate TLS at `serve` and break
the identity pin. A healthy status shows
`tcp://<name>…:443 (TLS over TCP) → tcp://127.0.0.1:7645`.

### Terminating vs. passthrough (why the daemon does the TLS)

peerhailer authenticates a peer at the TLS layer by **pinning**: the peer's self-signed
cert carries a `subjectAltName` of `peerhailer-vouch:<until>.<sig>` — the identity key
signing *"this TLS key is mine."* A terminating `serve` is a reverse proxy: it completes
the TLS handshake itself with a CA (Let's Encrypt) cert that has no such vouch, then
forwards plaintext to the daemon — so the caller never sees the daemon's cert, and the
pin fails. Passthrough makes `serve` a dumb TCP pipe: the handshake is end-to-end between
the caller and the daemon, so the daemon's vouched cert is what gets pinned.

The *terminating* form is the right tool for the **browser** case, which wants a
CA-trusted cert and can't present a peerhailer client cert — see the browser note in
[deploy-minimal-linux.md](deploy-minimal-linux.md) (`--hail-on-tls --tls-cert/--tls-key`).
Peers and browsers are different audiences; a node can serve both on different ports.

## 3. The address peers store

Path B publishes on the node's MagicDNS name, not a raw IP:

```sh
# on another machine
hail add phone https://termux-phone.<tailnet>.ts.net \
  --transport tailscale --key "$(cat phone.pub)"
```

## Verifying

The phone can only confirm its own Serve config (`serve status`, which should show the
`tcp://…:443 (TLS over TCP) → tcp://127.0.0.1:7645` passthrough). The real proof is a
second tailnet machine hailing it: from a peer that holds the phone's key,
`hail walk` should report `reached <phone> via https://<name>…ts.net`. If it instead
says `TLS pin failed`, `serve` is terminating TLS rather than passing it through — fix
the passthrough (§2). A plain browser `curl` is *not* a good check here: with the
daemon doing mutual TLS, a client that presents no vouched cert is refused, so a raw
curl failing does not mean peers can't reach it.

## Outbound from the phone

If the Android Tailscale app is off, ordinary Termux processes reach tailnet peers
only through the userspace daemon's proxy. Node 24's `fetch` works through the HTTP
side of it when environment-proxy support is on:

```sh
NODE_USE_ENV_PROXY=1 HTTP_PROXY=http://127.0.0.1:1055 hail walk
```

## Troubleshooting

- **`tailscaled.sock: no such file`** — you relied on `TS_SOCKET`; pass `--socket=`
  explicitly on every call.
- **A peer gets `TLS pin failed`** — `serve` is terminating TLS (presenting its own
  Let's Encrypt cert) instead of passing it through. Re-do §2: daemon on
  `--hail-on-tls`, and `serve reset` then `serve --bg --tcp 443 tcp://127.0.0.1:7645`
  (raw TCP, never the bare-port HTTPS proxy or `--tls-terminated-tcp`).
- **A peer times out / a `tcp` forward reaches nothing** — the daemon isn't up on
  `127.0.0.1:7645`; check `hail-daemon.log` for the `hails on https://127.0.0.1:7645`
  line, and that the phone didn't sleep the daemon (`termux-wake-lock`). Confirm the
  userspace tailscaled is up too (`status --self`).
- **`npm run typecheck` fails resolving `@typescript/typescript-android-arm64`** —
  TypeScript 7's native package has no Android arm64 build yet. For phone-local
  typechecks use TS 5: `npx -y -p typescript@5.9.3 tsc --noEmit`. (Runtime is
  unaffected — the daemon is plain Node.)

## Automating it

This bootstrap is scriptable and safe to hand to a coding agent running in the repo
on the phone: bring up Tailscale, start the node, publish with `serve`, then report
the node's tailnet address and the contents of `phone.pub`. The one step that can
block is tailnet authentication (the login URL) — an agent should surface that URL
for a human rather than try to bypass it. Keep the agent to bringing the node *up*;
wire admissions, grants, and routing separately once its address and key are known.
