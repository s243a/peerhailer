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
`serve` terminate the tailnet's TLS into it. A loopback bind behind `serve` counts
as an encrypted — and mutual — arrival, so `--hail-on-encrypted 127.0.0.1` serves
the gated routes (routing, and even a shell) with no extra TLS.

```sh
node bin/hail.js status 2>/dev/null || node bin/hail.js name phone
node bin/hail.js id > "$HOME/phone.pub"       # the key to hand to peers

setsid sh -c 'exec node bin/hail.js \
  daemon --hail-on-encrypted 127.0.0.1 --port 7645 --route \
  > "$HOME/hail-daemon.log" 2>&1 < /dev/null' &
sleep 2 && cat "$HOME/hail-daemon.log"         # expect: [daemon] hails on http://127.0.0.1:7645
```

Add `--route` for a routed destination or relay (as above); add `--ui` only if you
need the page or the route control API *on the phone* — but then `serve` would put
the unauthenticated `/api/*` control door on the whole tailnet. Leave `--ui` off for
a node that is only a peer, relay, or destination.

Publish the loopback port over the tailnet:

```sh
tailscale --socket="$HOME/.tailscale/tailscaled.sock" serve reset
tailscale --socket="$HOME/.tailscale/tailscaled.sock" serve --bg 7645
tailscale --socket="$HOME/.tailscale/tailscaled.sock" serve status
```

Use `serve --bg 7645` — the bare port publishes loopback `7645` over HTTPS on 443.
The `--http=7645` form terminates plaintext on 7645 and leaves the backend unreached
(a 502 from other machines); `serve reset` first clears a stale config. A healthy
status shows the node forwarding `/` → `http://127.0.0.1:7645`.

## 3. The address peers store

Path B publishes on the node's MagicDNS name, not a raw IP:

```sh
# on another machine
hail add phone https://termux-phone.<tailnet>.ts.net \
  --transport tailscale --key "$(cat phone.pub)"
```

## Verifying

The phone can only confirm its own Serve config (`serve status`). A real inbound
check needs a second tailnet machine to hail it: a desktop that hails the phone and
whose reply signature checks against the phone's key proves it is a full,
bidirectional peer — not outbound-only. See
[two-machines.md](two-machines.md#android-phones) for the `curl --resolve` probe and
how to read a 403 (reached the service) vs a 502 (Serve could not reach the backend)
vs a timeout (inbound not working).

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
- **A peer gets a 502** — `serve` could not reach the backend: you used `--http=`
  instead of the bare port, or the daemon is not on `127.0.0.1:7645`. `serve reset`,
  then `serve --bg 7645`.
- **A peer times out** — inbound is not reaching the phone; the userspace node may
  not be up (`status --self`), or the phone slept the daemon (`termux-wake-lock`).
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
