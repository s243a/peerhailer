# Connecting two machines

Everything before this ran on loopback, where a peer and its peer are the same
process. This is the procedure for the first time that stops being true.

Nothing here is discovery: peers are added by hand, because that is all that
exists today and because it is the right thing to test first — see
[discovery.md](discovery.md).

## What you are actually testing

Worth stating, because the setup steps look like plumbing and the point is not:

- a **signed record verifies across a network**, not just across a function call
- `bindKey` **ends trust-on-first-use** at the first verified contact
- `INTRODUCE` **gates gossip** in a real exchange rather than a unit test
- routes are **chosen and reordered** by what has actually worked

`last seen` changing from `never` is the single observation that proves the
first of those. Everything else is easier to read once it does.

## Exchanging identities

A peer is a key; the name is a label. So the setup is: each machine publishes
its public key, and the other adds it.

```sh
# on each machine
hail name <a-name-for-this-machine>
hail status                      # note the 'key:' line — its fingerprint
hail id > this-machine.pub
```

Move the `.pub` between them however you like. Over Tailscale, Taildrop is the
obvious choice and is already authenticated end to end:

```sh
tailscale file cp this-machine.pub <other-device>:
tailscale file get .             # on the receiving side
```

`tailscale status` lists the devices you can send to. The admin console at
<https://login.tailscale.com/admin/machines> shows the same thing — but do not
run `tailscale up` to find it. On an authenticated machine it prints no login
URL and may re-apply settings you did not mean to change.

Then, on each side:

```sh
hail add <other-name> <their-ip>:7645 --transport tailscale --key "$(cat other.pub)"
hail peers                       # compare the fingerprint against their 'hail status'
```

`hail peers` prints the first characters of each peer's fingerprint. Comparing
it against what the other machine reported is what proves the key arrived
intact. Over Taildrop that is a formality — it is an authenticated channel
between two machines you own — but it is the habit that matters when the channel
is not.

A bare `host:port` is accepted and becomes `http://host:port`; an explicit
scheme is left alone.

## One peer, both routes

A second `add` for the same name **merges** rather than replaces, so a peer can
hold its tailnet address and its LAN address at once:

```sh
hail add sol 100.101.7.22:7645  --transport tailscale --key "$(cat sol.pub)"
hail add sol 192.168.1.50:7645  --transport lan
```

Both paths then get tested from one machine, and `hail walk` reports which
address answered. Routes sort into bands — ones that have worked, then fresh
leads, then ones that never have — so after a successful hail the winner floats
to the top and you can see what the machine actually prefers.

The **LAN is the more interesting half**. Tailscale authenticates the transport
with WireGuard, so anything answering at a tailnet address is genuinely that
machine and trust-on-first-use is nearly safe. A household LAN is a broadcast
segment shared with every other device on it, and that is where binding a key
earns its keep.

## Running the daemon on both networks

```sh
hail daemon --host 0.0.0.0 --port 7645
```

`--host 0.0.0.0` answers on every interface, so one daemon serves the tailnet
and the LAN together and you stop switching machines to test each. It discovers
nothing and admits nobody; adding peers stays a deliberate act.

**Know what binding beyond loopback exposes.** `/hail` and plugin routes are
signature-checked. `/api/*` and the web page are **not authenticated** — the
boundary for those is that they normally answer only on `127.0.0.1`. Bound to
`0.0.0.0`, anyone who can reach the port can admit themselves as a peer or block
your real ones. That is a judgement about your network, not a bug being hidden:
acceptable on a household LAN and a single-user tailnet, and not acceptable
anywhere else until the control API is pinned back to loopback.

## Android phones

The Android Tailscale app and Termux do not share a `tailscaled` daemon. The app
can route ordinary Termux outbound traffic through the Android VPN when it is
connected, so a phone can still hail a desktop. It does not give Termux a
`tailscaled.sock`, and it does not make a Termux loopback daemon reachable from
the tailnet.

A phone is a full peer only when Termux runs its own userspace `tailscaled`. That
registers as a second tailnet node, with its own name and 100.x address, beside
the Android app's phone node:

```sh
termux-wake-lock

setsid sh -c 'exec tailscaled \
  --statedir="$HOME/.tailscale" \
  --socket="$HOME/.tailscale/tailscaled.sock" \
  --tun=userspace-networking \
  --socks5-server=127.0.0.1:1055 \
  --outbound-http-proxy-listen=127.0.0.1:1055 \
  > "$HOME/.tailscale/tailscaled.log" 2>&1 < /dev/null' &

tailscale --socket="$HOME/.tailscale/tailscaled.sock" up \
  --hostname=termux-tailscale-s24 \
  --accept-dns=false
```

If you have the Termux wrapper installed, use `tailscale-cli` instead of
repeating the socket flag:

```sh
tailscale-cli status --self
tailscale-cli serve --bg --http=7645 --yes 127.0.0.1:7645
tailscale-cli serve status
```

Userspace networking creates no `tailscale0` interface, so
`--hail-on tailscale0` has nothing to bind inside Termux. Keep peerhailer on
loopback and publish the loopback port with Tailscale Serve:

```sh
node bin/hail.js daemon --port 7645 --ui
tailscale-cli serve --bg --http=7645 --yes 127.0.0.1:7645
tailscale-cli serve status
```

The local phone can verify only the Serve configuration. A healthy status shows
the Termux node forwarding to loopback:

```text
http://termux-tailscale-s24.<tailnet>.ts.net:7645 (tailnet only)
|-- / proxy http://127.0.0.1:7645
```

The real inbound check needs a second tailnet machine:

```sh
curl -i http://termux-tailscale-s24.<tailnet>.ts.net:7645/
```

A 403 from peerhailer proves the request reached the loopback service; a timeout
does not. The address other peers store is the Termux node, for example:

```sh
hail add phone http://termux-tailscale-s24.<tailnet>.ts.net:7645 \
  --transport tailscale \
  --key "$(cat phone.pub)"
```

No Funnel is involved here; `tailscale serve` is tailnet-only. The Android app
node and the Termux userspace node do not conflict, because the Termux daemon is
not creating Android-wide VPN routes. The tradeoff is outbound: if the Android
app is off, ordinary Termux processes need the userspace SOCKS/HTTP proxy to
dial tailnet peers. Node 24's built-in `fetch` works through the HTTP side of
that proxy when environment proxy support is enabled:

```sh
NODE_USE_ENV_PROXY=1 HTTP_PROXY=http://127.0.0.1:1055 hail walk
```

On Play Store Termux, this repo's `npm run typecheck` can fail before checking
code because TypeScript 7 resolves a native package named
`@typescript/typescript-android-arm64`, which is not published. Use TypeScript 5
for phone-local typechecks until the native preview has an Android arm64 build:

```sh
npx -y -p typescript@5.9.3 tsc --noEmit
```

## When it does not work

- **Nothing answers over the LAN, Tailscale is fine.** Seen on the first real
  run, and confusing because the machines demonstrably reach each other:
  `tailscale ping` reported `direct 192.168.1.68:41641` in 2ms while TCP to the
  same address hung. Tailscale installs its own `ts-input` chain, so a host with
  `Chain INPUT (policy DROP)` accepts the tailnet and drops everything else —
  the LAN included. Check in this order:

  ```sh
  curl -s -o /dev/null -w '%{http_code}\n' http://<own-lan-ip>:7645/   # bound?
  iptables -L INPUT -n | head                                          # policy DROP?
  tailscale ping <peer>                                                # direct, or relayed?
  ```

  A daemon answering on its own LAN address while nothing external reaches it is
  a firewall, not a binding. Open it narrowly if you want the LAN path tested —
  `iptables -I INPUT -p tcp -s 192.168.1.0/24 --dport 7645 -j ACCEPT` — and know
  what that admits: the control API is on every bound interface and holds no
  authentication, so a default-DROP firewall may be the only thing keeping it
  off the LAN.

  Also check the access point: consumer routers often enable client isolation,
  which blocks host-to-host traffic even on the same SSID.
- **`unreachable`, immediately.** Older versions stored `host:port` and dialled
  it as a URL, which threw and read as the peer being down. Pull, and re-add.
- **`answered by someone else`.** The reply was signed by a key that is not the
  one held for that name. Either the address now belongs to a different machine
  — a DHCP lease turning over is the usual cause — or the key is wrong.
- **Node too old.** Ed25519 signing needs Node 16+. On an old machine this is a
  finding about that machine, worth reporting rather than working around.
