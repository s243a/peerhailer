# Running peerhailer on a minimal Linux target

Puppy Linux, a router, a rescue USB, an appliance — anywhere with a kernel and
not much else. peerhailer is unusually easy to put on one, and the reasons are
worth stating because they shape the whole procedure.

For the pairing itself — exchanging keys, adding peers — see
[two-machines.md](two-machines.md). This is only what a *minimal* target adds on
top: getting Node there, choosing how the tailnet arrives, and making the state
survive a reboot.

## Why it is easy: nothing to build

peerhailer has **zero dependencies**. No npm packages, no native modules, no
sqlite — the state is plain JSON files, everything else is Node's standard
library. So the entire install is a Node binary and the source; there is nothing
to compile on a toolchain the target does not have.

```sh
# the whole runtime — a portable tarball, no build, no `npm install`
wget https://nodejs.org/dist/v22.11.0/node-v22.11.0-linux-x64.tar.xz
tar xf node-v22.11.0-linux-x64.tar.xz
export PATH="$PWD/node-v22.11.0-linux-x64/bin:$PATH"
node -v            # needs >= 20
```

Copy or `git clone` peerhailer, `cd` in, and run `node bin/hail.js …`. That is
the install.

## The encrypted arrival: two paths

A declared shell (or any capability the operator marks) is served **only where
arrival is encrypted** — the daemon refuses it on a plaintext listener, on
purpose. So a remote shell needs the tailnet, and how you bind depends on
whether the target has a TUN device.

Check first:

```sh
ls /dev/net/tun        # present, or `modprobe tun` succeeds -> Path A
```

**Path A — kernel TUN (most real distros, including most Puppy builds).** A normal
Tailscale creates a `tailscale0` interface; bind it directly.

```sh
tailscaled &
tailscale up
tailscale ip -4                 # note the 100.x.y.z
node bin/hail.js --state /root/peerhailer/state.json \
  daemon --hail-on-tls tailscale0 --port 7645
```

Note `--hail-on-tls`, not `--hail-on-encrypted`, when a **shell** is declared:
the shell requires a *mutual* (bound) arrival, and `--hail-on-encrypted
tailscale0` — binding the tainet address directly — is encrypted but not bound,
so it serves lighter routes but 404s the shell. `--hail-on-tls` adds the mutual
pin (the caller presents a vouched client cert), which is what a remote shell
needs. Loopback binds count as bound, so Path B below serves the shell over
`--hail-on-encrypted 127.0.0.1` with no extra TLS.

**Path B — userspace only (no TUN; the Termux situation).** There is no
`tailscale0` to bind, so front a loopback port with `serve`, which terminates TLS
from the tailnet into loopback.

```sh
tailscaled --tun=userspace-networking --socket=/tmp/tsd.sock &
tailscale --socket=/tmp/tsd.sock up
node bin/hail.js --state /root/peerhailer/state.json \
  daemon --hail-on-encrypted 127.0.0.1 --port 7645
tailscale --socket=/tmp/tsd.sock serve --bg 7645
```

Pass `--socket=` explicitly rather than trusting `TS_SOCKET`, which has been
unreliable on userspace builds. The caller then dials the tailnet address:
`https://100.x.y.z:7645` on Path A (it is `--hail-on-tls`), `https://<host>.<tailnet>.ts.net` on Path B.

## The one guardrail: assert encryption only where it is real

`--hail-on-encrypted` is the operator asserting the arrival on that interface is
encrypted. It is true for `tailscale0` (WireGuard) and for `127.0.0.1` *behind
`tailscale serve`* (the only remote thing reaching it is the TLS proxy). It is
**false for a bare LAN interface** — `eth0`, `wlan0`. Asserting it there would
put the served capability, a shell included, in cleartext on the local network.

> **Never pass `--hail-on-encrypted` for a LAN interface.** Only `tailscale0` or
> `127.0.0.1`-behind-serve. If unsure what an interface is, use `--hail-on`
> instead: it is plaintext, so the shell simply refuses to serve there — the safe
> failure.

In both correct paths the daemon binds *only* the tailnet address or loopback, so
nothing is exposed to the LAN at all. A quick check once it is up, from the
shell or locally:

```sh
ss -ltnp | grep node     # should show only the 100.x address or 127.0.0.1,
                         # never 0.0.0.0 or a LAN IP
```

## Running as root

A target like Puppy runs as root by default, so a declared `shells add debug
"bash"` is a **root** shell. The scrubbed spawn environment still keeps the
control port and the daemon's secrets out of it, but it is root — full reach of
the box, which is the troubleshooting point and also the whole blast radius.

The grant is the gate: only a peer you admitted under a profile that allows
`shell:debug` reaches it, and it is revocable at any time —

```sh
hail forget <peer>                 # or
hail profiles remove remote-shell  # then restart the daemon
```

To dial it back for a particular use without giving up root generally: run
peerhailer as an unprivileged user (Puppy's `spot`), or declare a sandboxed shell
the operator can still reason about —

```sh
hail shells add debug "firejail --net=none bash"   # if firejail is present
```

Restriction here is a *declared* thing (the command names its own sandbox), not
machinery in the plugin — see [shell.md](shell.md).

## Persistence: the state must land in the save

A frugal or live install keeps changes in a **save file** that persists a fixed
part of the filesystem — on Puppy, `/root`. peerhailer's identity is the thing
that must survive a reboot: lose it and the key regenerates, so every peer that
paired with the old key is now talking to a stranger and authentication fails.

Two rules make it durable:

- **Put the state where the save reaches.** `--state /root/peerhailer/state.json`
  — and because `identity.json` is written *beside* the state file
  (`dirname(statePath)/identity.json`), that saves the key too. Keep the source
  under `/root` as well and it all persists together.
- **Commit the save once after pairing.** A save file commits at shutdown, on its
  interval, or **on demand** — so peerhailer's write reaches the RAM overlay
  immediately but the save file only at the next commit. You do not have to wait
  for shutdown: run your Puppy's save-to-file script (the Save applet, or a
  command like `save2flash` depending on the build) right after the one-time
  identity-and-pairing setup, and the key is durable from that moment. Day-to-day
  shell sessions add nothing persistent worth guarding, so one save after setup is
  enough.

## The shape, end to end

Target (Puppy, as root, state under `/root`):

```sh
node bin/hail.js --state /root/peerhailer/state.json name puppy
node bin/hail.js --state /root/peerhailer/state.json shells add debug "bash"
node bin/hail.js --state /root/peerhailer/state.json profiles add remote-shell --allows hail,shell:debug
node bin/hail.js --state /root/peerhailer/state.json id > puppy.pub
node bin/hail.js --state /root/peerhailer/state.json add devbox --key-file devbox.pub --profile remote-shell
node bin/hail.js --state /root/peerhailer/state.json daemon --hail-on-tls tailscale0 --port 7645
#   ^ Path A (mutual TLS, for the shell); Path B binds 127.0.0.1 --hail-on-encrypted + `tailscale serve --bg 7645`
```

Caller (dev box or phone):

```sh
hail add puppy https://100.x.y.z:7645 --key-file puppy.pub    # https: Path A serves the shell over mutual TLS
hail shell puppy debug exec "uname -a; head -3 /etc/os-release"
hail shell puppy debug open              # hold the id across steps, state persists
hail shell puppy debug send <id> "cd /root && ls"
hail shell puppy debug poll <id>
```
