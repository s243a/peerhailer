# The command line, start to finish

A walkthrough from a fresh clone to two machines talking. Everything here has
been run; where a command's output is shown, that is what it printed.

## Making `hail` a command

The package declares `bin: { hail: "bin/hail.js" }` and the file has a shebang,
so there are three ways to run it and they are all fine:

```sh
node bin/hail.js peers      # always works, from the checkout
./bin/hail.js peers         # same, it is executable
```

To type `hail` from anywhere, link it once from inside the checkout:

```sh
npm link                    # symlinks `hail` into your global bin
hail peers                  # thereafter, from any directory
npm unlink -g peerhailer    # undo
```

`npm link` keeps pointing at the checkout, so `git pull` updates the command
with no reinstall. If you would rather not touch global state:

```sh
alias hail='node ~/peerhailer/bin/hail.js'    # in ~/.bashrc
```

One wrinkle worth knowing if you keep more than one clone: both `npm link` and
the alias bind `hail` to **one** directory. A second checkout will not be what
runs when you type `hail`, which is confusing on a machine that is both a peer
and a development box. `node bin/hail.js` is unambiguous, which is why the rest
of this document uses it.

## What this machine is

```sh
node bin/hail.js name sol
node bin/hail.js status
```

```
name:    sol
key:     a5haM-hZN2M-wY7JG-kZFi6
state:   /home/you/.config/peerhailer/directory.json
admitted: 0
candidates: 0
```

The `key:` line is a **fingerprint** — a short hash of the public key, for
comparing by eye. The key itself is what travels:

```sh
node bin/hail.js id > sol.pub
```

An identity is generated on first use and lives beside the directory. On Windows
both land under `%APPDATA%`. The directory is plain JSON, small enough to read
and diff by hand, which matters for a tool whose bad day looks like "nothing
answers and I cannot tell why".

## Admitting a peer

A peer is a key; the name is a label. So admitting means adding the key:

```sh
node bin/hail.js add luna 192.168.1.68:7645 --transport lan --key-file luna.pub
node bin/hail.js peers
```

```
admitted:
  luna             [trusted]  GltKb-WAWSy-Ig  lan:http://192.168.1.68:7645  (last seen never)
```

Then compare `GltKb-WAWSy-Ig` against what `hail status` printed on that machine.
That is what proves the key arrived intact.

Details worth knowing:

- **`--key-file` beats `--key "$(cat …)"`.** If the file is missing, the shell
  substitution becomes an empty string, and asking for a key and getting nothing
  is refused rather than silently admitting a keyless peer.
- **A bare `host:port` is fine** and becomes `http://host:port`.
- **A second `add` merges.** Adding the same name with another address gives one
  peer with two routes, not two peers.
- **No key is allowed**, and means trust-on-first-use until a verified hail binds
  one. The peers list says `no key` so you can see which.

## Hailing

```sh
node bin/hail.js walk
```

```
reached luna via http://100.106.139.76:7645

heard of 1, none admitted:
  testpeer (from luna)
```

Two things happened. A signed record was verified against the key held for
`luna` — so `last seen` will now show a time — and `luna` mentioned a machine
this one has never met, which lands in **candidates**. Hearing a name is not a
reason to talk to it, so nothing was admitted.

Routes are tried in order of what has worked. A route that succeeded before is
preferred over a fresh lead, which means adding a second address and walking does
**not** exercise the new one until the old one fails.

Promoting a candidate is deliberate, and lands lower than a peer you typed an
address for:

```sh
node bin/hail.js add testpeer         # -> [known], not [trusted]
```

## Profiles

A profile is a named set of capabilities. `hail profiles` lists them.

```sh
node bin/hail.js profiles add phone --allows hail,directory
node bin/hail.js add myphone --profile phone
```

Two capabilities govern hailing, and they are **separate**: `hail` says a peer
may ask who this machine is, `directory` says it may also learn who this machine
knows. A profile granting only `hail` gets an answer with no peer list.
`introduce` is the third — whether this machine accepts *their* leads.

To raise a profile for a while and let it fall back:

```sh
node bin/hail.js add myphone --profile operator --until 2h
node bin/hail.js peers
```

```
  myphone   [operator until 2026-08-22T04:59:41.367Z]  …
```

It reverts to what it held before, the clock is this machine's, and it is
resolved when asked rather than swept by a timer.

## Blocking, and a key that changes

```sh
node bin/hail.js block luna       # by key where one is held, so renaming does not evade it
node bin/hail.js unblock luna
```

If something answers as a peer holding a key this machine does not have for it,
the key held keeps working and the competing one is **reported**:

```
  luna    [trusted]  GltKb-WAWSy-Ig  …
    ! also answered as luna holding r01sY-kLS_F-Gf (2x, first 2026-08-22T…)
    ! the key above is still the trusted one. If this machine's key changed,
    !   hail rotate luna --key-file <new.pub>
```

Nothing on the wire distinguishes a machine whose key changed from a machine
that is not that peer. Only you know which happened, which is why `rotate` is a
separate command that takes the new key explicitly.

## The daemon

```sh
node bin/hail.js daemon --port 7645 --hail-on wlan0,tailscale0 --ui
```

```
[ui] http://127.0.0.1:7645
[daemon] hails on http://192.168.1.68:7645
[daemon] hails on http://100.106.139.76:7645
```

Three independent things:

| Flag | Opens | Who may use it |
| --- | --- | --- |
| *(none)* | nothing a browser can reach | — |
| `--ui` | the page and `/api/*`, on loopback | this machine's browser |
| `--hail-on <iface>` | `/hail` and plugin routes | any peer, each authenticated |

**`--ui` is off by default** because the control API can admit and block peers
and holds no authentication of its own — its boundary is that it answers only on
loopback and only to its own page. The daemon says where the page *would* be
when it is off, so it is opt-in rather than hidden.

**`--hail-on` names interfaces, not addresses**, because `wlan0` outlives the
address DHCP gives it. An interface with no address is logged and skipped rather
than fatal — a laptop whose wifi is not up should still answer on its tailnet.

Changes made at another terminal while the daemon runs **reach disk but not its
memory**: it re-reads only when it makes a change itself. Restart it after a
`hail add` or it will keep answering from the older picture.

## Firewall

A default-DROP firewall is the usual reason a peer is reachable over Tailscale
and not over the LAN — Tailscale installs its own `ts-input` chain, so the
tunnel is accepted and the local network is not. The symptom is confusing,
because the machines demonstrably reach each other:

```sh
tailscale ping luna        # direct 192.168.1.68:41641 in 2ms
curl http://192.168.1.68:7645/hail   # hangs
```

To open the LAN, scoped to the subnet rather than the world:

```sh
iptables -I INPUT -p tcp -s 192.168.1.0/24 --dport 7645 -j ACCEPT
iptables -D INPUT -p tcp -s 192.168.1.0/24 --dport 7645 -j ACCEPT   # undo
```

**Know what that admits.** With `--hail-on`, the port serves only `/hail` and
plugin routes, every caller authenticated — the page and `/api/*` are not there,
and `curl http://192.168.1.68:7645/` answers `404`. That is the whole reason the
listeners are split: a firewall rule should admit what the person writing it
believes it admits.

If you instead bind the control door outward with `--host 0.0.0.0`, that same
rule puts an unauthenticated admit-and-block API on the network. The daemon warns
when you do.

Diagnosing in order:

```sh
curl -s -o /dev/null -w '%{http_code}\n' http://<own-lan-ip>:7645/   # bound at all?
iptables -L INPUT -n | head                                          # policy DROP?
tailscale ping <peer>                                                # direct, or relayed?
```

A daemon that answers on its own LAN address while nothing external arrives is a
firewall, not a binding.

## Reading a refusal

Refusals are deliberately uninformative to strangers, which makes them
uninformative to you as well. What each one means:

| What you see | What it is |
| --- | --- |
| `fetch failed` on every route | nothing is listening, or nothing routes there |
| the request hangs until timeout | a firewall dropping packets |
| the connection closes with no reply | this machine refused you and said nothing — you proved nothing about who you are |
| `403 denied` | you were identified, and lack the capability |
| `answered by someone else` | a reply signed by a key we do not hold for that name |

## Everything works without the daemon

Every command above reads and writes the directory file directly. A tool for
reaching machines that must itself be running before you can ask it anything
fails exactly when you need it.
