# Running peerhailer from WSL2

WSL2 is a good *caller* (an origin you drive `hail` from). It needs one networking
change to reach peers by name, and there is a workaround if you'd rather not make it.
This page covers what WSL gets right, what it gets wrong, the fix, and how to
manage without it.

## What works out of the box

Run Tailscale **inside** WSL (kernel mode; `ip addr show tailscale0` shows a
`100.x` address). WSL then reaches the tailnet directly. `tailscale ping <peer>`
answers, and a peer stored by **tailnet IP** (Path A targets like
`https://100.65.213.77:7645`) is reachable with no further setup.

It does **not** reach the Windows host's LAN, so a peer stored only by a
`192.168.x.x` address is out of reach from WSL. Give such peers a tailnet address.

## What breaks: MagicDNS names

A peer published through `tailscale serve` (Path B, the Termux phone) is stored
by its MagicDNS name, e.g. `https://termux-phone.<tailnet>.ts.net`. From stock WSL
every call to it fails with:

```
getaddrinfo ENOTFOUND termux-phone.<tailnet>.ts.net
```

`tailscale ping` still succeeds, so the route is fine and only name resolution
fails.

**Why.** WSL generates `/etc/resolv.conf` itself, as a symlink to
`/mnt/wsl/resolv.conf` that points at the WSL→Windows NAT gateway
(`nameserver 172.25.x.1`). That resolver knows nothing about `*.ts.net`. Tailscale's
MagicDNS resolver is `100.100.100.100`, and WSL's generated file never mentions it.

`tailscale set --accept-dns` does **not** fix this on WSL. `tailscale dns status`
reports *"Tailscale DNS: enabled"* but *"no resolvers configured, system default
will be used"*: Tailscale wants to handle DNS, yet WSL's regenerated symlink
wins. The fix has to stop WSL from owning the file.

Confirm this is your problem before changing anything. Ask Tailscale's resolver
directly:

```sh
nslookup termux-phone.<tailnet>.ts.net 100.100.100.100   # answers with the 100.x address
getent hosts termux-phone.<tailnet>.ts.net               # empty: glibc isn't asking it
```

## The fix

**1. Point the resolver at Tailscale now.** This takes effect immediately with no
restart. Keep the old symlink so you can revert:

```sh
sudo mv /etc/resolv.conf /etc/resolv.conf-back
printf 'nameserver 100.100.100.100\nnameserver 172.25.80.1\n' | sudo tee /etc/resolv.conf
getent hosts termux-phone.<tailnet>.ts.net               # now resolves
```

Put your own gateway from the old file in the second line. It is only a fallback:
`100.100.100.100` answers `*.ts.net` itself and forwards every other name upstream,
so ordinary DNS keeps working.

**2. Stop WSL regenerating it**, or the next WSL start reverts step 1. Add a
`[network]` section to `/etc/wsl.conf`, keeping any sections you already have:

```ini
[interop]
enabled = true
appendWindowsPath = false
[boot]
systemd=true
[network]
generateResolvConf = false
```

This takes effect on the next WSL start (`wsl --shutdown` from Windows, or a
reboot). There's no need to restart right away: step 1 holds until then, and from
then on WSL leaves the file alone.

With `systemd=true` and Tailscale managing DNS, Tailscale may later rewrite
`/etc/resolv.conf` itself, usually to `nameserver 100.100.100.100` plus a
`search <tailnet>.ts.net` line. That still resolves both tailnet and ordinary
names, so it isn't a problem.

**Verify after the next restart:** `getent hosts termux-phone.<tailnet>.ts.net`
still returns the 100.x address.

**To revert:**

```sh
sudo sed -i '/^\[network\]/,/^generateResolvConf/d' /etc/wsl.conf   # or delete those two lines by hand
sudo rm /etc/resolv.conf && sudo mv /etc/resolv.conf-back /etc/resolv.conf
```

## Getting by without it

If you'd rather not touch WSL's DNS, these avoid needing MagicDNS from the
caller, best first:

- **Store the peer by tailnet IP instead of its name.** peerhailer authenticates a
  peer by its **identity pin** (the cert's vouch, see [tls.md](tls.md)), not by
  hostname, so an IP address authenticates exactly as the name does. For a
  `serve`-published node, dial port 443:

  ```sh
  tailscale status | grep termux-phone        # find its 100.x address
  hail add phone https://100.122.247.26 --transport tailscale --key-file phone.pub
  ```

  The cost: an IP can change if the node is re-registered or re-authenticated.
  When it does, the stored address goes silently stale, which is exactly what the
  MagicDNS name exists to prevent. Recheck `tailscale status` if a peer stops
  answering.

- **A hosts entry.** `echo '100.122.247.26 termux-phone.<tailnet>.ts.net' | sudo tee -a /etc/hosts`
  keeps the stored address as the name but pins the IP locally. It goes stale the
  same way, and one line is needed per peer.

- **Drive from a machine that resolves MagicDNS.** A native Linux, macOS, or
  Windows Tailscale install wires the resolver itself. If WSL is only one of your
  machines, originating from another one avoids the issue entirely.

Prefer the real fix on a machine you use often. The workarounds each trade
MagicDNS's renumbering safety for not editing system DNS.
