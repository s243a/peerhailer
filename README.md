# peerhailer

Find your own machines, without announcing them to the network.

A peer answers one question — *who else do you know?* — and you walk outward
from the machines you already trust. No registry, no broadcast, no discovery
protocol shouting on your LAN. You hail peers you know, the way you hail a ship
rather than a crowd.

```
$ hail walk
reached luna via http://100.64.1.9:8787

heard of 1, none admitted:
  mars (from luna)

  admit one with: hail add <name> <address>
```

## Why

Before a client can connect to a machine, something has to be *running* there,
and you have to know where "there" is. Today that means opening a shell,
installing something, starting it, noting an address, and typing that address
into a settings pane somewhere else. Addresses leak into configuration and go
stale the moment a laptop changes network.

peerhailer keeps a directory of **names**, the routes each name was last
reachable on, and when. Names are the identity; addresses are cache.

## Identity is a key, not a name

Every machine holds an Ed25519 key, generated on first use. A name is a label a
person chose; the **key is the identity**. Records are signed, so the addresses
a peer reports are a claim only that key could have made, and a machine renaming
itself is still recognised.

```bash
hail id > sol.pub                              # on sol
hail add sol --key-file sol.pub                # on luna
```

Once a key is bound to a name, a record signed by any other key is refused —
that being what impersonation looks like. A peer with no key we hold cannot hail
us at all, and is told nothing about why.

## Capability profiles

A peer is admitted *into a profile*, and the profile decides what it may ask
for. `trusted` is the default: your own machines.

| Profile | Grants | For |
| --- | --- | --- |
| `trusted` *(pinned)* | hail, directory | Your own machines |
| `known` | nothing | Recorded, never answered — a phone you hail *from* |
| `carrier` | hail, directory, relay | A peer that may also carry traffic for you |

Profiles are offered pinned-first, and `trusted` is pinned because it is the
answer nearly every time. `hail profiles pin <name>` changes that, and you can
define your own. Pinning grants nothing — it decides what gets picked when
someone is moving quickly, which is reason enough to think about it.

```bash
hail add phone --key-file phone.pub --profile known
hail profiles
```

Knowing a machine exists and letting it use your services are different grants,
and relaying — which spends your bandwidth and exposure on someone else's
traffic — is not inherited by being a peer at all.

## Three rules it will not bend

**Records carry no credentials.** A record travels to every peer that asks, so
anything secret in it is replicated everywhere. A directory entry says a machine
exists and where it answered — proving you may talk to it happens per
connection, not by handing out a token that opens a shell.

**Trust does not travel with a peer list.** A peer naming another tells you it
exists, not that you should talk to it. Names you hear become *candidates*;
admitting one is something a person does. Otherwise one compromised peer becomes
a way to introduce arbitrary machines.

**Nothing second-hand is a fact.** A peer's view of a third machine is as old as
their last exchange. Status and addresses are hints to verify by connecting, and
a peer can never overwrite a route you have seen work yourself.

## Transports are backends

A peer on a tailnet and a peer reachable only over a private mesh are two
records with different transports. peerhailer resolves a name to a route and
does not care which kind it is — LAN, Tailscale, tinc, a relay. Discovery and
transport are separate concerns, so no particular overlay becomes a dependency.

## Use

```bash
hail name sol                   # set this machine's name
hail id                         # print its public key, for handing over
hail status                     # what this machine is, and who it knows
hail add luna http://host:8787 --key-file luna.pub    # admit a peer
hail profiles                   # what each capability profile grants
hail walk                       # ask known peers who else they know
hail peers                      # admitted peers, and candidates heard of
hail forget mars                # remove one, admitted or not
hail daemon --port 8787         # answer hails from other machines
```

The directory is plain JSON under `~/.config/peerhailer/`. Small enough to read,
edit and diff by hand — which matters for a tool whose bad day looks like
"nothing answers and I cannot tell why".

Every command works with no daemon running. A tool for reaching machines that
must itself be running before you can ask it anything fails exactly when you
need it.

## Embedding

```js
import { createDirectory, walk } from "peerhailer";

const directory = createDirectory({ self: { name: "here" }, admitted });
const { reached, candidates } = await walk(directory);
```

No framework and no dependencies outside Node. The daemon runs on machines with
nothing else installed, which are usually the ones most worth reaching.

It is JavaScript with JSDoc types rather than TypeScript, and type-checked by
`tsc` in strict mode all the same — `npm run typecheck` — with declarations
emitted for consumers by `npm run types`. The reasoning, and what would reverse
it, is in [docs/decisions.md](./docs/decisions.md).

## What it does not do

Not a router — peers do not currently relay for one another, though whether they
should is [an open question](https://github.com/s243a/t3code/blob/main/docs/fork/t3-p2p-proposal.md),
deferred rather than refused. Not a scheduler: you name the machine. Not an
identity system: it rides whatever you already authenticate with. And not a
substitute for a firewall — an unauthenticated caller is told nothing, but a
listening TCP service can only hide so much.

## Status

Early. The directory, the hello protocol, the daemon and the CLI work and are
tested; the covert transport described in the proposal is not built.

## Provenance

An independent project. Its design was worked out in a fork of
[t3code](https://github.com/s243a/t3code) — the
[proposal](https://github.com/s243a/t3code/blob/main/docs/fork/t3-p2p-proposal.md)
has the reasoning, including the arguments that were tried and dropped. It is
not affiliated with or maintained by the T3 Code project.

## License

MIT
