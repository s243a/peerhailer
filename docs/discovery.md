# Finding peers on a network

**Status: designed, not built.** Manual entry works today and is what the first
two-machine tests should use — see "Why manual comes first".

## Three ways to learn an address

**Someone tells you.** `hail add sol 192.168.1.50:7645`. Works now, needs no
protocol, and reveals nothing to anyone. The quiet option, and the one that
already carries every real test.

**A peer you trust tells you.** `hail walk` plus the `INTRODUCE` capability.
Also works now. On a home network where one machine is usually up, this covers
most of what discovery is for: admit the always-on box once by hand, and it
introduces the rest.

**A machine announces itself.** A beacon on the local segment — mDNS advertising
`_peerhailer._tcp.local`, or a plain UDP multicast if DNS-SD's baggage is not
wanted. This is the only one that finds a peer nobody has mentioned, and the
only one that tells strangers you exist.

### Not scanning ports

Probing every host on a subnet to see what answers is reconnaissance, not
discovery. It is indistinguishable from an attacker's first move, it trips
intrusion detection and corporate network access control, it is slow enough to
be useless past a /24, and on a network you do not own it may break the terms
you agreed to when you joined it.

Anyone who wants it can compose it — `nmap` and `hail add` are two commands. It
does not belong in the daemon, where it would run on networks the author never
saw.

## Announcing and listening are separate switches

The obvious spelling is one setting: discovery on or off. It is wrong, and the
case that proves it is ordinary. A laptop in a café wants to find its home
server if it happens to be reachable, and wants to tell the café nothing. That
is listening without announcing, and a single dial cannot express it.

| Setting | Governs | Default |
| --- | --- | --- |
| `announce` | interfaces we beacon on | **none** |
| `listen` | interfaces we accept beacons from | **none** |
| `accept` | interfaces and source ranges the daemon answers hails on | loopback |

Each is a **list of interfaces, never a boolean**. A machine has `eth0` at home,
`wlan0` in a café, `tailscale0` across the world, and `docker0` going nowhere;
"announce: on" means something different and mostly wrong on each of them.
Naming interfaces puts the blast radius in the config file where a person can
read it.

## Accept policy is exposure, not authority

The third setting is the one most likely to be misunderstood, so it is worth
stating flatly: **a source-address policy never grants anything.** Signatures
decide who a caller is. The policy only decides whether we parse their bytes at
all — the same job a firewall does, for the same reason.

If "on my LAN" were ever allowed to confer a capability, then joining a café
network would hand every stranger on it whatever that capability was. Being on
a network is not evidence of anything.

Both halves are worth having together: bind to a chosen address rather than
`0.0.0.0`, *and* filter by source. And they are separate from what is served
where — the control API and the GUI belong on loopback whatever else is bound,
because they can admit peers and hold no authentication of their own.

## Discovery is never admission

A beacon is an unauthenticated stranger claiming a name. Under the model this
project already has, that is the weakest introduction there is — weaker than
gossip from a trusted peer, which requires `INTRODUCE`.

So a discovered machine lands in candidates at most, and admitting stays a human
act. Otherwise anyone on a café network can call themselves `backup-server` and
wait. This is the same rule as gossip, and for the same reason: hearing a name
tells you something exists, not that you should talk to it.

## What a beacon carries

A **fingerprint**, an address, and a port. Not a name.

The fingerprint is what lets a listener tell "this is sol, whose key I hold"
from "someone claiming to be sol" — the distinction names cannot make, and the
reason blocking prefers keys.

The cost has to be stated plainly, because it is the reason `announce` defaults
to none: **a stable fingerprint broadcast on every network you join is a
tracking identifier.** A café that sees the same fingerprint on Tuesday and
Thursday knows the same machine returned, without ever talking to it. That is
acceptable on a home LAN and not acceptable on a network you do not trust, which
is a per-interface judgement — exactly what the per-interface setting is for.

A rotating identifier only recognisable by peers already holding your key would
remove the tracking without removing the discovery. That is the covert mode
already deferred elsewhere, and it should be designed with this rather than
bolted on.

## Why manual comes first

Discovery only supplies an address. Everything that happens next — dial, verify
the signature, bind the key on first contact, merge what the peer reports — is
identical however the address arrived, and none of it has ever run across a real
network.

Testing the shared path with typed-in addresses answers whether the protocol
works. Building the beacon first only adds a second way to reach code that has
not been shown to work once. The beacon is also new trust-adjacent surface, and
the model is currently in a shape a reviewer has read end to end; the honest
moment to extend it is after two machines have tried to falsify it.
