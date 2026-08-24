# Declared commands

**Status: designed, not built.** A sibling of the tunnel plugin: a tunnel exposes
a local *service* to a peer, this exposes a local *command*.

## The case that needs it

Everything else about reaching another T3 turned out to be solved. `t3 pair`
mints a one-time token with a five-minute default, prints it as a QR code that
touches no clipboard, and `--tailscale` pairs through an encrypted tailnet URL.
Tailscale carries the result between machines you own.

All of it assumes **a person is present** to run a command and move the output.
The gap is the unattended case: a machine asks another machine for access, and
nobody is at either keyboard.

A peerhailer node can close that without being a T3 plugin at all. It runs
`t3 pair` locally and hands the result to a peer that was allowed to ask. No
plugin system, no upstream dependency, no waiting for six open pull requests to
settle.

## The shape, and the rule that makes it safe

**The operator declares the command; the caller names it.**

```sh
hail commands add pair "t3 pair --ttl 5m"     # needs command:pair
hail commands
hail commands remove pair
```

A peer asks for `pair`. It cannot ask for `t3 pair --ttl 24h`, cannot append
arguments, and cannot name a command nobody wrote down. This is the same rule as
the tunnel's named endpoints — *a peer may cause something, never choose it* —
and it is the whole difference between this and a shell.

That the operator may declare anything, including a shell, is not a hole: it is
their machine and their decision, exactly as declaring a tunnel to any local port
is. The property being defended is that **the set of possible actions is fixed
before any peer connects**.

### One capability per command

`command:pair` says nothing about `command:deploy`. A single "may run commands"
permission would mean granting one grants every command a later version adds —
the same reasoning as one capability per tunnel endpoint.

Nothing built in grants any of them.

### No caller-supplied arguments, in any form

Not even ones that look harmless. A caller-supplied TTL is a number until
somebody passes `5m; rm -rf ~`, and the fix — validate, escape, quote — is the
class of defence this project has already refused twice, for shell commands and
for URL prefixes.

If a command genuinely needs to vary, declare two commands. Two lines of
configuration beats a parser.

### Bounded output, and a timeout

A command that prints forever is a way to spend this machine's memory, and one
that hangs is a way to hold a request open. Cap both, and say which happened.

## What this is, honestly

**A remote execution primitive, narrowed by declaration.** Comparable to the
tunnel plugin rather than to anything smaller: a tunnel reaches a local service
that may have no authentication of its own, and a command runs as the user
running the daemon. Both are bounded by what an operator wrote down, and both
deserve the same care.

The first declared command being `t3 pair` sharpens it: **its output is a bearer
credential.** Holding `command:pair` means *may obtain control of my T3*. That is
not a capability to put in a general-purpose profile, and it is why the command
plugin **requires an encrypted arrival** — its routes 404 on a plaintext
listener, exactly as a shell's do. A pairing URL read off the wire is a pairing
URL redeemed by somebody else, and the five-minute window does not help when the
attacker is faster than the human. Encrypted, not mutual: a pairing over a bare
tailnet address is the ordinary case and stays served.

## Why not just tunnel to T3 instead

Because a tunnel gives a peer the *whole* interface behind the endpoint, bounded
only by whatever authentication that service has. Tunnelling to T3's port means a
peer that already holds a credential can use it — useful, and a different
question from *obtaining* one.

A declared command is narrower: one fixed invocation, one bounded output. When
what you want is a token rather than a session, the smaller mechanism is the
right one.

## Open

- **Should output be sealed to the asking peer?** Today it would cross the same
  authenticated link as everything else, which is enough on an encrypted
  transport and not enough on a plaintext one. Same answer as the tunnel: it
  waits for TLS.
- **Should a command be rate-limited per peer?** `t3 pair` mints a one-time
  token, so a peer that asks a hundred times has a hundred live pairings. Almost
  certainly yes, and the shape is the tunnel's per-peer cap.
- **Should the operator see it happen?** A credential minted for a machine while
  nobody was watching is exactly the event a person would want in a list
  afterwards — the same argument as recording a competing key rather than only
  refusing it.
