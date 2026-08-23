# A shell plugin

**Status: designed, not built. The most dangerous plugin in the project — read
the ladder before the mechanism.**

## What it is, said plainly

An interactive shell a peer can open on this machine: a PTY, bytes in, bytes out,
whatever the peer types runs as the user running the daemon. It is **remote shell
access** — SSH, in one sentence — reached through the peer fabric instead of
through `sshd`.

There is no softer framing, and pretending otherwise is the failure mode. Every
other plugin here holds a rule this one cannot: *nothing a caller sends reaches a
shell.* The command plugin runs a fixed declared line; the tunnel carries bytes
to a declared endpoint; neither lets a peer choose what executes. **This one's
entire purpose is to let a peer choose what executes.** So it does not get to
reuse that safety argument, and it needs its own.

## Why it might be worth having anyway

The same reason people run `sshd`. A machine you own, in another room or another
country, that you want a terminal on — and you are already running peerhailer,
which already authenticates the peer, holds a capability model, and enforces an
encrypted arrival. A shell over that is `ssh` without a second daemon, a second
key system, or a second thing exposed to the network.

It is also the honest substrate for things above it: a supervisor that wants to
poke at a wedged agent, a `service:agent` that needs its logs read. Those could
each grow a bespoke narrow tool, or sit on one declared, capability-gated shell.

## Why it is the top of the ladder

The capabilities this fabric grants, in order of consequence:

| Capability | A compromised holder gets |
| --- | --- |
| `hail` | knows this machine exists |
| `directory` | knows who it knows |
| `command:pair` | a bearer credential |
| `tunnel:devtools` | a browser and its logins |
| `service:agent` | starts an agent that runs *some* commands |
| **`shell`** | **runs *any* command, interactively, now** |

`service:agent` is below `shell` because an agent is still mediated — it decides
what to run, and the bridge can review it. A shell is unmediated: the peer is the
one typing, there is no agent to gate, and there is no fixed command to declare.
It is the most direct grant of this machine to another that the fabric can make.

## What that demands

Nothing here is optional. Each is because of the row above.

- **Its own capability, `shell`, in no built-in profile.** Not bundled with
  anything, not implied by `trusted`. A peer gets a shell only by a grant that
  says `shell` and nothing weaker standing in for it.
- **An encrypted arrival, without exception.** A plaintext shell is a session
  anyone on the wire reads and injects keystrokes into — worse than the CDP case,
  because it is a root-ish prompt rather than a browser. So `network-trust.md`'s
  encrypted-only rule applies at its hardest: over Tailscale today, over pinned
  TLS when that lands, and never in plaintext even on a household LAN.
- **Off unless declared, like the page and chat.** A daemon with no `shell`
  declaration has no PTY route at all — not a refused one, an absent one. Opting
  in is a deliberate act with a deliberate capability behind it.
- **A recorded session, always.** `command:pair` records who ran what because a
  credential minted unwatched is what a person wants to see afterwards. A *shell*
  session is far more, and the same argument is far stronger: what commands ran,
  from which peer, when — kept, bounded, and visible where the run-history already
  is. A shell you cannot audit is one you should not have opened.
- **Bounded like everything else.** One session per peer by default, an idle
  timeout that closes an abandoned PTY, a cap on concurrent sessions. An
  unbounded shell plugin is a way to hold this machine's processes open from
  across the world.

## What it deliberately does *not* try to do

**It does not screen commands.** The lesson this project learned twice — for
shell strings and for URLs — is that you cannot safely decide security by parsing
what a shell will do. A shell plugin that tried to allow `ls` and block `rm` would
be `ls -la; rm -rf ~` away from being wrong, and worse, it would *imply* a safety
it cannot deliver. So it screens nothing: the gate is the capability and the
recording, not a filter on the bytes. If you do not trust a peer with an
unfiltered shell, do not grant `shell` — grant a `command:` for the specific
thing instead. **The narrower tool is the safer answer; the shell is for when you
actually mean "a terminal."**

**It does not confine to a directory.** `write_file` was confined and the shell
was not, and that asymmetry is documented in the bridge as the reason a confined
tool is safer than a shell. A shell plugin confines nothing, by nature — which is
the same reason it sits above the confined tools on the ladder, and the same
reason it is capability-gated so hard.

## Where a supervisor fits

A shell is exactly where the bridge's supervisor idea would want to reach, and
the composition is worth stating: a shell session could pass its commands through
a supervisor before they run — the `withSupervisor` seam, applied to shell input
rather than ACP tool calls. That turns "an unfiltered terminal" into "a terminal
a reviewer watches," which is the difference between `shell` being reckless and
being merely powerful. It is not required for a first version, but it is the
thing that would make `shell` safe to grant more widely, and the design should
leave room for it rather than assume the PTY is unwatched.

## Open

- **PTY on the far side of a tunnel.** A shell is inherently interactive and
  bidirectional; it wants the tunnel's byte transport, not a request/response
  route. That is the tunnel plugin's job — so a shell is perhaps not a route at
  all but a *declared endpoint* the tunnel reaches, `tunnel:shell` pointing at a
  local PTY spawner. Worth deciding: is `shell` a capability of its own, or is it
  `tunnel:shell` plus a PTY endpoint, reusing everything the tunnel already
  bounds and encrypts? The latter is less new code and inherits the tunnel's
  caps; the former is clearer about how dangerous it is. Lean toward `tunnel:` +
  endpoint for the mechanism, with the capability *named* `shell` so a person
  granting it sees what it is.
- **Whether it should exist at all before the supervisor does.** An unwatched
  remote shell is a lot to offer. A defensible sequence: build the supervisor
  first (done — the seam exists), then the shell as something a supervisor can be
  required for, rather than a shell anyone with the capability drives blind.
