# A shell plugin

**Status: built** (`src/builtin/shellPlugin.js`) — a pipe-based first cut; a real
PTY is a stdio swap validated on-device, the route surface unchanged. The most
dangerous plugin in the project — read the ladder before the mechanism.

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
| **`shell`** | **runs any command, interactively — and thereby the control API** |

`shell` is above everything because it does not stop at "any command." A PTY
spawned as the daemon user inherits the daemon's environment, cwd, filesystem
access to the **identity key, the grants store, and the state file**, and network
access to the **loopback control listener** — which mints grants, rotates keys,
and reloads plugins. A peer holding `shell` who runs `curl localhost:<control>/…`
exercises operator authority the fabric tracks no capability for. So the honest
row is: **`shell` ≈ operator of this host.** A peer you would not hand the
control port to must not hold `shell`. The tunnel's self-port guard closed
exactly this for tunnels; a shell needs the equivalent — at minimum a scrubbed
spawn environment carrying no control-port address and no auth material — and it
needs it *because* the ladder does not stop at "any command", it follows through
to "therefore operator authority."

`service:agent` is below `shell` because an agent is still mediated — it decides
what to run, and the bridge can review it. A shell is unmediated: the peer is the
one typing, there is no agent to gate, and there is no fixed command to declare.
It is the most direct grant of this machine to another that the fabric can make.

## What that demands

Nothing here is optional. Each is because of the row above.

- **Its own capability, `shell:<name>`, in no built-in profile.** Per-name, like
  the rest of the plugin family — so an operator declares a bare shell and a
  sandboxed one as *separate* grants (`shell:admin`, `shell:sandboxed`) — but
  never under the tunnel namespace: a person granting it must see "a shell", not
  "one more endpoint". Not bundled with anything, not implied by `trusted`. A
  peer gets a shell only by a grant that names it and nothing weaker.
- **An encrypted arrival, without exception.** A plaintext shell is a session
  anyone on the wire reads and injects keystrokes into — worse than the CDP case,
  because it is a root-ish prompt rather than a browser. So `network-trust.md`'s
  encrypted-only rule applies at its hardest: over Tailscale today, over pinned
  TLS when that lands, and never in plaintext even on a household LAN.
- **Off unless declared, like the page and chat.** A daemon with no `shell`
  declaration has no PTY route at all — not a refused one, an absent one. Opting
  in is a deliberate act with a deliberate capability behind it.
- **A recorded session, always.** `command:pair` records who ran what because a
  credential minted unwatched is what a person wants to see afterwards; the same
  argument applies to a shell, harder. What is recordable is *that* a session
  happened, from which peer, when and how long — kept, bounded, visible where the
  run-history is. What is **not** cleanly recordable is "the commands", for the
  reason below (a PTY byte log is not an audit trail); do not promise it. A shell
  whose *existence* you cannot see is one you should not have opened — which is
  the honest, deliverable version of the audit requirement.
- **Bounded like everything else.** One session per peer by default, an idle
  timeout that closes an abandoned PTY, a cap on concurrent sessions. An
  unbounded shell plugin is a way to hold this machine's processes open from
  across the world.

## What it deliberately does *not* try to do

**It screens no *commands*** — deliberately, and the word matters. The lesson this
project learned twice, for shell strings and for URLs, is that you cannot safely
decide security by parsing what a shell will do. A shell plugin that tried to allow `ls` and block `rm` would
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

But **"screens no commands" is not "shapes nothing."** Two things that are not
command content are the plugin's own integrity surface, and are shaped even
though the bytes are not:

- **The spawn environment.** The PTY must not inherit the control-port address or
  any auth material the CLI holds — see the ladder note above. Scrubbing the
  environment is not screening the caller's commands; it is denying the session a
  door to operator authority the caller was never granted.
- **The egress rendering.** A PTY's output is raw bytes to a terminal parser —
  escape sequences included. Whatever renders the session on the operator side
  (the CLI, the web UI) receives them, and this project has already been bitten by
  render-escaping once (chat's `esc` requirement). A hostile shell-holder emitting
  terminal control sequences into the operator's terminal is that problem at
  maximum, and it is the renderer's job to handle it, stated now as a requirement.

And the **recording promise needs scoping.** A recorded *byte stream* of a PTY is
not "what commands ran" — `vi`, `less`, and line-editing make the log unreadable
as an audit trail. If the audit is part of what justifies the plugin, the promise
is either scoped down honestly ("a replayable byte log", not an audit) or the
recording is defined as something an auditor can actually read. The `command:`
plugin's audit is genuinely stronger here; a PTY's is weaker, and the doc should
not imply parity.

## Where a supervisor fits

A supervisor is **optional here, not a precondition** — the gate is the
capability, and an operator who grants `shell:<name>` has already decided to
trust the holder with a terminal. But the composition is worth stating, because
it is cheap: the `send` handler is the single choke point for input, so a
reviewer could sit there — the `withSupervisor` seam applied to shell input
rather than ACP tool calls — turning "an unfiltered terminal" into "a terminal a
reviewer watches". That is the difference between reckless and merely powerful,
and it is a nice-to-have for granting more widely, not a gate the first version
waits behind. The plugin leaves the seam where it would attach and does not
build it.

## Open

- **PTY on the far side of a tunnel.** A shell is inherently interactive and
  bidirectional; it wants the tunnel's byte transport, not a request/response
  route. That is the tunnel plugin's job — so a shell is perhaps not a route at
  all but a *declared endpoint* the tunnel reaches, `tunnel:shell` pointing at a
  local PTY spawner. The deciding axis is not clarity-vs-code-reuse but **which
  admission check fires**: a route-plugin is capability-checked *per request*, a
  tunnel endpoint *per open, then bytes flow unchecked*. A shell is a session, so
  per-open is correct — the tunnel mechanism wins. But then the **name** is the
  grant surface: a person granting `tunnel:shell` sees "one more endpoint", not "a
  terminal", which is the wider-than-intended failure capability names exist to
  prevent. So: tunnel mechanism, capability **named `shell`**, never
  `tunnel:shell`.

  And note what the tunnel does *not* inherit correctly: the self-port guard has
  no PTY equivalent (above), and the idle timeout keys on peer activity — for a
  PTY that kills a long `make` producing output nobody typed at, or holds one open
  on a 4-minute keepalive byte. Idle for a shell must mean **no bytes in either
  direction**, which is not what the tunnel measures.
- **Restriction is a declared sandbox, not plugin machinery.** The earlier draft
  asked whether the shell should exist before a shell-aware supervisor does. It
  should: a supervisor is one optional way to restrict a shell, and it is not the
  only one, nor the cheapest. Because the operator declares the command, the
  command *can be the sandbox* — `firejail --net=none bash`, `bwrap …`,
  `unshare -Urn bash`, a container, or on Termux the Android app sandbox (with
  `proot` if wanted). The plugin runs what is declared and never looks inside it,
  so OS-level confinement composes for free, with no filter on the bytes and no
  implied safety the plugin cannot deliver. "Restrict this shell" is "declare a
  restricted shell." An operator who wants neither a sandbox nor a supervisor is
  granting a full terminal, deliberately — which is what `shell:<name>` in no
  profile is there to make them do.
