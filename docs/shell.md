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

## Running it on Android (Termux)

The phone is a first-class target — "drive a shell on the machine at home from
the one in your pocket, or the reverse" — and Termux has enough quirks that a
working setup looks broken in unhelpful ways. These were all hit driving a real
shell from a desktop into a Termux phone; none is theoretical.

**The exec shim, and why the shell "opens" then dies.** Play Store Termux execs
every binary through a shim it carries in `LD_PRELOAD=$PREFIX/lib/libtermux-exec.so`.
The scrubbed environment (which strips everything not on its allowlist) removed
it — and then `shell: true`, which goes through `/bin/sh` and `execve`, could not
start the shell at all: the child died with exit 126 ("Permission denied") the
instant the session opened. The symptom is maddening — `open` **succeeds** and
returns an id, then every `send`/`poll` is refused *"not your shell"*, because the
session was already gone. `scrubEnv` now preserves that one shim, matched by name
so it stays an allowlist and never becomes arbitrary `.so` injection. Nothing to
configure; noted because the failure points nowhere near its cause.

**`$PREFIX` is empty in the session.** The scrub allowlist keeps `PATH` (so
commands resolve) but not Termux's `$PREFIX`, so a script that reads `$PREFIX`
finds nothing. If a declared shell needs it, put it in the command itself —
`hail shells add debug "PREFIX=$PREFIX bash"` — rather than widening the scrub.

**It runs as the Termux app user, non-root.** `id` in the session shows
`u0_aXXX`, SELinux context `untrusted_app` — confined to Termux's own sandbox.
That is the ceiling regardless of the fabric; the shell reaches no more of the
phone than Termux itself does. Rooted Android is a separate question this does not
change.

**Process-group teardown works.** Verified on Termux: a detached spawn leads its
own group and `process.kill(-pid)` takes the whole tree, so the shell's cleanup
is sound on Android — the one primitive that could have differed does not.

## Reaching it: Tailscale on Android

The encrypted arrival the shell demands comes from Tailscale, and Tailscale on
Android is not the desktop story.

- **Userspace, no TUN.** Android hands Termux no TUN device, so `tailscaled` runs
  `--tun=userspace-networking` and there is **no `tailscale0` interface to bind**.
  You expose the loopback daemon over the tailnet with `tailscale serve --bg <port>`
  (HTTPS on 443 → `127.0.0.1:<port>`), *not* `serve --http`, and the peer dials the
  `https://<node>.<tailnet>.ts.net` name — `serve` terminates the TLS.
- **The socket path is explicit.** `TS_SOCKET` is unreliable on Android builds;
  pass `--socket=<path>` to *every* `tailscale` command, matching the `--socket=`
  tailscaled was started with (often `~/.tailscale/tailscaled.sock`). A bare
  `tailscale serve status` that says "failed to connect to local Tailscale
  daemon" is this, not a dead daemon.
- **The app node is not the Termux node.** The Tailscale Android app and the
  in-Termux `tailscaled` are *different* tailnet peers. Only the in-Termux one can
  `serve` a Termux-local port; the app keeps the phone on the tailnet but fronts
  nothing in Termux. If the phone shows online but the serve URL never answers,
  you are looking at the app node, not the Termux one.
- **The caller may not resolve MagicDNS.** The peer dials the `.ts.net` name, so a
  caller whose OS does not wire Tailscale's resolver — WSL is the common case —
  gets "could not resolve host" even though `tailscale ping` works. This is a
  caller-side fix, covered in its own section below.
- **The daemon must survive its launching shell.** A peerhailer daemon started
  with a plain `node … &` from a command that then returns is killed with that
  shell on Termux (you will see `[1]+ Done` and a dead port). Start it detached —
  `setsid sh -c 'cd ~/Projects/peerhailer; exec node bin/hail.js daemon …' &` — so
  it outlives the launcher.

The full step-by-step, Android and other minimal targets, is in
[deploy-minimal-linux.md](deploy-minimal-linux.md).

## Driving a shell from WSL (or any caller that cannot resolve MagicDNS)

This is a *caller* concern, not a target one — it applies whenever you drive a
shell from WSL, whatever the peer is. The caller dials the target by its
`.ts.net` name, and some environments do not wire Tailscale's resolver even
while the tailnet itself works. **WSL is the common one:** `tailscale ping <peer>`
succeeds, but `hail shell …` reports *could not resolve host*. The name, not the
route, is what is missing — so the fix is on the caller's DNS, not anything in
peerhailer.

Fix it once, and prefer the fix that keeps using the name:

- **`tailscale set --accept-dns` (preferred).** Wires MagicDNS into the caller's
  resolver, so every `.ts.net` name resolves — no per-command workaround and
  nothing baked in.
- **Point the resolver at `100.100.100.100`.** Tailscale's own DNS; add it to
  `/etc/resolv.conf` (or your WSL resolver config). Same effect, more manual.
- **A hosts entry (last resort).** Mapping the name to the tailnet IP in
  `/etc/hosts` works, but it *bakes in an address*: if that node renumbers, the
  entry goes silently stale — the exact failure the record's MagicDNS name exists
  to avoid. So keep the peer's stored address as the `.ts.net` **name**, not a
  resolved IP (a record survives renumbering; a pinned IP does not), and use a
  hosts entry only to get unblocked.

Any of these removes the need for the per-command DNS preload the shell
otherwise required from WSL.

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
