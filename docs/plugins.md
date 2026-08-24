# The plugins

The core finds machines and decides *who may ask for what*. It does nothing
else — a host with nothing loaded answers `404` for every route, `/hail`
included. Everything a peer can actually *do* is a plugin: a small module that
declares routes, each gated by a **capability** the caller must hold. A project
embedding peerhailer loads only the plugins it wants, so it never inherits a
service it did not ask for.

This page catalogs the built-in plugins. For the plugin *contract* — how a
plugin declares routes and capabilities, and why a handler never sees an
unauthenticated request — see the [Plugins section of the README](../README.md#plugins).

## The ladder of consequence

Capabilities are not a flat set. They differ in what a compromised holder gets,
and the plugins are best read in that order — each rung hands a peer more of your
machine than the last:

| Capability        | A holder can…                                        | Plugin       |
| ----------------- | ---------------------------------------------------- | ------------ |
| `hail`            | learn this machine exists and who it knows           | hail         |
| `diagnostics`     | read *why* a request of theirs was refused           | diagnostics  |
| `chat`            | leave and read short messages                        | chat         |
| `tunnel:<name>`   | reach one declared local endpoint, byte for byte     | tunnel       |
| `command:<name>`  | run one fixed command the operator wrote down        | command      |
| `service:<name>`  | start a declared long-running process, get its port  | service      |
| `shell:<name>`    | type anything into a shell — **≈ operator of this host** | shell    |

Nothing above the line is in a built-in profile by accident: `tunnel:`,
`command:`, `service:`, and `shell:` are granted only by a deliberate profile or
grant. The rule the dangerous ones share is **the operator declares, the caller
names** — a peer asks for `agent`, or `devtools`, or `pair`, and gets whatever
the operator wrote down under that name. No caller-supplied bytes reach a
command line (the shell's own stdin is the deliberate exception).

## hail — the hello protocol

Capability `hail`. Answers the one question the whole system rests on: *who else
do you know?* A peer hails, you reply with yourself and the peers you have
admitted, and the caller files the rest as candidates for a person to decide on.
Answering is itself a service, which is why it is a plugin and not built in — a
host that should stay silent simply does not load it. See
[discovery.md](discovery.md).

## diagnostics — why a request was refused

Capability `diagnostics`. A refusal tells an unauthorized caller nothing, by
design — but a peer you trust, debugging a connection, needs to know whether it
was an unknown key, a missing capability, or a stale hail. This plugin exposes
those reasons to a holder of `diagnostics`, and only while a debug window is
open. It is how "it will not connect" becomes answerable without weakening what a
stranger learns.

## chat — short messages between peers

Capability `chat`. Small text messages to and from admitted peers, kept in
memory. The lightest thing above hail: no filesystem, no process, just a note
left for a peer or read back. See [chat.md](chat.md).

## tunnel — carry bytes to a declared endpoint

Capability `tunnel:<name>`. Opens a byte pipe to *one* endpoint named in local
configuration — `tunnel:acp`, `tunnel:devtools` — and never parses what it
carries. The endpoint is **named, never addressed**: a caller says `acp`, not
`127.0.0.1:9000`, so this cannot become a general port-forward into services
that trust localhost. One capability per endpoint, and a tunnel belongs to the
peer that opened it. Bytes only cross where arrival is encrypted; see
[network-trust.md](network-trust.md) and [acp-tunnel.md](acp-tunnel.md).

## command — run one declared command

Capability `command:<name>`. Runs a single command the operator wrote down, to
completion, and returns its output — the case Tailscale and a pairing flow leave
open: "let this peer run *this one thing*." The operator writes the whole line; a
caller only names it, and nothing a peer sends is interpolated in. A command that
must vary is two declared commands, because validating a caller's value is the
mistake this refuses to make. Rate-limited and recorded. Like the tunnel, it is
served **only where arrival is encrypted** — its first intended use mints a
bearer credential (`command:pair`), which must not cross a plaintext LAN. See
[commands.md](commands.md).

## service — start a declared long-running process

Capability `service:<name>`. Where a command runs and finishes, a service *keeps
running* — spawning e.g. `bridge --listen {port}` so a peer can drive an agent on
this machine. `{port}` is the one substitution, and the machine chooses it (a
real allocated integer, never caller text). Starting returns a port; reaching it
is a separate tunnel capability, by design. Bounded per peer and in total, idle-
and lifetime-reaped, killed as a process group. See [services.md](services.md).

## shell — an interactive shell

Capability `shell:<name>`. The top of the ladder: **remote shell access**, SSH
reached through the fabric instead of `sshd`. It screens no commands — the gate
is the capability, not a filter on the bytes — so if you would not hand a peer an
unfiltered terminal, grant a narrower `command:` instead. To *restrict* one, the
operator declares a sandboxed shell (`firejail bash`, a container, Termux's own
sandbox), because the operator writes the command; an optional supervisor can sit
at the input choke point. What the plugin always owns: the capability gate, a
scrubbed spawn environment, encrypted-arrival-only, bounds, a recorded session
existence, and process-group teardown. In **no** built-in profile. See
[shell.md](shell.md) — read the ladder before the mechanism.

## Writing your own

A plugin is a name, the capabilities it introduces, the profiles it *suggests*
(never grants), and its routes — each naming the capability it requires. Load it
by name from configuration; it is never scanned for. The core authenticates and
capability-checks every caller before the handler runs, so a plugin cannot open a
door the fabric did not decide to open. The contract, with an `echo` example, is
in the [README](../README.md#plugins).
