# Declared services

**Status: designed, not built.** The third plugin shape, after tunnels and
commands, and the most dangerous — so the last to build and the one to review
hardest.

## The principle it rests on

Everything in this fabric is off until an operator turns it on. A capability is
granted, never inherited; a plugin is loaded, never assumed; the page, the chat,
and each tunnel endpoint are separate opt-ins. The result is a property worth
naming, because it is the point rather than a side effect:

**The attack surface is exactly what the operator chose, and nothing more.**

A headless relay has no inbox. A machine that declares no command cannot run one.
`tunnel:acp` says nothing about `service:agent`. Nobody carries a feature they
did not ask for, which means nobody carries its risk either. A service plugin has
to preserve that, because it is the one whose features are the most costly to
carry by accident.

## The gap the existing plugins leave

Two shapes exist. A **command** runs, finishes, and returns its output — bounded,
timed out, killed at thirty seconds. A **tunnel** connects to something already
listening and carries bytes. Neither can *start a thing that keeps running*.

The motivating case is spawning `bridge --listen <port>` on a machine so a peer
can drive an agent there. A command cannot: the bridge never finishes, so the
command's own timeout would kill it. A tunnel cannot: there is nothing to connect
to until something starts it. The missing shape is **start-and-persist**.

| | Lifetime | Returns |
| --- | --- | --- |
| command | runs to completion, bounded | output |
| tunnel | connects to what is already up | a byte stream |
| **service** | **starts, and stays up until stopped** | **a port to reach it at** |

## Shape

**The operator declares the service; the caller names it.** The tunnel and
command rule, a third time:

```sh
hail services add agent "bridge --listen {port} --agent claude"   # needs service:agent
```

A peer asks to start `agent`. It cannot pass a different command, cannot choose
the agent, cannot supply arguments. `{port}` is the one substitution, and it is
*chosen by this machine*, not by the caller — the caller receives the port that
was picked, it does not send one, so this is not a way to make the service bind
somewhere of the caller's choosing.

**Starting returns a port; reaching it is a tunnel.** A started service is a
local listener and nothing more until a tunnel carries bytes to it. The natural
composition: starting `agent` registers a tunnel to its port for the same peer,
so one request yields a reachable agent. That keeps the two capabilities
honest — `service:agent` starts it, a tunnel capability reaches it — rather than
folding a byte-carrier into the service.

**One running instance per peer, bounded.** A peer that can start a service can
start a hundred, each a subprocess. Cap it, per peer and in total, the way tunnels
and command runs already are.

**Stopped when the peer goes, and reap-able.** A service a peer started and
abandoned is a subprocess nobody will stop. Tie its life to the peer's tunnel, or
to an idle timer, or to an explicit stop — most likely all three.

## Why this is the top of the danger ladder

The capabilities this fabric can grant form a rough order of consequence:

| Capability | What a compromised holder gets |
| --- | --- |
| `hail` | learns this machine exists |
| `directory` | learns who it knows |
| `command:pair` | a bearer credential — control of a T3 |
| `tunnel:devtools` | drives a browser and everything it is logged into |
| **`service:agent`** | **starts an agent that runs arbitrary commands, unattended** |

`service:agent` is the most powerful thing here, because it does not do a fixed
dangerous thing — it starts a *general* one. An agent runs whatever it is told,
and this hands a remote peer the ability to start one, on request, with nobody
watching.

So it is not a capability for a general profile. It wants:

- **Its own capability**, never bundled — the principle above, applied to its
  most important case.
- **An encrypted arrival**, non-negotiably. The tunnel that reaches the agent
  carries a review conversation and the agent's actions; in plaintext that is a
  session anyone on the wire can watch and inject into. This is the
  encrypted-only rule from [network-trust.md](network-trust.md) at its sharpest.
- **A gate the operator can still see.** The bridge's own review — the approval
  cards — does not disappear because the client is remote; it appears on the
  remote client. But an operator granting `service:agent` should be able to watch
  what was started and stop it, which is the run-history argument one level up:
  a service started while nobody watched is exactly what a person wants in a list.

## Composition, end to end

With this shape, the whole "phone drives an agent at home" chain is declared
configuration rather than new code each time:

1. Home machine declares `service:agent` and grants it to the phone deliberately.
2. Phone asks to start `agent`; the home machine spawns `bridge --listen`, picks
   a port, and registers a tunnel to it for the phone.
3. Phone's bridge, in client mode, opens that tunnel and relays ACP down it.
4. The agent runs at home; its approval cards appear on the phone; a person
   reviews them there.

Steps 1–2 are this document. Step 3 is the bridge's unbuilt client side. Step 4
exists.

## Open

- **Does the caller ever need to influence the agent choice?** "Start a claude
  agent" versus "start a codex agent" is a real want, and it is a
  caller-supplied argument, which this project refuses. The answer is the command
  plugin's answer: declare two services. `service:claude` and `service:codex`,
  not `service:agent` with a parameter.
- **What stops a started service outliving the machine's intent?** Peer tunnel,
  idle timer, explicit stop — probably all three, and the interaction between
  them is the fiddly part.
- **Should starting be rate-limited the way `command:pair` is?** Starting a
  process is heavier than minting a token, so almost certainly yes, and lower.
