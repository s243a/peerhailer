# An ACP tunnel as the first plugin

**Status: designed, not built.**

## Why this one first

Every other plugin idea is a feature. This one is the reason the fabric exists:
a phone running T3 Code, driving a coding agent on a machine at home, over a
link authenticated by keys neither end had to type.

It is also the honest replacement for something worse. `shared-namespace.md`
starts from the case of a T3 token crossing a clipboard to reach another
instance — snoopable, unrevocable, and the thing this project keeps refusing to
store. A tunnel removes the need to move the token at all: the agent stays where
it is, and the peer link carries the conversation.

And it exercises the whole model at once. Nothing else proposed so far touches
identity, capability, grants and refusal in one flow.

## What has to cross

ACP is bidirectional, and the direction that matters is the awkward one:

| Message | Direction | Note |
| --- | --- | --- |
| `session/prompt`, `session/cancel` | client → agent | ordinary request/response |
| `session/update` | agent → client | streamed, many per turn |
| `session/request_permission` | agent → client | **blocks** until answered |

That last row is the whole difficulty. The permission card is the point of the
bridge, and it is the agent asking the client a question and waiting.

A peerhailer plugin route is a request that returns JSON. It cannot originate a
message, so it cannot carry ACP as it stands.

## Three transports, and why polling comes first

**Poll.** The client asks for pending messages; the daemon answers with whatever
has queued. Needs **no change to the plugin contract** — it is a route that
returns JSON, which is exactly what plugins already are. Costs latency and empty
round trips.

**Stream (SSE) plus POST.** What MCP Streamable HTTP does, and what the bridge
already speaks on its other side. Correct shape, lower latency, and it requires
plugin routes to hold a response open — a change to what a plugin is.

**WebSocket.** Cleanest protocol fit, largest change to the daemon.

Polling first, deliberately. The hard part of this is not the transport, it is
whether a remote peer may drive an agent at all, and the poll version answers
that question without changing what a plugin is allowed to be. If the trust path
holds, the transport can be replaced underneath it; if it does not, nothing was
spent building a streaming layer for it.

## The trust question, which is the real one

**This is the most dangerous capability in the system.** A peer holding it can
drive an agent that runs commands on this machine. Diagnostics leak information;
this executes.

So it does not live in `trusted`. `trusted` means "my own machines, may hail and
see who I know" — driving an agent is a different order of thing, and bundling
them would mean every machine you own could run code on every other by virtue of
being yours. It gets its own capability and its own profile, the way
`DIAGNOSTICS` is held by `operator` rather than by everyone trusted.

**Opened with a grant, not a standing permission.** A tunnel is a session with a
lifetime, which `shared-namespace.md` already identifies as the thing closest to
a credential in this design. Grants are the answer it reaches for: subject-bound
so the bytes are useless to anyone else, expiring in minutes, renewed rather
than held. A tunnel that outlives the intent that opened it is a back door.

**And the gate still applies.** The bridge's approval cards do not disappear
because the client is remote — they appear on the remote T3, which is the entire
point. The reviewer is a person somewhere else, and every finding from testing
that flow locally holds: they must be able to see the command, a denial must
stick, and a refusal must not be worked around silently.

## What this is not

**Not a VPN.** Nothing forwards arbitrary traffic. One protocol, one endpoint,
one capability — the narrowness is what makes it reviewable.

**Not a way to reach a machine you could not otherwise reach.** The tunnel runs
over a peer link that already exists. Bridging between networks is a separate
question, and the answer there is that introductions cross rather than packets.

## Open

- **Where the agent's own permission config lives.** The bridge gates MCP calls,
  and the agent has its own deny rules. A remote client should not be able to
  weaken either, which means `session/set_config_option` needs a policy.
- **One tunnel or many.** Two clients driving one agent is a conflict the ACP
  session model does not describe.
- **What happens when the peer link drops mid-turn.** The agent keeps running; a
  reconnecting client needs to find the turn it left, or cancel it.
