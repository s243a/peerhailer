# The session composer

**Status: v1 (local-first) is built.** From the daemon's page (`hail daemon --ui`),
one click launches a local **T3 Code** instance whose model is a coding agent
driven through [mcp-acp-bridge], optionally supervised from your own Claude Code
over MCP, and optionally fronted by a password bastion.

It is the "compose a session" idea reduced to what works today on one machine.
Reaching agents on *other* nodes over tunnels is the next step (see the end).

## What it composes

A session is three parts, and the page (`#composer`) picks them:

| part | choice | how it is wired |
| --- | --- | --- |
| **worker** | an agent (`codex-mcp`, `codex`, `claude`, `agy`, …) | T3's generic **ACP provider** is pointed at `bridge --agent <X>` — T3 needs no changes, its `acp` driver spawns any stdio ACP command |
| **supervision** | `None` or `MCP seat` | with the seat, the bridge runs `--supervisor-mcp`; its tool calls are held and reviewed by an MCP client you connect (your Claude Code) |
| **access** | optional password bastion | `createGate` fronts the T3 web app over TLS on `:8443` |

Supervision and the bastion are independent: one gates *what the agent does*, the
other gates *who reaches the web app*.

## The launch

`POST /api/compose/launch {agent, supervision, gate, cwd}` (loopback control only):

1. A fresh isolated `T3CODE_HOME` is created and its `settings.json` seeded with an
   `acp` provider instance named **Composer worker** whose command is the bridge.
2. `t3 serve` is spawned; the composer waits for `userdata/server-runtime.json` and
   returns the T3 **origin** and **pairing URL**.
3. If `gate`, a password bastion is started in front of the origin (requires a
   prior `hail gate set-password`).

The response: `{launchId, t3Url, pairingUrl, gateUrl?, seatLog}`. `Stop` tears the
T3 (and gate) child down and removes the temp home.

## Supervising with your Claude Code (the MCP seat)

The bridge's supervisor seat only exists in **stdio** mode — which is how T3 runs
it — and it prints its URL to stderr, so the provider command tees stderr to a
file the composer reads. Because T3 spawns the bridge on the **first thread**, the
seat URL appears only once you open a thread with the *Composer worker* provider;
the page polls `GET /api/compose/seat` and shows it then.

Point an MCP client at that URL to review. With Claude Code:

```
claude mcp add composer-seat --transport http <seatUrl>
```

then have it drive the seat's tools: `supervisor_claim` → `supervisor_pending`
(each held call is `{id, tool, args}`) → `supervisor_decide {id, verdict}` where
`approve` allows, `reject` denies, anything else passes to the human. Because it is
plain MCP request/response, **no extra OAuth/ACP token is needed** — your existing
Claude Code session is the supervisor. (The alternative, an ACP-push supervisor,
would need a separate OAuth'd Claude ACP client; that is a later gate type.)

**Pacing** (optional): the *Pacing* control shapes the supervisor's response
latency to look human — *Human-like* applies a clipped gamma profile so verdicts
land over seconds, not instantly (this passes `--supervisor-timing` to the worker
bridge; see mcp-acp-bridge `docs/supervisor.md` for the full profile options). It
only adds latency; it never changes a verdict.

**Fail-closed:** with no client holding the seat, a review passes to the human
(T3's own approval prompt), and if nobody answers, the bridge's gate denies at its
timeout. Nothing fails open.

## Configuration

- `MCP_ACP_BRIDGE` — path to the bridge entry (default
  `~/Projects/mcp-acp-bridge/bin/bridge.js`).
- `T3CODE_CMD` — how to launch T3 (default: the local `node
  ~/Projects/t3code/apps/server/src/bin.ts` if present, else `npx t3`). Set it to
  whatever runs `t3 serve` in your setup.

Worker auth is the agent's own: `codex-mcp` uses your codex login; `claude` the
local `claude` CLI; `agy` (Gemini) carries the Antigravity Terms-of-Service caveat
noted elsewhere.

## Scope and safety

- **Local only.** Every process is a loopback child of the daemon; the control
  routes are loopback-with-no-auth, like the rest of the page.
- **Isolated homes.** Each launch gets its own throwaway `T3CODE_HOME`; the real
  `~/.t3/userdata` is never touched.
- **Pairing still applies.** Even behind the bastion, the T3 app requires its
  pairing token — the composer returns it.

## Not yet built (the fabric version)

Running the worker on **another node** needs: a discovery route so nodes advertise
what they offer, pre-declared `service`+`tunnel` pairs, and — for remote MCP
supervision — a `--supervisor-mcp-port` addition to the bridge so the seat lands on
a fixed, tunnelable port. The local-first composer here is the foundation for that.

[mcp-acp-bridge]: ../../mcp-acp-bridge
