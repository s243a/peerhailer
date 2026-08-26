# The session composer

**Status: v1 (local-first) is built.** From the daemon's page (`hail daemon --ui`),
one click launches a local **T3 Code** instance whose model is a coding agent
driven through [mcp-acp-bridge], optionally supervised from your own Claude Code
over MCP, and optionally fronted by a password bastion.

It composes a session across the fabric: the worker can run locally or on
another node over a tunnel (see "Remote workers" below).

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

## Remote workers (the fabric)

The worker can run on **another node**. The composer's *Node* picker lists self
plus any admitted peer that advertises a launchable offer; picking a peer fills the
*Agent* picker from its offers, and Launch starts the worker there and points the
(local) T3 at it over a tunnel.

An **offer** is a service the operator declared with agent metadata, whose paired
tunnel exists. On the node that will run the worker:

```sh
hail services add agy-worker "node ~/mcp-acp-bridge/bin/bridge.js --agent agy --listen 9102"   --agent agy --role worker --label "Gemini worker" --tunnel agy-worker
hail tunnels add agy-worker 127.0.0.1:9102
hail profiles add composer --allows hail,offers,service:agy-worker,tunnel:agy-worker
hail add <composer-machine> --key <its-key> --profile composer   # admit the composer's daemon
hail daemon --hail-on-tls tailscale0
```

The composer's daemon then sees the node in `GET /api/compose/nodes` (it calls the
node's capability-gated `/offers` route via `callPeer`), and a launch:

1. starts the worker service on the node (`callPeer /service/<svc>/start` → a port
   the node's pre-declared tunnel already reaches);
2. spawns a local T3 whose `acp` provider is `hail tunnel <node> <tunnel> pipe`, so
   T3 drives the remote worker as if it were local.

T3's config only ever names the relay, so local-vs-remote and which-agent are the
composer's choices, not T3's.

### Supervising a *remote* worker

A remote worker can be MCP-supervised too, when the node offers a seat. The node's
worker runs in stdio mode behind `acp-passthrough` (so the bridge's seat wires) and
pins the seat with `--supervisor-mcp-port`, and declares a second tunnel to it:

```sh
hail services add agy-worker   "acp-passthrough --listen 9102 -- node ~/mcp-acp-bridge/bin/bridge.js --agent agy --supervisor-mcp --supervisor-mcp-port 9103"   --agent agy --role worker --label "Gemini worker" --tunnel agy-worker --supervisor-tunnel mcp-seat
hail tunnels add agy-worker 127.0.0.1:9102   # worker ACP
hail tunnels add mcp-seat   127.0.0.1:9103   # supervisor seat (fixed /mcp/supervisor)
# grant the composer: hail profiles add composer --allows hail,offers,service:agy-worker,tunnel:agy-worker,tunnel:mcp-seat
```

The offer then advertises `supervisorTunnel`; the composer re-enables Supervision
for that node, and on a supervised launch it forwards the seat tunnel to a local
port and hands you `http://127.0.0.1:<port>/mcp/supervisor` to point Claude Code
at. The seat's credential is the tunnel capability, not the URL — see
mcp-acp-bridge `docs/supervisor.md`. A fixed seat port means one supervised worker
process on that node.

## Driving a *remote* T3 (T3-to-T3 remote control)

Everything above tunnels the **agent** protocol: the worker runs on the node, a
local T3 drives it. A different shape drives the node's **T3 itself** — you get the
remote environment's own projects, threads, and provider logins, controlled from a
local T3 client. This uses T3's native client→server pairing, not a bridge: the
remote **mints a short-lived grant**, it crosses a tunnel, and a local T3 web app
registers the remote as a saved connection.

### On the remote node

Declare two things and grant them to the composer's daemon:

```sh
# A fixed command that mints a 15-minute, standard-scope, one-time grant against
# the already-running T3 (it discovers it via server-runtime.json). Nothing the
# caller sends chooses what runs — command:pair is far below `shell` on the ladder.
hail commands add pair "node ~/Projects/t3code/apps/server/src/bin.ts pair --ttl 15m --label 'remote control'"

# A tunnel to the T3 origin port — it serves HTTP and the /ws WebSocket together,
# so one tunnel carries the whole origin.
hail tunnels add t3 127.0.0.1:3773

hail profiles add controller --allows hail,offers,command:pair,tunnel:t3
hail add <composer-machine> --key <its-key> --profile controller
```

### From the composer

The `#composer` page's **Drive a remote T3** control picks a reachable peer and a
local T3 (use the one already running, or launch a throwaway). `Connect`
(`POST /api/compose/control {node, localT3}`):

1. runs the node's `command:pair` and reads the pairing URL + one-time token from
   its stdout;
2. forwards the node's `tunnel:t3` to a local port — `http://127.0.0.1:<port>` now
   *is* the remote T3, HTTP and WebSocket alike;
3. resolves the local T3 (reads `server-runtime.json` for a running one, or spawns
   one); and
4. returns a **deep link**: `<localT3>/pair?host=<enc http://127.0.0.1:<port>>#token=<token>`.

Open that link in your browser. T3's pairing route reads `?host=` as the backend
and the `#token` as the credential, runs the token→bearer→wsTicket→WS exchange, and
saves the remote as a `BearerConnectionTarget` — a persistent entry you can switch
into alongside the local environment. `Stop` closes the forward (and any T3 the
wizard launched). The grant expires on its own, so nothing lasting crosses.

**Why a derived grant, not the long-lived token:** the tunnel stays a byte carrier
and what crosses is worthless minutes later; the exit never attaches its own
credential (no confused deputy). See `docs/acp-tunnel.md`, "A second endpoint: T3
to T3, without moving the token."

**Caveat — a dev-mode remote.** Saved connections live in the *browser* (IndexedDB),
so the deep link must be opened in the browser that will drive the remote; the
wizard cannot seed it server-side. And a remote T3 running in **dev mode** (`devUrl`
set) constrains its CORS `allowedOrigins`: the local app's origin must be allowed,
or the browser blocks the cross-origin calls. A packaged/production remote uses
wildcard CORS and just works. Auth itself never checks Host, so the tunnel's
foreign host is fine either way.

**Verified live** (headless loopback): `npm run test:remote-control-real` spins up a
real T3, mints a real `t3 pair` grant, forwards its origin through a real tunnel, and
drives the full `token → bearer → wsTicket → /ws` chain both directly and through the
tunnel at a foreign Host. It needs a t3code checkout (set `T3CODE_BIN` or keep it at
`~/Projects/t3code`) and self-skips otherwise, so it is not wired into CI.

[mcp-acp-bridge]: ../../mcp-acp-bridge
