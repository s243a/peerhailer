/**
 * The session composer: one-click launch of a local T3 instance whose model is a
 * coding agent driven through mcp-acp-bridge, with a configurable supervision gate
 * and an optional password bastion.
 *
 * v1 is local-first (self as the node): everything runs on this machine, so there
 * are no tunnels and no bridge changes. The composer only ever spawns and tracks
 * local child processes — a T3 server and (optionally) a gate — the same shape the
 * service plugin uses for the processes a peer may start.
 *
 * The worker's tool-call gate is the bridge's MCP supervisor seat
 * (`--supervisor-mcp`), which only exists when the bridge runs over stdio — which
 * it does, because T3's ACP provider spawns it. The seat prints its loopback URL
 * to the bridge's stderr, so the provider command redirects that stderr to a file
 * this module reads back: a Claude Code MCP client points at that URL to review.
 */
import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { createServer as createHttpsServer } from "node:https";

import { createGate } from "./gate.js";
import { selfSignedCert } from "./cert.js";

/** The agents mcp-acp-bridge can drive (mirrors its adapters; see docs/agents.md). */
export const KNOWN_AGENTS = [
  "codex-mcp",
  "codex",
  "claude",
  "agy",
  "agy-gated",
  "agy-dual-gated",
  "agy-sandboxed",
];

const MAX_LAUNCHES = 4;

/**
 * @param {{
 *   gateConfig?: () => ({ passwordHash: string, secret: string } | null | undefined),
 *   identity?: any,
 *   fabric?: any,
 *   log?: (m: string) => void,
 * }} [options]
 */
export function createComposer({ gateConfig = () => null, identity, log = () => {}, fabric = null } = {}) {
  const bridgePath =
    process.env.MCP_ACP_BRIDGE || join(homedir(), "Projects/mcp-acp-bridge/bin/bridge.js");
  // Default T3 launcher: an explicit T3CODE_CMD wins; else the local t3code
  // source bin if it is present (this repo runs it with `node src/bin.ts`); else
  // a global `npx t3`.
  const localT3 = join(homedir(), "Projects/t3code/apps/server/src/bin.ts");
  const t3Cmd = (process.env.T3CODE_CMD || (existsSync(localT3) ? `node ${localT3}` : "npx t3"))
    .split(/\s+/)
    .filter(Boolean);
  /** launchId -> {home, ws, seatLog, t3, origin, pairingUrl, gate} */
  const launches = new Map();

  function agents() {
    return {
      agents: KNOWN_AGENTS,
      bridgePath,
      t3Cmd: t3Cmd.join(" "),
      gateConfigured: Boolean(gateConfig()),
      remote: Boolean(fabric),
    };
  }

  /** Self + admitted peers with the offers each advertises (for the node picker). */
  async function nodes() {
    if (!fabric?.listNodes) return { self: null, nodes: [] };
    return fabric.listNodes();
  }

  /**
   * @param {{agent: string, supervision?: "none"|"mcp", gate?: boolean, cwd?: string, timing?: object|null, node?: string, service?: string, tunnel?: string, supervisorTunnel?: string}} spec
   */
  async function launch({ agent, supervision = "none", gate = false, cwd, timing = null, node = "local", service, tunnel, supervisorTunnel } = /** @type {any} */ ({})) {
    const isLocal = !node || node === "local";
    if (isLocal && !KNOWN_AGENTS.includes(agent)) throw badRequest(`unknown agent '${agent}'`);
    if (gate && !gateConfig())
      throw badRequest("no gate password set — run: hail gate set-password", 502);
    if (launches.size >= MAX_LAUNCHES)
      throw badRequest(`too many active launches (max ${MAX_LAUNCHES}); stop one first`, 429);

    const launchId = randomUUID();
    const home = mkdtempSync(join(tmpdir(), "composer-t3-"));
    const removeHome = () => {
      try {
        rmSync(home, { recursive: true, force: true });
      } catch {}
    };
    const ws = cwd && existsSync(cwd) ? cwd : join(home, "ws");
    mkdirSync(join(home, "userdata"), { recursive: true });
    if (ws.startsWith(home)) mkdirSync(ws, { recursive: true });
    const seatLog = join(home, "seat.log");

    // T3's ACP provider = the worker bridge. Under MCP supervision the bridge
    // runs `--supervisor-mcp` and we tee its stderr (where the seat URL prints)
    // into seatLog via `sh -c`; otherwise it is spawned directly.
    let config;
    let remote = /** @type {any} */ (null);
    if (node && node !== "local") {
      // Remote worker: start the bridge service on the chosen node and point T3's
      // ACP provider at `hail tunnel <node> <tunnel> pipe`. Remote MCP supervision
      // is not wired yet (the seat is stdio/loopback), so supervision stays off.
      if (!fabric?.startRemote || !fabric?.tunnelPipeCommand) {
        removeHome();
        throw badRequest("remote launches are not available on this daemon");
      }
      if (!service || !tunnel) {
        removeHome();
        throw badRequest("a remote launch needs a service and tunnel (from /api/compose/nodes)");
      }
      const started = await fabric.startRemote(node, service);
      if (!started?.ok) {
        removeHome();
        throw badRequest(`could not start ${service} on ${node}: ${started?.error ?? "unreachable"}`, 502);
      }
      const info = started.response ?? {};
      if (!info.id) {
        removeHome();
        throw badRequest(`${node} refused to start ${service}: ${info.reason ?? info.error ?? "no id returned"}`, 502);
      }
      remote = { node, service, id: info.id, port: info.port };
      const pipe = fabric.tunnelPipeCommand(node, tunnel);
      config = { command: pipe.command, args: pipe.args };
      // Remote MCP supervision: expose the node's seat tunnel as a local port so a
      // Claude Code MCP client can reach it at the fixed /mcp/supervisor path.
      if (supervision === "mcp" && supervisorTunnel && fabric.forwardSeat) {
        try {
          const forward = await fabric.forwardSeat(node, supervisorTunnel);
          remote.seatForward = forward;
          remote.seatUrl = `http://127.0.0.1:${forward.port}/mcp/supervisor`;
        } catch (error) {
          // Rather than fail the launch, run the worker unsupervised.
          log(`[composer] could not forward the seat for ${node}: ${error instanceof Error ? error.message : error}`);
          supervision = "none";
        }
      } else {
        supervision = "none";
      }
    } else {
      const bridgeArgs = ["--agent", agent, "--cwd", ws];
      if (supervision === "mcp") {
        bridgeArgs.push("--supervisor-mcp");
        // Optional human-like response pacing on the supervisor's verdicts.
        if (timing) bridgeArgs.push("--supervisor-timing", JSON.stringify(timing));
        const inner = ["node", bridgePath, ...bridgeArgs].map(shq).join(" ");
        config = { command: "sh", args: ["-c", `exec ${inner} 2>> ${shq(seatLog)}`] };
      } else {
        config = { command: "node", args: [bridgePath, ...bridgeArgs] };
      }
    }
    writeFileSync(
      join(home, "userdata", "settings.json"),
      JSON.stringify(
        {
          providerInstances: {
            relay: { driver: "acp", enabled: true, displayName: "Composer worker", config },
          },
        },
        null,
        2,
      ),
    );

    // Spawn the T3 server in its own process group (so stop kills the whole tree).
    const [cmd = "node", ...rest] = t3Cmd;
    const t3 = spawn(cmd, [...rest, "serve", "--host", "127.0.0.1", "--no-browser"], {
      cwd: ws,
      env: { ...process.env, T3CODE_HOME: home },
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    });
    let t3out = "";
    let spawnError = /** @type {Error | null} */ (null);
    const capture = (/** @type {string | Buffer} */ d) => {
      t3out += d;
    };
    t3.stdout.setEncoding("utf8");
    t3.stdout.on("data", capture);
    t3.stderr.setEncoding("utf8");
    t3.stderr.on("data", capture);
    // Never let a spawn error (e.g. a missing T3CODE_CMD binary) become an
    // uncaught exception — that would take down the whole daemon.
    t3.on("error", (/** @type {Error} */ error) => {
      spawnError = error;
    });
    t3.on("exit", (/** @type {number | null} */ code) => log(`[composer] t3 for ${launchId} exited (${code})`));

    // Wait for it to report its origin (written to server-runtime.json).
    const runtimePath = join(home, "userdata", "server-runtime.json");
    let origin = null;
    for (let i = 0; i < 60 && !origin; i++) {
      await sleep(500);
      if (spawnError) {
        kill(t3);
        removeHome();
        throw badRequest(`t3 failed to spawn (T3CODE_CMD="${t3Cmd.join(" ")}"): ${spawnError.message}`, 502);
      }
      if (existsSync(runtimePath)) {
        try {
          origin = JSON.parse(readFileSync(runtimePath, "utf8")).origin ?? null;
        } catch {}
      }
      if (t3.exitCode !== null && !origin) {
        kill(t3);
        removeHome();
        throw badRequest(`t3 exited before serving (T3CODE_CMD="${t3Cmd.join(" ")}"):\n${tail(t3out)}`, 502);
      }
    }
    if (!origin) {
      kill(t3);
      removeHome();
      throw badRequest(`t3 did not report an origin (T3CODE_CMD="${t3Cmd.join(" ")}"):\n${tail(t3out)}`, 502);
    }
    const pairingUrl = (t3out.match(/pairing\s*url:?\s*(\S+)/i) || t3out.match(/(https?:\/\/\S*pair\S*)/) || [])[1] || null;

    const entry = { home, ws, seatLog, t3, origin, pairingUrl, gate: /** @type {import("node:http").Server | null} */ (null), remote };
    launches.set(launchId, entry);

    let gateUrl = null;
    if (gate) {
      try {
        const g = gateConfig();
        if (!g) throw badRequest("no gate password set — run: hail gate set-password", 502);
        const proxy = createGate({ target: origin, passwordHash: g.passwordHash, secret: g.secret, log });
        const server = createHttpsServer(selfSignedCert(identity), proxy.onRequest);
        server.on("upgrade", proxy.onUpgrade);
        // Port 0 (OS-chosen): a second gated launch cannot collide on a fixed
        // 8443 and strand this T3.
        const port = await new Promise((resolve, reject) => {
          server.once("error", reject);
          server.listen(0, "127.0.0.1", () => resolve(/** @type {import("node:net").AddressInfo} */ (server.address()).port));
        });
        entry.gate = server;
        gateUrl = `https://127.0.0.1:${port}`;
      } catch (error) {
        // Strand nothing: tear the T3 down and forget the launch before failing.
        launches.delete(launchId);
        kill(t3);
        removeHome();
        throw badRequest(`gate failed to start: ${error instanceof Error ? error.message : String(error)}`, 502);
      }
    }

    log(`[composer] launched ${launchId}: ${agent} → ${origin}${gateUrl ? ` (gated ${gateUrl})` : ""}`);
    return { launchId, agent, supervision, node, t3Url: origin, pairingUrl, gateUrl, seatUrl: remote?.seatUrl ?? null, seatLog };
  }

  /** The supervisor seat URL, once T3 has activated the worker (bridge spawned). */
  /** @param {string} launchId */
  function seat(launchId) {
    const entry = launches.get(launchId);
    if (!entry) return { error: "no such launch" };
    if (entry.remote?.seatUrl) return { seatUrl: entry.remote.seatUrl };
    let seatUrl = null;
    try {
      // Loopback only: the seat is on 127.0.0.1, so refuse a forged seat line a
      // malicious agent might print to the bridge's stderr.
      const m = readFileSync(entry.seatLog, "utf8").match(/connect a supervisor MCP client at\s+(https?:\/\/127\.0\.0\.1:\d+\/\S+)/);
      if (m) seatUrl = m[1];
    } catch {}
    return seatUrl
      ? { seatUrl }
      : { seatUrl: null, hint: "open a thread in T3 with the 'Composer worker' provider to activate the supervisor seat" };
  }

  /** @param {string} launchId */
  async function stop(launchId) {
    const entry = launches.get(launchId);
    if (!entry) return { stopped: false };
    launches.delete(launchId);
    kill(entry.t3);
    entry.gate?.close();
    if (entry.remote) {
      try {
        entry.remote.seatForward?.close?.();
      } catch {}
      if (fabric?.stopRemote) {
        try {
          await fabric.stopRemote(entry.remote.node, entry.remote.service, entry.remote.id);
        } catch {}
      }
    }
    try {
      rmSync(entry.home, { recursive: true, force: true });
    } catch {}
    return { stopped: true };
  }

  function closeAll() {
    for (const id of [...launches.keys()]) void stop(id);
  }

  function list() {
    return {
      launches: [...launches.entries()].map(([id, e]) => ({
        launchId: id,
        t3Url: e.origin,
        gated: Boolean(e.gate),
      })),
    };
  }

  return { agents, nodes, launch, seat, stop, list, closeAll };
}

/** @param {import("node:child_process").ChildProcess} child */
function kill(child) {
  if (!child || child.exitCode !== null || child.signalCode) return;
  const pid = child.pid;
  if (typeof pid !== "number") return;
  const term = (/** @type {NodeJS.Signals} */ signal) => {
    try {
      process.kill(-pid, signal);
    } catch {
      try {
        child.kill(signal);
      } catch {}
    }
  };
  term("SIGTERM");
  // Escalate for a child that ignores SIGTERM, so `stop` does not report success
  // over a process that is still alive.
  setTimeout(() => {
    if (child.exitCode === null && child.signalCode === null) term("SIGKILL");
  }, 3000).unref?.();
}

const sleep = (/** @type {number} */ ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Single-quote a token for `sh -c`, escaping embedded quotes.
 * @param {unknown} value */
function shq(value) {
  return `'${String(value).replaceAll("'", `'\\''`)}'`;
}

/** @param {unknown} text @param {number} [n] */
function tail(text, n = 600) {
  return String(text).slice(-n);
}

/** @param {string} message @param {number} [status] */
function badRequest(message, status = 400) {
  const error = new Error(message);
  // @ts-expect-error tag for the route to map to an HTTP status
  error.status = status;
  return error;
}
