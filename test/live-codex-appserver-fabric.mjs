/**
 * Attach to an existing codex session across the fabric.
 *
 * codex's app-server protocol persists every session; a fresh client can
 * `thread/list` what is on the machine, `thread/read` its history, and
 * `thread/resume` to pick it up. This proves that over a real peerhailer tunnel:
 * connection A (the "worker") starts a session and stores something; a SEPARATE
 * connection B (the "console"), reached only through the tunnel, then lists A's
 * session, reads it back, resumes it, and continues it — the remote-visibility
 * and steer-an-existing-agent idea, demonstrated end to end.
 *
 * Bare `codex app-server` is served on a loopback port by acp-passthrough; the
 * tunnel carries it. No shared daemon needed — the session store is the shared
 * state. (A live *mid-turn* steer of another client's in-flight turn additionally
 * needs codex's managed app-server daemon; that is the harder variant.)
 */
import { spawn } from "node:child_process";
import { mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { PassThrough } from "node:stream";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import hailPlugin from "../src/builtin/hailPlugin.js";
import { createTunnelPlugin } from "../src/builtin/tunnelPlugin.js";
import { callPeer } from "../src/hail.js";
import { pipeTunnel } from "../src/tunnelClient.js";

const here = dirname(fileURLToPath(import.meta.url));
const PASSTHROUGH = process.env.PASSTHROUGH ?? resolve(here, "../../mcp-acp-bridge/bin/acp-passthrough.js");
const CODEX = process.env.CODEX ?? join(process.env.HOME, ".local/bin/codex");
const PORT = 9211;
const workspace = mkdtempSync(join(tmpdir(), "fabric-appsrv-"));

if (!existsSync(PASSTHROUGH) || !existsSync(CODEX)) {
  console.log(`SKIP — need acp-passthrough (${PASSTHROUGH}) and standalone codex (${CODEX})`);
  process.exit(0);
}

// 1. passthrough serving bare `codex app-server` on a loopback port
const shim = spawn("node", [PASSTHROUGH, "--listen", String(PORT), "--", CODEX, "app-server"], {
  cwd: workspace,
  stdio: ["ignore", "pipe", "pipe"],
});
await new Promise((res, rej) => {
  let log = "";
  const to = setTimeout(() => rej(new Error("passthrough did not start:\n" + log)), 15000);
  const check = (d) => ((log += d), /listening for ACP/.test(log) && (clearTimeout(to), res()));
  shim.stdout.on("data", check);
  shim.stderr.on("data", check);
});
console.log(`[1] acp-passthrough serving "codex app-server" on 127.0.0.1:${PORT}`);

// 2. in-process home daemon, pinned mutual TLS, one granted tunnel endpoint
const home = generateIdentity();
const caller = generateIdentity();
const directory = createDirectory({ self: { name: "home", publicKey: home.publicKey } });
directory.useProfiles({ agents: { name: "agents", allows: ["hail", "tunnel:codex-appserver"] } });
directory.admit({ name: "caller", publicKey: caller.publicKey }, { profile: "agents" });
const tunnel = createTunnelPlugin({ endpoints: { "codex-appserver": `127.0.0.1:${PORT}` } });
const daemon = createDaemon({ directory, identity: home, plugins: [hailPlugin, tunnel] });
const bound = await daemon.listenHail({ port: 0, hosts: ["127.0.0.1"], tls: true });
console.log(`[2] home daemon (pinned mutual TLS) on https://127.0.0.1:${bound[0].port}`);

const record = { name: "home", addresses: [{ value: `https://127.0.0.1:${bound[0].port}` }], publicKey: home.publicKey };
const as = { name: "caller", publicKey: caller.publicKey, privateKey: caller.privateKey };
const call = (path, body) => callPeer(record, path, body, { as });

// One tunnel connection = one app-server process. Open it, run fn(client), close.
async function overTunnel(fn) {
  const toT = new PassThrough();
  const fromT = new PassThrough();
  const pumping = pipeTunnel(call, "codex-appserver", { input: toT, output: fromT }, { pollMs: 20 });
  let idc = 0;
  const pending = new Map();
  const notes = [];
  let buf = "";
  const rpc = (method, params) =>
    new Promise((resolve, reject) => {
      const id = ++idc;
      pending.set(id, { resolve, reject });
      toT.write(JSON.stringify({ jsonrpc: "2.0", id, method, params: params ?? {} }) + "\n");
    });
  fromT.on("data", (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf("\n")) !== -1) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (!line) continue;
      let m;
      try {
        m = JSON.parse(line);
      } catch {
        continue;
      }
      if (m.id !== undefined && m.method === undefined) {
        const w = pending.get(m.id);
        if (w) {
          pending.delete(m.id);
          m.error ? w.reject(new Error(JSON.stringify(m.error))) : w.resolve(m.result);
        }
      } else if (m.method) {
        notes.push(m);
      }
    }
  });
  const waitNote = (pred, ms = 30000) =>
    new Promise((resolve, reject) => {
      const t0 = Date.now();
      const tick = () => {
        const hit = notes.find(pred);
        if (hit) return resolve(hit);
        if (Date.now() - t0 > ms) return reject(new Error("timed out waiting for a notification"));
        setTimeout(tick, 50);
      };
      tick();
    });
  const streamText = () =>
    notes.filter((n) => n.method === "item/agentMessage/delta").map((n) => n.params?.delta ?? "").join("");
  try {
    return await fn({ rpc, notes, waitNote, streamText });
  } finally {
    toT.end();
    await pumping.catch(() => {});
  }
}

// 3. WORKER — start a session over the tunnel and store a codeword
console.log("[3] worker: creating a session over the tunnel...");
const threadId = await overTunnel(async (c) => {
  await c.rpc("initialize", { clientInfo: { name: "worker", version: "0" } });
  const th = await c.rpc("thread/start", { cwd: workspace });
  const id = th.thread?.id ?? th.threadId ?? th.id;
  await c.rpc("turn/start", { threadId: id, input: [{ type: "text", text: "Remember this codeword: PLATYPUS. Reply with exactly: STORED" }] });
  await c.waitNote((n) => n.method === "turn/completed");
  console.log(`   worker stored, thread ${id} — said: ${c.streamText().trim().slice(0, 40)}`);
  return id;
});

// 4. CONSOLE — a SEPARATE connection over the tunnel: list, read, resume, continue
console.log("[4] console: a fresh connection attaches to that session...");
const outcome = await overTunnel(async (c) => {
  await c.rpc("initialize", { clientInfo: { name: "console", version: "0" } });
  const list = await c.rpc("thread/list", {});
  const rows = list.data ?? list.threads ?? [];
  const seen = rows.some((r) => (r.id ?? r.threadId) === threadId);
  console.log(`   thread/list returned ${rows.length} sessions; worker's thread present: ${seen}`);
  const read = await c.rpc("thread/read", { threadId, includeTurns: true });
  const items = JSON.stringify(read);
  const readablePlatypus = /platypus/i.test(items);
  console.log(`   thread/read: history visible, mentions the codeword: ${readablePlatypus}`);
  await c.rpc("thread/resume", { threadId });
  await c.rpc("turn/start", { threadId, input: [{ type: "text", text: "What codeword did I ask you to remember? Reply with just the word." }] });
  await c.waitNote((n) => n.method === "turn/completed");
  const recalled = c.streamText().trim();
  console.log(`   resumed + continued — recalled: ${recalled.slice(0, 40)}`);
  return { seen, readablePlatypus, recalled };
});

// 5. teardown
await daemon.close();
tunnel.stop?.();
shim.kill("SIGTERM");

console.log("\n--- result ---");
console.log("console saw worker's session in thread/list:", outcome.seen);
console.log("console could read its history:", outcome.readablePlatypus);
console.log("console recalled after resume:", outcome.recalled);
let ok = true;
if (!outcome.seen) { console.error("FAIL: a fresh connection did not see the session over the fabric"); ok = false; }
if (!/platypus/i.test(outcome.recalled)) { console.error("FAIL: resume+continue did not recall the session"); ok = false; }
console.log(
  ok
    ? "\nPASS — a fresh client attached to an existing codex session across the fabric: listed it, read its history, resumed and continued it"
    : "\nFAILED",
);
process.exit(ok ? 0 : 1);
