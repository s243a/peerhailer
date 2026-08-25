/**
 * Watch and steer another client's live codex turn, across the fabric.
 *
 * The hardest variant of the visibility idea: not just resuming a finished
 * session, but reaching into one that is running *right now* and redirecting it.
 * Two connections come in over the same peerhailer tunnel to a shared
 * `codex app-server` (mcp-acp-bridge's appserver-hub). The WORKER starts a long
 * turn; the STEERER — which never started it — sees the live thread/turn on the
 * broadcast stream and sends turn/steer. The worker's output changes course.
 *
 * Shared process via the hub, because codex's own managed daemon needs the
 * standalone installer and an undocumented socket handshake. The steer primitive
 * and the sharing are the point; the tunnel is the same one every other endpoint
 * rides.
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
const HUB = process.env.HUB ?? resolve(here, "../../mcp-acp-bridge/bin/appserver-hub.js");
const CODEX = process.env.CODEX ?? join(process.env.HOME, ".local/bin/codex");
const PORT = 9212;
const workspace = mkdtempSync(join(tmpdir(), "fabric-steer-"));

if (!existsSync(HUB) || !existsSync(CODEX)) {
  console.log(`SKIP — need appserver-hub (${HUB}) and standalone codex (${CODEX})`);
  process.exit(0);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 1. one shared `codex app-server`, fronted by the hub on a loopback port
const hub = spawn("node", [HUB, "--listen", String(PORT), "--", CODEX, "app-server"], { cwd: workspace, stdio: ["ignore", "pipe", "pipe"] });
await new Promise((res, rej) => {
  let l = "";
  const t = setTimeout(() => rej(new Error("hub did not start:\n" + l)), 10000);
  const c = (d) => ((l += d), /clients on/.test(l) && (clearTimeout(t), res()));
  hub.stdout.on("data", c);
  hub.stderr.on("data", c);
});
console.log(`[1] appserver-hub sharing one codex app-server on 127.0.0.1:${PORT}`);

// 2. in-process home daemon, pinned mutual TLS, one granted tunnel endpoint
const home = generateIdentity();
const caller = generateIdentity();
const directory = createDirectory({ self: { name: "home", publicKey: home.publicKey } });
directory.useProfiles({ agents: { name: "agents", allows: ["hail", "tunnel:codex-hub"] } });
directory.admit({ name: "caller", publicKey: caller.publicKey }, { profile: "agents" });
const tunnel = createTunnelPlugin({ endpoints: { "codex-hub": `127.0.0.1:${PORT}` } });
const daemon = createDaemon({ directory, identity: home, plugins: [hailPlugin, tunnel] });
const bound = await daemon.listenHail({ port: 0, hosts: ["127.0.0.1"], tls: true });
console.log(`[2] home daemon (pinned mutual TLS) on https://127.0.0.1:${bound[0].port}`);

const record = { name: "home", addresses: [{ value: `https://127.0.0.1:${bound[0].port}` }], publicKey: home.publicKey };
const as = { name: "caller", publicKey: caller.publicKey, privateKey: caller.privateKey };
const call = (path, body) => callPeer(record, path, body, { as });

// A persistent connection over the tunnel (stays open — worker and steerer run at once)
function connect() {
  const toT = new PassThrough();
  const fromT = new PassThrough();
  const pumping = pipeTunnel(call, "codex-hub", { input: toT, output: fromT }, { pollMs: 20 });
  let idc = 0;
  const pending = new Map();
  const notes = [];
  let buf = "";
  const rpc = (method, params) =>
    new Promise((resolve) => {
      const id = ++idc;
      pending.set(id, resolve);
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
      try { m = JSON.parse(line); } catch { continue; }
      if (m.id !== undefined && m.method === undefined) {
        const r = pending.get(m.id);
        if (r) { pending.delete(m.id); r(m.result); }
      } else if (m.method) notes.push(m);
    }
  });
  const deltas = () => notes.filter((n) => n.method === "item/agentMessage/delta");
  const text = () => deltas().map((n) => n.params?.delta ?? "").join("");
  return { rpc, notes, deltas, text, close: () => { toT.end(); return pumping.catch(() => {}); } };
}

await sleep(600); // let the hub's initialize settle
console.log("[3] worker (over the tunnel) starts a long turn...");
const worker = connect();
const th = await worker.rpc("thread/start", { cwd: workspace, approvalPolicy: "never", sandbox: "read-only" });
const threadId = th.thread?.id;
worker.rpc("turn/start", { threadId, input: [{ type: "text", text: "Write the numbers 1 to 90, one per line, each with a brief note. Output steadily." }] });

console.log("[4] steerer (a SECOND tunnel connection) attaches and steers the live turn...");
const steerer = connect();
let live = null;
for (let k = 0; k < 60 && !live; k++) {
  await sleep(300);
  const d = steerer.deltas()[0];
  if (d) live = { threadId: d.params.threadId, turnId: d.params.turnId };
}
console.log(`   steerer saw the live turn on the broadcast stream: ${JSON.stringify(live)}`);
const mark = steerer.text().length;
await steerer.rpc("turn/steer", { threadId: live.threadId, expectedTurnId: live.turnId, input: [{ type: "text", text: "New instruction: stop the number list and reply with only the word: MANGO" }] });
console.log("   steerer sent turn/steer");
for (let k = 0; k < 40 && !/mango/i.test(steerer.text().slice(mark)); k++) await sleep(500);
const changed = /mango/i.test(steerer.text().slice(mark));

// teardown
await worker.close();
await steerer.close();
await daemon.close();
tunnel.stop?.();
hub.kill("SIGTERM");

console.log("\n--- result ---");
console.log("steerer saw the worker's live turn:", !!live);
console.log("steer redirected the worker's output:", changed);
console.log("worker stream tail:", worker.text().slice(-90).replace(/\n/g, " "));
const ok = !!live && changed;
console.log(
  ok
    ? "\nPASS — over the fabric, a second connection watched another client's live codex turn and steered it (MANGO)"
    : "\nFAILED",
);
process.exit(ok ? 0 : 1);
