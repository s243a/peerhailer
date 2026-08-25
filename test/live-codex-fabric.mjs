/**
 * Prove codex-mcp end to end over the whole peerhailer fabric, on one machine:
 * a real pinned-mutual-TLS daemon, a granted tunnel endpoint, and an ACP client
 * driving codex through it. The loopback stand-in for "Puppy is down" — same
 * path, same auth, same tunnel, just both ends here.
 */
import { spawn } from "node:child_process";
import { mkdtempSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import hailPlugin from "../src/builtin/hailPlugin.js";
import { createTunnelPlugin } from "../src/builtin/tunnelPlugin.js";
import { callPeer } from "../src/hail.js";
import { pipeTunnel } from "../src/tunnelClient.js";

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
// Cross-repo live test: needs the mcp-acp-bridge sibling and an authed `codex`.
// Point BRIDGE elsewhere, or it defaults to ../mcp-acp-bridge next to this repo.
const here = dirname(fileURLToPath(import.meta.url));
const BRIDGE = process.env.BRIDGE ?? resolve(here, "../../mcp-acp-bridge/bin/bridge.js");
const PORT = 9207;
const workspace = mkdtempSync(join(tmpdir(), "fabric-codex-"));

if (!existsSync(BRIDGE)) {
  console.log(`SKIP — mcp-acp-bridge not found at ${BRIDGE} (set BRIDGE=... to run this cross-repo proof)`);
  process.exit(0);
}

// 1. codex-mcp bridge as an ACP listener on a loopback port
const bridge = spawn(
  "node",
  [BRIDGE, "--agent", "codex-mcp", "--codex-approval", "untrusted", "--listen", String(PORT)],
  { cwd: workspace, stdio: ["ignore", "pipe", "pipe"] },
);
let blog = "";
await new Promise((res, rej) => {
  const to = setTimeout(() => rej(new Error("bridge did not start:\n" + blog)), 15000);
  const check = (d) => {
    blog += d;
    if (/listening for ACP/.test(blog)) {
      clearTimeout(to);
      res();
    }
  };
  bridge.stdout.on("data", check);
  bridge.stderr.on("data", check);
});
console.log(`[1] codex-mcp bridge listening on 127.0.0.1:${PORT}`);

// 2. an in-process 'home' daemon: pinned mutual TLS, one granted tunnel endpoint
const home = generateIdentity();
const caller = generateIdentity();
const directory = createDirectory({ self: { name: "home", publicKey: home.publicKey } });
directory.useProfiles({ agents: { name: "agents", allows: ["hail", "tunnel:acp-codex-mcp"] } });
directory.admit({ name: "caller", publicKey: caller.publicKey }, { profile: "agents" });
const tunnel = createTunnelPlugin({ endpoints: { "acp-codex-mcp": `127.0.0.1:${PORT}` } });
const daemon = createDaemon({ directory, identity: home, plugins: [hailPlugin, tunnel] });
const bound = await daemon.listenHail({ port: 0, hosts: ["127.0.0.1"], tls: true });
const daemonPort = bound[0].port;
console.log(`[2] home daemon (pinned mutual TLS) on https://127.0.0.1:${daemonPort}`);

// 3. the caller's authenticated call into home (its key + client cert)
const record = { name: "home", addresses: [{ value: `https://127.0.0.1:${daemonPort}` }], publicKey: home.publicKey };
const as = { name: "caller", publicKey: caller.publicKey, privateKey: caller.privateKey };
const call = (path, body) => callPeer(record, path, body, { as });

// 4. an ACP client attached to the tunnel through two PassThroughs
const clientToTunnel = new PassThrough();
const tunnelToClient = new PassThrough();
const pumping = pipeTunnel(call, "acp-codex-mcp", { input: clientToTunnel, output: tunnelToClient }, { pollMs: 20 });

let idc = 0;
const pending = new Map();
const permissions = [];
let chunks = [];
let buf = "";
const write = (o) => clientToTunnel.write(JSON.stringify(o) + "\n");
const rpc = (method, params) =>
  new Promise((resolve) => {
    const id = ++idc;
    pending.set(id, resolve);
    write({ jsonrpc: "2.0", id, method, params });
  });
tunnelToClient.on("data", (d) => {
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
      const r = pending.get(m.id);
      if (r) {
        pending.delete(m.id);
        r(m.result);
      }
      continue;
    }
    if (m.method === "session/update") {
      const u = m.params?.update;
      if (u?.sessionUpdate === "agent_message_chunk") chunks.push(u.content.text);
      continue;
    }
    if (m.method === "session/request_permission") {
      const title = m.params?.toolCall?.title ?? "";
      permissions.push(title);
      console.log(`   [CARD over fabric] ${title}`);
      write({ jsonrpc: "2.0", id: m.id, result: { outcome: { outcome: "selected", optionId: "allow-once" } } });
      continue;
    }
    if (m.id !== undefined && m.method) write({ jsonrpc: "2.0", id: m.id, result: {} });
  }
});

// 5. drive the conversation through the fabric
await rpc("initialize", { protocolVersion: 1 });
const ses = await rpc("session/new", { cwd: workspace });
const sessionId = ses.sessionId;
const ask = async (text) => {
  chunks = [];
  const t = Date.now();
  const r = await rpc("session/prompt", { sessionId, prompt: [{ type: "text", text }] });
  return { text: chunks.join("").trim(), ms: Date.now() - t, stop: r?.stopReason };
};
console.log("[3] driving codex over the tunnel...");
const first = await ask("Use your shell to create a file named codeword.txt containing exactly PLATYPUS, then reply exactly: STORED");
console.log(`   turn 1 (${first.ms}ms): ${first.text.slice(0, 80)}`);
const second = await ask("Read codeword.txt and reply with just the codeword.");
console.log(`   turn 2 (${second.ms}ms): ${second.text.slice(0, 80)}`);

// 6. teardown
clientToTunnel.end();
await pumping.catch(() => {});
await daemon.close();
tunnel.stop?.();
bridge.kill("SIGTERM");

const wrote = existsSync(join(workspace, "codeword.txt")) ? readFileSync(join(workspace, "codeword.txt"), "utf8").trim() : "(missing)";
console.log("\n--- result ---");
console.log("cards crossed the fabric:", permissions.length);
console.log("codeword.txt:", wrote);
console.log("turn 2 recall:", second.text);
let ok = true;
if (permissions.length === 0) { console.error("FAIL: no card crossed the fabric — the gate did not round-trip"); ok = false; }
if (!/platypus/i.test(wrote)) { console.error("FAIL: the allowed command did not run"); ok = false; }
if (!/platypus/i.test(second.text)) { console.error("FAIL: no multi-turn recall"); ok = false; }
console.log(
  ok
    ? "\nPASS — codex-mcp end to end over peerhailer (pinned mutual TLS + tunnel + ACP): the gate card crossed the fabric, an allow ran the command, multi-turn held"
    : "\nFAILED",
);
process.exit(ok ? 0 : 1);
