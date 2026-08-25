/**
 * The ACP-native path, end to end over the fabric: an agent driven through its own
 * ACP adapter (defaults to @zed-industries/codex-acp; claude-code-acp needs its
 * own login), exposed on a loopback port by
 * the acp-passthrough shim, reached across a real pinned-mutual-TLS peerhailer
 * tunnel. No bridge, no MCP gate — claude's *own* permission card is what crosses
 * the fabric, and the client answers it. The counterpart to live-codex-fabric.
 */
import { spawn } from "node:child_process";
import { mkdtempSync, existsSync, readFileSync, writeFileSync } from "node:fs";
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
const ADAPTER = process.env.ACP_ADAPTER ?? "npx -y @zed-industries/codex-acp";
const PORT = 9208;
const workspace = mkdtempSync(join(tmpdir(), "fabric-native-"));

if (!existsSync(PASSTHROUGH)) {
  console.log(`SKIP — acp-passthrough not found at ${PASSTHROUGH} (set PASSTHROUGH=... to run)`);
  process.exit(0);
}

// 1. the passthrough shim, serving claude's ACP adapter on a loopback port
const shim = spawn("node", [PASSTHROUGH, "--listen", String(PORT), "--", ...ADAPTER.split(" ")], {
  cwd: workspace,
  stdio: ["ignore", "pipe", "pipe"],
});
let slog = "";
await new Promise((res, rej) => {
  const to = setTimeout(() => rej(new Error("passthrough did not start:\n" + slog)), 15000);
  const check = (d) => {
    slog += d;
    if (/listening for ACP/.test(slog)) {
      clearTimeout(to);
      res();
    }
  };
  shim.stdout.on("data", check);
  shim.stderr.on("data", check);
});
console.log(`[1] acp-passthrough serving "${ADAPTER}" on 127.0.0.1:${PORT}`);

// 2. in-process 'home' daemon, pinned mutual TLS, one granted tunnel endpoint
const home = generateIdentity();
const caller = generateIdentity();
const directory = createDirectory({ self: { name: "home", publicKey: home.publicKey } });
directory.useProfiles({ agents: { name: "agents", allows: ["hail", "tunnel:acp-native"] } });
directory.admit({ name: "caller", publicKey: caller.publicKey }, { profile: "agents" });
const tunnel = createTunnelPlugin({ endpoints: { "acp-native": `127.0.0.1:${PORT}` } });
const daemon = createDaemon({ directory, identity: home, plugins: [hailPlugin, tunnel] });
const bound = await daemon.listenHail({ port: 0, hosts: ["127.0.0.1"], tls: true });
const daemonPort = bound[0].port;
console.log(`[2] home daemon (pinned mutual TLS) on https://127.0.0.1:${daemonPort}`);

// 3. the caller's authenticated call into home
const record = { name: "home", addresses: [{ value: `https://127.0.0.1:${daemonPort}` }], publicKey: home.publicKey };
const as = { name: "caller", publicKey: caller.publicKey, privateKey: caller.privateKey };
const call = (path, body) => callPeer(record, path, body, { as });

// 4. an ACP client on the tunnel, with the fs + permission handlers claude
//    delegates to its client — this is where its native card lands
const clientToTunnel = new PassThrough();
const tunnelToClient = new PassThrough();
const pumping = pipeTunnel(call, "acp-native", { input: clientToTunnel, output: tunnelToClient }, { pollMs: 20 });

let idc = 0;
const pending = new Map();
const permissions = [];
let chunks = [];
let buf = "";
const write = (o) => clientToTunnel.write(JSON.stringify(o) + "\n");
const reply = (id, result) => write({ jsonrpc: "2.0", id, result });
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
      if (u?.sessionUpdate === "agent_message_chunk" && u.content?.type === "text") chunks.push(u.content.text);
      continue;
    }
    if (m.method === "session/request_permission") {
      const opts = m.params?.options ?? [];
      const allow = opts.find((o) => /allow/i.test(o.kind ?? "") || /allow|yes|once/i.test(o.optionId ?? "")) ?? opts[0];
      const title = m.params?.toolCall?.title ?? m.params?.toolCall?.kind ?? "(tool)";
      permissions.push(title);
      console.log(`   [NATIVE CARD over fabric] ${title} -> ${allow?.optionId}`);
      reply(m.id, { outcome: { outcome: "selected", optionId: allow?.optionId } });
      continue;
    }
    if (m.method === "fs/read_text_file") {
      const p = m.params?.path;
      let content = "";
      try {
        content = readFileSync(p, "utf8");
      } catch {}
      reply(m.id, { content });
      continue;
    }
    if (m.method === "fs/write_text_file") {
      try {
        writeFileSync(m.params.path, m.params.content ?? "");
      } catch {}
      reply(m.id, {});
      continue;
    }
    if (m.id !== undefined && m.method) reply(m.id, {}); // anything else claude asks: answer empty
  }
});

// 5. drive claude over its native ACP, through the tunnel
await rpc("initialize", {
  protocolVersion: 1,
  clientCapabilities: { fs: { readTextFile: true, writeTextFile: true }, terminal: false },
});
const ses = await rpc("session/new", { cwd: workspace, mcpServers: [] });
const sessionId = ses.sessionId;
const ask = async (text) => {
  chunks = [];
  const t = Date.now();
  const r = await rpc("session/prompt", { sessionId, prompt: [{ type: "text", text }] });
  return { text: chunks.join("").trim(), ms: Date.now() - t, stop: r?.stopReason };
};
console.log("[3] driving the agent over its native ACP, through the tunnel...");
const first = await ask("Create a file named codeword.txt in the current directory containing exactly PLATYPUS. Then reply with exactly: STORED");
console.log(`   turn 1 (${first.ms}ms): ${first.text.slice(0, 100)}`);
const second = await ask("Read codeword.txt and reply with just the codeword.");
console.log(`   turn 2 (${second.ms}ms): ${second.text.slice(0, 100)}`);

// 6. teardown
clientToTunnel.end();
await pumping.catch(() => {});
await daemon.close();
tunnel.stop?.();
shim.kill("SIGTERM");

const wrote = existsSync(join(workspace, "codeword.txt")) ? readFileSync(join(workspace, "codeword.txt"), "utf8").trim() : "(missing)";
console.log("\n--- result ---");
console.log("native cards over fabric:", permissions.length);
console.log("codeword.txt:", wrote);
console.log("turn 2 recall:", second.text);
let ok = true;
if (permissions.length === 0) console.error("NOTE: no native card surfaced (the adapter auto-allowed under its own default policy)");
if (!/platypus/i.test(wrote)) { console.error("FAIL: the file was not written through native ACP fs"); ok = false; }
if (!/platypus/i.test(second.text)) { console.error("FAIL: no multi-turn recall over native ACP"); ok = false; }
console.log(
  ok
    ? "\nPASS — an agent driven end to end over peerhailer via its NATIVE ACP adapter (no bridge, no MCP gate): the native path crossed the fabric, file written, multi-turn held"
    : "\nFAILED",
);
process.exit(ok ? 0 : 1);
