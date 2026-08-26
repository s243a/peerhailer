/**
 * The T3-to-T3 remote-control path, against a REAL T3 and a REAL peerhailer
 * tunnel — the regression guard behind the faked `live-remote-control.mjs`.
 *
 * It spins up a real T3 server in an isolated home, mints real `t3 pair` grants,
 * forwards the T3's origin through a real tunnel to a local port, and drives T3's
 * own remote-pairing auth chain (token → bearer → wsTicket → /ws) BOTH directly
 * and through the tunnel at a foreign Host. If the tunnel side passes, the deep
 * link `controlRemote` builds points at a backend that honours the whole chain.
 *
 * Requires a t3code checkout — set T3CODE_BIN or keep it at ~/Projects/t3code.
 * Skips (exit 0) when that is absent, so it never breaks a bare CI. Not wired
 * into CI for that reason; run it by hand:  node test/live-remote-control-real.mjs
 */
import assert from "node:assert/strict";
import net from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import hailPlugin from "../src/builtin/hailPlugin.js";
import { createTunnelPlugin } from "../src/builtin/tunnelPlugin.js";
import { callPeer } from "../src/hail.js";
import { forwardTunnel } from "../src/tunnelClient.js";

const T3_BIN = process.env.T3CODE_BIN || join(homedir(), "Projects/t3code/apps/server/src/bin.ts");
if (!existsSync(T3_BIN)) {
  console.log(`SKIP — no t3code bin at ${T3_BIN} (set T3CODE_BIN to run this).`);
  process.exit(0);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const home = mkdtempSync(join(tmpdir(), "t3-real-"));
/** @type {import("node:child_process").ChildProcess | null} */
let t3 = null;
/** @type {{ close: () => Promise<unknown> } | null} */
let fwd = null;
/** @type {{ close: () => Promise<unknown> } | null} */
let daemon = null;

const kill = (pid) => {
  try { process.kill(-pid, "SIGTERM"); } catch { try { process.kill(pid, "SIGTERM"); } catch {} }
};

async function main() {
  // 1) A real T3 in an isolated home. --dev-url set so non-web routes are wired
  //    (serving from source has no static bundle); the URL need not be reachable.
  // T3 rejects --port 0, so grab a free ephemeral port and hand it that.
  const t3Port = await new Promise((res) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => res(port)); });
  });
  t3 = spawn("node", [T3_BIN, "serve", "--host", "127.0.0.1", "--port", String(t3Port), "--no-browser", "--dev-url", "http://127.0.0.1:5173"], {
    env: { ...process.env, T3CODE_HOME: home },
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
  });
  const runtimePath = join(home, "userdata", "server-runtime.json");
  let origin = null;
  for (let i = 0; i < 60 && !origin; i++) {
    await sleep(500);
    if (existsSync(runtimePath)) {
      try { origin = JSON.parse(readFileSync(runtimePath, "utf8")).origin ?? null; } catch {}
    }
    if (t3.exitCode !== null && !origin) throw new Error("t3 exited before serving");
  }
  if (!origin) throw new Error("t3 did not report an origin");
  const { hostname, port } = new URL(origin);
  console.log(`real T3 at ${origin}`);

  // 2) Two real one-time grants (one for the direct chain, one for the tunnel).
  const mint = (label) => {
    const r = spawnSync("node", [T3_BIN, "pair", "--ttl", "15m", "--label", label], {
      env: { ...process.env, T3CODE_HOME: home }, encoding: "utf8",
    });
    const m = (r.stdout || "").match(/^Token:\s*(\S+)/m);
    if (!m) throw new Error(`could not mint a grant: ${(r.stdout || r.stderr || "").slice(0, 200)}`);
    return m[1];
  };
  const tokenDirect = mint("real-direct");
  const tokenTunnel = mint("real-tunnel");

  // 3) A real tunnel forwarding the T3 origin (HTTP+WS) to a local port.
  const me = generateIdentity();
  const caller = generateIdentity();
  const directory = createDirectory({ self: { name: "home", publicKey: me.publicKey } });
  directory.useProfiles({ p: { name: "p", allows: ["hail", "tunnel:t3"] } });
  directory.admit({ name: "caller", publicKey: caller.publicKey }, { profile: "p" });
  daemon = createDaemon({
    directory, identity: me,
    plugins: [hailPlugin, createTunnelPlugin({ endpoints: { t3: `${hostname}:${port}` } })],
  });
  const bound = await daemon.listenHail({ port: 0, hosts: ["127.0.0.1"], tls: true });
  const record = { name: "home", addresses: [{ value: `https://127.0.0.1:${bound[0].port}` }], publicKey: me.publicKey };
  const as = { name: "caller", publicKey: caller.publicKey, privateKey: caller.privateKey };
  const call = (path, body) => callPeer(record, path, body, { as });
  fwd = await forwardTunnel(call, "t3", { port: 0 });
  const tunnelBase = `http://127.0.0.1:${fwd.port}`;

  // 4) T3's own remote-pairing auth chain, direct then through the tunnel.
  await runChain("direct", origin, tokenDirect);
  await runChain("tunnel", tunnelBase, tokenTunnel);

  console.log("\nPASS — real T3 + real tunnel: the remote-pairing auth chain works directly AND through the tunnel at a foreign Host.");
}

async function runChain(label, base, pairingToken) {
  // token → bearer (OAuth token-exchange, form-encoded)
  const exch = await fetch(`${base}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: pairingToken,
      subject_token_type: "urn:t3:params:oauth:token-type:environment-bootstrap",
      requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
    }),
  });
  const exchText = await exch.text();
  assert.ok(exch.ok, `${label}: /oauth/token ${exch.status}: ${exchText.slice(0, 200)}`);
  const bearer = JSON.parse(exchText).access_token;
  assert.ok(bearer, `${label}: no access_token`);

  // bearer → short-lived ws ticket (POST)
  const tick = await fetch(`${base}/api/auth/websocket-ticket`, {
    method: "POST", headers: { authorization: `Bearer ${bearer}` },
  });
  const tickText = await tick.text();
  assert.ok(tick.ok, `${label}: /api/auth/websocket-ticket ${tick.status}: ${tickText.slice(0, 200)}`);
  const ticket = JSON.parse(tickText).ticket;
  assert.ok(ticket, `${label}: no ticket`);

  // ticket → open WebSocket
  const wsUrl = base.replace(/^http/, "ws") + "/ws?wsTicket=" + encodeURIComponent(ticket);
  await new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    const timer = setTimeout(() => { try { ws.close(); } catch {} reject(new Error(`${label}: ws did not open in 8s`)); }, 8000);
    ws.onopen = () => { clearTimeout(timer); ws.close(); resolve(); };
    ws.onerror = (e) => { clearTimeout(timer); reject(new Error(`${label}: ws error ${e?.message ?? e?.type ?? ""}`)); };
    ws.onclose = (e) => { if (e.code !== 1000 && e.code !== 1005) { clearTimeout(timer); reject(new Error(`${label}: ws closed ${e.code} ${e.reason || ""}`)); } };
  });
  console.log(`  ${label}: oauth/token ✓  websocket-ticket ✓  /ws ✓`);
}

let code = 0;
try {
  await main();
} catch (error) {
  console.error("FAIL —", error?.message ?? error);
  code = 1;
} finally {
  try { await fwd?.close(); } catch {}
  try { await daemon?.close(); } catch {}
  if (t3?.pid) kill(t3.pid);
  await sleep(500);
  try { rmSync(home, { recursive: true, force: true }); } catch {}
}
process.exit(code);
