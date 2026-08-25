/**
 * The session composer, end to end, with fakes — so it runs anywhere without a
 * real T3 or a real agent. A fake `t3 serve` writes `server-runtime.json` and
 * spawns the seeded ACP provider (as real T3 does on the first thread); a fake
 * bridge prints the supervisor-seat line (as `bridge --supervisor-mcp` does).
 * Verifies: launch reports the origin + pairing URL, the seat URL is captured
 * from the bridge's stderr, and stop tears everything down.
 *
 *   node test/live-composer.mjs
 */
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const scratch = mkdtempSync(join(tmpdir(), "composer-live-"));
const fakeBridge = join(scratch, "fake-bridge.js");
const fakeT3 = join(scratch, "fake-t3.js");

writeFileSync(
  fakeBridge,
  `process.stderr.write("[supervisor] seat open — connect a supervisor MCP client at http://127.0.0.1:55555/mcp/FAKETOKEN\\n");\nprocess.stdin.resume();\n`,
);
writeFileSync(
  fakeT3,
  `import { writeFileSync, readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";
const home = process.env.T3CODE_HOME;
mkdirSync(join(home, "userdata"), { recursive: true });
writeFileSync(join(home, "userdata", "server-runtime.json"), JSON.stringify({ origin: "http://127.0.0.1:3773" }));
console.log("Pairing URL: http://127.0.0.1:3773/pair#token=FAKEPAIR");
try {
  const cfg = JSON.parse(readFileSync(join(home, "userdata", "settings.json"), "utf8")).providerInstances.relay.config;
  spawn(cfg.command, cfg.args, { stdio: ["pipe", "pipe", "inherit"] });
} catch (e) { console.error("provider spawn failed", e.message); }
setInterval(() => {}, 1 << 30);
`,
);

process.env.MCP_ACP_BRIDGE = fakeBridge;
process.env.T3CODE_CMD = `node ${fakeT3}`;

const { createComposer } = await import("../src/composer.js");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const composer = createComposer({ gateConfig: () => null, identity: null, log: () => {} });

const info = composer.agents();
assert.ok(info.agents.includes("codex-mcp"), "agents list includes codex-mcp");
assert.equal(info.gateConfigured, false, "no gate password → gateConfigured false");

const res = await composer.launch({ agent: "codex-mcp", supervision: "mcp" });
console.log(`launched: ${res.t3Url}  pairing=${res.pairingUrl ? "yes" : "no"}`);
assert.equal(res.t3Url, "http://127.0.0.1:3773", "origin returned");
assert.match(res.pairingUrl ?? "", /FAKEPAIR/, "pairing URL captured");

let seatUrl = null;
for (let i = 0; i < 30 && !seatUrl; i++) {
  await sleep(300);
  seatUrl = composer.seat(res.launchId).seatUrl;
}
console.log(`seat url: ${seatUrl}`);
assert.match(seatUrl ?? "", /\/mcp\/FAKETOKEN$/, "supervisor seat URL captured from the bridge stderr");

const stopped = await composer.stop(res.launchId);
assert.equal(stopped.stopped, true, "stop reports success");
assert.equal(existsSync(res.seatLog), false, "temp home removed on stop");
composer.closeAll();

console.log("\nPASS — composer launched (fake T3), captured the supervisor seat URL, and tore down");
process.exit(0);
