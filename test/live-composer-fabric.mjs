/**
 * The composer's remote (fabric) path, with fakes — no real T3, peer, or agent.
 * A fake `fabric` stands in for the peer wire (listNodes/startRemote/stopRemote +
 * a tunnel-pipe command); a fake `t3 serve` writes its runtime file and spawns the
 * seeded provider. Verifies that a remote launch: starts the worker service on the
 * chosen node, points T3's ACP provider at `hail tunnel <node> <tunnel> pipe`,
 * forces supervision off (no remote MCP seat yet), and stops the remote service on
 * teardown.
 *
 *   node test/live-composer-fabric.mjs
 */
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const fakeT3 = mkdtempSync(join(tmpdir(), "cf-")) + "/t3.mjs";
writeFileSync(
  fakeT3,
  `import { writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";
const h = process.env.T3CODE_HOME;
mkdirSync(join(h, "userdata"), { recursive: true });
writeFileSync(join(h, "userdata", "server-runtime.json"), JSON.stringify({ origin: "http://127.0.0.1:3773" }));
console.log("Pairing URL: http://127.0.0.1:3773/pair#t");
try { const c = JSON.parse(readFileSync(join(h, "userdata", "settings.json"), "utf8")).providerInstances.relay.config; spawn(c.command, c.args, { stdio: ["ignore", "inherit", "inherit"] }); } catch {}
setInterval(() => {}, 1 << 30);
`,
);
process.env.T3CODE_CMD = `node ${fakeT3}`;
process.env.MCP_ACP_BRIDGE = "/tmp/should-not-be-used-for-remote.js";

const { createComposer } = await import("../src/composer.js");

const calls = [];
const fabric = {
  tunnelPipeCommand: (peer, tunnel) => ({ command: "echo", args: ["tunnel", peer, tunnel, "pipe"] }),
  startRemote: async (peer, service) => (calls.push(["start", peer, service]), { ok: true, response: { id: "svc-abc", name: service, port: 9102 } }),
  stopRemote: async (peer, service, id) => (calls.push(["stop", peer, service, id]), { ok: true, response: { stopped: true } }),
  listNodes: async () => ({
    self: "me",
    nodes: [{ peer: "puppy", reachable: true, offers: [{ service: "agy-worker", label: "Gemini", agent: "agy", role: "worker", tunnel: "agy-worker" }] }],
  }),
};
const composer = createComposer({ gateConfig: () => null, identity: null, log: () => {}, fabric });

assert.equal(composer.agents().remote, true, "remote is advertised when fabric is present");
const nodes = await composer.nodes();
assert.equal(nodes.self, "me");
assert.equal(nodes.nodes[0].offers[0].service, "agy-worker");

const res = await composer.launch({ node: "puppy", service: "agy-worker", tunnel: "agy-worker", supervision: "mcp" });
assert.equal(res.node, "puppy");
assert.equal(res.supervision, "none", "remote supervision is forced off in v1");

const home = res.seatLog.replace(/\/seat\.log$/, "");
const cfg = JSON.parse(readFileSync(join(home, "userdata", "settings.json"), "utf8")).providerInstances.relay.config;
assert.equal(cfg.command, "echo");
assert.equal(cfg.args.join(" "), "tunnel puppy agy-worker pipe", "T3 provider points at the tunnel pipe");
assert.deepEqual(
  calls.find((c) => c[0] === "start"),
  ["start", "puppy", "agy-worker"],
  "the worker service was started on the node",
);

await composer.stop(res.launchId);
assert.deepEqual(
  calls.find((c) => c[0] === "stop"),
  ["stop", "puppy", "agy-worker", "svc-abc"],
  "the remote service was stopped on teardown",
);

console.log("PASS — remote launch: started the service, relayed T3 through the tunnel, supervision off, stopped remotely");
process.exit(0);
