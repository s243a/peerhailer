/**
 * Starting a declared long-running process.
 *
 * The tests that matter are the refusals and the bounds: a caller cannot name a
 * service nobody declared, cannot influence the command, cannot exhaust the
 * machine, cannot touch another peer's service — and a machine-chosen port is
 * what gets substituted, never caller text.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { capabilityFor, createServicePlugin, MAX_PER_PEER } from "../src/builtin/servicePlugin.js";
import { collectRoutes, REFUSE } from "../src/plugins.js";

const sol = { name: "sol", publicKey: "KEY-SOL" };
const mars = { name: "mars", publicKey: "KEY-MARS" };
const call = (routes, path, input) => routes.get(`POST ${path}`)?.handler({ log: () => {}, ...input });

/** A spawn stub: records the command line, returns a fake child we can drive. */
function fakeSpawn() {
  const spawned = [];
  const spawnImpl = (command) => {
    const handlers = {};
    const stdoutData = new Set();
    const on = (event, fn) => (handlers[event] ??= new Set()).add(fn);
    const child = {
      pid: 1000 + spawned.length,
      on,
      once: on,
      kill: () => {},
      emit: (event) => handlers[event]?.forEach((fn) => fn()),
      stdout: {
        on: (event, fn) => event === "data" && stdoutData.add(fn),
        off: (event, fn) => event === "data" && stdoutData.delete(fn),
      },
    };
    // `say` pushes a chunk to whoever is reading stdout — how a report-mode
    // child announces its bound port in these tests.
    spawned.push({ command, child, say: (text) => stdoutData.forEach((fn) => fn(text)) });
    return child;
  };
  return { spawnImpl, spawned };
}

const fixedPort = () => Promise.resolve(9000);

test("the machine's port is substituted, never the caller's text", async () => {
  const { spawnImpl, spawned } = fakeSpawn();
  const plugin = createServicePlugin({
    services: { agent: "bridge --listen {port} --agent claude" },
    spawnImpl,
    allocatePortImpl: fixedPort,
  });
  const routes = collectRoutes([plugin], { log: () => {} });

  const result = await call(routes, "/service/agent/start", { caller: sol });
  assert.equal(result.port, 9000, "the caller is told the chosen port");
  assert.equal(spawned[0].command, "bridge --listen 9000 --agent claude", "and it was substituted into the declared line");
  // The caller sent nothing that could reach the command.
  assert.ok(!spawned[0].command.includes("undefined"));

  plugin.stop();
});

test("a service nobody declared has no route", () => {
  const plugin = createServicePlugin({ services: { agent: "true" } });
  const routes = collectRoutes([plugin], { log: () => {} });
  assert.ok(routes.has("POST /service/agent/start"));
  assert.equal(routes.get("POST /service/database/start"), undefined);
});

test("each service carries its own capability", () => {
  const plugin = createServicePlugin({ services: { agent: "true", db: "true" } });
  const routes = collectRoutes([plugin], { log: () => {} });
  assert.equal(routes.get("POST /service/agent/start").capability, "service:agent");
  assert.equal(routes.get("POST /service/db/start").capability, "service:db");
  assert.deepEqual(plugin.capabilities.sort(), [capabilityFor("agent"), capabilityFor("db")].sort());
});

test("one peer cannot exhaust the machine, and cannot lock out another", async () => {
  const { spawnImpl } = fakeSpawn();
  let p = 9000;
  const plugin = createServicePlugin({
    services: { agent: "run {port}" },
    spawnImpl,
    allocatePortImpl: () => Promise.resolve(p++),
  });
  const routes = collectRoutes([plugin], { log: () => {} });

  const outcomes = [];
  for (let i = 0; i < MAX_PER_PEER + 2; i += 1) {
    outcomes.push(await call(routes, "/service/agent/start", { caller: sol }));
  }
  assert.equal(outcomes.filter((r) => r[REFUSE]).length, 2, "capped per peer");

  const other = await call(routes, "/service/agent/start", { caller: mars });
  assert.notEqual(other[REFUSE], true, "another peer is unaffected");
  plugin.stop();
});

test("a service belongs to the peer that started it", async () => {
  const { spawnImpl } = fakeSpawn();
  const plugin = createServicePlugin({ services: { agent: "run {port}" }, spawnImpl, allocatePortImpl: fixedPort });
  const routes = collectRoutes([plugin], { log: () => {} });

  const { id } = await call(routes, "/service/agent/start", { caller: sol });
  for (const path of ["/service/agent/stop", "/service/agent/status"]) {
    const refused = await call(routes, path, { caller: mars, body: { id } });
    assert.equal(refused[REFUSE], true, `${path} refuses a peer that does not own it`);
  }
  // Ownership is by key, so the same key spelled differently still owns it.
  const status = await call(routes, "/service/agent/status", {
    caller: { name: "sol", publicKey: "KEY-SOL\n" },
    body: { id },
  });
  assert.equal(status.running, true, "a whitespace-different spelling of the key still owns the service");
  plugin.stop();
});

test("a caller with no key cannot start anything", async () => {
  const plugin = createServicePlugin({ services: { agent: "true" }, allocatePortImpl: fixedPort });
  const routes = collectRoutes([plugin], { log: () => {} });
  const refused = await call(routes, "/service/agent/start", { caller: { name: "anon" } });
  assert.equal(refused[REFUSE], true);
});

test("a service that exits on its own leaves the table", async () => {
  const { spawnImpl, spawned } = fakeSpawn();
  const plugin = createServicePlugin({ services: { agent: "run {port}" }, spawnImpl, allocatePortImpl: fixedPort });
  const routes = collectRoutes([plugin], { log: () => {} });

  const { id } = await call(routes, "/service/agent/start", { caller: sol });
  assert.equal(call(routes, "/service/agent/status", { caller: sol, body: { id } }).running, true);

  spawned[0].child.emit("exit"); // the process dies on its own
  const gone = call(routes, "/service/agent/status", { caller: sol, body: { id } });
  assert.equal(gone[REFUSE], true, "a dead service is not a phantom the caller thinks is up");
  assert.ok(plugin.history().some((e) => e.event === "exited"));
  plugin.stop();
});

test("what was started is recorded for a person to read", async () => {
  const { spawnImpl } = fakeSpawn();
  const plugin = createServicePlugin({ services: { agent: "run {port}" }, spawnImpl, allocatePortImpl: fixedPort });
  const routes = collectRoutes([plugin], { log: () => {} });

  const { id } = await call(routes, "/service/agent/start", { caller: sol });
  await call(routes, "/service/agent/stop", { caller: sol, body: { id } });

  const events = plugin.history().map((e) => e.event);
  assert.deepEqual(events, ["started", "stopped"]);
  assert.equal(plugin.history()[0].name, "agent");
});

test("a real process is started, reachable on its port, and stopped", async () => {
  // A tiny Node listener that binds the port the machine chose.
  const plugin = createServicePlugin({
    services: { echo: `node -e "require('node:net').createServer((s)=>s.end('ok')).listen({port},'127.0.0.1')"` },
  });
  const routes = collectRoutes([plugin], { log: () => {} });
  const caller = { name: "sol", publicKey: "KEY-SOL" };

  const started = await call(routes, "/service/echo/start", { caller });
  assert.ok(started.port > 0, "a real port was allocated and returned");
  await new Promise((r) => setTimeout(r, 400)); // let node boot and bind

  // Connect to it — proof the declared process actually came up on that port.
  const { connect } = await import("node:net");
  const reached = await new Promise((resolve) => {
    const s = connect({ host: "127.0.0.1", port: started.port }, () => {});
    let got = "";
    s.on("data", (d) => (got += d));
    s.on("end", () => resolve(got));
    s.on("error", () => resolve(""));
    setTimeout(() => { s.destroy(); resolve(got); }, 1500);
  });
  assert.equal(reached, "ok", "the started service answered on its port");

  await call(routes, "/service/echo/stop", { caller, body: { id: started.id } });
  await new Promise((r) => setTimeout(r, 300));

  // After stop, nothing answers there.
  const afterStop = await new Promise((resolve) => {
    const s = connect({ host: "127.0.0.1", port: started.port }, () => { s.destroy(); resolve("still up"); });
    s.on("error", () => resolve("down"));
    setTimeout(() => { s.destroy(); resolve("down"); }, 800);
  });
  assert.equal(afterStop, "down", "stop killed the process");
  plugin.stop();
});

test("concurrent starts cannot race past the per-peer cap", async () => {
  const { spawnImpl } = fakeSpawn();
  let p = 9000;
  // A port allocator that yields the event loop, so every start reaches its
  // await before any of them registers — the exact window the cap race lived in.
  const allocatePortImpl = () => new Promise((r) => setImmediate(() => r(p++)));
  const plugin = createServicePlugin({ services: { agent: "run {port}" }, spawnImpl, allocatePortImpl });
  const routes = collectRoutes([plugin], { log: () => {} });

  const fired = Array.from({ length: MAX_PER_PEER + 4 }, () =>
    call(routes, "/service/agent/start", { caller: sol }),
  );
  const outcomes = await Promise.all(fired);

  assert.equal(outcomes.filter((r) => !r[REFUSE]).length, MAX_PER_PEER, "the cap holds even when starts race");
  assert.equal(plugin.listRunning().length, MAX_PER_PEER, "and the table reflects it, no over-admission");
  plugin.stop();
});

test("a child erroring after stop records no phantom", async () => {
  const { spawnImpl, spawned } = fakeSpawn();
  const plugin = createServicePlugin({ services: { agent: "run {port}" }, spawnImpl, allocatePortImpl: fixedPort });
  const routes = collectRoutes([plugin], { log: () => {} });

  const { id } = await call(routes, "/service/agent/start", { caller: sol });
  await call(routes, "/service/agent/stop", { caller: sol, body: { id } });
  spawned[0].child.emit("error"); // a late error from the deliberately-stopped child

  assert.deepEqual(
    plugin.history().map((e) => e.event),
    ["started", "stopped"],
    "the audit log carries no 'failed to start' phantom for a service the operator stopped",
  );
  plugin.stop();
});

test("a failed port allocation frees the reserved slot", async () => {
  const { spawnImpl } = fakeSpawn();
  const plugin = createServicePlugin({
    services: { agent: "run {port}" },
    spawnImpl,
    allocatePortImpl: () => Promise.reject(new Error("no ports")),
  });
  const routes = collectRoutes([plugin], { log: () => {} });

  const refused = await call(routes, "/service/agent/start", { caller: sol });
  assert.equal(refused[REFUSE], true, "allocation failure refuses the start");
  assert.equal(plugin.listRunning().length, 0, "and leaves no reserved ghost holding a slot");
  plugin.stop();
});

test("report mode: the caller gets the port the child announced, not an allocated one", async () => {
  const { spawnImpl, spawned } = fakeSpawn();
  const plugin = createServicePlugin({
    services: { agent: { command: "bridge --listen 0 --announce-port", reportsPort: true } },
    spawnImpl,
    // allocatePort must never be consulted in report mode; make it fail loudly.
    allocatePortImpl: () => Promise.reject(new Error("report mode must not allocate")),
  });
  const routes = collectRoutes([plugin], { log: () => {} });

  const pending = call(routes, "/service/agent/start", { caller: sol });
  assert.equal(spawned[0].command, "bridge --listen 0 --announce-port", "run verbatim — no {port} substitution");
  spawned[0].say("booting...\n"); // noise before the announcement is ignored
  spawned[0].say('{"port":54321}\n');
  const result = await pending;

  assert.equal(result.port, 54321, "the announced port is what the caller receives");
  assert.equal(plugin.listRunning()[0].port, 54321, "and what the table records");
  plugin.stop();
});

test("report mode: a child that never announces is refused, not guessed", async () => {
  const { spawnImpl } = fakeSpawn();
  const plugin = createServicePlugin({
    services: { agent: { command: "run", reportsPort: true } },
    spawnImpl,
    announceMs: 20,
  });
  const routes = collectRoutes([plugin], { log: () => {} });

  const refused = await call(routes, "/service/agent/start", { caller: sol });
  assert.equal(refused[REFUSE], true, "silence is a refusal, never a returned port");
  assert.equal(plugin.listRunning().length, 0, "and it leaves no reserved slot behind");
  assert.ok(plugin.history().some((e) => e.event === "no port announced"));
  plugin.stop();
});

test("report mode: a child that dies before announcing is refused", async () => {
  const { spawnImpl, spawned } = fakeSpawn();
  const plugin = createServicePlugin({
    services: { agent: { command: "run", reportsPort: true } },
    spawnImpl,
    announceMs: 5000,
  });
  const routes = collectRoutes([plugin], { log: () => {} });

  const pending = call(routes, "/service/agent/start", { caller: sol });
  spawned[0].child.emit("exit"); // dies before saying a port
  const refused = await pending;
  assert.equal(refused[REFUSE], true, "an early exit fails closed");
  assert.equal(plugin.listRunning().length, 0);
  plugin.stop();
});
