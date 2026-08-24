/**
 * A shell a peer can open.
 *
 * The tests that matter: the capability gates it, the spawn environment is
 * scrubbed so no secret leaks into a process a peer types into, bytes move both
 * ways, idle means *no bytes* (not "stopped polling"), and a session's existence
 * is recorded even though its bytes are not.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  capabilityFor,
  createShellPlugin,
  scrubEnv,
  MAX_SHELLS,
  IDLE_MS,
} from "../src/builtin/shellPlugin.js";
import { collectRoutes, REFUSE } from "../src/plugins.js";

const sol = { name: "sol", publicKey: "KEY-SOL" };
const mars = { name: "mars", publicKey: "KEY-MARS" };
const call = (routes, path, input) => routes.get(`POST ${path}`)?.handler({ log: () => {}, ...input });

/** A spawn stub: records the command, opts (env!), and a drivable child. */
function fakeSpawn() {
  const spawned = [];
  const spawnImpl = (command, opts) => {
    const handlers = {};
    const out = { stdout: new Set(), stderr: new Set() };
    const stdinWrites = [];
    const on = (event, fn) => (handlers[event] ??= new Set()).add(fn);
    const child = {
      pid: 2000 + spawned.length,
      on,
      kill: () => {},
      emit: (event) => handlers[event]?.forEach((fn) => fn()),
      stdin: { write: (buf) => stdinWrites.push(buf) },
      stdout: { on: (e, fn) => e === "data" && out.stdout.add(fn) },
      stderr: { on: (e, fn) => e === "data" && out.stderr.add(fn) },
    };
    spawned.push({
      command,
      opts,
      child,
      stdinWrites,
      say: (text, which = "stdout") => out[which].forEach((fn) => fn(Buffer.from(text))),
    });
    return child;
  };
  return { spawnImpl, spawned };
}

test("scrubEnv keeps benign vars and drops everything else, secrets included", () => {
  const env = scrubEnv({
    PATH: "/bin",
    HOME: "/home/x",
    LC_ALL: "C",
    PEERHAILER_CONTROL: "127.0.0.1:9999",
    HAIL_TOKEN: "s3cr3t",
    AWS_SECRET_ACCESS_KEY: "nope",
  });
  assert.deepEqual(env, { PATH: "/bin", HOME: "/home/x", LC_ALL: "C" });
  assert.ok(!("PEERHAILER_CONTROL" in env), "no control-port address reaches the shell");
  assert.ok(!("HAIL_TOKEN" in env), "no auth material reaches the shell");
});

test("scrubEnv preserves the Termux exec shim, but no other LD_PRELOAD", () => {
  const shim = "/data/data/com.termux/files/usr/lib/libtermux-exec.so";
  // Without this, `shell: true` on Termux exits 126 the instant a shell opens.
  assert.equal(scrubEnv({ PATH: "/b", LD_PRELOAD: shim }).LD_PRELOAD, shim, "the shim is kept, matched by name");
  // But it stays an allowlist — an arbitrary preload is not a way to inject a .so.
  assert.ok(!("LD_PRELOAD" in scrubEnv({ PATH: "/b", LD_PRELOAD: "/tmp/evil.so" })), "a foreign LD_PRELOAD is dropped");
  assert.ok(!("LD_PRELOAD" in scrubEnv({ PATH: "/b" })), "absent off Termux");
});

test("the shell is spawned with the scrubbed env and its own process group", () => {
  const { spawnImpl, spawned } = fakeSpawn();
  const plugin = createShellPlugin({ shells: { bash: "bash" }, spawnImpl, spawnEnv: { PATH: "/usr/bin" } });
  const routes = collectRoutes([plugin], { log: () => {} });

  call(routes, "/shell/bash/open", { caller: sol });
  assert.deepEqual(spawned[0].opts.env, { PATH: "/usr/bin" }, "exactly the env we were given, nothing inherited");
  assert.equal(spawned[0].opts.detached, true, "its own group, so the whole tree is killable");
  assert.equal(spawned[0].command, "bash");
  plugin.stop();
});

test("a shell nobody declared has no route, and each carries its own capability", () => {
  const plugin = createShellPlugin({ shells: { admin: "bash", sandboxed: "firejail bash" } });
  const routes = collectRoutes([plugin], { log: () => {} });
  assert.ok(routes.has("POST /shell/admin/open"));
  assert.equal(routes.get("POST /shell/database/open"), undefined);
  assert.equal(routes.get("POST /shell/admin/open").capability, "shell:admin");
  assert.equal(routes.get("POST /shell/sandboxed/open").capability, "shell:sandboxed");
  assert.equal(plugin.requiresEncryptedArrival, true, "the host is told these need an encrypted arrival");
});

test("a caller with no key cannot open a shell", () => {
  const plugin = createShellPlugin({ shells: { bash: "bash" } });
  const routes = collectRoutes([plugin], { log: () => {} });
  const refused = call(routes, "/shell/bash/open", { caller: { name: "anon" } });
  assert.equal(refused[REFUSE], true);
});

test("one shell per peer, and one peer cannot lock out another", () => {
  const { spawnImpl } = fakeSpawn();
  const plugin = createShellPlugin({ shells: { bash: "bash" }, spawnImpl });
  const routes = collectRoutes([plugin], { log: () => {} });

  assert.ok(call(routes, "/shell/bash/open", { caller: sol }).id, "first shell opens");
  assert.equal(call(routes, "/shell/bash/open", { caller: sol })[REFUSE], true, "a second for the same peer is refused");
  assert.ok(call(routes, "/shell/bash/open", { caller: mars }).id, "another peer is unaffected");
  plugin.stop();
});

test("the machine holds no more than MAX_SHELLS across all peers", () => {
  const { spawnImpl } = fakeSpawn();
  const plugin = createShellPlugin({ shells: { bash: "bash" }, spawnImpl });
  const routes = collectRoutes([plugin], { log: () => {} });

  for (let i = 0; i < MAX_SHELLS; i += 1) {
    assert.ok(call(routes, "/shell/bash/open", { caller: { name: `p${i}`, publicKey: `KEY-${i}` } }).id);
  }
  const over = call(routes, "/shell/bash/open", { caller: { name: "extra", publicKey: "KEY-EXTRA" } });
  assert.equal(over[REFUSE], true, "past the cap the machine refuses");
  plugin.stop();
});

test("a shell belongs to the peer that opened it", () => {
  const { spawnImpl } = fakeSpawn();
  const plugin = createShellPlugin({ shells: { bash: "bash" }, spawnImpl });
  const routes = collectRoutes([plugin], { log: () => {} });

  const { id } = call(routes, "/shell/bash/open", { caller: sol });
  for (const path of ["/shell/bash/send", "/shell/bash/poll", "/shell/bash/close"]) {
    assert.equal(call(routes, path, { caller: mars, body: { id } })[REFUSE], true, `${path} refuses a non-owner`);
  }
  // Ownership is by key, so a whitespace-different spelling still owns it.
  const polled = call(routes, "/shell/bash/poll", { caller: { name: "sol", publicKey: "KEY-SOL\n" }, body: { id } });
  assert.equal(polled.closed, false, "the same key spelled differently still owns the shell");
  plugin.stop();
});

test("bytes move both ways: send reaches stdin, output comes back on poll", () => {
  const { spawnImpl, spawned } = fakeSpawn();
  const plugin = createShellPlugin({ shells: { bash: "bash" }, spawnImpl });
  const routes = collectRoutes([plugin], { log: () => {} });

  const { id } = call(routes, "/shell/bash/open", { caller: sol });
  call(routes, "/shell/bash/send", { caller: sol, body: { id, data: Buffer.from("ls -la\n").toString("base64") } });
  assert.equal(spawned[0].stdinWrites[0].toString(), "ls -la\n", "the caller's keystrokes reached the shell's stdin");

  spawned[0].say("total 0\n", "stdout");
  spawned[0].say("permission denied\n", "stderr");
  const polled = call(routes, "/shell/bash/poll", { caller: sol, body: { id } });
  const text = Buffer.from(polled.data, "base64").toString();
  assert.ok(text.includes("total 0") && text.includes("permission denied"), "stdout and stderr both come back, merged");
  plugin.stop();
});

test("idle means no bytes either way — a poll is not activity", () => {
  let t = 1000;
  const { spawnImpl } = fakeSpawn();
  const plugin = createShellPlugin({ shells: { bash: "bash" }, spawnImpl, now: () => t });
  const routes = collectRoutes([plugin], { log: () => {} });

  const { id } = call(routes, "/shell/bash/open", { caller: sol });
  // Poll repeatedly while time advances — draining nothing is not activity.
  t += IDLE_MS / 2;
  call(routes, "/shell/bash/poll", { caller: sol, body: { id } });
  t += IDLE_MS / 2 + 1; // now past IDLE_MS since the last actual byte (open)
  // A second peer opening triggers reap.
  call(routes, "/shell/bash/open", { caller: mars });

  assert.equal(plugin.listOpen().some((s) => sameName(s, "sol")), false, "the idle shell was reaped despite the polls");
  assert.ok(plugin.history().some((e) => e.event === "closed: idle"));
  plugin.stop();
});

function sameName(entry, name) {
  return entry.peerKey === (name === "sol" ? "KEY-SOL" : "KEY-MARS");
}

test("output keeps a shell alive across the idle window", () => {
  let t = 1000;
  const { spawnImpl, spawned } = fakeSpawn();
  const plugin = createShellPlugin({ shells: { bash: "bash" }, spawnImpl, now: () => t });
  const routes = collectRoutes([plugin], { log: () => {} });

  call(routes, "/shell/bash/open", { caller: sol });
  t += IDLE_MS - 10;
  spawned[0].say("still working...\n"); // a byte out, resetting the idle clock
  t += 20; // only 30ms past the last byte, well within the window
  call(routes, "/shell/bash/open", { caller: mars }); // trigger reap

  assert.equal(plugin.listOpen().length, 2, "the busy shell survived; output is activity");
  plugin.stop();
});

test("closing kills the shell and records the session, exit leaves the table", () => {
  const { spawnImpl, spawned } = fakeSpawn();
  const plugin = createShellPlugin({ shells: { bash: "bash" }, spawnImpl });
  const routes = collectRoutes([plugin], { log: () => {} });

  const first = call(routes, "/shell/bash/open", { caller: sol });
  call(routes, "/shell/bash/close", { caller: sol, body: { id: first.id } });
  assert.equal(plugin.listOpen().length, 0, "a closed shell leaves the table");

  const second = call(routes, "/shell/bash/open", { caller: sol });
  spawned[1].child.emit("exit"); // the shell exits on its own
  assert.equal(call(routes, "/shell/bash/poll", { caller: sol, body: { id: second.id } })[REFUSE], true, "an exited shell is gone");

  const events = plugin.history().map((e) => e.event);
  assert.deepEqual(events, ["opened", "closed", "opened", "closed: exited"]);
  assert.ok(plugin.history().every((e) => !("data" in e)), "the record holds session existence, never the bytes");
  plugin.stop();
});

test("a shell that floods output past the buffer is closed, not a memory leak", () => {
  const { spawnImpl, spawned } = fakeSpawn();
  const plugin = createShellPlugin({ shells: { bash: "bash" }, spawnImpl });
  const routes = collectRoutes([plugin], { log: () => {} });

  const { id } = call(routes, "/shell/bash/open", { caller: sol });
  spawned[0].say(Buffer.alloc(1024 * 1024 + 1)); // more than MAX_BUFFERED at once
  const polled = call(routes, "/shell/bash/poll", { caller: sol, body: { id } });
  assert.equal(polled.closed, true);
  assert.match(polled.error, /more output than the session will hold/);
  assert.ok(
    plugin.history().some((e) => e.event === "closed: output limit"),
    "the audit log records why it closed, not a generic exit",
  );
  plugin.stop();
});
