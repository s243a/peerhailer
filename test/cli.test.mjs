/**
 * The command line, run as a person runs it.
 *
 * Everything else here imports `src/`, which meant `bin/hail.js` could be — and
 * for several commits was — syntactically invalid while the whole suite passed.
 * A help string with a newline inside it broke every command, and nothing
 * noticed until someone typed one.
 *
 * These are smoke tests. They do not check behaviour that unit tests cover;
 * they check that the entry point loads and that the commands a person reaches
 * for first actually run.
 */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const CLI = fileURLToPath(new URL("../bin/hail.js", import.meta.url));

/** @param {string[]} args */
async function hail(state, args) {
  try {
    const { stdout, stderr } = await run(process.execPath, [CLI, "--state", state, ...args]);
    return { code: 0, out: stdout + stderr };
  } catch (error) {
    return { code: error.code ?? 1, out: `${error.stdout ?? ""}${error.stderr ?? ""}` };
  }
}

test("the CLI loads and its common commands run", async () => {
  const dir = mkdtempSync(join(tmpdir(), "peerhailer-cli-"));
  const state = join(dir, "directory.json");

  try {
    // Parsing the file at all is the thing that was broken.
    const help = await hail(state, ["--help"]);
    assert.match(help.out, /peer presence and discovery/);

    assert.equal((await hail(state, ["name", "host"])).code, 0);
    assert.match((await hail(state, ["status"])).out, /name:\s+host/);
    assert.match((await hail(state, ["id"])).out, /BEGIN PUBLIC KEY/);

    // Define a profile, assign it, raise it, and see the raise reported.
    assert.equal((await hail(state, ["profiles", "add", "phone", "--allows", "hail,directory"])).code, 0);
    assert.equal((await hail(state, ["add", "myphone", "--profile", "phone"])).code, 0);
    assert.equal((await hail(state, ["add", "myphone", "--profile", "operator", "--until", "2h"])).code, 0);

    const peers = await hail(state, ["peers"]);
    assert.match(peers.out, /myphone/);
    assert.match(peers.out, /operator until/, "an elevation is visible where profiles are read");

    // And the ways these go wrong are said out loud rather than ignored.
    assert.notEqual((await hail(state, ["add", "x", "--profile", "phone", "--until", "soonish"])).code, 0);
    assert.notEqual((await hail(state, ["add", "y", "--until", "2h"])).code, 0);
    assert.notEqual((await hail(state, ["profiles", "add", "trusted", "--allows", "hail"])).code, 0);
    assert.notEqual((await hail(state, ["add", "z", "--key", ""])).code, 0);

    // A security-posture boolean flag that swallowed a value must fail loudly,
    // not silently disable itself: `--require-target-binding yes` reads as the
    // string "yes", which is `!== true`, so without the guard the operator would
    // believe they closed the door and left it open.
    const trap = await hail(state, ["daemon", "--require-target-binding", "yes"]);
    assert.notEqual(trap.code, 0, "a value on the bare flag is refused, not quietly ignored");
    assert.match(trap.out, /takes no value/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the page is off by default, and says so", async () => {
  const dir = mkdtempSync(join(tmpdir(), "peerhailer-ui-"));
  const state = join(dir, "directory.json");
  await hail(state, ["name", "host"]);

  /** Run the daemon briefly and collect what it said on the way up. */
  const boot = (args) =>
    new Promise((resolve) => {
      const child = execFile(process.execPath, [CLI, "--state", state, ...args], () => {});
      let out = "";
      child.stdout?.on("data", (chunk) => (out += chunk));
      child.stderr?.on("data", (chunk) => (out += chunk));
      setTimeout(() => {
        child.kill();
        resolve(out);
      }, 1500);
    });

  try {
    // The control listener exists only for the page — the CLI reads the state
    // file directly — so no page means no port a browser can reach at all.
    const quiet = await boot(["daemon", "--port", "0"]);
    assert.match(quiet, /not served/, "the default is off");
    assert.match(quiet, /--ui/, "and says how to turn it on, or nobody finds it");
    assert.doesNotMatch(quiet, /^\[ui\] http/m, "nothing is bound for it");

    const withUi = await boot(["daemon", "--port", "0", "--ui"]);
    assert.match(withUi, /\[ui\] http:\/\/127\.0\.0\.1:/, "asked for, and served");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a daemon boots with a tunnel declared — the port-in-TDZ crash stays fixed", async () => {
  // The tunnel plugin refuses a tunnel to the daemon's own port, so it reads
  // `--port` while the plugin list is built. That declaration used to come
  // *after* the list, so a configured tunnel crashed startup with
  // "Cannot access 'port' before initialization". Only tunnels trip it.
  const dir = mkdtempSync(join(tmpdir(), "peerhailer-tun-"));
  const state = join(dir, "directory.json");
  await hail(state, ["name", "host"]);
  await hail(state, ["tunnels", "add", "acp", "127.0.0.1:9100"]);
  const boot = () =>
    new Promise((resolve) => {
      const child = execFile(process.execPath, [CLI, "--state", state, "daemon", "--port", "0", "--hail-on", "127.0.0.1"], () => {});
      let out = "";
      child.stdout?.on("data", (c) => (out += c));
      child.stderr?.on("data", (c) => (out += c));
      setTimeout(() => {
        child.kill();
        resolve(out);
      }, 1500);
    });
  try {
    const out = await boot();
    assert.doesNotMatch(out, /Cannot access 'port'|ReferenceError/, "the plugin list no longer reaches port in its TDZ");
    assert.match(out, /\[tunnel\] acp/, "the tunnel loaded and the daemon came up");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
