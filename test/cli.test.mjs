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
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
