/**
 * The shell, end to end: a real daemon, a real `sh`, a real socket.
 *
 * The plugin and client are unit-tested against fakes; this proves the two halves
 * meet — a peer authenticates, the capability admits it, a shell spawns, bytes
 * cross the wire both ways, and a session held by id survives across calls. This
 * is the path an agent troubleshooting a remote machine actually walks.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import hailPlugin from "../src/builtin/hailPlugin.js";
import { createShellPlugin } from "../src/builtin/shellPlugin.js";
import { callPeer } from "../src/hail.js";
import { openShell, sendShell, pollShell, closeShell, execShell } from "../src/shellClient.js";

/** Boot a daemon that offers `shell:sh`, and a caller admitted to use it. */
async function bootShellDaemon() {
  const me = generateIdentity();
  const caller = generateIdentity();
  const directory = createDirectory({ self: { name: "target", publicKey: me.publicKey } });
  directory.useProfiles({ sysadmin: { name: "sysadmin", allows: ["hail", "shell:sh"] } });
  directory.admit({ name: "caller", publicKey: caller.publicKey, profile: "sysadmin" });

  const shell = createShellPlugin({ shells: { sh: "sh" } });
  const daemon = createDaemon({ directory, identity: me, plugins: [hailPlugin, shell] });
  const { port } = await daemon.listen({ port: 0 });

  const record = { name: "target", addresses: [{ value: `http://127.0.0.1:${port}` }], publicKey: me.publicKey };
  const as = { name: "caller", privateKey: caller.privateKey };
  const call = (path, body) => callPeer(record, path, body, { as });
  return { daemon, shell, call, record, caller };
}

test("a peer runs a command in a real shell over the fabric and gets its output", async () => {
  const { daemon, shell, call } = await bootShellDaemon();
  try {
    const result = await execShell(call, "sh", "echo hello-from-the-shell");
    assert.equal(result.ok, true, result.ok ? "" : result.error);
    assert.equal(result.complete, true, "the command finished within the poll window");
    assert.match(result.output, /hello-from-the-shell/, "its stdout came back across the wire");
  } finally {
    shell.stop();
    await daemon.close();
  }
});

test("a session held by id keeps shell state across separate calls", async () => {
  const { daemon, shell, call } = await bootShellDaemon();
  try {
    const opened = await openShell(call, "sh");
    assert.equal(opened.ok, true);
    const id = opened.response.id;

    // Two independent send calls — the kind an agent makes across tool calls.
    // The second depends on state the first left, so this only passes if the
    // remote shell persisted between them.
    await sendShell(call, "sh", id, "X=persisted\n");
    await sendShell(call, "sh", id, "echo value-is-$X\n");

    // Poll until the output arrives (a couple of loops on a fast machine).
    let out = "";
    for (let i = 0; i < 40 && !out.includes("value-is-"); i += 1) {
      const polled = await pollShell(call, "sh", id);
      if (polled.response?.data) out += Buffer.from(polled.response.data, "base64").toString();
      if (!out.includes("value-is-")) await new Promise((r) => setTimeout(r, 50));
    }
    assert.match(out, /value-is-persisted/, "the variable set in the first call survived into the second");

    const closed = await closeShell(call, "sh", id);
    assert.equal(closed.response.closed, true);
  } finally {
    shell.stop();
    await daemon.close();
  }
});

test("a caller without the capability is refused the shell", async () => {
  const me = generateIdentity();
  const stranger = generateIdentity();
  const directory = createDirectory({ self: { name: "target", publicKey: me.publicKey } });
  // Admitted, but on a profile that does not allow shell:sh.
  directory.useProfiles({ guest: { name: "guest", allows: ["hail"] } });
  directory.admit({ name: "stranger", publicKey: stranger.publicKey, profile: "guest" });

  const shell = createShellPlugin({ shells: { sh: "sh" } });
  const daemon = createDaemon({ directory, identity: me, plugins: [hailPlugin, shell] });
  const { port } = await daemon.listen({ port: 0 });
  try {
    const record = { name: "target", addresses: [{ value: `http://127.0.0.1:${port}` }], publicKey: me.publicKey };
    const opened = await openShell(
      (path, body) => callPeer(record, path, body, { as: { name: "stranger", privateKey: stranger.privateKey } }),
      "sh",
    );
    assert.equal(opened.ok, false, "the capability gate refuses a peer that does not hold shell:sh");
  } finally {
    shell.stop();
    await daemon.close();
  }
});
