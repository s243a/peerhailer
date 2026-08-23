/**
 * Driving a shell on another machine.
 *
 * The client is thin, so the tests are about the shapes that matter: send
 * base64-encodes stdin, poll decodes output, and `exec` reads to its sentinel
 * and hands back the command's output without it — across the stateless calls an
 * agent actually makes.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { openShell, sendShell, pollShell, closeShell, execShell } from "../src/shellClient.js";
import { callPeer } from "../src/hail.js";
import { generateIdentity } from "../src/identity.js";

/** A fake remote shell: send appends output, poll drains it, echo emits its arg. */
function fakeRemote() {
  let buffer = "";
  let closed = false;
  const seen = [];
  /** @type {import("../src/shellClient.js").Call} */
  const call = async (path, body = {}) => {
    seen.push({ path, body });
    if (path.endsWith("/open")) return { ok: true, response: { id: "S1", name: "bash" } };
    if (path.endsWith("/send")) {
      const text = Buffer.from(body.data, "base64").toString();
      for (const line of text.split("\n")) {
        if (!line) continue;
        const echo = line.match(/^echo (.+)$/);
        buffer += echo ? `${echo[1]}\n` : `ran: ${line}\n`;
      }
      return { ok: true, response: { sent: true } };
    }
    if (path.endsWith("/poll")) {
      const data = Buffer.from(buffer).toString("base64");
      buffer = "";
      return { ok: true, response: { data, closed } };
    }
    if (path.endsWith("/close")) {
      closed = true;
      return { ok: true, response: { closed: true } };
    }
    return { ok: false, error: "unknown route" };
  };
  return { call, seen };
}

test("send base64-encodes stdin and poll decodes output", async () => {
  const { call } = fakeRemote();
  const opened = await openShell(call, "bash");
  assert.equal(opened.response.id, "S1");

  await sendShell(call, "bash", "S1", "ls -la\n");
  const polled = await pollShell(call, "bash", "S1");
  assert.equal(Buffer.from(polled.response.data, "base64").toString(), "ran: ls -la\n");

  const closedRes = await closeShell(call, "bash", "S1");
  assert.equal(closedRes.response.closed, true);
});

test("send carries the exact bytes — the caller owns the newline", async () => {
  const { call, seen } = fakeRemote();
  await sendShell(call, "bash", "S1", "abc");
  const send = seen.find((c) => c.path.endsWith("/send"));
  assert.equal(Buffer.from(send.body.data, "base64").toString(), "abc", "no newline was added");
});

test("exec runs a command and returns its output without the sentinel", async () => {
  const { call } = fakeRemote();
  const result = await execShell(call, "bash", "uname -a", { wait: async () => {}, pollMs: 0 });
  assert.equal(result.ok, true);
  assert.equal(result.complete, true);
  assert.ok(result.output.includes("ran: uname -a"), "the command's output comes back");
  assert.ok(!result.output.includes("HAIL_DONE"), "the sentinel is stripped, not shown");
});

test("exec closes even when the command output never returns the sentinel", async () => {
  // A remote that never echoes anything — poll always empty, never closed.
  let closes = 0;
  const call = async (path) => {
    if (path.endsWith("/open")) return { ok: true, response: { id: "S1" } };
    if (path.endsWith("/send")) return { ok: true, response: { sent: true } };
    if (path.endsWith("/poll")) return { ok: true, response: { data: "", closed: false } };
    if (path.endsWith("/close")) return (closes += 1), { ok: true, response: { closed: true } };
    return { ok: false, error: "?" };
  };
  const result = await execShell(call, "bash", "sleep 999", { wait: async () => {}, pollMs: 0, maxPolls: 5 });
  assert.equal(result.ok, true);
  assert.equal(result.complete, false, "it gave up rather than hanging");
  assert.equal(closes, 1, "and closed the session it opened");
});

test("exec surfaces a failed open without sending anything", async () => {
  const call = async (path) => (path.endsWith("/open") ? { ok: false, error: "no address answered" } : { ok: true, response: {} });
  const result = await execShell(call, "bash", "whoami", { wait: async () => {} });
  assert.equal(result.ok, false);
  assert.match(result.error, /no address answered/);
});

test("callPeer signs like a hail and posts the route body to the peer's address", async () => {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, body: JSON.parse(init.body) });
    return { ok: true, json: async () => ({ id: "S9" }) };
  };
  const me = generateIdentity();
  const record = { name: "phone", addresses: [{ value: "http://100.64.0.2:7645" }], publicKey: me.publicKey };
  const as = { name: "me", privateKey: me.privateKey };

  const result = await callPeer(record, "/shell/bash/open", { hello: 1 }, { fetchImpl, as });
  assert.equal(result.ok, true);
  assert.equal(result.response.id, "S9");
  assert.equal(calls[0].url, "http://100.64.0.2:7645/shell/bash/open", "posted to the route on the peer");
  assert.equal(calls[0].body.from.name, "me", "carries the signed caller identity");
  assert.ok(calls[0].body.signature, "and a signature");
  assert.equal(calls[0].body.hello, 1, "and the route body alongside");
});
