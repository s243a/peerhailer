/**
 * The chat control routes end to end: two daemons, mutually admitted with `chat`,
 * exchange messages through the page's `/api/chat/*` routes. Proves outgoing is
 * delivered over the peer's `/chat/send` and recorded on our side, incoming lands
 * in the thread, `/api/chat/state` lists the conversation, and `/api/chat/clear`
 * forgets it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import hailPlugin from "../src/builtin/hailPlugin.js";
import { createChatPlugin } from "../src/builtin/chatPlugin.js";

const CHAT = { chatp: { name: "chatp", allows: ["hail", "chat"] } };

async function node(name) {
  const id = generateIdentity();
  const directory = createDirectory({ self: { name, publicKey: id.publicKey } });
  directory.useProfiles(CHAT);
  const chat = createChatPlugin();
  const daemon = createDaemon({ directory, identity: id, plugins: [hailPlugin, chat] });
  const hail = await daemon.listenHail({ port: 0, hosts: ["127.0.0.1"], tls: true });
  const control = await daemon.listen({ port: 0 });
  return { name, id, directory, chat, daemon, hailPort: hail[0].port, controlPort: control.port };
}

const api = (n, path) => fetch(`http://127.0.0.1:${n.controlPort}${path}`).then((r) => r.json());
const post = (n, path, body) =>
  fetch(`http://127.0.0.1:${n.controlPort}${path}`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  }).then(async (r) => ({ status: r.status, json: await r.json() }));

test("two peers exchange chat through the page routes; state lists it; clear forgets it", async (t) => {
  const A = await node("alice");
  const B = await node("bob");
  t.after(() => { A.daemon.close(); B.daemon.close(); });

  // Mutual admission, each carrying the other's hail address so callNode reaches it.
  A.directory.admit({ name: "bob", publicKey: B.id.publicKey, addresses: [{ value: `https://127.0.0.1:${B.hailPort}` }] }, { profile: "chatp" });
  B.directory.admit({ name: "alice", publicKey: A.id.publicKey, addresses: [{ value: `https://127.0.0.1:${A.hailPort}` }] }, { profile: "chatp" });

  // Alice → Bob through Alice's page.
  const sent = await post(A, "/api/chat/send", { peer: "bob", text: "hello from alice" });
  assert.equal(sent.status, 200, `send ok (${JSON.stringify(sent.json)})`);
  assert.equal(sent.json.ok, true);

  // Bob → Alice through Bob's page.
  const reply = await post(B, "/api/chat/send", { peer: "alice", text: "hi from bob" });
  assert.equal(reply.status, 200, `reply ok (${JSON.stringify(reply.json)})`);

  // Alice's thread with Bob: her line (mine), then his (theirs), in order.
  const aThread = await api(A, "/api/chat/thread?peer=bob");
  assert.equal(aThread.messages.length, 2, "two messages in the thread");
  assert.deepEqual(aThread.messages.map((m) => [m.mine, m.text]), [
    [true, "hello from alice"],
    [false, "hi from bob"],
  ]);
  assert.equal(aThread.messages[1].from, "bob", "the incoming line is attributed to its sender, bob");

  // Bob's mirror.
  const bThread = await api(B, "/api/chat/thread?peer=alice");
  assert.deepEqual(bThread.messages.map((m) => [m.mine, m.text]), [
    [false, "hello from alice"],
    [true, "hi from bob"],
  ]);

  // State lists the conversation with a resolved name and count.
  const state = await api(A, "/api/chat/state");
  assert.equal(state.enabled, true);
  const conv = state.conversations.find((c) => c.name === "bob");
  assert.ok(conv && conv.count === 2, "state lists the bob conversation with count 2");
  assert.ok(state.peers.includes("bob"), "bob is an admitted peer you can chat with");

  // Unknown peer and empty text are refused cleanly.
  assert.equal((await post(A, "/api/chat/send", { peer: "nobody", text: "x" })).status, 404);
  assert.equal((await post(A, "/api/chat/send", { peer: "bob", text: "   " })).status, 400);

  // Clear forgets Alice's side.
  const cleared = await post(A, "/api/chat/clear", { peer: "bob" });
  assert.equal(cleared.json.cleared, true);
  assert.equal((await api(A, "/api/chat/thread?peer=bob")).messages.length, 0, "thread is empty after clear");
});

test("chat routes are inert when the plugin is absent (no --chat)", async (t) => {
  const id = generateIdentity();
  const directory = createDirectory({ self: { name: "solo", publicKey: id.publicKey } });
  const daemon = createDaemon({ directory, identity: id, plugins: [hailPlugin] });
  const control = await daemon.listen({ port: 0 });
  t.after(() => daemon.close());
  const base = `http://127.0.0.1:${control.port}`;
  const state = await fetch(`${base}/api/chat/state`).then((r) => r.json());
  assert.equal(state.enabled, false, "chat reports disabled");
  const send = await fetch(`${base}/api/chat/send`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ peer: "x", text: "y" }) });
  assert.equal(send.status, 501, "send is 501 when chat is off");
});
