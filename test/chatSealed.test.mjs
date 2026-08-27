/**
 * Sealed chat, end to end: Alice's message to Bob is sealed to Bob's advertised
 * X25519 key and signed by Alice's identity — so it crosses the wire opaque, Bob
 * opens it, and the sealed sender is bound to the authenticated caller. Plus the
 * consumer-contract refusals: a replayed sealed block is dropped, and a sealed
 * sender that isn't the caller is refused.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import hailPlugin from "../src/builtin/hailPlugin.js";
import { createChatPlugin } from "../src/builtin/chatPlugin.js";
import { seal } from "../src/sealing.js";
import { REFUSE } from "../src/plugins.js";

const CHAT = { chatp: { name: "chatp", allows: ["hail", "chat"] } };

async function node(name, { canOpen = false } = {}) {
  const id = generateIdentity();
  const directory = createDirectory({ self: { name, publicKey: id.publicKey, sealPublicKey: id.sealPublicKey } });
  directory.useProfiles(CHAT);
  const chat = createChatPlugin(canOpen ? { identity: id } : {});
  const daemon = createDaemon({ directory, identity: id, plugins: [hailPlugin, chat] });
  const hail = await daemon.listenHail({ port: 0, hosts: ["127.0.0.1"], tls: true });
  const control = await daemon.listen({ port: 0 });
  return { name, id, directory, chat, daemon, hailPort: hail[0].port, controlPort: control.port };
}
const post = (n, path, body) =>
  fetch(`http://127.0.0.1:${n.controlPort}${path}`, { method: "POST", headers: { "content-type": "application/json", connection: "close" }, body: JSON.stringify(body) }).then(async (r) => ({ status: r.status, json: await r.json() }));

test("Alice's chat to Bob crosses the wire sealed and Bob opens it, sender bound", async (t) => {
  const A = await node("alice");
  const B = await node("bob", { canOpen: true });
  t.after(async () => { await A.daemon.close(); await B.daemon.close(); });

  // Alice admits Bob WITH his sealing key; Bob admits Alice.
  A.directory.admit({ name: "bob", publicKey: B.id.publicKey, sealPublicKey: B.id.sealPublicKey, addresses: [{ value: `https://127.0.0.1:${B.hailPort}` }] }, { profile: "chatp" });
  B.directory.admit({ name: "alice", publicKey: A.id.publicKey }, { profile: "chatp" });

  const sent = await post(A, "/api/chat/send", { peer: "bob", text: "meet at noon" });
  assert.equal(sent.status, 200, JSON.stringify(sent.json));

  // Bob's stored thread has the plaintext, marked sealed, attributed to alice.
  const conv = B.chat.conversations()[0];
  assert.ok(conv, "bob has a conversation");
  const msgs = B.chat.thread(conv.peerKey);
  assert.equal(msgs.at(-1).text, "meet at noon", "bob opened the sealed message");
  assert.equal(msgs.at(-1).sealed, true, "it arrived sealed, not cleartext");
  assert.equal(msgs.at(-1).from, "alice");
});

test("a replayed sealed block is dropped; a sealed sender that isn't the caller is refused", () => {
  const alice = generateIdentity();
  const mallory = generateIdentity();
  const bob = generateIdentity();
  const chat = createChatPlugin({ identity: bob });
  const relay = chat.routes.find((r) => r.path === "/chat/send").handler;
  const aliceCaller = { name: "alice", publicKey: alice.publicKey };

  const inner = JSON.stringify({ text: "hi", at: Date.now(), nonce: "nonce-1" });
  const sealed = seal(inner, bob.sealPublicKey, { signer: { publicKey: alice.publicKey, privateKey: alice.privateKey } });

  // First delivery lands; a replay of the same block is a no-op duplicate.
  assert.equal(relay({ body: { sealed }, caller: aliceCaller }).received, true);
  assert.equal(relay({ body: { sealed }, caller: aliceCaller }).duplicate, true, "same nonce replay dropped");

  // Alice's sealed block delivered by Mallory (authenticated as mallory) is refused.
  const inner2 = JSON.stringify({ text: "x", at: Date.now(), nonce: "nonce-2" });
  const sealed2 = seal(inner2, bob.sealPublicKey, { signer: { publicKey: alice.publicKey, privateKey: alice.privateKey } });
  const refused = relay({ body: { sealed: sealed2 }, caller: { name: "mallory", publicKey: mallory.publicKey } });
  assert.equal(refused[REFUSE], true, "sealed sender must match the caller");
});
