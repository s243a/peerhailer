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
import { generateIdentity, sameKey } from "../src/identity.js";
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

  // Alice admits Bob WITH his sealing key on the record; Bob admits Alice.
  A.directory.admit({ name: "bob", publicKey: B.id.publicKey, sealPublicKey: B.id.sealPublicKey, addresses: [{ value: `https://127.0.0.1:${B.hailPort}` }] }, { profile: "chatp" });
  B.directory.admit({ name: "alice", publicKey: A.id.publicKey }, { profile: "chatp" });

  // A sealing key merely present on the admitted record is NOT trusted to
  // encrypt to — only a verified walk binds it. So the first send, before any
  // walk, goes cleartext (no silent seal to an unverified key).
  assert.equal(A.directory.sealKeyFor("bob"), null, "unverified sealing key is not sealed to");
  const early = await post(A, "/api/chat/send", { peer: "bob", text: "hello" });
  assert.equal(early.json.sealed, false, "pre-walk send is cleartext");

  // A verified walk binds Bob's sealing key from his signed record — modelled
  // here by bindSealKey, exactly what walk() calls after verifyRecord succeeds.
  A.directory.bindSealKey("bob", B.id.sealPublicKey);
  assert.ok(sameKey(A.directory.sealKeyFor("bob"), B.id.sealPublicKey), "verified key is now trusted");

  const sent = await post(A, "/api/chat/send", { peer: "bob", text: "meet at noon" });
  assert.equal(sent.status, 200, JSON.stringify(sent.json));
  assert.equal(sent.json.sealed, true, "post-walk send is sealed");
  assert.equal(sent.json.message.sealed, true, "sender's own copy is marked sealed");

  // Bob's stored thread has the plaintext, marked sealed, attributed to alice.
  const conv = B.chat.conversations()[0];
  assert.ok(conv, "bob has a conversation");
  const msgs = B.chat.thread(conv.peerKey);
  assert.equal(msgs.at(-1).text, "meet at noon", "bob opened the sealed message");
  assert.equal(msgs.at(-1).sealed, true, "it arrived sealed, not cleartext");
  assert.equal(msgs.at(-1).from, "alice");

  // Finding 1 regression: a gossip mention / re-admit after binding must not
  // drop the verified key and silently downgrade the next send to cleartext.
  A.directory.learnFrom("someone", [{ name: "bob", publicKey: B.id.publicKey, addresses: [{ value: "https://127.0.0.1:9" }] }]);
  A.directory.admit({ name: "bob", addresses: [{ value: `https://127.0.0.1:${B.hailPort}` }] }, { profile: "chatp" });
  assert.ok(sameKey(A.directory.sealKeyFor("bob"), B.id.sealPublicKey), "verified key survives gossip and re-admit");
});

test("a gossiped sealing key is never trusted; a peer with no verified key stays cleartext", () => {
  const alice = generateIdentity();
  const bob = generateIdentity();
  const mallory = generateIdentity();
  const dir = createDirectory({ self: { name: "me", publicKey: alice.publicKey, sealPublicKey: alice.sealPublicKey } });
  dir.useProfiles(CHAT);

  // An introducer gossips bob's real identity key but staples mallory's sealing
  // key beside it. Even after admitting that candidate, the stapled key is not
  // trusted — sealKeyFor stays null until a walk verifies bob's own signed key.
  dir.learnFrom("introducer", [{ name: "bob", publicKey: bob.publicKey, sealPublicKey: mallory.sealPublicKey, addresses: [{ value: "https://127.0.0.1:9" }] }]);
  dir.admit({ name: "bob", addresses: [{ value: "https://127.0.0.1:9" }] }, { profile: "chatp" });
  assert.equal(dir.sealKeyFor("bob"), null, "a gossiped/stapled sealing key is never sealed to");

  // The walk verifies bob's real signed record; only then is a key trusted, and
  // it is bob's own, not the introducer's.
  dir.bindSealKey("bob", bob.sealPublicKey, bob.publicKey);
  assert.ok(sameKey(dir.sealKeyFor("bob"), bob.sealPublicKey));
  // A later verified key that disagrees is never silently swapped in — it raises
  // a conflict, and the send path then fails closed rather than sealing to a key
  // that might be stale or attacker-supplied.
  dir.bindSealKey("bob", mallory.sealPublicKey, bob.publicKey);
  assert.equal(dir.sealState("bob"), "conflict", "a disagreeing verified key is a conflict");
  assert.equal(dir.sealKeyFor("bob"), null, "no key is handed out under conflict");
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
