/**
 * Regressions for four correctness fixes from a full-system review: the chat
 * replay-guard reserving a nonce before validation (#13), chat retention not
 * expiring idle threads or evicting least-recently-touched (#6), a permanent
 * profile keeping a stale temporary expiry (#4), and a control listener that
 * could not report a bind failure (#5).
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { createChatPlugin } from "../src/builtin/chatPlugin.js";
import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import { seal } from "../src/sealing.js";
import { REFUSE } from "../src/plugins.js";

test("#13 a malformed sealed message does not burn its nonce", () => {
  const alice = generateIdentity();
  const bob = generateIdentity();
  const chat = createChatPlugin({ identity: bob });
  const relay = chat.routes.find((r) => r.path === "/chat/send").handler;
  const caller = { name: "alice", publicKey: alice.publicKey };
  const signer = { publicKey: alice.publicKey, privateKey: alice.privateKey };

  // Empty text but a valid nonce N → refused, and N must NOT be reserved.
  const bad = seal(JSON.stringify({ text: "   ", at: Date.now(), nonce: "N" }), bob.sealPublicKey, { signer });
  assert.equal(relay({ body: { sealed: bad }, caller })[REFUSE], true);
  // A corrected retry that reuses N must land, not read as a phantom duplicate.
  const good = seal(JSON.stringify({ text: "fixed", at: Date.now(), nonce: "N" }), bob.sealPublicKey, { signer });
  assert.equal(relay({ body: { sealed: good }, caller }).received, true, "the refused attempt did not spend the nonce");
});

test("#6 an idle conversation expires when read, and empty threads drop", () => {
  let t = 1000;
  const chat = createChatPlugin({ now: () => t, messageMs: 100 });
  chat.say("peer-a", "hi");
  assert.equal(chat.conversations().length, 1);
  t = 5000; // well past messageMs
  assert.equal(chat.conversations().length, 0, "the idle thread is pruned on read, not left visible");
  assert.deepEqual(chat.thread("peer-a"), []);
});

test("#6 eviction is least-recently-touched, not oldest-created", () => {
  const chat = createChatPlugin({ maxConversations: 2 });
  chat.say("A", "1");
  chat.say("B", "1");
  chat.say("A", "2"); // touch A — it must now outrank B
  chat.say("C", "1"); // over the ceiling: the coldest (B) is evicted
  const names = chat.conversations().map((c) => c.peerKey).sort();
  assert.deepEqual(names, ["A", "C"], "the recently-touched A survives; the cold B is evicted");
});

test("#4 an explicit permanent profile clears a running temporary elevation", () => {
  const bob = generateIdentity();
  const dir = createDirectory({ self: { name: "me" } });
  dir.admit({ name: "p", publicKey: bob.publicKey, addresses: [{ value: "https://127.0.0.1:9" }] }, { profile: "trusted", until: Date.now() + 1_000_000 });
  assert.ok(dir.get("p").profileUntil, "the temporary elevation is set");
  const readmitted = dir.admit({ name: "p", publicKey: bob.publicKey, addresses: [{ value: "https://127.0.0.1:9" }] }, { profile: "carrier" });
  assert.equal(readmitted.profile, "carrier");
  assert.equal(readmitted.profileUntil, undefined, "a deliberate permanent profile does not keep the old expiry");
});

test("#5 a control listener on an occupied port rejects instead of crashing", async (t) => {
  const mk = (name) => createDaemon({ directory: createDirectory({ self: { name } }), identity: generateIdentity(), plugins: [] });
  const a = mk("a");
  const first = await a.listen({ port: 0 });
  const b = mk("b");
  t.after(async () => { await a.close(); try { await b.close(); } catch { /* never bound */ } });
  await assert.rejects(() => b.listen({ port: first.port }), /EADDRINUSE|address already in use/i, "the bind failure rejects the promise");
});
