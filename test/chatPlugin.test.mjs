/**
 * Messages between admitted peers.
 *
 * The peer-to-peer half only. What matters: a peer holding `chat` can leave a
 * note, a peer without it cannot, one peer cannot read another's thread, and the
 * store is bounded because a peer can add to it.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { createChatPlugin, MAX_MESSAGE, MAX_PER_PEER } from "../src/builtin/chatPlugin.js";
import { collectRoutes, REFUSE } from "../src/plugins.js";

const call = (routes, path, input) => routes.get(`POST ${path}`)?.handler({ log: () => {}, ...input });

test("a peer holding chat can leave a note, and it is kept by key", async () => {
  const plugin = createChatPlugin();
  const routes = collectRoutes([plugin], { log: () => {} });
  const sol = { name: "sol", publicKey: "KEY-SOL" };

  const result = await call(routes, "/chat/send", { caller: sol, body: { text: "the build box is going down" } });
  assert.equal(result.received, true);

  const thread = plugin.thread("KEY-SOL");
  assert.equal(thread.length, 1);
  assert.equal(thread[0].from, "sol");
  assert.equal(thread[0].mine, false, "it came from them");
});

test("the capability gates it — a peer without chat never reaches the handler", async () => {
  const { createDaemon } = await import("../src/server.js");
  const { createDirectory } = await import("../src/directory.js");
  const { generateIdentity, signPayload } = await import("../src/identity.js");

  const me = generateIdentity();
  const talker = generateIdentity();
  const quiet = generateIdentity();
  const directory = createDirectory({ self: { name: "me", publicKey: me.publicKey } });
  directory.useProfiles({ chatty: { name: "chatty", allows: ["hail", "chat"] } });
  directory.admit({ name: "sol", publicKey: talker.publicKey, profile: "chatty" });
  directory.admit({ name: "mars", publicKey: quiet.publicKey, profile: "trusted" });

  const daemon = createDaemon({ directory, identity: me, plugins: [createChatPlugin()] });
  const { port } = await daemon.listen({ port: 0 });

  const send = async (name, identity) => {
    const from = { name, at: Date.now() };
    return fetch(`http://127.0.0.1:${port}/chat/send`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ from, signature: signPayload(from, identity.privateKey), text: "hi" }),
    }).then((r) => r.status).catch(() => "dropped");
  };

  try {
    assert.equal(await send("sol", talker), 200, "a peer holding chat is heard");
    assert.notEqual(await send("mars", quiet), 200, "trusted is not the same as may chat");
  } finally {
    await daemon.close();
  }
});

test("empty and oversized messages are refused", async () => {
  const plugin = createChatPlugin();
  const routes = collectRoutes([plugin], { log: () => {} });
  const sol = { name: "sol", publicKey: "KEY-SOL" };

  assert.equal((await call(routes, "/chat/send", { caller: sol, body: { text: "   " } }))[REFUSE], true);
  assert.equal((await call(routes, "/chat/send", { caller: sol, body: { text: "x".repeat(MAX_MESSAGE + 1) } }))[REFUSE], true);
  assert.equal((await call(routes, "/chat/send", { caller: { name: "anon" }, body: { text: "hi" } }))[REFUSE], true);
});

test("a thread is bounded, because a peer can add to it", async () => {
  let clock = 1_000_000;
  const plugin = createChatPlugin({ now: () => clock, maxPerPeer: 5, messageMs: 10 * 60_000 });
  const routes = collectRoutes([plugin], { log: () => {} });
  const sol = { name: "sol", publicKey: "KEY-SOL" };

  for (let i = 0; i < 8; i += 1) await call(routes, "/chat/send", { caller: sol, body: { text: `m${i}` } });
  assert.equal(plugin.thread("KEY-SOL").length, 5, "capped at maxPerPeer, newest kept");
  assert.equal(plugin.thread("KEY-SOL")[0].text, "m3");

  clock += 11 * 60_000;
  await call(routes, "/chat/send", { caller: sol, body: { text: "fresh" } });
  assert.equal(plugin.thread("KEY-SOL").length, 1, "older than messageMs is dropped");
});

test("one peer cannot read another's thread through the protocol", () => {
  const plugin = createChatPlugin();
  const routes = collectRoutes([plugin], { log: () => {} });
  // No route returns a thread — `thread()` is host-only.
  const paths = [...routes.keys()].filter((k) => k.includes("/chat/"));
  assert.deepEqual(paths, ["POST /chat/send"], "the only chat route is send");
});

test("this machine can say something to a peer, recorded as ours", () => {
  const plugin = createChatPlugin();
  plugin.say("KEY-SOL", "on my way");
  const [message] = plugin.thread("KEY-SOL");
  assert.equal(message.mine, true);
  assert.equal(message.from, "me");
});
