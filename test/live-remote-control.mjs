/**
 * T3-to-T3 remote control, end to end with fakes — no real peer, no real T3
 * required for the "existing" path. A fake fabric mints a canned pairing URL and
 * forwards a fake tunnel to a fixed local port; the composer turns that into the
 * deep link a local T3 client opens to register the remote as a saved connection.
 *
 *   node test/live-remote-control.mjs
 */
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { createComposer } = await import("../src/composer.js");

const forwards = [];
const fabric = {
  runCommand: async (_node, name) => ({
    ok: true,
    response: {
      command: name,
      output:
        "Pairing URL: http://127.0.0.1:9300/pair#token=ABC123DEF456\nToken: ABC123DEF456\nExpires: 2026-08-26T03:00:00Z\n",
    },
  }),
  forward: async () => {
    const f = { port: 49999, closed: false, close() { this.closed = true; } };
    forwards.push(f);
    return f;
  },
};

// --- Path 1: reuse an already-running local T3 (read from server-runtime.json) ---
const fakeHome = mkdtempSync(join(tmpdir(), "t3-existing-"));
mkdirSync(join(fakeHome, "userdata"), { recursive: true });
writeFileSync(
  join(fakeHome, "userdata", "server-runtime.json"),
  JSON.stringify({ origin: "http://127.0.0.1:3773" }),
);
process.env.T3CODE_HOME = fakeHome;

const composer = createComposer({ fabric, log: () => {} });

const res = await composer.controlRemote({ node: "puppy", localT3: "existing" });
console.log("existing → deepLink:", res.deepLink);
assert.equal(res.remoteOrigin, "http://127.0.0.1:49999", "tunnel origin is the forwarded local port");
assert.equal(
  res.deepLink,
  "http://127.0.0.1:3773/pair?host=http%3A%2F%2F127.0.0.1%3A49999#token=ABC123DEF456",
  "deep link points the local /pair route at the tunnelled remote via ?host= and carries the token in the hash",
);
assert.equal(res.remotePairingUrl, "http://127.0.0.1:9300/pair#token=ABC123DEF456", "the remote's own URL is reported");
assert.match(res.expiresAt ?? "", /2026-08-26T03:00:00Z/, "expiry parsed from the mint output");

const stopped = await composer.stopControl(res.controlId);
assert.equal(stopped.stopped, true, "stopControl reports success");
assert.equal(forwards[0].closed, true, "stop closes the tunnel forward");

// --- Path 2: no running local T3 + 'existing' → a clear refusal ---
process.env.T3CODE_HOME = mkdtempSync(join(tmpdir(), "t3-empty-"));
let refused = null;
try {
  await composer.controlRemote({ node: "puppy", localT3: "existing" });
} catch (e) {
  refused = e;
}
assert.ok(refused && /no running local T3/.test(refused.message), "existing with no local T3 refuses clearly");
// and the forward it opened before discovering that is not leaked
assert.equal(forwards[1].closed, true, "the forward is closed when local-T3 resolution fails");

composer.closeAll();
console.log("\nPASS — remote control minted a grant, forwarded the tunnel, and built the pairing deep link; teardown closed the forward");
process.exit(0);
