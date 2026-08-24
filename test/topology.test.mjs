/**
 * Longer chains: bridge nodes with several addresses, and how the plugins behave
 * at each arrival posture.
 *
 * A "bridge node" here is a node that advertises more than one address — a
 * "wifi"/plaintext listener, a "tailnet"/asserted-encrypted listener, a pinned
 * mutual-TLS listener, a loopback listener — each with its own arrival posture.
 * There is no byte-relaying (peerhailer dials targets directly; see
 * docs/decisions.md "Bridging carries introductions, not packets"); a chain is a
 * reachability graph formed by which interface two nodes share, and the
 * interesting question is how a capability is gated per listener.
 *
 * We can't bind real NICs in a test, so an "interface" is a listener with a
 * chosen posture. `listenHail` decides the posture:
 *   - plaintext              — `encrypted: false`
 *   - asserted-encrypted     — `encrypted: true`; loopback also counts as *mutual*
 *   - encrypted, not mutual  — `encrypted: true` on a non-loopback host (0.0.0.0),
 *                              which is the real `--hail-on-encrypted tailscale0` case
 *   - pinned mutual TLS       — `tls: true`, caller pins the server and presents a
 *                              vouched client cert
 *
 * The enforcement is at the exit (src/server.js): a route 404s where its
 * `requiresEncryptedArrival` marker is not satisfied — the same 404 an undeclared
 * route gives, so a peer on the wrong interface cannot even tell the capability
 * exists. 403 means the route *was* reached and refused there; 2xx means served.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer as netServer } from "node:net";

import { createDaemon } from "../src/server.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import { callPeer, walk } from "../src/hail.js";
import hailPlugin from "../src/builtin/hailPlugin.js";
import { createShellPlugin } from "../src/builtin/shellPlugin.js";
import { createTunnelPlugin } from "../src/builtin/tunnelPlugin.js";
import { createCommandPlugin } from "../src/builtin/commandPlugin.js";
import { createServicePlugin } from "../src/builtin/servicePlugin.js";

/** A local TCP echo, so the tunnel endpoint has a real far side to reach. */
function echoServer() {
  const server = netServer((socket) => socket.pipe(socket));
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = /** @type {import("node:net").AddressInfo} */ (server.address());
      resolve({ port, close: () => new Promise((r) => server.close(() => r(undefined))) });
    });
  });
}

/**
 * A bridge node offering all four capability plugins, and a caller admitted to
 * every one of them. Returns helpers to open interfaces and probe them.
 */
async function bootBridge() {
  const me = generateIdentity();
  const caller = generateIdentity();
  const echo = await echoServer();

  const directory = createDirectory({ self: { name: "bridge", publicKey: me.publicKey } });
  directory.useProfiles({
    guest: { name: "guest", allows: ["hail", "shell:sh", "tunnel:echo", "command:echo", "service:svc"] },
  });
  directory.admit({ name: "caller", publicKey: caller.publicKey, profile: "guest" });

  const shell = createShellPlugin({ shells: { sh: "sh" } });
  const tunnel = createTunnelPlugin({ endpoints: { echo: `127.0.0.1:${echo.port}` } });
  const command = createCommandPlugin({ commands: { echo: "echo topology-ok" } });
  const service = createServicePlugin({ services: { svc: "sleep 1" } });
  const daemon = createDaemon({ directory, identity: me, plugins: [hailPlugin, shell, tunnel, command, service] });

  /**
   * Open one interface at a posture and return a `reach(path, body)` bound to it.
   * `withCert` presents a vouched client cert (needed for a mutual-TLS shell).
   */
  const openIface = async (posture) => {
    const opts =
      posture === "plaintext"
        ? { port: 0, hosts: ["127.0.0.1"], encrypted: false }
        : posture === "encrypted-mutual"
          ? { port: 0, hosts: ["127.0.0.1"], encrypted: true }
          : posture === "encrypted-only"
            ? { port: 0, hosts: ["0.0.0.0"], encrypted: true } // non-loopback: encrypted, not mutual
            : { port: 0, hosts: ["127.0.0.1"], tls: true }; // pinned mutual TLS
    const bound = await daemon.listenHail(opts);
    const tls = posture === "tls";
    const scheme = tls ? "https" : "http";
    const reach = (path, body, { withCert = false } = {}) => {
      const record = { name: "bridge", addresses: [{ value: `${scheme}://127.0.0.1:${bound[0].port}` }], publicKey: me.publicKey };
      const as = withCert
        ? { name: "caller", privateKey: caller.privateKey, publicKey: caller.publicKey }
        : { name: "caller", privateKey: caller.privateKey };
      return callPeer(record, path, body, { as });
    };
    return { bound, reach };
  };

  return { daemon, shell, echo, openIface, key: me.publicKey, caller };
}

/**
 * Classify what happened to one call, from `callPeer`'s result:
 *   allowed — 2xx, the route served and permitted
 *   refused — 403, the route was reached and refused *there* (capability, cert)
 *   gated   — 404, the arrival gate (or an undeclared route) hid it entirely
 */
async function probe(reach, path, body = {}, opts) {
  const r = await reach(path, body, opts);
  if (r.ok) return "allowed";
  if (/HTTP 403/.test(r.error)) return "refused";
  if (/HTTP 404/.test(r.error)) return "gated";
  return `error:${r.error}`;
}

/** Close a shell/tunnel session if one opened, so nothing lingers. */
async function tidy(reach, kind, result) {
  const id = result?.ok && result.response?.id;
  if (id) await reach(`/${kind}/${kind === "shell" ? "sh" : "echo"}/close`, { id }).catch(() => {});
}

test("the shell's mutual gate, walked up the arrival ladder", async () => {
  const bridge = await bootBridge();
  try {
    const plaintext = await bridge.openIface("plaintext");
    const encryptedOnly = await bridge.openIface("encrypted-only");
    const encryptedMutual = await bridge.openIface("encrypted-mutual");
    const tls = await bridge.openIface("tls");

    // Plaintext: not served at all — the route 404s as if it did not exist, which
    // is the whole point (a peer on the wrong interface cannot tell it is there).
    assert.equal(await probe(plaintext.reach, "/shell/sh/open"), "gated", "no shell on a plaintext listener");

    // Encrypted but not mutual (the bare tailnet address): encrypted is not
    // enough for a shell — it wants a *bound* arrival, so it still 404s. This is
    // the most security-relevant rung (the --hail-on-encrypted-misassertion
    // stand-in), so if the environment cannot bind it, fail loudly rather than
    // skip: the rung must be exercised, not quietly dropped.
    assert.ok(encryptedOnly.bound.length > 0, "the encrypted-not-mutual listener bound (0.0.0.0) — the rung is exercised");
    assert.equal(await probe(encryptedOnly.reach, "/shell/sh/open"), "gated", "encrypted alone does not open a shell — mutual is required");

    // Encrypted *and* mutual (loopback counts as bound): served.
    const onLoopback = await encryptedMutual.reach("/shell/sh/open");
    assert.equal(onLoopback.ok, true, "a shell is served where arrival is encrypted and mutual");
    await tidy(encryptedMutual.reach, "shell", onLoopback);

    // Pinned mutual TLS with a vouched client cert: served over a direct link,
    // no tailnet in the path — the point of --hail-on-tls.
    const onTls = await tls.reach("/shell/sh/open", {}, { withCert: true });
    assert.equal(onTls.ok, true, "a shell is served over pinned mutual TLS when the caller presents its vouched cert");
    await tidy((p, b) => tls.reach(p, b, { withCert: true }), "shell", onTls);

    // Same TLS listener, no client cert: encrypted and past the route gate, but
    // the mutual-pin check refuses it at the handler — a 403, not a 404.
    assert.equal(await probe(tls.reach, "/shell/sh/open"), "refused", "TLS without a vouched client cert is refused, not served");
  } finally {
    bridge.shell.stop();
    await bridge.echo.close();
    await bridge.daemon.close();
  }
});

test("tunnel, command, and service all require an encrypted arrival", async () => {
  // The three non-shell capability plugins now carry the same gate as the shell:
  // a tunnel's bytes, a command's bearer credential, and a service's start
  // request + handed-back port must none of them cross a plaintext LAN. All are
  // `true` (encrypted), not `"mutual"` — a tunnel, pairing, or service started
  // over a bare tailnet address is the ordinary case, and requiring a client cert
  // there would refuse it. So on plaintext they 404, and on an encrypted arrival
  // they are served. Only the shell stays `"mutual"`, being interactive host
  // control.
  const bridge = await bootBridge();
  try {
    const plaintext = await bridge.openIface("plaintext");
    const encrypted = await bridge.openIface("encrypted-mutual");

    // Gated on plaintext — the same 404 an undeclared route gives.
    assert.equal(await probe(plaintext.reach, "/tunnel/echo/open"), "gated", "no tunnel on a plaintext listener");
    assert.equal(await probe(plaintext.reach, "/command/echo/run"), "gated", "no command on a plaintext listener");
    assert.equal(await probe(plaintext.reach, "/service/svc/status", { id: "nope" }), "gated", "no service on a plaintext listener");

    // Served where arrival is encrypted.
    const tunnel = await encrypted.reach("/tunnel/echo/open");
    assert.equal(tunnel.ok, true, "a tunnel opens where arrival is encrypted");
    await tidy(encrypted.reach, "tunnel", tunnel);
    assert.equal(await probe(encrypted.reach, "/command/echo/run"), "allowed", "a command runs where arrival is encrypted");
    // service/status with a bogus id is refused at the handler ("not your
    // service") — a 403, which proves the route was reached past the arrival gate.
    assert.equal(await probe(encrypted.reach, "/service/svc/status", { id: "nope" }), "refused", "the service route is reached where arrival is encrypted");
  } finally {
    bridge.shell.stop();
    await bridge.echo.close();
    await bridge.daemon.close();
  }
});

test("A→B→C: a walk carries C's introduction from B to A, but never a route to C", async () => {
  // A can reach B; B knows C on an interface A is not on. peerhailer dials
  // directly — there is no relay — so the walk demonstrates the honest boundary:
  //   - it makes C a *candidate* in A's directory (knowledge crosses one hop),
  //   - it never *admits* C (trust does not travel; admitting is a person's act),
  //   - A's own reach to C is a direct dial to C's address, never forwarded
  //     through B (bytes do not cross): unreachable there is unreachable, period.
  // C is modeled as a record B holds at an address that does not answer from
  // here (nothing listens on :1) — standing in for "C's interface, which A is
  // not on", since one host cannot make an address reachable from B but not A.
  const a = generateIdentity();
  const b = generateIdentity();
  const cKey = generateIdentity().publicKey;
  const cAddress = "http://127.0.0.1:1";

  // B: a real bridge. It admits A (so A may read its directory) and C (so C is in
  // the list A reads), both under a profile that is hail-able and introduce-able.
  const bDir = createDirectory({ self: { name: "B", publicKey: b.publicKey } });
  bDir.useProfiles({ peer: { name: "peer", allows: ["hail", "directory", "introduce"] } });
  bDir.admit({ name: "A", publicKey: a.publicKey, profile: "peer" });
  bDir.admit({ name: "C", publicKey: cKey, addresses: [{ transport: "tailscale", value: cAddress }], profile: "peer" });
  const bDaemon = createDaemon({ directory: bDir, identity: b, plugins: [hailPlugin] });
  const bBound = await bDaemon.listenHail({ port: 0, hosts: ["127.0.0.1"], encrypted: false }); // hail rides plaintext

  // A: admits B at B's reachable ("wifi") address, granting it `introduce` so A
  // follows B's introductions.
  const aDir = createDirectory({ self: { name: "A", publicKey: a.publicKey } });
  aDir.useProfiles({ peer: { name: "peer", allows: ["hail", "directory", "introduce"] } });
  aDir.admit({ name: "B", publicKey: b.publicKey, addresses: [{ transport: "lan", value: `http://127.0.0.1:${bBound[0].port}` }], profile: "peer" });

  try {
    const result = await walk(aDir, { as: { name: "A", publicKey: a.publicKey, privateKey: a.privateKey } });

    // Knowledge crossed: A reached B and learned C as a candidate — but only that.
    assert.ok(result.reached.some((r) => r.name === "B"), "A reached B");
    assert.ok(result.candidates.some((c) => c.name === "C"), "A heard of C through B");
    assert.equal(aDir.get("C"), null, "C was not admitted — trust did not travel with the introduction");

    // Bytes do not cross: A's own reach to C is a direct dial to C's address,
    // which A cannot reach; nothing routes it through B.
    const cRecord = aDir.listCandidates().find((c) => c.name === "C");
    const reachC = await callPeer(cRecord, "/hail", {}, { as: { name: "A", privateKey: a.privateKey } });
    assert.equal(reachC.ok, false, "A cannot reach C — there is no relay through B");
    assert.match(reachC.error, /http:\/\/127\.0\.0\.1:1\b/, "the failed dial went straight to C's address, never through B");
  } finally {
    await bDaemon.close();
  }
});

test("a multi-address record dials past a dead interface to a live one", async () => {
  // The bridge advertises two addresses; the first is dead (an interface that
  // moved or was never reachable from here), the second live. `orderForDialing`
  // tries them in turn and the call still lands — the everyday multi-homed case,
  // and the closest thing to a "chain" the architecture has: reachability is
  // whichever advertised address answers, not a route through anyone.
  const bridge = await bootBridge();
  try {
    const live = await bridge.openIface("encrypted-mutual");
    const record = {
      name: "bridge",
      publicKey: bridge.key,
      addresses: [
        { transport: "lan", value: "http://127.0.0.1:1", lastOk: null }, // nothing listens on :1
        { transport: "tailscale", value: `http://127.0.0.1:${live.bound[0].port}`, lastOk: null },
      ],
    };
    const as = { name: "caller", privateKey: bridge.caller.privateKey };
    const result = await callPeer(record, "/hail", {}, { as });
    assert.equal(result.ok, true, "the dead first address was skipped and the live one answered");
    assert.match(result.address.value, /:(?!1$)\d+$/, "the address that answered was the live one, not :1");
  } finally {
    bridge.shell.stop();
    await bridge.echo.close();
    await bridge.daemon.close();
  }
});
