/**
 * The password gate: sign in once, then reach the protected site — and nothing
 * without the cookie, including the WebSocket a modern app needs.
 *
 * The crypto is unit-tested; the door is tested end to end over real sockets,
 * because the whole value is what an unauthenticated request actually gets.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:http";
import { request as httpRequest } from "node:http";

import {
  createGate,
  hashPassword,
  verifyPassword,
  mintSession,
  verifySession,
  newSecret,
  GATE_PREFIX,
} from "../src/gate.js";

// ---- unit: password hashing ----

test("a password verifies against its own hash and nothing else", () => {
  const stored = hashPassword("correct horse battery staple");
  assert.ok(verifyPassword("correct horse battery staple", stored), "the right password verifies");
  assert.equal(verifyPassword("wrong", stored), false, "a wrong password does not");
  assert.equal(verifyPassword("correct horse battery staple", "garbage"), false, "a malformed hash never verifies");
  assert.notEqual(stored, hashPassword("correct horse battery staple"), "a fresh salt makes each hash different");
});

// ---- unit: session tokens ----

test("a session token verifies until it expires, and never if tampered", () => {
  const secret = newSecret();
  const token = mintSession(secret, 1000);
  assert.equal(verifySession(secret, token, 500), true, "valid before expiry");
  assert.equal(verifySession(secret, token, 1500), false, "invalid after expiry");
  assert.equal(verifySession("a different secret", token, 500), false, "a different secret does not verify");
  assert.equal(verifySession(secret, token.slice(0, -2) + "xx", 500), false, "a tampered signature does not verify");
  assert.equal(verifySession(secret, "not.a.token", 500), false, "garbage does not verify");
});

// ---- integration harness ----

/** A backend that echoes the path over HTTP and echoes raw bytes over an upgrade. */
function backend() {
  const server = createServer((req, res) => {
    res.writeHead(200, { "content-type": "text/plain", "x-backend": "yes" });
    res.end(`backend saw ${req.url}`);
  });
  server.on("upgrade", (req, socket) => {
    socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
    socket.pipe(socket); // echo whatever the client sends after the handshake
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ port: server.address().port, close: () => new Promise((r) => server.close(() => r())) }));
  });
}

/** A gate (TLS not required, so the test can use plain http) in front of a backend. */
async function bootGate({ password = "s3cret", rate, now, trustForwarded = false } = {}) {
  const back = await backend();
  const gate = createGate({
    target: `http://127.0.0.1:${back.port}`,
    passwordHash: hashPassword(password),
    secret: newSecret(),
    requireTls: false,
    trustForwarded,
    ...(rate ? { rate } : {}),
    ...(now ? { now } : {}),
  });
  const server = createServer(gate.onRequest);
  server.on("upgrade", gate.onUpgrade);
  await new Promise((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = server.address().port;
  return {
    port,
    back,
    close: async () => {
      await new Promise((r) => server.close(() => r()));
      await back.close();
    },
  };
}

/** A tiny HTTP client returning status, headers, and body. */
function http(port, path, { method = "GET", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ hostname: "127.0.0.1", port, path, method, headers }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

/** Pull the gate cookie value out of a Set-Cookie header. */
function cookieFrom(res) {
  const set = res.headers["set-cookie"]?.[0] ?? "";
  return set.split(";")[0]; // "phgate=<token>"
}

const login = (port, password, next = "/", headers = {}) =>
  http(port, `${GATE_PREFIX}/login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: `password=${encodeURIComponent(password)}&next=${encodeURIComponent(next)}`,
  });

// ---- integration: the door ----

test("without a session, every path is the login page — the backend is not reached", async () => {
  const g = await bootGate();
  try {
    const res = await http(g.port, "/anything");
    assert.equal(res.status, 200);
    assert.match(res.body, /This site is protected/, "the login page, not the app");
    assert.ok(!res.headers["x-backend"], "the backend was never proxied to");
  } finally {
    await g.close();
  }
});

test("the right password sets a session cookie; a wrong one is refused with no cookie", async () => {
  const g = await bootGate({ password: "open-sesame" });
  try {
    const bad = await login(g.port, "nope");
    assert.equal(bad.status, 401);
    assert.ok(!bad.headers["set-cookie"], "a failed login mints no session");

    const good = await login(g.port, "open-sesame");
    assert.equal(good.status, 302, "a good login redirects");
    assert.match(good.headers["set-cookie"][0], /phgate=.+; Path=\/; HttpOnly; Secure; SameSite=Strict/, "with a hardened cookie");
  } finally {
    await g.close();
  }
});

test("with the session cookie, requests reach the backend; a tampered cookie does not", async () => {
  const g = await bootGate();
  try {
    const cookie = cookieFrom(await login(g.port, "s3cret"));

    const proxied = await http(g.port, "/app/page", { headers: { cookie } });
    assert.equal(proxied.status, 200);
    assert.equal(proxied.headers["x-backend"], "yes", "the response came from the backend");
    assert.match(proxied.body, /backend saw \/app\/page/, "the exact path was proxied through");

    const tampered = await http(g.port, "/app/page", { headers: { cookie: cookie.slice(0, -2) + "zz" } });
    assert.match(tampered.body, /This site is protected/, "a tampered cookie falls back to the login page");
    assert.ok(!tampered.headers["x-backend"], "and never reaches the backend");
  } finally {
    await g.close();
  }
});

test("the post-login redirect can only be a local path — no open redirect", async () => {
  const g = await bootGate();
  try {
    // A scheme-relative target via `//` or a backslash (which a browser treats
    // as `/` in a Location) must not send the signed-in operator off-site.
    for (const evil of ["//evil.com", "/\\evil.com", "https://evil.com", "/\tx", "/ok\\bad"]) {
      const res = await login(g.port, "s3cret", evil);
      assert.equal(res.status, 302);
      assert.equal(res.headers.location, "/", `redirect to a hostile next (${JSON.stringify(evil)}) is refused → /`);
    }
    // A genuine local path is honored.
    const ok = await login(g.port, "s3cret", "/app/deep/page");
    assert.equal(ok.headers.location, "/app/deep/page", "a local path is kept");
  } finally {
    await g.close();
  }
});

test("failed logins are rate-limited into a lockout", async () => {
  let t = 1000;
  const g = await bootGate({ rate: { max: 3, windowMs: 60_000, lockoutMs: 60_000 }, now: () => t });
  try {
    for (let i = 0; i < 3; i += 1) assert.equal((await login(g.port, "wrong")).status, 401, `attempt ${i + 1} refused`);
    const locked = await login(g.port, "wrong");
    assert.equal(locked.status, 429, "past the limit, the door locks");
    assert.match(locked.body, /Too many attempts/);
    // Even the *correct* password is refused while locked out.
    assert.equal((await login(g.port, "s3cret")).status, 429, "the lockout does not care that this one is correct");
  } finally {
    await g.close();
  }
});

test("with trustForwarded, lockout is per X-Forwarded-For client, not per socket", async () => {
  // Behind a loopback-terminating proxy every socket is 127.0.0.1; trusting the
  // proxy's X-Forwarded-For keeps one client's failures from locking out another.
  let t = 1000;
  const g = await bootGate({ trustForwarded: true, rate: { max: 2, windowMs: 60_000, lockoutMs: 60_000 }, now: () => t });
  try {
    const xffA = { "x-forwarded-for": "100.64.0.1" };
    const xffB = { "x-forwarded-for": "100.64.0.2" };
    assert.equal((await login(g.port, "wrong", "/", xffA)).status, 401);
    assert.equal((await login(g.port, "wrong", "/", xffA)).status, 401);
    assert.equal((await login(g.port, "wrong", "/", xffA)).status, 429, "client A is locked out");
    // Client B, a different forwarded address, is unaffected — no shared bucket.
    assert.equal((await login(g.port, "s3cret", "/", xffB)).status, 302, "client B still signs in");
  } finally {
    await g.close();
  }
});

test("a WebSocket upgrade is proxied for a session, and dropped without one", async () => {
  const g = await bootGate();
  try {
    const cookie = cookieFrom(await login(g.port, "s3cret"));

    // With the cookie: the upgrade reaches the backend, which echoes.
    const echoed = await wsEcho(g.port, "hello-through-the-gate", cookie);
    assert.equal(echoed, "hello-through-the-gate", "bytes crossed the proxied socket both ways");

    // Without it: the socket is destroyed, so the upgrade never completes.
    await assert.rejects(wsEcho(g.port, "nope", undefined), /closed|reset|ECONN|socket hang up/i, "an unauthenticated upgrade is dropped");
  } finally {
    await g.close();
  }
});

test("with requireTls, a cleartext request is refused", async () => {
  const back = await backend();
  const gate = createGate({ target: `http://127.0.0.1:${back.port}`, passwordHash: hashPassword("x"), secret: newSecret(), requireTls: true });
  const server = createServer(gate.onRequest);
  await new Promise((r) => server.listen(0, "127.0.0.1", () => r()));
  try {
    const res = await http(server.address().port, "/");
    assert.equal(res.status, 400, "a plaintext arrival is refused when TLS is required");
    assert.match(res.body, /must be served over TLS/);
  } finally {
    await new Promise((r) => server.close(() => r()));
    await back.close();
  }
});

/** Open a raw upgrade through the gate, send one frame of bytes, resolve the echo. */
function wsEcho(port, message, cookie) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      hostname: "127.0.0.1",
      port,
      path: "/socket",
      headers: {
        connection: "Upgrade",
        upgrade: "websocket",
        "sec-websocket-key": "x3JJHMbDL1EzLkh9GBhXDw==",
        "sec-websocket-version": "13",
        ...(cookie ? { cookie } : {}),
      },
    });
    req.on("upgrade", (_res, socket) => {
      socket.once("data", (buf) => {
        socket.destroy();
        resolve(buf.toString());
      });
      socket.write(message);
    });
    req.on("response", () => reject(new Error("no upgrade — server responded normally")));
    req.on("error", reject);
    req.end();
  });
}
