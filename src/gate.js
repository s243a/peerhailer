/**
 * A password gate in front of a local web app — a bastion for serving something
 * like T3 to a browser without exposing it directly.
 *
 * This is deliberately *not* a plugin. Every peerhailer plugin route is reached
 * only after a signed hail authenticates the caller and a capability admits it
 * (see plugins.js — "A plugin never sees an unauthenticated request"). A browser
 * can do neither: it holds no Ed25519 key to sign with, and it needs cookies and
 * a streamed proxy the plugin contract never hands out. So the gate is its own
 * door, with its own auth model — a password and a signed session cookie — kept
 * out of the peer-authenticated core rather than punching a hole in it.
 *
 * The shape:
 *   - a login page (password), served for any request without a valid session;
 *   - on the right password, an HMAC-signed, expiring session cookie;
 *   - every other request reverse-proxied to a locally-declared target (the
 *     operator names it; the browser never supplies it — the tunnel/command
 *     rule), including WebSocket upgrades, since a modern app is not usable
 *     without them.
 *
 * It is meant to run **over TLS** — a password on a plaintext link is no gate.
 * The cookie is always `Secure`; the caller (bin/hail.js) serves it on an https
 * listener. `requireTls` (default true) makes the handler refuse a cleartext
 * arrival outright, so a misconfiguration fails closed.
 *
 * @module gate
 */
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

/** Where the gate's own endpoints live, kept unlikely to collide with the app. */
export const GATE_PREFIX = "/__peerhailer_gate__";
export const DEFAULT_COOKIE = "phgate";
export const DEFAULT_SESSION_MS = 12 * 60 * 60_000;
/** Failed logins before a lockout, the window they are counted in, and how long the lockout lasts. */
export const DEFAULT_RATE = { max: 10, windowMs: 60_000, lockoutMs: 5 * 60_000 };

/**
 * Hash a password for storage: scrypt with a random salt, `saltHex:hashHex`.
 * Never store the password itself — the file it lands in travels and is read.
 *
 * @param {string} password
 * @returns {string}
 */
export function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(String(password), salt, 64);
  return `${salt.toString("hex")}:${hash.toString("hex")}`;
}

/**
 * Verify a password against a stored `saltHex:hashHex`, in constant time.
 *
 * @param {string} password
 * @param {string} stored
 * @returns {boolean}
 */
export function verifyPassword(password, stored) {
  const [saltHex, hashHex] = String(stored ?? "").split(":");
  if (!saltHex || !hashHex) return false;
  try {
    const expected = Buffer.from(hashHex, "hex");
    const actual = scryptSync(String(password), Buffer.from(saltHex, "hex"), expected.length);
    // Both are the same length by construction, so timingSafeEqual is safe to call.
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

/** A fresh session secret, for signing cookies. Persist it so sessions survive a restart. */
export function newSecret() {
  return randomBytes(32).toString("hex");
}

const b64url = (/** @type {Buffer} */ buf) => buf.toString("base64url");

/**
 * Mint a signed session token that expires at `now + ttlMs`.
 *
 * The payload is only an expiry — the gate has one principal (whoever holds the
 * password), so there is no identity to carry, and a smaller token is a smaller
 * thing to get wrong. The signature is what makes it unforgeable; the expiry is
 * what bounds a stolen one.
 *
 * @param {string} secret
 * @param {number} exp absolute ms
 * @returns {string}
 */
export function mintSession(secret, exp) {
  const payload = b64url(Buffer.from(JSON.stringify({ exp })));
  const sig = b64url(createHmac("sha256", secret).update(payload).digest());
  return `${payload}.${sig}`;
}

/**
 * Verify a session token: signature first (constant time), then expiry.
 *
 * @param {string} secret
 * @param {string | undefined} token
 * @param {number} now
 * @returns {boolean}
 */
export function verifySession(secret, token, now) {
  const [payload, sig] = String(token ?? "").split(".");
  if (!payload || !sig) return false;
  const expected = createHmac("sha256", secret).update(payload).digest();
  let given;
  try {
    given = Buffer.from(sig, "base64url");
  } catch {
    return false;
  }
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return false;
  try {
    const { exp } = JSON.parse(Buffer.from(payload, "base64url").toString());
    return Number.isFinite(exp) && now < exp;
  } catch {
    return false;
  }
}

/** Read one cookie value from a Cookie header. */
function readCookie(/** @type {string|undefined} */ header, /** @type {string} */ name) {
  for (const part of String(header ?? "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return undefined;
}

/** Strip our own cookie from a Cookie header so it is not forwarded upstream. */
function withoutGateCookie(/** @type {string|undefined} */ header, /** @type {string} */ name) {
  const kept = String(header ?? "")
    .split(";")
    .map((p) => p.trim())
    .filter((p) => p && p.split("=")[0] !== name);
  return kept.length ? kept.join("; ") : undefined;
}

/**
 * Hop-by-hop headers, which belong to one connection and must not be forwarded
 * across the proxy. Everything else is passed through.
 */
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

/**
 * A minimal, dependency-free login page. `next` is where to go on success.
 * @param {string} [next]
 * @param {string} [error]
 */
function loginPage(next = "/", error) {
  const esc = (/** @type {string} */ s) =>
    String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in</title><style>
body{font:16px system-ui,sans-serif;background:#111;color:#eee;display:grid;place-items:center;height:100vh;margin:0}
form{background:#1c1c1c;padding:2rem;border-radius:12px;min-width:280px;box-shadow:0 8px 30px #0008}
h1{font-size:1.1rem;margin:0 0 1rem}input{width:100%;padding:.6rem;margin:.3rem 0 1rem;border-radius:8px;border:1px solid #333;background:#0d0d0d;color:#eee;box-sizing:border-box}
button{width:100%;padding:.6rem;border:0;border-radius:8px;background:#3b6ef5;color:#fff;font-weight:600;cursor:pointer}
.err{color:#ff8080;font-size:.85rem;margin:0 0 .5rem}</style></head>
<body><form method="POST" action="${GATE_PREFIX}/login">
<h1>This site is protected</h1>
${error ? `<p class="err">${esc(error)}</p>` : ""}
<input type="hidden" name="next" value="${esc(next ?? "/")}">
<label>Password<input type="password" name="password" autofocus autocomplete="current-password"></label>
<button type="submit">Sign in</button></form></body></html>`;
}

/** Parse `application/x-www-form-urlencoded` bodies (what the login form posts). */
function parseForm(/** @type {string} */ body) {
  /** @type {Record<string, string>} */
  const out = {};
  for (const pair of String(body ?? "").split("&")) {
    const [k, v] = pair.split("=");
    if (k) out[decodeURIComponent(k)] = decodeURIComponent((v ?? "").replace(/\+/g, " "));
  }
  return out;
}

/** A `next` path is only honored if it is a local absolute path — never an open redirect. */
function safeNext(/** @type {any} */ next) {
  return typeof next === "string" && next.startsWith("/") && !next.startsWith("//") ? next : "/";
}

/**
 * Build the gate: a request handler and an upgrade (WebSocket) handler, plus the
 * password helpers re-exported for a caller that manages the stored hash.
 *
 * @param {{
 *   target: string,
 *   passwordHash: string,
 *   secret: string,
 *   sessionMs?: number,
 *   cookieName?: string,
 *   requireTls?: boolean,
 *   rate?: {max: number, windowMs: number, lockoutMs: number},
 *   now?: () => number,
 *   requestImpl?: typeof httpRequest,
 *   log?: (message: string) => void,
 * }} config
 */
export function createGate({
  target,
  passwordHash,
  secret,
  sessionMs = DEFAULT_SESSION_MS,
  cookieName = DEFAULT_COOKIE,
  requireTls = true,
  rate = DEFAULT_RATE,
  now = Date.now,
  requestImpl,
  log = () => {},
}) {
  const upstream = new URL(target);
  const proxyRequest = requestImpl ?? (upstream.protocol === "https:" ? httpsRequest : httpRequest);

  // Per-source failed-login accounting, so one address cannot spend another's
  // allowance and a locked-out one cannot keep guessing. Bounded so a spray of
  // source addresses cannot itself grow this without limit.
  /** @type {Map<string, {fails: number, first: number, lockedUntil: number}>} */
  const attempts = new Map();
  const MAX_TRACKED = 4096;

  const sourceOf = (/** @type {any} */ req) => req.socket?.remoteAddress ?? "unknown";

  /** @returns {number} ms remaining on a lockout, or 0 */
  const lockedFor = (/** @type {string} */ source) => {
    const a = attempts.get(source);
    return a && a.lockedUntil > now() ? a.lockedUntil - now() : 0;
  };

  const recordFailure = (/** @type {string} */ source) => {
    const t = now();
    const a = attempts.get(source) ?? { fails: 0, first: t, lockedUntil: 0 };
    if (t - a.first > rate.windowMs) {
      a.fails = 0;
      a.first = t;
    }
    a.fails += 1;
    if (a.fails >= rate.max) a.lockedUntil = t + rate.lockoutMs;
    if (attempts.size >= MAX_TRACKED && !attempts.has(source)) attempts.clear();
    attempts.set(source, a);
  };

  const clearFailures = (/** @type {string} */ source) => attempts.delete(source);

  const cookieHeader = (/** @type {string} */ token, /** @type {number} */ maxAgeMs) =>
    `${cookieName}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(maxAgeMs / 1000)}`;

  const hasSession = (/** @type {any} */ req) => verifySession(secret, readCookie(req.headers.cookie, cookieName), now());

  /** Refuse a cleartext arrival when TLS is required — fail closed. */
  const overTls = (/** @type {any} */ req) => Boolean(req.socket?.encrypted);

  /**
   * Reverse-proxy one request upstream. Headers pass through except hop-by-hop
   * and our own cookie; the response streams straight back.
   */
  const proxy = (/** @type {any} */ req, /** @type {any} */ res) => {
    /** @type {Record<string, any>} */
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (!HOP_BY_HOP.has(k)) headers[k] = v;
    }
    headers.host = upstream.host;
    const forwardedCookie = withoutGateCookie(req.headers.cookie, cookieName);
    if (forwardedCookie) headers.cookie = forwardedCookie;
    else delete headers.cookie;

    const up = proxyRequest(
      { protocol: upstream.protocol, hostname: upstream.hostname, port: upstream.port, method: req.method, path: req.url, headers },
      (upRes) => {
        /** @type {Record<string, any>} */
        const out = {};
        for (const [k, v] of Object.entries(upRes.headers)) if (!HOP_BY_HOP.has(k)) out[k] = v;
        res.writeHead(upRes.statusCode ?? 502, out);
        upRes.pipe(res);
      },
    );
    up.on("error", (err) => {
      log(`[gate] upstream error: ${err instanceof Error ? err.message : err}`);
      if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain" });
      res.end("gate: the protected site is not reachable");
    });
    req.pipe(up);
  };

  const serveLogin = (/** @type {any} */ req, /** @type {any} */ res, /** @type {{status?: number, error?: string}} */ { status = 200, error } = {}) => {
    const next = safeNext(new URL(req.url ?? "/", "http://x").searchParams.get("next") ?? req.url);
    res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    res.end(loginPage(next, error));
  };

  /** @type {import("node:http").RequestListener} */
  const onRequest = async (req, res) => {
    if (requireTls && !overTls(req)) {
      res.writeHead(400, { "content-type": "text/plain" });
      res.end("gate: refused a cleartext connection — the gate must be served over TLS");
      return;
    }
    const url = new URL(req.url ?? "/", "http://localhost");

    // Logout: clear the cookie and show the login page.
    if (url.pathname === `${GATE_PREFIX}/logout`) {
      res.writeHead(302, { "set-cookie": `${cookieName}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`, location: `${GATE_PREFIX}/login` });
      res.end();
      return;
    }

    // The login endpoint: GET shows the form, POST checks the password.
    if (url.pathname === `${GATE_PREFIX}/login`) {
      if (req.method !== "POST") return serveLogin(req, res);
      const source = sourceOf(req);
      const wait = lockedFor(source);
      if (wait > 0) {
        log(`[gate] locked out ${source} for ${Math.ceil(wait / 1000)}s`);
        return serveLogin(req, res, { status: 429, error: `Too many attempts. Try again in ${Math.ceil(wait / 1000)}s.` });
      }
      let body = "";
      for await (const chunk of req) {
        body += chunk;
        if (body.length > 4096) break; // a password form is tiny; do not buffer more
      }
      const { password, next } = parseForm(body);
      if (passwordHash && verifyPassword(password ?? "", passwordHash)) {
        clearFailures(source);
        const token = mintSession(secret, now() + sessionMs);
        res.writeHead(302, { "set-cookie": cookieHeader(token, sessionMs), location: safeNext(next) });
        res.end();
        log(`[gate] sign-in from ${source}`);
      } else {
        recordFailure(source);
        log(`[gate] failed sign-in from ${source}`);
        serveLogin(req, res, { status: 401, error: "Wrong password." });
      }
      return;
    }

    // Everything else: proxy if signed in, otherwise show the login page (with
    // the requested path carried so a successful sign-in returns to it).
    if (hasSession(req)) return proxy(req, res);
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
    res.end(loginPage(req.url));
  };

  /**
   * Proxy a WebSocket upgrade — but only for a signed-in session. A modern app
   * (T3 among them) is unusable without this, so the gate is not done until it
   * carries the socket too. An unauthenticated or cleartext upgrade is dropped.
   *
   * @param {import("node:http").IncomingMessage} req
   * @param {import("node:stream").Duplex} socket
   * @param {Buffer} head
   */
  const onUpgrade = (req, socket, head) => {
    if ((requireTls && !overTls(req)) || !hasSession(req)) {
      socket.destroy();
      return;
    }
    /** @type {Record<string, any>} */
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) headers[k] = v;
    headers.host = upstream.host;
    const forwardedCookie = withoutGateCookie(req.headers.cookie, cookieName);
    if (forwardedCookie) headers.cookie = forwardedCookie;
    else delete headers.cookie;

    const up = proxyRequest({
      protocol: upstream.protocol,
      hostname: upstream.hostname,
      port: upstream.port,
      method: req.method,
      path: req.url,
      headers,
    });
    up.on("upgrade", (upRes, upSocket, upHead) => {
      const statusLine = `HTTP/1.1 ${upRes.statusCode} ${upRes.statusMessage}\r\n`;
      const lines = [];
      for (let i = 0; i < upRes.rawHeaders.length; i += 2) lines.push(`${upRes.rawHeaders[i]}: ${upRes.rawHeaders[i + 1]}`);
      socket.write(statusLine + lines.join("\r\n") + "\r\n\r\n");
      if (upHead?.length) socket.write(upHead);
      upSocket.pipe(socket);
      socket.pipe(upSocket);
      const drop = () => {
        upSocket.destroy();
        socket.destroy();
      };
      upSocket.on("error", drop);
      socket.on("error", drop);
    });
    up.on("error", () => socket.destroy());
    if (head?.length) up.write(head);
    up.end();
  };

  return { onRequest, onUpgrade, hashPassword, verifyPassword };
}
