/**
 * A POST over TLS that pins the server to a key we already hold.
 *
 * `callPeer` uses this for `https://` addresses. It is small on purpose: Node's
 * `https` does the handshake, and this adds only the pin — the same comparison
 * the hail already rests on, at the TLS layer. The pin lives in `secureConnect`
 * because `rejectUnauthorized: false` (which we must set, to stop Node applying
 * the web PKI) skips `checkServerIdentity` entirely.
 *
 * The request is not sent until the pin passes. Headers and the signed body are
 * written only *after* `secureConnect` verifies the key, so a man-in-the-middle
 * presenting its own cert receives nothing to replay — the socket is destroyed
 * mid-handshake instead. A pin that let one byte through would be pointless.
 *
 * @module pinnedFetch
 */
import { request as httpsRequest } from "node:https";

import { certMatchesKey } from "./cert.js";

/**
 * @param {string} url  an `https://` URL
 * @param {{ method?: string, headers?: Record<string, string>, body?: string, signal?: AbortSignal }} init
 * @param {string | undefined} expectedKeyPem  the peer's identity key, from the directory
 * @returns {Promise<{ ok: boolean, status: number, json: () => Promise<any>, text: () => Promise<string> }>}
 */
export function pinnedFetch(url, { method = "POST", headers = {}, body, signal } = {}, expectedKeyPem) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const isIp = /^[\d.]+$/.test(u.hostname) || u.hostname.includes(":");
    const req = httpsRequest(
      {
        hostname: u.hostname,
        port: u.port || 443,
        path: u.pathname + u.search,
        method,
        headers,
        // SNI only for real hostnames; setting it to an IP is deprecated and
        // pointless here — the server has one cert and we pin its key, not a name.
        ...(isIp ? {} : { servername: u.hostname }),
        // A fresh connection per request, never pooled: a reused connection is
        // one whose pin we did not re-verify, and pooling also skips the
        // `secureConnect` the pin lives in.
        agent: false,
        // No CA — we pin the key ourselves, below. Node would otherwise reject a
        // self-signed cert before we ever see it.
        rejectUnauthorized: false,
      },
      (res) => {
        /** @type {Buffer[]} */
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          const status = res.statusCode ?? 0;
          resolve({
            ok: status >= 200 && status < 300,
            status,
            json: async () => JSON.parse(text || "{}"),
            text: async () => text,
          });
        });
      },
    );

    req.on("socket", (socket) => {
      socket.on("secureConnect", () => {
        // The pin, total: a matching key sends the request; anything else — wrong
        // key, no cert, a parse error — destroys the socket before a byte leaves.
        if (certMatchesKey(/** @type {any} */ (socket).getPeerCertificate(true), expectedKeyPem)) {
          if (body) req.write(body);
          req.end();
        } else {
          req.destroy(new Error("TLS pin failed: the peer's cert is not the key held for it"));
        }
      });
    });

    if (signal) signal.addEventListener("abort", () => req.destroy(new Error("aborted")));
    req.on("error", reject);
    // Note: no req.end() here — it is called only after the pin passes.
  });
}
