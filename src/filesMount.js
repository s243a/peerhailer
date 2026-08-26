/**
 * Mount a peer's share as a loopback WebDAV endpoint, so the operating system and
 * external tools use it as ordinary files.
 *
 * WebDAV is chosen because it is HTTP — no dependency, and every OS mounts it
 * natively (Windows "Map network drive", macOS Finder, Linux davfs2/gio, rclone).
 * Each WebDAV verb is translated to the files plugin's own routes over the signed
 * `callPeer` path, so the peer still enforces the share's root, bounds and
 * read-only-ness; the bridge trusts nothing new.
 *
 * This is the *permissive* mode, and it is a real escalation: a mount is reachable
 * by **every local process**, not one reviewed click. So it binds loopback only,
 * is opt-in, and writes still depend on the remote share being writable (a PUT to
 * a read-only share is refused upstream and surfaced as 403). Only the verbs the
 * plugin supports are offered — list/get/put; DELETE, MKCOL and LOCK are not, and
 * say so rather than pretending.
 *
 * @module filesMount
 */
import { createServer } from "node:http";

import { listFiles, statFile, getFile, putFile } from "./filesClient.js";
import { MAX_FILE } from "./builtin/filesPlugin.js";

const xmlEscape = (/** @type {unknown} */ s) =>
  String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c] ?? c);

/** The path a caller asked for, as clean share-relative segments (no leading /). */
function relPath(/** @type {string} */ urlPath) {
  return decodeURIComponent(urlPath).replace(/^\/+/, "").replace(/\/+$/, "");
}

/** One <D:response> block for a resource. */
function responseXml(/** @type {string} */ href, /** @type {{ isDir: boolean, size?: number | null }} */ { isDir, size }) {
  const type = isDir ? "<D:collection/>" : "";
  const len = isDir ? "" : `<D:getcontentlength>${size ?? 0}</D:getcontentlength>`;
  return (
    `<D:response><D:href>${xmlEscape(href)}</D:href><D:propstat><D:prop>` +
    `<D:resourcetype>${type}</D:resourcetype>${len}</D:prop>` +
    `<D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>`
  );
}

/**
 * A WebDAV request handler over one peer share.
 * @param {{ call: (path: string, body: any) => Promise<any>, share: string, log?: (m: string) => void }} deps
 */
export function createFilesMount({ call, share, log = () => {} }) {
  // Bounded: a mount is reachable by any local process, so a PUT body is capped at
  // MAX_FILE and resolves to null past it (the handler answers 413) — the daemon
  // must not double-buffer gigabytes before the peer's own cap fires far away.
  const readBody = (/** @type {import("node:http").IncomingMessage} */ req) =>
    new Promise((resolve) => {
      /** @type {Buffer[]} */
      const chunks = [];
      let total = 0;
      let over = false;
      req.on("data", (/** @type {Buffer} */ c) => {
        if (over) return;
        total += c.length;
        if (total > MAX_FILE) { over = true; req.destroy(); resolve(null); return; }
        chunks.push(c);
      });
      req.on("end", () => { if (!over) resolve(Buffer.concat(chunks)); });
      req.on("close", () => { if (!over) resolve(Buffer.concat(chunks)); });
      req.on("error", () => { if (!over) resolve(null); });
    });

  /** @param {import("node:http").IncomingMessage} req @param {import("node:http").ServerResponse} res */
  return async function handler(req, res) {
    const method = req.method ?? "GET";
    const path = relPath((req.url ?? "/").split("?")[0] ?? "/");
    const href = "/" + (path ? path.split("/").map(encodeURIComponent).join("/") : "");
    const done = (/** @type {number} */ code, /** @type {any} */ headers = {}, /** @type {any} */ body = "") => {
      res.writeHead(code, headers ?? {});
      res.end(body);
    };
    // Map a client error to a WebDAV status by its shape, not a substring of the
    // message — so a transport failure (ECONNREFUSED contains "refused") is a 502,
    // not a misleading 403.
    const statusFor = (/** @type {string} */ err) => {
      const e = String(err ?? "");
      if (/read-only|is a symlink|not inside the share/i.test(e)) return 403;
      if (/larger than/i.test(e)) return 413;
      if (/not a file|cannot access|no data|upstream 404/i.test(e)) return 404;
      return 502; // peer down / transport / unknown upstream
    };
    try {
      if (method === "OPTIONS") {
        return done(200, { DAV: "1", Allow: "OPTIONS, HEAD, GET, PUT, PROPFIND", "MS-Author-Via": "DAV", "content-length": "0" });
      }
      if (method === "PROPFIND") {
        const depth = String(req.headers.depth ?? "1");
        // Is the target a directory? The root always is; otherwise stat it.
        let isDir = path === "";
        let size = null;
        if (path !== "") {
          const st = await statFile(call, share, path);
          if (!st?.ok) return done(404, {}, "");
          isDir = st.response?.type === "dir";
          size = st.response?.size ?? null;
        }
        const parts = [responseXml(href || "/", { isDir, size })];
        if (isDir && depth !== "0") {
          const listed = await listFiles(call, share, path);
          for (const e of listed?.response?.entries ?? []) {
            const childHref = (href === "/" ? "" : href) + "/" + encodeURIComponent(e.name);
            parts.push(responseXml(childHref, { isDir: e.type === "dir", size: e.size }));
          }
        }
        const xml = `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">${parts.join("")}</D:multistatus>`;
        return done(207, { "content-type": "application/xml; charset=utf-8" }, xml);
      }
      if (method === "GET" || method === "HEAD") {
        const got = await getFile(call, share, path);
        if (!got.ok) return done(statusFor(got.error), {}, got.error ?? "");
        const buf = got.buffer ?? Buffer.alloc(0);
        const headers = { "content-type": "application/octet-stream", "content-length": String(buf.length) };
        return method === "HEAD" ? done(200, headers, "") : done(200, headers, buf);
      }
      if (method === "PUT") {
        const body = await readBody(req);
        if (body === null) return done(413, { "content-length": "0" }, "");
        const put = await putFile(call, share, path, body);
        if (!put.ok) return done(statusFor(put.error), {}, put.error ?? "");
        return done(201, { "content-length": "0" }, "");
      }
      // Verbs the underlying share does not offer. Honest, not faked.
      if (["DELETE", "MKCOL", "MOVE", "COPY", "LOCK", "UNLOCK", "PROPPATCH"].includes(method)) {
        return done(501, { Allow: "OPTIONS, HEAD, GET, PUT, PROPFIND" }, `${method} is not supported by this share`);
      }
      return done(405, {}, "");
    } catch (error) {
      log(`[mount] ${method} ${href} failed: ${/** @type {any} */ (error)?.message ?? error}`);
      return done(500, {}, "");
    }
  };
}

/**
 * Start a loopback WebDAV server fronting a peer share. Returns the local URL a
 * tool or the OS mounts, and a close().
 * @param {{ call: (path: string, body: any) => Promise<any>, share: string, host?: string, log?: (m: string) => void }} deps
 */
export function mountShare({ call, share, host = "127.0.0.1", log = () => {} }) {
  const handler = createFilesMount({ call, share, log });
  const server = createServer((req, res) => {
    handler(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  });
  return new Promise((resolve) => {
    server.listen(0, host, () => {
      const { port } = /** @type {import("node:net").AddressInfo} */ (server.address());
      const url = `http://${host}:${port}/`;
      log(`[mount] ${share} mounted at ${url}`);
      resolve({
        port,
        url,
        close: () =>
          new Promise((doneClose) => {
            server.close(() => doneClose(undefined));
            server.closeAllConnections?.();
          }),
      });
    });
  });
}
