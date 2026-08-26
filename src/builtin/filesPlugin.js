/**
 * Share files with an admitted peer, capability-gated, over an encrypted arrival.
 *
 * A **share** is a named place this machine will list/read/(optionally)write for a
 * peer holding `files:<name>`. Where the bytes actually live is the share's
 * **backend** — a small interface so a share can be a local directory today and
 * something else (an HTTP origin) without the peer knowing the difference. The
 * peer only ever names a share and a path; the command, the disk layout, and the
 * protocol behind it are never advertised.
 *
 * This is a request/response channel (base64 in JSON), not a stream: it is for the
 * small-to-moderate files people actually pass around — a config, a key, a note, a
 * small archive — bounded by `MAX_FILE`. A directory sync belongs to Tailscale or
 * rsync; this is the "hand that one file to that peer" case the fabric owns.
 *
 * Security is the whole job here:
 *  - **No escape.** A path is resolved *inside* the share root; anything that would
 *    climb out (`..`, an absolute path, a symlink past the root) is refused, not
 *    clamped. A share is a subtree, never a foothold on the rest of the disk.
 *  - **Read-only by default.** `put` exists only when the share is declared
 *    `writable`, and even then it is bounded and cannot escape the root.
 *  - **Bounded.** File size and listing length are capped, because a peer must not
 *    be able to make this machine read a hundred gigs into memory or enumerate the
 *    world.
 *  - **Encrypted arrival**, like chat: the fabric cannot see what a file holds, so
 *    it must not carry one in the clear.
 *
 * @module builtin/filesPlugin
 */
import { readFile, writeFile, readdir, stat, mkdir, realpath, open, lstat } from "node:fs/promises";
import { constants } from "node:fs";
import { resolve, join, sep, dirname } from "node:path";

import { REFUSE } from "../plugins.js";

/**
 * A file this channel will carry, capped. base64 in JSON is not a stream, and the
 * whole request rides the fabric's ~1 MB message envelope — so the ceiling is that
 * envelope minus base64's ~4/3 inflation, not an arbitrary large number. This is a
 * channel for small files (configs, keys, notes), by design.
 */
export const MAX_FILE = 700_000;
/** The most entries a single `list` returns — an inbox, not a crawler. */
export const MAX_ENTRIES = 2000;

const USABLE_NAME = /^[a-z0-9][a-z0-9-]*$/i;

/**
 * Reject a caller-chosen path that is absolute or climbs out of a root. Returns
 * the cleaned, root-relative segments, or null when the path is not allowed. The
 * caller still resolves against the real backend root and re-checks — this is the
 * cheap structural gate before any filesystem call.
 * @param {unknown} path
 */
export function safeSegments(path) {
  const raw = typeof path === "string" ? path : "";
  // Backslashes are separators on Windows and data on POSIX; treat both as
  // separators so a `..\\` cannot slip past a POSIX check.
  const parts = raw.split(/[\\/]+/).filter((p) => p && p !== ".");
  if (parts.some((p) => p === "..")) return null; // no climbing, ever
  if (/^([a-zA-Z]:|~)/.test(raw.trim())) return null; // no drive letters or ~
  return parts;
}

/**
 * A local-directory backend. Every path is resolved inside `root` and re-checked
 * against the real (symlink-followed) root, so neither `..` nor a symlink can
 * reach outside the share.
 * @param {{ root: string, writable?: boolean }} decl
 */
function localBackend({ root, writable = false }) {
  const rootAbs = resolve(root);
  /** Resolve a caller path inside the root, or throw a refusal. */
  const within = async (/** @type {string} */ path, { forWrite = false } = {}) => {
    const segs = safeSegments(path);
    if (segs === null) throw { refuse: "that path is not inside the share" };
    const target = segs.length ? join(rootAbs, ...segs) : rootAbs;
    // realpath the deepest existing ancestor and confirm it is still the root's
    // subtree — this is what closes a symlink that points out of the share.
    const anchor = forWrite ? dirname(target) : target;
    try {
      const real = await realpath(anchor);
      const realRoot = await realpath(rootAbs);
      if (real !== realRoot && !real.startsWith(realRoot + sep)) throw { refuse: "that path is not inside the share" };
    } catch (/** @type {any} */ error) {
      if (error && typeof error === "object" && "refuse" in error) throw error;
      // ENOENT on a not-yet-created file (write) is fine; other errors bubble as errors.
      if (!(forWrite && error?.code === "ENOENT")) throw { error: `cannot access that path: ${error?.code ?? error?.message ?? error}` };
    }
    return target;
  };
  return {
    supports: new Set(["list", "get", "put", "stat"]),
    writable,
    async list(/** @type {string} */ path) {
      const dir = await within(path);
      const dirents = await readdir(dir, { withFileTypes: true });
      const entries = [];
      for (const d of dirents.slice(0, MAX_ENTRIES)) {
        let size = null;
        try {
          if (d.isFile()) size = (await stat(join(dir, d.name))).size;
        } catch {}
        entries.push({ name: d.name, type: d.isDirectory() ? "dir" : d.isFile() ? "file" : "other", size });
      }
      return { entries, truncated: dirents.length > MAX_ENTRIES };
    },
    async stat(/** @type {string} */ path) {
      const s = await stat(await within(path));
      return { type: s.isDirectory() ? "dir" : "file", size: s.isFile() ? s.size : null };
    },
    async get(/** @type {string} */ path) {
      const file = await within(path);
      const s = await stat(file);
      if (!s.isFile()) throw { error: "not a file" };
      if (s.size > MAX_FILE) throw { error: `file is larger than the ${MAX_FILE}-byte limit` };
      return await readFile(file);
    },
    async put(/** @type {string} */ path, /** @type {Buffer} */ buf) {
      if (!writable) throw { refuse: "this share is read-only" };
      const file = await within(path, { forWrite: true });
      await mkdir(dirname(file), { recursive: true });
      // Refuse to write *through* a symlink at the final component: a pre-existing
      // symlink in the share must not redirect the write outside the root. The
      // parent chain is already realpath-checked inside `within`; O_NOFOLLOW makes
      // the final-component check atomic on POSIX, and the lstat pre-check gives a
      // clear error and covers platforms without the flag.
      const existing = await lstat(file).catch(() => null);
      if (existing && existing.isSymbolicLink()) throw { refuse: "that path is a symlink" };
      const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | (constants.O_NOFOLLOW ?? 0);
      let handle;
      try {
        handle = await open(file, flags, 0o644);
      } catch (/** @type {any} */ error) {
        if (error?.code === "ELOOP") throw { refuse: "that path is a symlink" };
        throw { error: `cannot write: ${error?.code ?? error?.message ?? error}` };
      }
      try {
        await handle.writeFile(buf);
      } finally {
        await handle.close();
      }
      return buf.length;
    },
  };
}

/**
 * An HTTP(S) backend: the share fronts a file store this machine reaches by URL, so
 * a peer reads/writes it without the store trusting the peer. No directory listing
 * (plain HTTP has no standard one), so `list` is unsupported and refused cleanly.
 * @param {{ base: string, writable?: boolean }} decl
 */
function httpBackend({ base, writable = false }) {
  const root = base.endsWith("/") ? base : base + "/";
  const urlFor = (/** @type {string} */ path) => {
    const segs = safeSegments(path);
    if (segs === null) throw { refuse: "that path is not inside the share" };
    return root + segs.map(encodeURIComponent).join("/");
  };
  return {
    supports: new Set(["get", ...(writable ? ["put"] : [])]),
    writable,
    async get(/** @type {string} */ path) {
      // No redirect-following: a compromised upstream must not be able to bounce the
      // daemon to an internal or metadata endpoint (SSRF).
      const r = await fetch(urlFor(path), { redirect: "manual" });
      if (r.status >= 300 && r.status < 400) throw { error: "upstream redirected — refused" };
      if (!r.ok) throw { error: `upstream ${r.status}` };
      const declared = Number(r.headers.get("content-length"));
      if (Number.isFinite(declared) && declared > MAX_FILE) throw { error: `file is larger than the ${MAX_FILE}-byte limit` };
      const reader = r.body?.getReader?.();
      if (!reader) {
        const buf = Buffer.from(await r.arrayBuffer());
        if (buf.length > MAX_FILE) throw { error: `file is larger than the ${MAX_FILE}-byte limit` };
        return buf;
      }
      // Bounded read: abort past the cap even when content-length lies or is absent.
      const chunks = [];
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.length;
        if (total > MAX_FILE) {
          await reader.cancel().catch(() => {});
          throw { error: `file is larger than the ${MAX_FILE}-byte limit` };
        }
        chunks.push(Buffer.from(value));
      }
      return Buffer.concat(chunks);
    },
    async put(/** @type {string} */ path, /** @type {Buffer} */ buf) {
      if (!writable) throw { refuse: "this share is read-only" };
      const r = await fetch(urlFor(path), { method: "PUT", body: /** @type {any} */ (buf), redirect: "manual" });
      if (r.status >= 300 && r.status < 400) throw { error: "upstream redirected — refused" };
      if (!r.ok) throw { error: `upstream ${r.status}` };
      return buf.length;
    },
  };
}

const BACKENDS = { local: localBackend, http: httpBackend };
export const BACKEND_KINDS = Object.keys(BACKENDS);

/** @param {any} decl */
function makeBackend(decl) {
  if (typeof decl === "string") return localBackend({ root: decl }); // bare string = a read-only local root
  const kind = decl?.backend ?? "local";
  const make = /** @type {any} */ (BACKENDS)[kind];
  if (!make) throw new Error(`peerhailer: unknown files backend '${kind}' (have: ${BACKEND_KINDS.join(", ")})`);
  return make(decl);
}

/**
 * @param {{ shares?: Record<string, any> }} [options]
 */
export function createFilesPlugin({ shares = {} } = {}) {
  for (const name of Object.keys(shares)) {
    if (!USABLE_NAME.test(name)) throw new Error(`peerhailer: '${name}' is not a usable share name (letters, digits, dashes)`);
  }
  const backends = new Map(Object.entries(shares).map(([name, decl]) => [name, makeBackend(decl)]));

  const capabilityFor = (/** @type {string} */ name) => `files:${name}`;

  /** Turn a backend throw ({refuse}|{error}|Error) into a route reply. */
  const fault = (/** @type {any} */ error) => {
    if (error && typeof error === "object" && "refuse" in error) return { [REFUSE]: true, reason: String(error.refuse) };
    if (error && typeof error === "object" && "error" in error) return { error: String(error.error) };
    return { error: String(error?.message ?? error) };
  };
  const needs = (/** @type {any} */ backend, /** @type {string} */ op) => backend.supports.has(op);

  return {
    name: "files",
    description: "List, read and (when writable) write files in a declared share, for holders of `files:<name>`.",
    requiresEncryptedArrival: true,
    capabilities: Object.keys(shares).map(capabilityFor),

    routes: Object.keys(shares).flatMap((name) => {
      const backend = backends.get(name);
      const capability = capabilityFor(name);
      /** @param {(body: any) => Promise<any>} run */
      const route = (/** @type {string} */ op, /** @type {(body: any) => Promise<any>} */ run) => ({
        method: "POST",
        path: `/files/${name}/${op}`,
        capability,
        /** @param {any} input */
        handler: async ({ body, caller }) => {
          if (!caller?.publicKey) return { [REFUSE]: true, reason: "no key to attribute this to" };
          if (!needs(backend, op)) return { error: `this share does not support ${op}` };
          try {
            return await run(body ?? {});
          } catch (error) {
            return fault(error);
          }
        },
      });
      return [
        route("list", async (body) => await backend.list(body.path ?? "")),
        route("stat", async (body) => await backend.stat(body.path ?? "")),
        route("get", async (body) => {
          const buf = await backend.get(body.path ?? "");
          return { data: buf.toString("base64"), size: buf.length };
        }),
        route("put", async (body) => {
          const data = typeof body.data === "string" ? body.data : "";
          const buf = Buffer.from(data, "base64");
          if (buf.length > MAX_FILE) return { error: `file is larger than the ${MAX_FILE}-byte limit` };
          const written = await backend.put(body.path ?? "", buf);
          return { written };
        }),
      ];
    }),
  };
}
