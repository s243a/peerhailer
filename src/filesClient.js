/**
 * The calling side of the files plugin: list, get and put over a peer's share.
 * Each helper takes a `call(path, body)` — the same signed `callPeer` closure the
 * CLI and composer build — and returns the peer's reply. Bytes cross as base64;
 * `getFile` hands back a Buffer, `putFile` takes one.
 */

/** @param {(path: string, body: any) => Promise<any>} call */
export const listFiles = (call, /** @type {string} */ share, /** @type {string} */ path = "") => call(`/files/${share}/list`, { path });

/** @param {(path: string, body: any) => Promise<any>} call */
export const statFile = (call, /** @type {string} */ share, /** @type {string} */ path = "") => call(`/files/${share}/stat`, { path });

/**
 * Read a file from a peer's share. Returns { ok, buffer, size } or { ok:false, error }.
 * @param {(path: string, body: any) => Promise<any>} call
 */
export async function getFile(call, /** @type {string} */ share, /** @type {string} */ path) {
  const res = await call(`/files/${share}/get`, { path });
  if (!res?.ok) return { ok: false, error: res?.error ?? "refused" };
  const r = res.response ?? {};
  if (typeof r.error === "string") return { ok: false, error: r.error };
  if (typeof r.data !== "string") return { ok: false, error: "no data in reply" };
  return { ok: true, buffer: Buffer.from(r.data, "base64"), size: r.size ?? null };
}

/**
 * Write a Buffer (or string) to a file in a peer's share.
 * @param {(path: string, body: any) => Promise<any>} call
 * @param {Buffer | string} data
 */
export async function putFile(call, /** @type {string} */ share, /** @type {string} */ path, data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
  const res = await call(`/files/${share}/put`, { path, data: buf.toString("base64") });
  if (!res?.ok) return { ok: false, error: res?.error ?? "refused" };
  const r = res.response ?? {};
  if (typeof r.error === "string") return { ok: false, error: r.error };
  return { ok: true, written: r.written ?? buf.length };
}
