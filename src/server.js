/**
 * The daemon: answers hails, and serves a local API to whatever wants the
 * directory.
 *
 * Two audiences with different rights, which is why they are separated by more
 * than a path:
 *
 * `/hail` faces other machines. It answers admitted peers and nothing else.
 *
 * Everything under `/api` is for whatever runs alongside on this machine — a
 * CLI, an editor, a client wanting a peer picker. It binds to loopback by
 * default, because a directory that can be edited remotely is a way to admit a
 * peer without anybody agreeing to it.
 *
 * An unauthenticated caller learns nothing. Announcing "invalid token" would
 * confirm a peer is here and that tokens are the way in, which is a scanner's
 * reason to come back; every rejection returns the same 404 a bare host would.
 * That is the `anonymous` posture — honest about what a listening TCP service
 * can achieve, and no more.
 *
 * @module server
 */
import { createServer } from "node:http";

import { verifyPayload } from "./identity.js";
import { signRecord } from "./peerRecord.js";
import { HAIL } from "./profiles.js";

const MAX_BODY = 1_000_000;
/** How stale a signed hail may be. Generous: clocks drift, and this is not a nonce. */
const FRESHNESS_MS = 5 * 60_000;

/**
 * @param {import("node:http").IncomingMessage} request
 * @returns {Promise<string>}
 */
function readBody(request) {
  return new Promise((resolve, reject) => {
    let size = 0;
    /** @type {Buffer[]} */
    const chunks = [];
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new Error("body too large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}

/**
 * @param {{
 *   directory: ReturnType<typeof import("./directory.js").createDirectory>,
 *   identity: {publicKey: string, privateKey: string},
 *   log?: (message: string) => void,
 * }} options
 */
export function createDaemon({ directory, identity, log = () => {} }) {
  /**
   * Every failure looks like this. Same status, same body, same shape.
   *
   * @param {import("node:http").ServerResponse} response
   */
  const nothingHere = (response) => {
    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "not found" }));
  };

  /**
   * @param {import("node:http").ServerResponse} response
   * @param {number} status
   * @param {unknown} payload
   */
  const send = (response, status, payload) => {
    response.writeHead(status, { "content-type": "application/json" });
    response.end(JSON.stringify(payload));
  };

  /**
   * Why a caller was turned away — to our own log, never to them.
   *
   * The caller is told the same nothing whichever branch it was. An operator
   * staring at a peer that will not connect needs the reason; a stranger
   * probing does not.
   *
   * @param {string} reason
   */
  const debugRefusal = (reason) => {
    log(`[hail] refused: ${reason}`);
    return null;
  };

  /**
   * Who is calling, if anyone we know.
   *
   * The caller signs its own name and a timestamp; we check that against the
   * key we hold for that name. A name alone proves nothing — the key is the
   * identity — and a profile without the hail capability is turned away just
   * the same as a stranger.
   *
   * @param {any} body
   */
  const authenticate = (body) => {
    const claim = body?.from;
    if (typeof claim?.name !== "string") return debugRefusal("no name in claim");

    const known = directory.get(claim.name);
    if (!known?.publicKey) return debugRefusal(`unknown or keyless peer ${claim.name}`);
    if (!verifyPayload(claim, body?.signature, known.publicKey)) {
      return debugRefusal(`signature from ${claim.name} did not verify`);
    }

    // Replay is bounded rather than prevented: a signed hail is a request to be
    // told who we know, so a stale one costs the same as a fresh one. The window
    // exists so a captured request cannot be useful indefinitely.
    const age = Math.abs(Date.now() - (Number(claim.at) || 0));
    if (!Number.isFinite(age) || age > FRESHNESS_MS) return debugRefusal(`stale hail from ${claim.name}`);

    return directory.allowsCapability(claim.name, HAIL)
      ? known
      : debugRefusal(`${claim.name} has no hail capability`);
  };

  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://localhost");

    try {
      if (url.pathname === "/hail" && request.method === "POST") {
        const body = JSON.parse((await readBody(request)) || "{}");
        const caller = authenticate(body);
        if (!caller) return nothingHere(response);

        const answer = directory.hailResponse();
        log(`[hail] ${caller.name} answered with ${answer.peers.length} peers`);
        return send(response, 200, { ...answer, signed: signRecord(directory.self, identity.privateKey) });
      }

      if (url.pathname === "/api/peers" && request.method === "GET") {
        return send(response, 200, {
          self: directory.self,
          admitted: directory.listAdmitted(),
          candidates: directory.listCandidates(),
        });
      }

      if (url.pathname === "/api/peers" && request.method === "POST") {
        const body = JSON.parse((await readBody(request)) || "{}");
        const admitted = directory.admit(body);
        return admitted
          ? send(response, 200, admitted)
          : send(response, 400, { error: "a name is required" });
      }

      if (url.pathname === "/api/peers" && request.method === "DELETE") {
        const name = url.searchParams.get("name");
        return send(response, 200, { forgotten: name ? directory.forget(name) : false });
      }

      return nothingHere(response);
    } catch (cause) {
      log(`[daemon] ${url.pathname} failed: ${cause instanceof Error ? cause.message : String(cause)}`);
      return nothingHere(response);
    }
  });

  return {
    server,
    /** Loopback unless told otherwise: the API admits peers, so it stays local. */
    listen: ({ port = 8787, host = "127.0.0.1" } = {}) =>
      new Promise((resolve) => {
        server.listen(port, host, () => {
          // A TCP listen always yields AddressInfo; the union covers pipes.
          const address = /** @type {import("node:net").AddressInfo} */ (server.address());
          log(`[daemon] listening on http://${host}:${address.port}`);
          resolve({ port: address.port, host });
        });
      }),
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
