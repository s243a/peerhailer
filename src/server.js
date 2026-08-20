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
import { timingSafeEqual } from "node:crypto";

const MAX_BODY = 1_000_000;

/** Constant time, so a rejection cannot be turned into a guessing game. */
function secretMatches(given, expected) {
  if (!expected) return true;
  if (typeof given !== "string") return false;
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let size = 0;
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
 *   directory: object,
 *   token?: string,
 *   log?: (message: string) => void,
 * }} options
 */
export function createDaemon({ directory, token, log = () => {} }) {
  /** Every failure looks like this. Same status, same body, same shape. */
  const nothingHere = (response) => {
    response.writeHead(404, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "not found" }));
  };

  const send = (response, status, payload) => {
    response.writeHead(status, { "content-type": "application/json" });
    response.end(JSON.stringify(payload));
  };

  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://localhost");

    try {
      if (url.pathname === "/hail" && request.method === "POST") {
        const bearer = (request.headers.authorization ?? "").replace(/^Bearer /, "");
        if (!secretMatches(bearer, token)) return nothingHere(response);
        const answer = directory.hailResponse();
        log(`[hail] answered with ${answer.peers.length} peers`);
        return send(response, 200, answer);
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
      log(`[daemon] ${url.pathname} failed: ${cause?.message ?? cause}`);
      return nothingHere(response);
    }
  });

  return {
    server,
    /** Loopback unless told otherwise: the API admits peers, so it stays local. */
    listen: ({ port = 8787, host = "127.0.0.1" } = {}) =>
      new Promise((resolve) => {
        server.listen(port, host, () => {
          const address = server.address();
          log(`[daemon] listening on http://${host}:${address.port}`);
          resolve({ port: address.port, host });
        });
      }),
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
