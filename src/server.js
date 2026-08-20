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
import { collectRoutes } from "./plugins.js";
import { DIAGNOSTICS, HAIL, listProfiles, rejectionFor } from "./profiles.js";
import { fingerprint } from "./identity.js";
import { renderPage } from "./ui.js";

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
 *   profiles?: Record<string, any>,
 *   diagnostics?: ReturnType<typeof import("./diagnostics.js").createDiagnostics>,
 *   plugins?: import("./plugins.js").Plugin[],
 *   onChange?: () => void,
 *   log?: (message: string) => void,
 * }} options
 */
export function createDaemon({
  directory,
  identity,
  profiles = {},
  diagnostics,
  plugins = [],
  onChange,
  log = () => {},
}) {
  /**
   * Turn a caller away, in the style its profile calls for.
   *
   * `deny` answers, because a refusal a peer cannot see is one its operator
   * debugs as a network fault. `drop` closes without a reply, for peers that
   * should learn nothing — note the connection was already accepted by then, so
   * this hides the refusal rather than this machine. Being genuinely unfindable
   * needs a transport that can refuse before accepting.
   *
   * The reply never says *which* rule refused. Unknown peer, bad signature,
   * wrong key, missing capability and blocked all read alike, or the answer
   * becomes an oracle for working out which one to attack.
   *
   * @param {import("node:http").ServerResponse} response
   * @param {string} [profileName]
   */
  const turnAway = (response, profileName) => {
    if (rejectionFor(profileName, profiles) === "drop") {
      response.destroy();
      return;
    }
    response.writeHead(403, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "denied" }));
  };

  /**
   * For paths that are not part of the protocol at all.
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
  const debugRefusal = (reason, claimed = "unnamed") => {
    log(`[hail] refused: ${reason}`);
    diagnostics?.refused(claimed, reason);
    return null;
  };

  /**
   * Which profile decides how a caller is turned away.
   *
   * A caller we can identify is refused in its own profile's style — a blocked
   * peer is dropped, an unauthorized one is told. A caller we cannot identify
   * falls to `unknown`, which answers by default.
   *
   * @param {any} body
   */
  const rejectionProfile = (body) => {
    const name = body?.from?.name;
    return typeof name === "string"
      ? directory.effectiveProfile(name).profile
      : directory.trust().unknownProfile;
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
   * @param {string} [capability] what the caller must hold, beyond being known
   */
  const authenticate = (body, capability = HAIL) => {
    const claim = body?.from;
    if (typeof claim?.name !== "string") return debugRefusal("no name in claim");

    const known = directory.get(claim.name);
    if (!known?.publicKey) return debugRefusal(`unknown or keyless peer ${claim.name}`, claim.name);
    if (!verifyPayload(claim, body?.signature, known.publicKey)) {
      return debugRefusal(`signature from ${claim.name} did not verify`, claim.name);
    }

    // Replay is bounded rather than prevented: a signed hail is a request to be
    // told who we know, so a stale one costs the same as a fresh one. The window
    // exists so a captured request cannot be useful indefinitely.
    const age = Math.abs(Date.now() - (Number(claim.at) || 0));
    if (!Number.isFinite(age) || age > FRESHNESS_MS) return debugRefusal(`stale hail from ${claim.name}`, claim.name);

    return directory.allowsCapability(claim.name, capability)
      ? known
      : debugRefusal(`${claim.name} has no ${capability} capability`, claim.name);
  };

  // Resolved once: a route table that changes per request is one nobody can
  // reason about, and conflicts are worth refusing at startup rather than
  // resolving by whichever plugin happened to be listed first.
  const pluginRoutes = collectRoutes(plugins, { log });

  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://localhost");

    try {
      const pluginRoute = pluginRoutes.get(`${request.method} ${url.pathname}`);
      if (pluginRoute) {
        const body = JSON.parse((await readBody(request)) || "{}");
        // Authentication and capability happen here, in the core, before the
        // plugin is reached. A plugin cannot opt out of this, which is what
        // makes loading one a smaller decision than writing one.
        const caller = authenticate(body, pluginRoute.capability);
        if (!caller) return turnAway(response, rejectionProfile(body));

        const result = await pluginRoute.handler({ body, caller, directory, identity, log });
        return send(response, 200, result ?? {});
      }

      if (url.pathname === "/hail" && request.method === "POST") {
        const body = JSON.parse((await readBody(request)) || "{}");
        const caller = authenticate(body);
        if (!caller) return turnAway(response, rejectionProfile(body));

        const answer = directory.hailResponse();
        log(`[hail] ${caller.name} answered with ${answer.peers.length} peers`);
        return send(response, 200, { ...answer, signed: signRecord(directory.self, identity.privateKey) });
      }

      if (url.pathname === "/diagnostics" && request.method === "POST") {
        const body = JSON.parse((await readBody(request)) || "{}");
        const claimed = body?.from?.name;
        // Identity is checked the same way as a hail; the capability and the
        // window are what differ. Both must hold, and a caller that fails
        // either is told nothing more than any other refusal.
        const caller = authenticate(body, DIAGNOSTICS);
        if (!caller) return turnAway(response, rejectionProfile(body));
        if (!diagnostics?.isOpen()) {
          debugRefusal(`${claimed} asked for diagnostics while the window was shut`, claimed);
          return turnAway(response, rejectionProfile(body));
        }
        log(`[diagnostics] answered ${caller.name}`);
        return send(response, 200, diagnostics.report({ self: directory.self, directory, caller: caller.name }));
      }

      if (url.pathname === "/" && request.method === "GET") {
        // Same loopback address as the API it reads. A page that can admit
        // peers has no business being reachable from anywhere else.
        response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        response.end(
          renderPage({ name: directory.self.name, fingerprint: fingerprint(identity.publicKey) }),
        );
        return;
      }

      if (url.pathname === "/api/profiles" && request.method === "GET") {
        return send(response, 200, listProfiles(profiles));
      }

      if (url.pathname === "/api/block" && request.method === "POST") {
        const body = JSON.parse((await readBody(request)) || "{}");
        if (typeof body?.name !== "string") return send(response, 400, { error: "a name is required" });
        const peer = directory.get(body.name) ?? { name: body.name };
        const list = body.blocked === false ? directory.unblock(body.name) : directory.block(peer);
        onChange?.();
        return send(response, 200, list);
      }

      if (url.pathname === "/api/peers" && request.method === "GET") {
        return send(response, 200, {
          self: directory.self,
          // The effective profile travels with each peer: what was assigned is
          // not always what applies, and the page would otherwise show a grant
          // a blocked peer does not have.
          admitted: directory.listAdmitted().map((peer) => ({
            ...peer,
            effective: directory.effectiveProfile(peer.name),
          })),
          candidates: directory.listCandidates(),
        });
      }

      if (url.pathname === "/api/peers" && request.method === "POST") {
        const body = JSON.parse((await readBody(request)) || "{}");
        const admitted = directory.admit(
          body,
          ...(typeof body?.profile === "string" ? [{ profile: body.profile }] : []),
        );
        if (!admitted) return send(response, 400, { error: "a name is required" });
        onChange?.();
        return send(response, 200, admitted);
      }

      if (url.pathname === "/api/peers" && request.method === "DELETE") {
        const name = url.searchParams.get("name");
        const forgotten = name ? directory.forget(name) : false;
        if (forgotten) onChange?.();
        return send(response, 200, { forgotten });
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
