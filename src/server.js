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

import { sameKey, verifyPayload } from "./identity.js";
import { signRecord } from "./peerRecord.js";
import { collectRoutes, REFUSE } from "./plugins.js";
import { verifyGrant } from "./grants.js";
import {
  BLOCKED_PROFILE,
  DELEGATE,
  DIAGNOSTICS,
  HAIL,
  listProfiles,
  rejectionFor,
} from "./profiles.js";
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
 *   applyChange?: (mutate: (directory: any) => any) => any,
 *   log?: (message: string) => void,
 * }} options
 */
export function createDaemon({
  directory,
  identity,
  profiles = {},
  diagnostics,
  plugins = [],
  applyChange,
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
   * Does a grant in this request carry the capability?
   *
   * The issuer must be a peer this machine admitted *and* one it allows to
   * delegate — a grant is only worth what its issuer could have given, and an
   * issuer nobody trusts to delegate could otherwise mint capability from
   * nothing.
   *
   * @param {any} body
   * @param {string | null | undefined} presenterKey
   * @param {string} capability
   */
  const grantAllows = (body, presenterKey, capability) => {
    const envelope = body?.grant;
    if (!envelope) return null;

    const checked = verifyGrant(envelope, { presenterKey: presenterKey ?? null, capability });
    if (!checked.ok) {
      debugRefusal(`grant refused: ${checked.error}`, body?.from?.name ?? "unnamed");
      return null;
    }

    const issuer = directory.getByKey(checked.grant.issuerKey);
    if (!issuer) {
      debugRefusal(`grant issued by an unknown peer`, body?.from?.name ?? "unnamed");
      return null;
    }
    if (!directory.allowsCapability(issuer.name, DELEGATE)) {
      debugRefusal(`${issuer.name} may not delegate`, body?.from?.name ?? "unnamed");
      return null;
    }
    // And never more than the issuer itself holds here.
    if (!directory.allowsCapability(issuer.name, capability)) {
      debugRefusal(`${issuer.name} cannot delegate ${capability}, not holding it`, body?.from?.name ?? "unnamed");
      return null;
    }
    return checked.grant;
  };

  /**
   * Who is calling, if anyone we know, and may they ask for this?
   *
   * Identity is proved by signature. The capability comes either from the
   * profile this machine assigns that peer, or from a grant it presents — which
   * is checked against the key it just authenticated with, so a grant
   * authorises a machine rather than whoever is carrying it.
   *
   * @param {any} body
   * @param {string} [capability]
   */
  /**
   * Who this is, if they proved it. Capability is a separate question, asked
   * after — because *how* we refuse must depend on what we can prove, never on
   * what the caller claims.
   *
   * @param {any} body
   * @returns {{name: string, key: string, known: any} | null}
   */
  const identify = (body) => {
    const claim = body?.from;
    if (typeof claim?.name !== "string") return debugRefusal("no name in claim");

    const known = directory.get(claim.name);
    // Two ways to be someone here. Either this machine admitted you and holds
    // your key, or you carry a grant naming your key — which is how a peer
    // nobody admitted can still be let in, on the say-so of one who was.
    const presenterKey = known?.publicKey ?? body?.grant?.grant?.subjectKey ?? null;
    if (!presenterKey) {
      return debugRefusal(`unknown peer ${claim.name}, and no grant naming a key`, claim.name);
    }
    if (!verifyPayload(claim, body?.signature, presenterKey)) {
      return debugRefusal(`signature from ${claim.name} did not verify`, claim.name);
    }
    if (known?.publicKey && body?.grant && !sameKey(presenterKey, known.publicKey)) {
      return debugRefusal(`${claim.name} presented a key we do not hold for it`, claim.name);
    }

    // Replay is bounded rather than prevented: a signed hail asks to be told
    // who we know, so a stale one costs what a fresh one costs. The window
    // exists so a captured request is not useful indefinitely.
    const age = Math.abs(Date.now() - (Number(claim.at) || 0));
    if (!Number.isFinite(age) || age > FRESHNESS_MS) return debugRefusal(`stale hail from ${claim.name}`, claim.name);

    return { name: claim.name, key: presenterKey, known: known ?? null };
  };

  /**
   * Whether a proven caller may do this particular thing.
   *
   * @param {any} body
   * @param {string} [capability]
   */
  const authenticate = (body, capability = HAIL) => {
    const proven = identify(body);
    if (!proven) return null;
    const { name, key, known } = proven;

    if (known && directory.allowsCapability(name, capability)) return known;

    const viaGrant = grantAllows(body, key, capability);
    if (viaGrant) {
      log(`[grant] ${name} used ${viaGrant.issuer}'s grant for ${capability}`);
      return known ?? { name, publicKey: key, viaGrant: viaGrant.issuer };
    }
    return debugRefusal(`${name} has no ${capability} capability`, name);
  };

  /**
   * How to refuse: from what we proved, never from what was claimed.
   *
   * `rejectionProfile` used to resolve the *claimed* name before any signature
   * was checked, which handed anyone a one-bit question they had not earned —
   * a silent close meant "that name is blocked here", a 403 meant it was not.
   * Names could be enumerated with no credential at all.
   *
   * A caller who proves nothing is dropped, identically every time, which is
   * what `drop` is for: the peer you most want to be invisible to is the one
   * who cannot say who they are. A caller who proves who they are gets the
   * style their own profile calls for — a real peer with a real misconfiguration
   * should see a refusal rather than debug a phantom network fault.
   *
   * @param {any} body
   */
  const refusalStyle = (body) => {
    const proven = identify(body);
    if (!proven) return BLOCKED_PROFILE;
    return directory.effectiveProfile(proven.name).profile;
  };

  /**
   * Change the directory, durably.
   *
   * A host that persists supplies this, and is expected to apply the mutation
   * to *current* state rather than to whatever it loaded at startup. That
   * matters because this daemon is not the only writer: someone at a terminal
   * changes the same file, and a change applied to a stale copy silently
   * discards theirs.
   *
   * Without one, changes are in-memory only — which is right for an embedder
   * that has its own storage, or none.
   *
   * @param {(directory: any) => any} mutate
   */
  const change = (mutate) => (applyChange ? applyChange(mutate) : mutate(directory));

  // Resolved once: a route table that changes per request is one nobody can
  // reason about, and a conflict is worth refusing at startup rather than
  // settling by whichever plugin happened to be listed first.
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
        if (!caller) return turnAway(response, refusalStyle(body));

        const result = await pluginRoute.handler({ body, caller, directory, identity, log });
        if (result && result[REFUSE]) {
          // The plugin decided against it; the host still owns how that looks,
          // so a refusal from a plugin is indistinguishable from any other.
          if (result.reason) log(`[${pluginRoute.plugin}] refused: ${result.reason}`);
          return turnAway(response, refusalStyle(body));
        }
        return send(response, 200, result ?? {});
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
        const list = change((peers) =>
          body.blocked === false
            ? peers.unblock(body.name)
            : peers.block(peers.get(body.name) ?? { name: body.name }),
        );
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
        const admitted = change((peers) =>
          peers.admit(body, ...(typeof body?.profile === "string" ? [{ profile: body.profile }] : [])),
        );
        if (!admitted) return send(response, 400, { error: "a name is required" });
        return send(response, 200, admitted);
      }

      if (url.pathname === "/api/peers" && request.method === "DELETE") {
        const name = url.searchParams.get("name");
        const forgotten = name ? change((peers) => peers.forget(name)) : false;
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
