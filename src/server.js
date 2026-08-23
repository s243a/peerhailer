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

import { normalizeKey, sameKey, verifyPayload } from "./identity.js";
import { signRecord } from "./peerRecord.js";
import { collectRoutes, REFUSE } from "./plugins.js";
import { verifyGrant } from "./grants.js";
import { isBlocked } from "./trust.js";
import {
  BLOCKED_PROFILE,
  DELEGATE,
  DIRECTORY,
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
 *   allowedOrigins?: string[],
 *   onReload?: () => any | Promise<any>,
 *   applyChange?: (mutate: (directory: any) => any) => any,
 *   log?: (message: string) => void,
 * }} options
 */
export function createDaemon({
  directory,
  identity,
  profiles: initialProfiles = {},
  diagnostics,
  plugins: initialPlugins = [],
  /**
   * Origins allowed to use the control API from a browser. Empty by default:
   * a page you did not write has no business admitting peers, and the common
   * case is the page this daemon serves itself, which is same-origin.
   *
   * Anyone building their own front end names theirs here, and gets the CORS
   * headers that make it work — an allowlist without them would refuse in the
   * browser while appearing to permit.
   */
  allowedOrigins = [],
  onReload,
  applyChange,
  log = () => {},
}) {
  // Rebindable by `reload`, so declaring a tunnel or a command does not cost a
  // restart. Declared here rather than beside their first use, because a `let`
  // below its first reference is a temporal dead zone error that a syntax check
  // does not catch.
  let plugins = initialPlugins;
  let profiles = initialProfiles;

  /**
   * Every runtime mutation goes through here: applied to what is on disk now,
   * then adopted in memory. Declared before its users rather than after,
   * because reaching past it is how a change ends up memory-only.
   *
   * @param {(directory: any) => any} mutate
   */
  const change = (mutate) => (applyChange ? applyChange(mutate) : mutate(directory));

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

    // The subject's own standing, which nothing here used to ask about. A grant
    // records what someone was allowed when it was minted; blocking says what
    // they are allowed now, and precedence rule one is that blocked beats
    // everything "whatever else says otherwise". A grant is an accelerator for a
    // peer nobody has admitted, never an override for a peer somebody refused.
    //
    // Until this existed the hole was bounded only by the five-minute TTL: block
    // a peer holding a fresh grant and it kept working until the clock ran out.
    // That also makes the TTL a policy choice rather than the only defence.
    // Blocking is the instrument here, and only blocking. Demoting a peer does
    // *not* revoke a grant it already holds: the grant records what an issuer
    // allowed, expiry bounds how long that lasts, and block is what says "now".
    // Worth stating because a renewal loop lives on this path, and somebody will
    // try to end a tunnel by demoting its subject and be wrong.
    const subject = { publicKey: checked.grant.subjectKey, name: body?.from?.name };
    if (isBlocked(directory.blocklist(), subject)) {
      debugRefusal(`grant presented by a blocked peer`, body?.from?.name ?? "unnamed");
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

    // The rest of the list gets the same treatment, because the rest of the
    // list is now consumed. Checking only the requested capability was right
    // while that was all anyone read; once a route may ask what else the grant
    // carries, an unchecked entry is an issuer delegating something it does not
    // hold — escalation with extra steps, which is the thing grants refuse.
    //
    // Filtered rather than refused, so a grant naming one capability the issuer
    // has since lost still confers the others: when an issuer's standing
    // shrinks, every outstanding grant shrinks with it at next use.
    const conferrable = (checked.grant.capabilities ?? []).filter((held) =>
      directory.allowsCapability(issuer.name, held),
    );
    return { ...checked.grant, capabilities: conferrable };
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
   * One channel remains, and is left open knowingly: a claimed name that hits
   * `admitted` with a key costs a signature check, one that misses returns at
   * once. Status is uniform — every unproven caller is dropped — but the time
   * taken still says whether a name is in this directory. Tens of microseconds,
   * measurable across loopback and lost in the jitter of any real network, so
   * it is recorded rather than defended against. Verify it on two machines
   * before treating it as either real or theoretical.
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
    // A peer admitted by address with no key yet, and presenting no grant, has
    // nothing to be checked against and is refused. That resolves itself on the
    // first verified `walk` contact, which binds the key — but until then a
    // keyless peer cannot hail in, which reads like a bug when you meet it.
    const presenterKey = known?.publicKey ?? body?.grant?.grant?.subjectKey ?? null;
    if (!presenterKey) {
      return debugRefusal(`unknown peer ${claim.name}, and no grant naming a key`, claim.name);
    }
    if (!verifyPayload(claim, body?.signature, presenterKey)) {
      // Deliberately not recorded as a key conflict. Two reasons, and both were
      // learned by writing it the other way first: on this path `presenterKey`
      // *is* the held key, so the call compared a key with itself and recorded
      // nothing — and a hail carries `{name, at}`, so the signer's actual key
      // appears nowhere for us to record even in principle. `walk` can do this
      // because the signed record carries the competing key; here there is none.
      //
      // Worse, `change` writes whether or not a mutation changes anything, so
      // the no-op call meant a full state-file write for every failed signature
      // — from anyone who knows an admitted peer's name, which gossip publishes.
      //
      // The event is not lost: `debugRefusal` records it in diagnostics, which
      // is in memory, bounded, and what a debug window is for.
      return debugRefusal(`signature from ${claim.name} did not verify`, claim.name);
    }
    // Compare the grant's own subject against the key we hold. Comparing
    // `presenterKey` could never fail: it *is* the held key whenever we have
    // one, so the old form was a check that never fired.
    const grantSubject = body?.grant?.grant?.subjectKey;
    if (known?.publicKey && grantSubject && !sameKey(grantSubject, known.publicKey)) {
      return debugRefusal(`${claim.name} presented a key we do not hold for it`, claim.name);
    }

    // Replay is bounded rather than prevented: a signed hail asks to be told
    // who we know, so a stale one costs what a fresh one costs. The window
    // exists so a captured request is not useful indefinitely.
    const age = Math.abs(Date.now() - (Number(claim.at) || 0));
    if (!Number.isFinite(age) || age > FRESHNESS_MS) return debugRefusal(`stale hail from ${claim.name}`, claim.name);

    // First contact proves possession of this key, which is the same evidence
    // `walk` binds on. Binding here closes a window: an admitted peer with no
    // key yet had its *name* available to anyone holding any valid grant —
    // claim the name, sign with your own key, and `presenterKey` falls back to
    // the grant's subject, so the signature verifies and the keyless peer's
    // profile is inherited. `bindKey` never replaces a key already held, so
    // this can only ever fill a blank.
    if (known && !known.publicKey) {
      // Through `change`, like every other mutation this daemon makes at
      // runtime. Calling the directory straight left the binding in memory
      // only: a restart un-bound it and reopened the window this closes, and it
      // reintroduced exactly the disk divergence that made a daemon overwrite a
      // second terminal's work.
      change((peers) => peers.bindKey(claim.name, presenterKey));
    }

    // Normalized here, once, because a PEM carries whitespace that is not part
    // of the key and a grant-path caller supplies its own. Anything downstream
    // that buckets by this string — a rate limit, a history — would otherwise
    // count one key as many, and the caller chooses how many.
    return {
      name: claim.name,
      key: normalizeKey(presenterKey) ?? presenterKey,
      known: directory.get(claim.name) ?? known ?? null,
    };
  };

  /**
   * Whether a proven caller may do this particular thing.
   *
   * Takes the identity rather than deriving it, so one request costs one
   * verification and leaves one trace.
   *
   * @param {{name: string, key: string, known: any} | null} proven
   * @param {any} body
   * @param {string} [capability]
   */
  const authenticate = (proven, body, capability = HAIL) => {
    if (!proven) return null;
    const { name, key, known } = proven;

    if (known && directory.allowsCapability(name, capability)) return known;

    const viaGrant = grantAllows(body, key, capability);
    if (viaGrant) {
      log(`[grant] ${name} used ${viaGrant.issuer}'s grant for ${capability}`);
      // The grant's capabilities travel with the caller. Without them a route
      // could only ask about the caller's *profile*, so a peer let in by a
      // signed, scoped, expiring grant was strictly weaker than one holding an
      // assignment — which inverts what a grant is: a peer nobody admitted,
      // vouched for deliberately.
      return {
        // `key` arrives normalized from `identify`, so a plugin bucketing on it
        // counts one key once however the caller spelled it.
        ...(known ?? { name, publicKey: key }),
        viaGrant: viaGrant.issuer,
        grantedCapabilities: [...(viaGrant.capabilities ?? [])],
      };
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
   * Takes an already-proven identity rather than a body: verifying twice
   * charged every failed hail two entries in a fifty-deep diagnostics history,
   * halving what a person could actually read back, and paid for a second
   * signature check to learn nothing new.
   *
   * @param {{name: string} | null} proven
   */
  const refusalStyle = (proven) =>
    proven ? directory.effectiveProfile(proven.name).profile : BLOCKED_PROFILE;

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

  // Resolved once: a route table that changes per request is one nobody can
  // reason about, and a conflict is worth refusing at startup rather than
  // settling by whichever plugin happened to be listed first.
  // Rebuildable, because declaring a tunnel or a command should not cost a
  // restart. Restarting a daemon is not something a daemon can do to itself
  // without a supervisor, and it would throw away the run history and every open
  // tunnel to pick up one line of configuration.
  let pluginRoutes = collectRoutes(plugins, { log });

  /**
   * Refuse anything a web page could have sent on your behalf.
   *
   * Binding to loopback keeps the network out. It does nothing about the
   * browser you are already running: any page you visit can issue a request to
   * `127.0.0.1`, and while the reply is unreadable to it, the *effect* lands.
   * A `text/plain` POST admitted a peer as `trusted` in one line of `fetch`.
   *
   * Two checks, both cheap. Requiring `application/json` makes a state-changing
   * request non-simple, so a browser must preflight it — and we answer no
   * preflight, so it is never sent. Refusing a foreign `Origin` covers what is
   * left, including a page that finds another way to shape the request.
   *
   * Neither is authentication. They are the difference between a local API and
   * an API every website can reach.
   *
   * @param {import("node:http").IncomingMessage} request
   */
  const cameFromAPage = (request) => {
    // A hostname we never bound means somebody pointed a name at us.
    const hostHeader = String(request.headers.host ?? "");
    const hostname = hostHeader.replace(/:\d+$/, "").toLowerCase();
    if (!controlNames.has(hostname)) return true;

    const origin = request.headers.origin;
    if (typeof origin === "string" && origin !== "" && !isOwnOrigin(origin, request)) {
      return !allowedOrigins.includes(origin);
    }

    const method = request.method ?? "GET";
    if (method === "GET" || method === "HEAD") return false;

    // Only `application/json` is preflighted; the simple types are what a page
    // may send without asking us first.
    const type = String(request.headers["content-type"] ?? "").split(";")[0]?.trim().toLowerCase();
    return type !== "application/json";
  };

  /**
   * @param {string} origin
   * @param {import("node:http").IncomingMessage} request
   */
  const isOwnOrigin = (origin, request) => {
    const host = request.headers.host;
    if (!host) return false;
    try {
      return new URL(origin).host === host;
    } catch {
      return false;
    }
  };

  /**
   * The request handler, told which door this arrived at.
   *
   * `control` serves the page and `/api/*`, which hold no authentication of
   * their own and are therefore bound to loopback and nowhere else. `hail`
   * serves plugin routes, which authenticate every caller, and is the only
   * scope safe to expose on a network.
   *
   * Two listeners rather than a check inside one handler: a conditional can be
   * got wrong, and being wrong once is enough. Here the control API is simply
   * not listening on the external interface, so there is nothing to reach.
   *
   * @param {"control" | "hail"} scope
   * @returns {import("node:http").RequestListener}
   */
  const handlerFor = (scope) => async (request, response) => {
    const url = new URL(request.url ?? "/", "http://localhost");

    try {
      const pluginRoute = pluginRoutes.get(`${request.method} ${url.pathname}`);
      if (pluginRoute) {
        const body = JSON.parse((await readBody(request)) || "{}");
        // Authentication and capability happen here, in the core, before the
        // plugin is reached. A plugin cannot opt out of this, which is what
        // makes loading one a smaller decision than writing one.
        // Identity is established once. Whether it suffices, and how to refuse
        // if it does not, are both answered from that one result.
        const proven = identify(body);
        const caller = authenticate(proven, body, pluginRoute.capability);
        if (!caller) return turnAway(response, refusalStyle(proven));

        const result = await pluginRoute.handler({ body, caller, directory, identity, log });
        if (result && result[REFUSE]) {
          // The plugin decided against it; the host still owns how that looks,
          // so a refusal from a plugin is indistinguishable from any other.
          if (result.reason) log(`[${pluginRoute.plugin}] refused: ${result.reason}`);
          return turnAway(response, refusalStyle(proven));
        }
        return send(response, 200, result ?? {});
      }

      const origin = String(request.headers.origin ?? "");
      const namedOrigin = scope === "control" && origin !== "" && allowedOrigins.includes(origin);
      if (namedOrigin) {
        response.setHeader("access-control-allow-origin", origin);
        response.setHeader("vary", "origin");
        if (request.method === "OPTIONS") {
          // The preflight. Answered only for origins someone named; every other
          // page gets no answer and so never sends the request itself.
          response.setHeader("access-control-allow-methods", "GET, POST, DELETE, OPTIONS");
          response.setHeader("access-control-allow-headers", "content-type");
          response.writeHead(204);
          response.end();
          return;
        }
      }

      // Anything added below must also be reserved in `plugins.js`, or a plugin
      // can claim the path and answer it outside this guard.
      //
      // Only what this door actually serves. Guarding everything meant an
      // unknown path answered "refused" rather than "no such thing", which says
      // something about this machine that a 404 does not.
      const controlPath = url.pathname === "/" || url.pathname.startsWith("/api/");
      if (scope === "control" && controlPath && cameFromAPage(request)) {
        // Said plainly, because a silent 403 here reads as a bug in the page.
        log(`[api] refused a cross-origin ${request.method} ${url.pathname}`);
        return send(response, 403, {
          error: "refused: send application/json from this page's own origin",
        });
      }

      if (scope === "control" && url.pathname === "/" && request.method === "GET") {
        // Same loopback address as the API it reads. A page that can admit
        // peers has no business being reachable from anywhere else.
        response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        response.end(
          renderPage({ name: directory.self.name, fingerprint: fingerprint(identity.publicKey) }),
        );
        return;
      }

      if (scope === "control" && url.pathname === "/api/profiles" && request.method === "GET") {
        return send(response, 200, listProfiles(profiles));
      }

      if (scope === "control" && url.pathname === "/api/block" && request.method === "POST") {
        const body = JSON.parse((await readBody(request)) || "{}");
        if (typeof body?.name !== "string") return send(response, 400, { error: "a name is required" });
        const list = change((peers) =>
          body.blocked === false
            ? peers.unblock(body.name)
            : peers.block(peers.get(body.name) ?? { name: body.name }),
        );
        return send(response, 200, list);
      }

      if (scope === "control" && url.pathname === "/api/peers" && request.method === "GET") {
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

      // Pick up configuration changed at another terminal.
      //
      // On the control door only: it changes what peers may reach, so it is a
      // local decision, not one a peer makes. The host supplies the rebuilding,
      // because only the host knows how its plugins are constructed.
      if (scope === "control" && url.pathname === "/api/reload" && request.method === "POST") {
        if (!onReload) return send(response, 501, { error: "this host cannot reload" });
        // The body is read and discarded even though nothing uses it: an unread
        // body on a keep-alive connection leaves bytes for the next parse.
        await readBody(request).catch(() => "");
        try {
          return send(response, 200, await onReload());
        } catch (error) {
          return send(response, 500, { error: String(error instanceof Error ? error.message : error) });
        }
      }

      // What peers have actually run here.
      //
      // Kept in the daemon's memory rather than the directory file, because a
      // record of who ran what is not a credential and not a peer — and because
      // writing per run is how a state file becomes an amplification target.
      // That makes this page the only place it can be read, which is the whole
      // reason the route exists: a record nothing surfaces reads as covered
      // while telling nobody anything.
      if (scope === "control" && url.pathname === "/api/command-history" && request.method === "GET") {
        const entries = plugins
          .flatMap((plugin) => (typeof plugin.history === "function" ? plugin.history() : []))
          .map((entry) => ({
            capability: entry.capability,
            // A fingerprint, not the key: this is for recognising a peer, and a
            // page full of PEMs is a page nobody reads.
            peer: entry.peerKey ? fingerprint(entry.peerKey) : "unknown",
            at: entry.at,
            outcome: entry.outcome,
          }))
          .sort((left, right) => (right.at ?? 0) - (left.at ?? 0));
        return send(response, 200, { entries });
      }

      // What this machine offers, as it knows itself. Locally sourced: nothing
      // advertises its abilities over the wire yet, which is the namespace
      // design's job — see docs/shared-namespace.md.
      if (scope === "control" && url.pathname === "/api/plugins" && request.method === "GET") {
        return send(response, 200, {
          plugins: plugins.map((plugin) => ({
            name: plugin.name,
            description: plugin.description ?? "",
            capabilities: plugin.capabilities ?? [],
            routes: (plugin.routes ?? []).map((route) => ({
              method: route.method,
              path: route.path,
              capability: route.capability,
            })),
          })),
        });
      }

      // What a caller actually receives, gate by gate. Rendering this is the
      // only honest way to check the rules: `hail` is answered at all,
      // `directory` is answered with the peer list, and a profile holding
      // neither gets nothing. Describing that is not the same as showing it.
      if (scope === "control" && url.pathname === "/api/shared" && request.method === "GET") {
        const profileName = url.searchParams.get("profile") ?? "";
        const known = listProfiles(profiles).find((entry) => entry.name === profileName);
        if (!known) return send(response, 404, { error: `no profile called ${profileName}` });

        const mayHail = (known.allows ?? []).includes(HAIL);
        const maySeePeers = (known.allows ?? []).includes(DIRECTORY);
        const answer = directory.hailResponse();
        return send(response, 200, {
          profile: known.name,
          allows: known.allows ?? [],
          gates: { hail: mayHail, directory: maySeePeers },
          receives: mayHail
            ? { self: answer.self, peers: maySeePeers ? answer.peers : [] }
            : null,
        });
      }

      if (scope === "control" && url.pathname === "/api/peers" && request.method === "POST") {
        const body = JSON.parse((await readBody(request)) || "{}");
        const admitted = change((peers) =>
          peers.admit(body, ...(typeof body?.profile === "string" ? [{ profile: body.profile }] : [])),
        );
        if (!admitted) return send(response, 400, { error: "a name is required" });
        return send(response, 200, admitted);
      }

      if (scope === "control" && url.pathname === "/api/peers" && request.method === "DELETE") {
        const name = url.searchParams.get("name");
        const forgotten = name ? change((peers) => peers.forget(name)) : false;
        return send(response, 200, { forgotten });
      }

      return nothingHere(response);
    } catch (cause) {
      log(`[daemon] ${url.pathname} failed: ${cause instanceof Error ? cause.message : String(cause)}`);
      return nothingHere(response);
    }
  };

  /**
   * Names the control door will answer to.
   *
   * Origin and Host agreeing proves nothing on its own: a page at
   * `evil.example` whose DNS answers `127.0.0.1` sends both as `evil.example`,
   * and a check that compares them to each other calls that same-origin. What
   * makes it a rebinding attack is that the browser then treats the reply as
   * readable — so the directory it wanted is handed over.
   *
   * Answering only to names we chose is what closes it: a rebound request
   * carries the attacker's hostname, which is not one of them.
   */
  const controlNames = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

  const control = createServer(handlerFor("control"));
  /** @type {import("node:http").Server[]} */
  const hailServers = [];

  /** @param {import("node:http").Server} target */
  const stop = (target) =>
    new Promise((resolve) => {
      // `server.close` waits for open connections to end on their own, and the
      // page polls on a keep-alive socket — so a daemon with a browser pointed
      // at it never finished closing, and Ctrl-C appeared to do nothing at all.
      // Stopping means stopping.
      target.close(() => resolve(undefined));
      target.closeAllConnections?.();
    });

  return {
    server: control,

    /**
     * Pick up configuration that changed while this was running.
     *
     * Routes, profiles and plugins are read once at startup, and the daemon
     * never re-reads its own state file — so a `hail tunnels add` at another
     * terminal reached disk and not the running process. This is the door for
     * that, without the process ending.
     *
     * Anything a departing plugin was holding is released first: a tunnel whose
     * endpoint was removed should not survive the removal.
     *
     * @param {{plugins?: any[], profiles?: Record<string, any>, state?: any}} next
     */
    reload: ({ plugins: nextPlugins, profiles: nextProfiles, state } = {}) => {
      if (Array.isArray(nextPlugins)) {
        for (const plugin of plugins) plugin.stop?.();
        plugins = nextPlugins;
        pluginRoutes = collectRoutes(plugins, { log });
      }
      if (nextProfiles) {
        profiles = nextProfiles;
        directory.useProfiles(nextProfiles);
      }
      if (state) directory.adopt(state);
      log(`[daemon] reloaded: ${pluginRoutes.size} routes, ${Object.keys(profiles).length} profiles`);
      return { routes: pluginRoutes.size, profiles: Object.keys(profiles).length };
    },
    /** Loopback unless told otherwise: the API admits peers, so it stays local. */
    listen: ({ port = 8787, host = "127.0.0.1" } = {}) =>
      new Promise((resolve) => {
        // Whatever it was told to bind is a name it may answer to.
        controlNames.add(String(host).toLowerCase());
        control.listen(port, host, () => {
          // A TCP listen always yields AddressInfo; the union covers pipes.
          const address = /** @type {import("node:net").AddressInfo} */ (control.address());
          log(`[daemon] control on http://${host}:${address.port} — page and local API`);
          resolve({ port: address.port, host });
        });
      }),

    /**
     * Answer hails on chosen addresses, and nothing else there.
     *
     * A separate listener per address rather than one bound to `0.0.0.0`, so
     * what is exposed is what was named. Plugin routes authenticate every
     * caller; the page and `/api/*` are not served here at all, which is the
     * point — a firewall rule admitting this port admits only hails.
     *
     * An address that cannot be bound is logged and skipped rather than taking
     * the daemon down with it: a laptop whose wifi is not up yet should still
     * answer on its tailnet.
     *
     * @param {{port?: number, hosts: string[]}} options
     */
    listenHail: async ({ port = 8787, hosts }) => {
      /** @type {{host: string, port: number}[]} */
      const bound = [];
      for (const host of hosts) {
        const server = createServer(handlerFor("hail"));
        try {
          await new Promise((resolve, reject) => {
            server.once("error", reject);
            server.listen(port, host, () => resolve(undefined));
          });
          const address = /** @type {import("node:net").AddressInfo} */ (server.address());
          hailServers.push(server);
          bound.push({ host, port: address.port });
          log(`[daemon] hails on http://${host}:${address.port}`);
        } catch (error) {
          log(`[daemon] not listening on ${host}: ${error instanceof Error ? error.message : error}`);
        }
      }
      return bound;
    },

    close: async () => {
      await Promise.all(hailServers.map(stop));
      hailServers.length = 0;
      await stop(control);
    },
  };
}
