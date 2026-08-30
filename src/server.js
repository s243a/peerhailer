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
import { createServer as createHttpsServer } from "node:https";

import { normalizeKey, sameKey, verifyPayload } from "./identity.js";
import { selfSignedCert, certVouchedBy } from "./cert.js";
import { signRecord, TARGET_BINDING_VERSION } from "./peerRecord.js";
import { collectRoutes, REFUSE } from "./plugins.js";
import { verifyGrant } from "./grants.js";
import { isBlocked } from "./trust.js";
import {
  BLOCKED_PROFILE,
  DELEGATE,
  DIRECTORY,
  DIAGNOSTICS,
  HAIL,
  isAssignableProfile,
  listProfiles,
  rejectionFor,
} from "./profiles.js";
import { randomUUID } from "node:crypto";
import { fingerprint } from "./identity.js";
import { renderPage } from "./ui.js";
import { createComposer } from "./composer.js";
import { callPeer } from "./hail.js";
import { forwardTunnel } from "./tunnelClient.js";
import { mountShare } from "./filesMount.js";
import { seal } from "./sealing.js";
import { MAX_MESSAGE } from "./builtin/chatPlugin.js";
import { RoutedMessageInputError } from "./routedMessage.js";

const MAX_BODY = 1_000_000;
/** How stale a signed hail may be. Generous: clocks drift, and this is not a nonce. */
const FRESHNESS_MS = 5 * 60_000;

/** The request body exceeded {@link MAX_BODY} — a 413 on the control API. */
class RequestTooLarge extends Error {}
/** The request body was not valid JSON — a 400 on the control API. */
class MalformedRequest extends Error {}

/**
 * @param {import("node:http").IncomingMessage} request
 * @returns {Promise<string>}
 */
function readBody(request) {
  return new Promise((resolve, reject) => {
    // Reject an over-declared body before reading a byte of it, without destroying
    // the socket — so a caller can still be answered (a 413 on the control API).
    // The streaming guard below stays for a body that under-declares or omits its
    // length: that one is dropped (socket destroyed) rather than answered.
    const declared = Number(request.headers["content-length"]);
    if (Number.isFinite(declared) && declared > MAX_BODY) {
      reject(new RequestTooLarge("body too large"));
      return;
    }
    let size = 0;
    /** @type {Buffer[]} */
    const chunks = [];
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new RequestTooLarge("body too large"));
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
 * Read and parse a JSON request body, as a typed operation. An empty body is `{}`
 * (the routes all treat a missing field as absent). The two failure modes are
 * *typed* — {@link RequestTooLarge} (from `readBody`) and {@link MalformedRequest}
 * — so the caller can answer each with the right status where that is wanted (the
 * control API) and conceal it where it is not (a peer-facing plugin route).
 *
 * @param {import("node:http").IncomingMessage} request
 * @returns {Promise<any>}
 */
async function readJson(request) {
  const raw = await readBody(request);
  try {
    return JSON.parse(raw || "{}");
  } catch {
    throw new MalformedRequest("request body is not valid JSON");
  }
}

/**
 * @param {{
 *   directory: ReturnType<typeof import("./directory.js").createDirectory>,
 *   identity: {publicKey: string, privateKey: string},
 *   profiles?: Record<string, any>,
 *   diagnostics?: ReturnType<typeof import("./diagnostics.js").createDiagnostics>,
 *   plugins?: import("./plugins.js").Plugin[],
 *   allowedOrigins?: string[],
 *   requireTargetBinding?: boolean,
 *   onReload?: () => any | Promise<any>,
 *   applyChange?: (mutate: (directory: any) => any) => any,
 *   gateConfig?: () => ({ passwordHash: string, secret: string } | null | undefined),
 *   tunnelPipeCommand?: any,
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
  /**
   * Require every hail to name its target — the fully-closed state of the
   * target-binding migration (docs/hail-target-binding.md). Off by default so a
   * mixed fleet still interoperates: a hail from a caller not yet known to bind
   * is accepted `to`-less, while a *present* `to` is always checked and a
   * grant-bearing hail always requires one. Turn on once every peer that hails
   * this machine speaks v1, and the residual `to`-less path closes entirely.
   */
  requireTargetBinding = false,
  onReload,
  applyChange,
  /** Session composer: whether a gate password is set, for the optional bastion. */
  gateConfig = () => null,
  /** Builds `{command,args}` for `hail tunnel <peer> <name> pipe` — enables remote workers. */
  tunnelPipeCommand = null,
  log = () => {},
}) {
  // Our own fingerprint, computed once: the value a bound hail's `to` must
  // equal. Null only without an identity, a degenerate setup in which we cannot
  // enforce binding at all.
  const selfFingerprint = identity?.publicKey ? fingerprint(identity.publicKey) : null;
  // Rebindable by `reload`, so declaring a tunnel or a command does not cost a
  // restart. Declared here rather than beside their first use, because a `let`
  // below its first reference is a temporal dead zone error that a syntax check
  // does not catch.
  let plugins = initialPlugins;
  let profiles = initialProfiles;
  // The resolvable profile set, read from the directory when it exposes one so
  // listing, assignment validation, and rejection style never lag behind
  // resolution — a `profiles remove` applied through `applyChange` updates the
  // directory's set, and reading it here keeps the page's offered/accepted set in
  // step. Falls back to the local `profiles` (still set by `reload`) if a host
  // wired an older directory without the accessor.
  const currentProfiles = () => directory.currentProfiles?.() ?? profiles;

  // The fabric seam for the composer: enumerate peers' offers and start/stop a
  // worker service on one, all via the same signed `callPeer` the CLI uses.
  // Present only when the host can build a tunnel-pipe command (bin/hail.js does).
  const asSelf = () => ({ name: directory.self?.name, publicKey: identity?.publicKey, privateKey: identity?.privateKey });
  const callNode = (/** @type {string} */ name, /** @type {string} */ path, /** @type {any} */ body) => {
    const record = directory.get?.(name);
    return record ? callPeer(record, path, body, { as: asSelf() }) : Promise.resolve({ ok: false, error: "unknown peer" });
  };
  const raceTimeout = (/** @type {Promise<any>} */ promise, /** @type {number} */ ms) =>
    Promise.race([promise, new Promise((resolve) => setTimeout(() => resolve({ ok: false, error: "timeout" }), ms))]);
  const fabric = tunnelPipeCommand
    ? {
        tunnelPipeCommand,
        startRemote: (/** @type {string} */ peer, /** @type {string} */ service) => callNode(peer, `/service/${service}/start`, {}),
        stopRemote: (/** @type {string} */ peer, /** @type {string} */ service, /** @type {any} */ id) => callNode(peer, `/service/${service}/stop`, { id }),
        // Run a declared command on a peer and hand back its captured stdout —
        // used to mint a T3 pairing grant on the remote (command:pair).
        runCommand: (/** @type {string} */ peer, /** @type {string} */ name) => callNode(peer, `/command/${name}/run`, {}),
        // Forward a peer's tunnel to a fresh local TCP port. forwardSeat is this
        // for the supervisor seat; forward is the general case (the remote T3's
        // origin, which serves HTTP+WS together, for T3-to-T3 remote control).
        forward: (/** @type {string} */ peer, /** @type {string} */ tunnel) => {
          const record = directory.get?.(peer);
          if (!record) return Promise.reject(new Error("unknown peer"));
          const call = (/** @type {string} */ path, /** @type {any} */ body) => callPeer(record, path, body, { as: asSelf() });
          return forwardTunnel(call, tunnel, { port: 0, log });
        },
        forwardSeat: (/** @type {string} */ peer, /** @type {string} */ seatTunnel) => {
          const record = directory.get?.(peer);
          if (!record) return Promise.reject(new Error("unknown peer"));
          const call = (/** @type {string} */ path, /** @type {any} */ body) => callPeer(record, path, body, { as: asSelf() });
          return forwardTunnel(call, seatTunnel, { port: 0, log });
        },
        listNodes: async () => {
          const admitted = directory.listAdmitted?.() ?? [];
          const nodes = await Promise.all(
            admitted.map(async (peer) => {
              const r = await raceTimeout(callNode(peer.name, "/offers", {}), 4000);
              return r?.ok
                ? { peer: peer.name, reachable: true, offers: r.response?.offers ?? [] }
                : { peer: peer.name, reachable: false, error: r?.error ?? "unreachable" };
            }),
          );
          return { self: directory.self?.name ?? null, nodes };
        },
      }
    : null;

  // Local-first-plus-fabric session composer: spawns/tracks T3 (+ gate) children,
  // and can start a worker on a peer. Loopback control routes below drive it.
  const composer = createComposer({ gateConfig, identity, log, fabric });
  /** mountId -> { peer, share, url, close } — active WebDAV mounts of peer shares. */
  const mounts = new Map();

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
    if (rejectionFor(profileName, currentProfiles()) === "drop") {
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

    // Target binding. `claim.to` is signed (it is inside `from`, which the
    // signature above covered), so an attacker cannot strip or alter it without
    // breaking the signature — the only `to`-less bytes they can replay are ones
    // the caller genuinely signed without a `to`, i.e. an old caller.
    //
    // The rule, fail-closed in every branch:
    //  - `to` present  → it must be us. A captured hail names its target and is
    //    inert if replayed at any other peer. Enforced the moment both sides
    //    speak v1, with no migration step.
    //  - `to` absent + a grant → refuse. A grant-presenter may carry no record
    //    for us to learn its support from, and a grant is the highest-value
    //    replay target, so `to` is mandatory on any grant-bearing hail from day
    //    one — nothing to migrate.
    //  - `to` absent + caller known to bind (sticky, signed observation) →
    //    refuse. This closes the downgrade: a replayed old-style hail from a
    //    caller we have since seen sign `to` is not accepted.
    //  - `to` absent + require-target-binding on → refuse. The flag-day state.
    //  - otherwise tolerated: a genuinely old caller we have no support signal
    //    for. The residual the migration shrinks to zero.
    const to = claim.to;
    const carriesGrant = Boolean(body?.grant);
    let callerBoundToUs = false;
    if (typeof to === "string" && to.length > 0) {
      // Fail closed if we cannot check it: a present `to` we cannot compare
      // (no identity of our own) is refused, not waved through. Such a daemon
      // cannot sign a hail response either, so this only ever bites a degenerate
      // setup — in the safe direction.
      if (!selfFingerprint || to !== selfFingerprint) {
        return debugRefusal(`hail from ${claim.name} was addressed to another peer`, claim.name);
      }
      callerBoundToUs = true;
    } else if (carriesGrant) {
      return debugRefusal(`grant-bearing hail from ${claim.name} named no target`, claim.name);
    } else if (known?.bindingSeen) {
      return debugRefusal(`hail from ${claim.name} named no target, but ${claim.name} binds`, claim.name);
    } else if (requireTargetBinding) {
      return debugRefusal(`hail from ${claim.name} named no target`, claim.name);
    }

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

    // Learn "this caller binds targets" from the hail itself. A correct `to` is
    // signed proof the caller's client computes our fingerprint and signs it —
    // the same fact a `walk` would read from its record's version, but observed
    // here in real time and without dialing anyone, so it needs no MagicDNS and
    // no reload. That closes the gap where the running daemon only learned
    // support from a CLI walk: from the first correctly-bound hail on, a later
    // `to`-less hail from this caller is refused as a downgrade. Through
    // `change` so it persists and is immediate; guarded so only that first hail
    // writes, never one per request.
    if (callerBoundToUs && known && (known.bindingSeen ?? 0) < TARGET_BINDING_VERSION) {
      change((peers) => peers.noteBinding(claim.name, TARGET_BINDING_VERSION));
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
   * @param {{ encryptedArrival?: boolean | (() => boolean), requireClientCert?: boolean, arrivalMutual?: boolean | (() => boolean) }} [options]
   * @returns {import("node:http").RequestListener}
   */
  const handlerFor = (scope, { encryptedArrival = false, requireClientCert = false, arrivalMutual = false } = {}) => async (request, response) => {
    /** @type {URL | undefined} */
    let url;
    try {
      // Inside the try: Node's HTTP parser accepts request-targets that `new URL`
      // rejects (e.g. `GET //[ HTTP/1.1`), and a throw here on the arrival door is
      // an unhandled rejection that takes the whole daemon down — an unauthenticated
      // remote crash. The catch answers it like any other unmatched request.
      url = new URL(request.url ?? "/", "http://localhost");
      const pluginRoute = pluginRoutes.get(`${request.method} ${url.pathname}`);
      if (pluginRoute) {
        // Evaluated per request: the control door's answer depends on the host
        // it was bound to, which is not known when the handler is created.
        const arrivalEncrypted = typeof encryptedArrival === "function" ? encryptedArrival() : encryptedArrival;
        const arrivalIsMutual = typeof arrivalMutual === "function" ? arrivalMutual() : arrivalMutual;
        // A route that requires an encrypted arrival is simply not served where
        // arrival is not encrypted — it 404s exactly as an undeclared route
        // would, revealing nothing. This is where the shell plugin's
        // `requiresEncryptedArrival` becomes real: on a plaintext hail listener
        // it is as if the route does not exist, so a plaintext remote shell is
        // impossible rather than merely discouraged. The listener is the only
        // place that knows whether arrival is encrypted, so the check lives here.
        if (pluginRoute.requiresEncryptedArrival && !arrivalEncrypted) return nothingHere(response);
        // The strongest routes (the shell) ask for a *mutual* arrival: mutual
        // TLS, where the caller's identity is bound to the socket, or a
        // trusted-local (loopback) one where binding is moot. A merely-encrypted
        // door — a provided-cert listener a browser reaches, or a tailnet address
        // bound directly — carries the pre-TLS replay posture (a captured hail
        // replays within the freshness window), so a shell is not served there.
        if (pluginRoute.requiresEncryptedArrival === "mutual" && !arrivalIsMutual) return nothingHere(response);

        // A plugin route is peer-facing and conceals: a malformed or oversized
        // body reveals nothing beyond "not here", exactly as an unmatched route
        // would — so it is answered that way rather than with a diagnostic status.
        let body;
        try {
          body = await readJson(request);
        } catch {
          return nothingHere(response);
        }
        // Authentication and capability happen here, in the core, before the
        // plugin is reached. A plugin cannot opt out of this, which is what
        // makes loading one a smaller decision than writing one.
        // Identity is established once. Whether it suffices, and how to refuse
        // if it does not, are both answered from that one result.
        const proven = identify(body);
        const caller = authenticate(proven, body, pluginRoute.capability);
        if (!caller) return turnAway(response, refusalStyle(proven));

        // Runs after `authenticate`, not before: the check needs `caller.publicKey`
        // to know whose vouch to require, so it cannot move earlier however tempting.
        // On a TLS arrival, the caller must also present a client cert its own
        // identity vouches for — mutual pinning. This binds the TLS session to
        // the hail's signer: a valid but replayed hail arriving over an
        // attacker's socket lacks that cert, and is refused here even though its
        // signature verifies. `.encrypted` is only true on the TLS listeners, so
        // a plaintext or loopback arrival skips this.
        if (requireClientCert && !certVouchedBy(/** @type {any} */ (request.socket).getPeerCertificate(true), caller.publicKey)) {
          return turnAway(response, refusalStyle(proven));
        }

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
        return send(response, 200, listProfiles(currentProfiles()));
      }

      if (scope === "control" && url.pathname === "/api/block" && request.method === "POST") {
        const body = await readJson(request);
        if (typeof body?.name !== "string") return send(response, 400, { error: "a name is required" });
        const result = change((peers) =>
          body.blocked === false
            ? peers.unblock(body.name)
            : // blockPeer, not a bare block: a candidate's gossiped key is hearsay
              // and is only key-blocked when the caller explicitly confirms it
              // (includeKey) — otherwise it blocks by name, honestly. See directory.
              peers.blockPeer(body.name, { includeKey: body.includeKey === true }),
        );
        return send(response, 200, result);
      }

      if (scope === "control" && url.pathname === "/api/peers" && request.method === "GET") {
        return send(response, 200, {
          self: directory.self,
          // The effective profile travels with each peer: what was assigned is
          // not always what applies, and the page would otherwise show a grant
          // a blocked peer does not have.
          admitted: directory.listAdmitted().map((peer) => {
            const status = directory.profileStatus?.(peer.name);
            return {
              ...peer,
              effective: directory.effectiveProfile(peer.name),
              // Parked = an assigned profile that no longer resolves; surfaced so
              // a demotion to "granted nothing" is visible rather than silent.
              parked: status?.parked ? status.assigned : null,
            };
          }),
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

      // Chat: short in-memory messages to and from admitted peers, surfaced for
      // the page. The chat plugin (present only with --chat) holds them; here we
      // resolve peer names, deliver outgoing over the peer's /chat/send, and
      // record our own side. Text is attacker-chosen — the page MUST escape it.
      const chat = /** @type {any} */ (
        plugins.find(
          (pl) => pl && typeof (/** @type {any} */ (pl).conversations) === "function" && typeof (/** @type {any} */ (pl).say) === "function",
        )
      );
      const chatNames = () => new Map((directory.listAdmitted?.() ?? []).map((peer) => [peer.publicKey, peer.name]));
      // The sealing trust for a peer, with fingerprints of the held and pending
      // keys — so a person resolving a conflict compares two keys, not a bare
      // button. `null` name (an unresolved conversation) is unverified.
      const sealInfo = (/** @type {string | null | undefined} */ name) => {
        if (!name) return { seal: "unverified" };
        const rec = directory.get?.(name);
        return {
          seal: directory.sealState?.(name) ?? "unverified",
          ...(rec?.sealPublicKey ? { sealFp: fingerprint(rec.sealPublicKey) } : {}),
          ...(rec?.sealConflict ? { sealPendingFp: fingerprint(rec.sealConflict) } : {}),
        };
      };
      if (scope === "control" && url.pathname === "/api/chat/state" && request.method === "GET") {
        if (!chat) return send(response, 200, { enabled: false, self: directory.self?.name ?? null, conversations: [], peers: [] });
        const names = chatNames();
        const conversations = chat.conversations().map((/** @type {any} */ c) => {
          const peerName = names.get(c.peerKey);
          return {
            key: c.peerKey,
            name: peerName ?? null,
            fp: fingerprint(c.peerKey),
            count: c.count,
            last: c.last,
            ...sealInfo(peerName),
          };
        });
        // Admitted peers you could start a chat with, even before any message.
        const peers = (directory.listAdmitted?.() ?? []).map((peer) => ({ name: peer.name, ...sealInfo(peer.name) }));
        return send(response, 200, { enabled: true, self: directory.self?.name ?? null, conversations, peers });
      }
      if (scope === "control" && url.pathname === "/api/chat/thread" && request.method === "GET") {
        if (!chat) return send(response, 200, { messages: [] });
        const record = directory.get?.(url.searchParams.get("peer") ?? "");
        if (!record) return send(response, 404, { error: "unknown peer" });
        return send(response, 200, { messages: chat.thread(record.publicKey) });
      }
      if (scope === "control" && url.pathname === "/api/chat/send" && request.method === "POST") {
        if (!chat) return send(response, 501, { error: "chat is off — start the daemon with --chat" });
        const body = await readJson(request);
        const record = directory.get?.(body?.peer ?? "");
        const text = typeof body?.text === "string" ? body.text : "";
        if (!record) return send(response, 404, { error: "unknown peer" });
        if (!text.trim()) return send(response, 400, { error: "an empty message is not a message" });
        // The same limit the receiver enforces (chatPlugin's MAX_MESSAGE). Checked
        // here too, so an oversized send — from a script, not the UI, which has no
        // length cap — is refused with the reason rather than round-tripping to the
        // peer and coming back as a concealed, generic "the peer did not accept it".
        if (text.length > MAX_MESSAGE) {
          return send(response, 400, { error: `that message is over the ${MAX_MESSAGE}-character limit` });
        }
        // Seal end to end when we hold a *verified* sealing key for the peer:
        // encrypt to it, signed with our identity so the peer authenticates us.
        // `sealKeyFor` returns a key only once a walk bound it from the peer's
        // signed record — a key that merely rode in on gossip is not trusted, so
        // it cannot silently redirect our ciphertext to an introducer's key.
        // Falls back to cleartext only for a peer we have never verified a
        // sealing key for (an older build); once verified, `sealSeen` is sticky
        // and the send stays sealed, so there is no silent downgrade after that.
        // Fail closed rather than ever downgrading a peer we know can seal. Two
        // states forbid a send: `conflict` (two verified keys disagree — a
        // rotation or an attack) and `reverify` (the peer has been sealed to
        // before but the key is currently absent — a rotation, or a stale writer
        // rolled it back). Only a peer we have *never* sealed to falls back to
        // cleartext. A person resolves a conflict with `hail seal accept`.
        const trust = directory.sealState?.(record.name) ?? "unverified";
        if (trust === "conflict" || trust === "reverify") {
          return send(response, 409, {
            error: trust === "conflict"
              ? "this peer's sealing key is in conflict — resolve it with `hail seal accept` before sending"
              : "this peer's sealing key needs re-verifying (walk it) before sending — not downgrading to cleartext",
            sealState: trust,
          });
        }
        const sealKey = directory.sealKeyFor?.(record.name) ?? null;
        let payload;
        let sealed = false;
        if (sealKey) {
          const signer = { publicKey: identity.publicKey, privateKey: identity.privateKey };
          const inner = JSON.stringify({ text, at: Date.now(), nonce: randomUUID() });
          payload = { sealed: seal(inner, sealKey, { signer }) };
          sealed = true;
        } else {
          payload = { text };
        }
        const result = await callNode(record.name, "/chat/send", payload);
        if (!result?.ok) return send(response, 502, { error: result?.error ?? "the peer did not accept the message" });
        // Record on our own copy whether it went sealed, so the sender's UI can
        // show the 🔒 — and, by its absence, a cleartext send to a peer with no
        // verified sealing key.
        const message = chat.say(record.publicKey, text, { sealed });
        return send(response, 200, { ok: true, message, sealed });
      }
      if (scope === "control" && url.pathname === "/api/chat/clear" && request.method === "POST") {
        if (!chat) return send(response, 200, { cleared: false });
        const body = await readJson(request);
        const record = directory.get?.(body?.peer ?? "");
        if (record) chat.forget(record.publicKey);
        return send(response, 200, { cleared: Boolean(record) });
      }

      // Files explorer: browse and transfer with a peer's share through the page.
      // The peer's own plugin enforces the share's root, bounds and read-only-ness;
      // this side only forwards over the signed callPeer path, so nothing new is
      // trusted here. `share` and `op` are validated because they become URL path
      // segments — a peer name and a share name, never a free path.
      if (scope === "control" && url.pathname === "/api/files/browse" && request.method === "POST") {
        const body = await readJson(request);
        const op = ["list", "get", "put", "stat"].includes(body?.op) ? body.op : "list";
        const share = String(body?.share ?? "");
        if (!body?.peer || !/^[a-z0-9][a-z0-9-]*$/i.test(share)) {
          return send(response, 400, { error: "a peer and a valid share name are required" });
        }
        const payload = op === "put" ? { path: String(body?.path ?? ""), data: String(body?.data ?? "") } : { path: String(body?.path ?? "") };
        const r = await callNode(String(body.peer), `/files/${share}/${op}`, payload);
        if (!r?.ok) return send(response, 502, { error: /** @type {any} */ (r)?.error ?? "the peer refused" });
        return send(response, 200, /** @type {any} */ (r).response ?? {});
      }

      // The permissive mode: mount a peer's share as a loopback WebDAV endpoint an
      // external tool or the OS can use. A mount is reachable by every local
      // process, so it is loopback-only and operator-started here on the control
      // door; the peer still gates every read and write.
      if (scope === "control" && url.pathname === "/api/files/mounts" && request.method === "GET") {
        return send(response, 200, { mounts: [...mounts.entries()].map(([id, m]) => ({ mountId: id, peer: m.peer, share: m.share, url: m.url })) });
      }
      if (scope === "control" && url.pathname === "/api/files/mount" && request.method === "POST") {
        const body = await readJson(request);
        const share = String(body?.share ?? "");
        const peer = String(body?.peer ?? "");
        if (!peer || !/^[a-z0-9][a-z0-9-]*$/i.test(share)) return send(response, 400, { error: "a peer and a valid share name are required" });
        if (!directory.get?.(peer)) return send(response, 404, { error: "unknown peer" });
        if (mounts.size >= 8) return send(response, 429, { error: "too many mounts; stop one first" });
        try {
          const call = (/** @type {string} */ path, /** @type {any} */ callBody) => callNode(peer, path, callBody);
          const mount = await mountShare({ call, share, log });
          const mountId = randomUUID();
          mounts.set(mountId, { peer, share, url: mount.url, close: mount.close });
          log(`[mount] ${peer}:${share} mounted at ${mount.url}`);
          return send(response, 200, { mountId, peer, share, url: mount.url });
        } catch (error) {
          return send(response, 500, { error: String(/** @type {any} */ (error)?.message ?? error) });
        }
      }
      if (scope === "control" && url.pathname === "/api/files/mount/stop" && request.method === "POST") {
        const body = await readJson(request);
        const entry = mounts.get(String(body?.mountId ?? ""));
        if (!entry) return send(response, 200, { stopped: false });
        mounts.delete(String(body.mountId));
        try { await entry.close(); } catch {}
        return send(response, 200, { stopped: true });
      }

      // Originate an M1 signed-cleartext multi-hop message. The routing plugin
      // (present only with --route) wraps/authenticates around the pure engine; we
      // hand it a destination identity key and JSON payload and report what came back.
      if (scope === "control" && url.pathname === "/api/route/send" && request.method === "POST") {
        const router = /** @type {any} */ (plugins.find((pl) => pl && typeof (/** @type {any} */ (pl).send) === "function" && pl.name === "route"));
        if (!router) return send(response, 501, { error: "routing is off — start the daemon with --route" });
        const body = await readJson(request);
        if (!body?.dest) return send(response, 400, { error: "a destination key is required" });
        try {
          // Confidential by default: a send with no usable key is refused, never sent in
          // the clear. `public: true` is the explicit opt-out for non-sensitive payloads
          // (and the way a data-free discovery probe is sent).
          const result = await router.send(String(body.dest), body.payload, {
            ttl: body?.ttl,
            budget: body?.budget,
            public: body?.public === true,
          });
          if (result?.reason === "invalid destination identity key") return send(response, 400, { error: result.reason });
          return send(response, 200, result);
        } catch (error) {
          // A control caller can exceed the routed-body ceiling even while the
          // enclosing request remains under MAX_BODY (base64 needs headroom).
          // Everything else — key/record drift, signing/RNG failure, or a delivery
          // callback throwing — is an internal fault and belongs to the generic 500
          // path below, which logs it without exposing details.
          if (error instanceof RoutedMessageInputError) return send(response, 400, { error: error.message });
          throw error;
        }
      }

      // Discover a routed destination's sealing key with a DATA-FREE public probe (no
      // application data leaves this node), then report the pending fingerprint to approve.
      // The routed key store is in-memory in this daemon, so discovery/approval are live
      // control operations, not state-file edits like Tier-0 `hail seal accept`.
      if (scope === "control" && (url.pathname === "/api/route/discover" || url.pathname === "/api/route/seal") && request.method === "POST") {
        const router = /** @type {any} */ (plugins.find((pl) => pl && typeof (/** @type {any} */ (pl).send) === "function" && pl.name === "route"));
        if (!router) return send(response, 501, { error: "routing is off — start the daemon with --route" });
        const body = await readJson(request);
        if (!body?.dest) return send(response, 400, { error: "a destination key is required" });
        const dest = String(body.dest);
        if (url.pathname === "/api/route/discover") {
          try {
            await router.send(dest, null, { public: true });
          } catch (error) {
            if (error instanceof RoutedMessageInputError) return send(response, 400, { error: error.message });
            throw error;
          }
        }
        return send(response, 200, { state: router.routedSealState(dest), detail: router.routedSealDetail(dest) });
      }

      // Approve a discovered Tier-1 key for sealing — the manual gate. Optionally pinned to
      // the fingerprint the operator reviewed, so an approval cannot race a changed key.
      if (scope === "control" && url.pathname === "/api/route/seal-approve" && request.method === "POST") {
        const router = /** @type {any} */ (plugins.find((pl) => pl && typeof (/** @type {any} */ (pl).send) === "function" && pl.name === "route"));
        if (!router) return send(response, 501, { error: "routing is off — start the daemon with --route" });
        const body = await readJson(request);
        if (!body?.dest) return send(response, 400, { error: "a destination key is required" });
        // A pin, if given, must be a real PEM string. Reject a non-string rather than
        // silently treating it as no pin — an intended pin becoming an unpinned approval
        // of whatever key is currently held is a footgun.
        if (body.sealKey !== undefined && typeof body.sealKey !== "string") {
          return send(response, 400, { error: "sealKey must be a PEM string" });
        }
        const result = router.approveRoutedSeal(String(body.dest), typeof body.sealKey === "string" ? body.sealKey : undefined);
        return send(response, result.ok ? 200 : 409, result);
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
        const known = listProfiles(currentProfiles()).find((entry) => entry.name === profileName);
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
        const body = await readJson(request);
        // An unrecognised profile now fails closed (grants nothing), so admitting
        // to one silently would strand the peer — reject it at the door instead.
        if (typeof body?.profile === "string" && !isAssignableProfile(body.profile, currentProfiles())) {
          return send(response, 400, {
            error: body.profile === "blocked" ? "`blocked` is not assignable — use the block control" : `no profile called ${body.profile}`,
          });
        }
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

      // Resolve a sealing conflict deliberately — the operator act a replayable
      // re-walk is not allowed to perform. Routed through `change`, so it applies
      // to current disk state and cannot be rolled back by a stale writer.
      if (scope === "control" && url.pathname === "/api/seal/accept" && request.method === "POST") {
        const body = await readJson(request);
        const name = typeof body?.peer === "string" ? body.peer : "";
        const sealKey = typeof body?.sealKey === "string" && body.sealKey.trim() ? body.sealKey : undefined;
        if (!name || !directory.get?.(name)) return send(response, 404, { error: "unknown peer" });
        const state = directory.sealState?.(name);
        // Accept the presented key for a conflict, or an explicit key to lift a
        // reverify wedge. Never for a verified/unverified peer.
        if (state !== "conflict" && !(state === "reverify" && sealKey)) {
          return send(response, 409, { error: "nothing to accept — resolve a conflict, or pass a key for a reverify", sealState: state });
        }
        const accepted = change((peers) => peers.acceptSealKey(name, sealKey));
        return send(response, 200, { accepted: Boolean(accepted?.sealPublicKey), sealState: directory.sealState?.(name) });
      }

      // The session composer: one-click launch of a local T3 instance whose model
      // is a bridged coding agent, with an optional MCP supervision seat and an
      // optional password bastion. Loopback control only — it spawns processes,
      // so it is far more powerful than the rest of the page: never expose these
      // to a browser origin via --allow-origin.
      if (scope === "control" && url.pathname === "/api/compose/agents" && request.method === "GET") {
        return send(response, 200, composer.agents());
      }
      if (scope === "control" && url.pathname === "/api/compose/nodes" && request.method === "GET") {
        return send(response, 200, await composer.nodes());
      }
      if (scope === "control" && url.pathname === "/api/compose/launch" && request.method === "POST") {
        const body = await readJson(request);
        try {
          return send(response, 200, await composer.launch(body));
        } catch (error) {
          const e = /** @type {any} */ (error);
          return send(response, e?.status ?? 500, { error: String(e?.message ?? error) });
        }
      }
      if (scope === "control" && url.pathname === "/api/compose/seat" && request.method === "GET") {
        return send(response, 200, composer.seat(url.searchParams.get("launchId") ?? ""));
      }
      if (scope === "control" && url.pathname === "/api/compose/stop" && request.method === "POST") {
        const body = await readJson(request);
        return send(response, 200, await composer.stop(body?.launchId));
      }
      // T3-to-T3 remote control: mint a grant on a peer, tunnel its T3 origin
      // here, and hand back a deep link the local T3 client opens to drive it.
      if (scope === "control" && url.pathname === "/api/compose/control" && request.method === "POST") {
        const body = await readJson(request);
        try {
          return send(response, 200, await composer.controlRemote(body));
        } catch (error) {
          const e = /** @type {any} */ (error);
          return send(response, e?.status ?? 500, { error: String(e?.message ?? error) });
        }
      }
      if (scope === "control" && url.pathname === "/api/compose/control/stop" && request.method === "POST") {
        const body = await readJson(request);
        return send(response, 200, await composer.stopControl(body?.controlId));
      }

      return nothingHere(response);
    } catch (cause) {
      // The control API is a loopback management surface: a malformed or oversized
      // request there is the caller's own mistake, and the status that says which —
      // so a script or the page can act on it — beats a blank 404. A hail listener
      // is peer-facing and deliberately conceals: an unexpected throw is answered
      // like any unmatched route, revealing nothing. (Plugin routes conceal their
      // own body errors above, on either listener.)
      // `url` may be undefined if it was the thing that threw — fall back to the
      // raw target so the log never throws a second time inside the catch.
      if (scope === "control") {
        if (cause instanceof RequestTooLarge) return send(response, 413, { error: "request body too large" });
        if (cause instanceof MalformedRequest) return send(response, 400, { error: "request body is not valid JSON" });
        log(`[daemon] ${url?.pathname ?? request.url} failed: ${cause instanceof Error ? cause.message : String(cause)}`);
        return send(response, 500, { error: "internal error" });
      }
      log(`[daemon] ${url?.pathname ?? request.url} failed: ${cause instanceof Error ? cause.message : String(cause)}`);
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

  // The control door counts as an encrypted arrival only while it is loopback —
  // local traffic over `127.0.0.1` needs no wire encryption. Bound to a LAN
  // interface it is neither loopback nor asserted-encrypted, so marked routes
  // (the shell) 404 there rather than being served in cleartext through the door
  // the two-listener split never meant to expose. Set at `listen()` from host.
  let controlLoopback = true;
  const isLoopbackHost = (/** @type {string} */ h) => {
    const s = String(h).toLowerCase();
    return s === "localhost" || s === "::1" || s === "[::1]" || s.startsWith("127.");
  };
  const control = createServer(handlerFor("control", { encryptedArrival: () => controlLoopback, arrivalMutual: () => controlLoopback }));
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
      // This function must never gain an `await`. Its safety is that the swap
      // below is synchronous — single-threaded, so no request handler can see a
      // half-swapped route table. The caller does the async work (rebuilding
      // plugins) *before* calling this; an await moved inside here would reopen
      // exactly that window.
      // Do ALL the potentially-throwing directory work FIRST — a malformed profile set or
      // a malformed `adopt` state both throw — so a bad reload leaves the OLD plugin set
      // (and its policy, e.g. the confidentiality floor) whole, rather than installing a
      // possibly-weaker new set and only then failing. `useProfiles` runs before `adopt`,
      // so malformed profiles are rejected before the directory is touched at all. The
      // plugin swap below cannot throw (collectRoutes logs-and-skips), so once past this
      // block the reload commits cleanly.
      if (nextProfiles) directory.useProfiles(nextProfiles);
      if (state) directory.adopt(state);
      if (nextProfiles) profiles = nextProfiles;
      if (Array.isArray(nextPlugins)) {
        // Build the replacement into a temporary *before* touching any live reference,
        // then swap both at once. Only after the swap are the replaced plugins stopped,
        // best-effort and fire-and-forget (a sync throw or a rejected async stop() must
        // not tear the reload, and awaiting here would break the no-await invariant).
        const nextRoutes = collectRoutes(nextPlugins, { log });
        const oldPlugins = plugins;
        plugins = nextPlugins;
        pluginRoutes = nextRoutes;
        // Stop only the plugins actually retired — an instance carried into the
        // new set (a module-level singleton like `hailPlugin`, or an external
        // plugin that exports an object rather than a factory) is still serving,
        // and stopping it would leave the daemon running a torn-down plugin.
        const retired = oldPlugins.filter((plugin) => !nextPlugins.includes(plugin));
        Promise.allSettled(retired.map((plugin) => Promise.resolve().then(() => plugin.stop?.()))).catch(() => {});
      }
      log(`[daemon] reloaded: ${pluginRoutes.size} routes, ${Object.keys(profiles).length} profiles`);
      // A reload rebuilds plugin instances, so instance-owned state is reset — most
      // notably chat's replay nonce cache and command history. State a host injects
      // from outside the plugin instances is untouched, but only that host knows
      // whether its replacement plugins reuse it (the CLI reports its route guard
      // explicitly after this generic reload completes).
      if (Array.isArray(nextPlugins)) {
        log(`[daemon]          plugin instance state reset (chat replay guard, command history); host-injected state unchanged`);
      }
      return { routes: pluginRoutes.size, profiles: Object.keys(profiles).length };
    },
    /** Loopback unless told otherwise: the API admits peers, so it stays local. */
    listen: ({ port = 8787, host = "127.0.0.1" } = {}) =>
      new Promise((resolve, reject) => {
        // Whatever it was told to bind is a name it may answer to.
        controlNames.add(String(host).toLowerCase());
        controlLoopback = isLoopbackHost(host);
        // A bind failure (a port already in use) emits `error`; without this it
        // is unhandled and crashes the process instead of rejecting the caller,
        // the same way `listenHail` already guards its listeners.
        const onError = (/** @type {Error} */ err) => reject(err);
        control.once("error", onError);
        control.listen(port, host, () => {
          control.removeListener("error", onError);
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
     * `encrypted` is the operator's assertion that arrival on these hosts is
     * encrypted — a tailnet today, pinned TLS later. It gates the routes that
     * require it (the shell): false, and a marked route 404s here as if it did
     * not exist. Default false, so the fail-closed direction is the one an
     * operator gets without saying anything.
     *
     * @param {{port?: number, hosts: string[], encrypted?: boolean, tls?: boolean, cert?: string, key?: string}} options
     */
    listenHail: async ({ port = 8787, hosts, encrypted = false, tls = false, cert, key }) => {
      /** @type {{host: string, port: number}[]} */
      const bound = [];
      // A pinned-TLS listener *is* an encrypted arrival — the handshake proves it,
      // so the operator no longer asserts `encrypted`. Two shapes:
      //   - self-signed (default): the cert is a subkey the identity vouches for;
      //     the caller pins it, and `requestCert` + `requireClientCert` pin the
      //     caller back (mutual TLS).
      //   - provided cert (a real/Let's Encrypt one, via `cert`/`key`): for
      //     clients that validate against a CA — a browser — which cannot present
      //     a peerhailer client cert, so mutual pinning is off here. Peers use the
      //     self-signed listener; this one is for the browser case.
      let tlsOptions = null;
      let requireClientCert = false;
      if (tls && cert && key) {
        tlsOptions = { cert, key };
      } else if (tls) {
        tlsOptions = { ...selfSignedCert(identity), requestCert: true, rejectUnauthorized: false };
        requireClientCert = true;
      }
      for (const host of hosts) {
        const server = tlsOptions
          ? createHttpsServer(
              tlsOptions,
              // Mutual when we pin the client (self-signed listener), or when the
              // bind host is loopback (local-trusted, binding moot).
              handlerFor("hail", { encryptedArrival: true, requireClientCert, arrivalMutual: requireClientCert || isLoopbackHost(host) }),
            )
          : createServer(handlerFor("hail", { encryptedArrival: encrypted, arrivalMutual: isLoopbackHost(host) }));
        try {
          await new Promise((resolve, reject) => {
            server.once("error", reject);
            server.listen(port, host, () => resolve(undefined));
          });
          const address = /** @type {import("node:net").AddressInfo} */ (server.address());
          hailServers.push(server);
          bound.push({ host, port: address.port });
          log(`[daemon] hails on ${tlsOptions ? "https" : "http"}://${host}:${address.port}${tlsOptions ? (requireClientCert ? " (pinned TLS, mutual)" : " (provided cert)") : ""}`);
        } catch (error) {
          log(`[daemon] not listening on ${host}: ${error instanceof Error ? error.message : error}`);
        }
      }
      return bound;
    },

    close: async () => {
      // Listeners first, so no new request lands on a resource being torn down.
      await Promise.all(hailServers.map(stop));
      hailServers.length = 0;
      await stop(control);
      // Then the plugins — shell/service/tunnel hold child processes and tunnels
      // that were otherwise orphaned on shutdown, because close() never stopped
      // them. Best-effort (sync throw or rejected stop() must not block the rest),
      // symmetric with the teardown `reload` does when it replaces a plugin set.
      await Promise.allSettled(plugins.map((plugin) => Promise.resolve().then(() => plugin.stop?.())));
      composer.closeAll();
      for (const [, m] of mounts) { try { await m.close(); } catch {} }
      mounts.clear();
    },
  };
}
