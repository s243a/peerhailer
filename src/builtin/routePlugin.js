/**
 * The routing plugin (M1): a peer holding `route` may hand this machine a message
 * to relay onward, or to authenticate and deliver if this machine is the
 * destination. The pure algorithm and its bounds live in `../routing.js`; this
 * surface wraps once at origin and opens once at destination while every relay
 * carries the wrapper opaquely. One route, `POST /route/relay`, over an encrypted
 * arrival. See docs/routing.md and docs/routing-security-roadmap.md.
 *
 * `route` is its own capability, distinct from `RELAY` (which carries a single
 * declared hop) and from `tunnel:*`: a peer you will relay *for* is not thereby a
 * peer that may reach your local services.
 *
 * Wire transition: intermediate Stage-1 engines are compatible because `payload`
 * is opaque, but endpoints are a flag day until route-version negotiation exists:
 * a new destination refuses an old raw payload; an old destination would hand the
 * new wrapper to its legacy consumer. Upgrade destinations before originating M1.
 *
 * @module builtin/routePlugin
 */
import { createPrivateKey, randomBytes } from "node:crypto";

import { keyId } from "../routeManifest.js";
import { createRouteReplayGuard, DEFAULT_MAX_VALIDITY_MS } from "../routeReplayGuard.js";
import { openRoutedMessage, wrapRoutedMessage } from "../routedMessage.js";
import { createRoutedKeyStore } from "../routedKeyStore.js";
import { resolveRoutedSeal } from "../routedSealResolver.js";
import { signRecord } from "../peerRecord.js";
import { createRouter } from "../routing.js";
import { REFUSE } from "../plugins.js";

/** A caller may hand us at most this many relays per window before we refuse. */
export const RELAY_WINDOW_MS = 10_000;
export const MAX_RELAYS_PER_WINDOW = 60;
/** Bound every simultaneous recursive search and its at-most-one active forward. */
export const MAX_IN_FLIGHT_RELAYS = 8;
export const MAX_IN_FLIGHT_PER_CALLER = 2;
/** One minute on the wire; comfortably inside the guard's five-minute ceiling. */
export const ROUTED_MESSAGE_VALIDITY_MS = 60_000;

/** Never crosses JSON; marks an internal `deliver` result that open refused. */
const OPEN_REFUSAL = Symbol("route.open-refusal");

/**
 * Wire field: the destination piggybacks its *signed* self-record on a routed response
 * so the origin can learn its advertised sealing key (M2 Tier-1 discovery). It crosses
 * JSON, so it is a reserved string key, not a symbol. Public and self-signed: a relay
 * may drop it (the origin simply gets no Tier-1 key) or replay an older one (the store
 * catches the identity match and flags a conflict), but cannot forge a new key.
 */
export const ROUTED_RECORD_FIELD = "__routedRecord";

/** A JSON-object response we can safely add a field to — not an array, Buffer, or class
 * instance, which spreading would flatten into indexed/own properties.
 * @param {any} v */
const isPlainObject = (v) => {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
};

/**
 * @param {{
 *   self: string,
 *   privateKey: string,
 *   selfRecord: () => any,
 *   neighbors: () => string[],
 *   forward: (peer: string, envelope: any) => Promise<any>,
 *   deliver: (payload: any, meta: { origin: string, originKeyId: string, via: string[] }) => any,
 *   authorizeOrigin: (origin: {originKeyId: string}) => boolean,
 *   isBlocked?: (key: string) => boolean,
 *   policy?: any,
 *   ttlMax?: number,
 *   budgetMax?: number,
 *   now?: () => number,
 *   replayGuard?: ReturnType<typeof createRouteReplayGuard>,
 *   routedKeyStore?: ReturnType<typeof createRoutedKeyStore>,
 *   sealPrivateKey?: string,   // this machine's X25519 private key (PEM); enables opening sealed
 *   tier0Seal?: (destKey: string) => { state: "verified" | "conflict" | "reverify" | "unverified", key: string | null },
 *   requireSealed?: boolean,   // local confidentiality floor: refuse a clear delivery
 *   allowRecordCarried?: boolean, // opt in to sealing to a Tier-1 record-carried key
 *   newMessageId?: () => string,
 *   messageValidityMs?: number,
 * }} deps
 */
export function createRoutePlugin(deps) {
  const now = deps.now ?? Date.now;
  const replayGuard = deps.replayGuard ?? createRouteReplayGuard({ now });
  const routedKeyStore = deps.routedKeyStore ?? createRoutedKeyStore();
  const newMessageId = deps.newMessageId ?? (() => randomBytes(16).toString("base64url"));
  const messageValidityMs = deps.messageValidityMs ?? ROUTED_MESSAGE_VALIDITY_MS;

  let selfKeyId;
  try {
    selfKeyId = keyId(deps.self);
    if (keyId(createPrivateKey(deps.privateKey)) !== selfKeyId) throw new Error("private key mismatch");
    if (keyId(deps.selfRecord?.()?.publicKey) !== selfKeyId) throw new Error("self record mismatch");
  } catch (cause) {
    throw new Error("route plugin requires one coherent Ed25519 identity, private key, and self record", { cause });
  }
  if (typeof deps.authorizeOrigin !== "function") throw new Error("route plugin requires an origin-authorization policy");
  if (typeof deps.deliver !== "function") throw new Error("route plugin requires a delivery function");
  if (!replayGuard || typeof replayGuard.check !== "function" || typeof replayGuard.admit !== "function") {
    throw new Error("route plugin requires a two-phase replay guard");
  }
  if (!Number.isSafeInteger(messageValidityMs) || messageValidityMs <= 0 || messageValidityMs > DEFAULT_MAX_VALIDITY_MS) {
    throw new Error(`route message validity must be 1..${DEFAULT_MAX_VALIDITY_MS} ms`);
  }
  // Validate the sealing key once here, so a misconfigured key is a clear construction
  // error rather than surfacing later as every sealed delivery failing to "open".
  if (deps.sealPrivateKey !== undefined) {
    let usable = false;
    try {
      usable = createPrivateKey(deps.sealPrivateKey).asymmetricKeyType === "x25519";
    } catch {
      usable = false;
    }
    if (!usable) throw new Error("route plugin sealPrivateKey must be an X25519 private key");
  }

  const deliver = deps.deliver;
  const rawRouter = createRouter({
    ...deps,
    // The pure engine invokes this only after its outer destination equals self.
    // Discard its advisory outer origin and hand consumers only the authenticated
    // key recovered from the signed manifest.
    deliver: async (wrapper, meta) => {
      const opened = openRoutedMessage(wrapper, {
        selfKeyId,
        guard: replayGuard,
        authorizeOrigin: deps.authorizeOrigin,
        ...(deps.sealPrivateKey !== undefined ? { sealPrivateKey: deps.sealPrivateKey } : {}),
        requireSealed: deps.requireSealed === true,
      });
      if (!opened.ok) return { [OPEN_REFUSAL]: opened.reason };
      // Await the consumer before attaching: a consumer may return a promise, and
      // spreading that instead of its resolved response would corrupt the result.
      const response = await deliver(opened.body, {
        ...meta,
        origin: opened.originKeyId,
        originKeyId: opened.originKeyId,
      });
      return attachDiscovery(response);
    },
  });

  /**
   * Piggyback a signed, **key-only** self-record on a delivery response so the origin can
   * learn our advertised sealing key (M2 Tier-1). Deliberately NOT our full record: it
   * carries name, identity key, and sealing key — never our addresses. Discovery is *key*
   * discovery; handing a routed origin (and every relay on the return path) our direct
   * addresses would undercut F2F reachability.
   *
   * Attaches only to a plain-object response: spreading an array or a class instance (a
   * consumer could return either, and the in-process self-delivery path never JSON-round-
   * trips it) would corrupt it, so such a response is passed through unchanged.
   * @param {any} response
   */
  const attachDiscovery = (response) => {
    if (!isPlainObject(response)) return response;
    const self = deps.selfRecord();
    const signed = signRecord(
      { name: self?.name, publicKey: self?.publicKey, sealPublicKey: self?.sealPublicKey, addresses: [], lastSeen: null },
      deps.privateKey,
    );
    return signed ? { ...response, [ROUTED_RECORD_FIELD]: signed } : response;
  };

  /**
   * Learn a destination's advertised sealing key from the self-record it piggybacked on
   * the response. The store verifies the record against `destKeyId`, so a dropped,
   * swapped, or replayed record cannot install a wrong key here.
   * @param {string} destKeyId
   * @param {any} result
   */
  const observeDiscovery = (destKeyId, result) => {
    const record = result?.response?.[ROUTED_RECORD_FIELD];
    if (record) routedKeyStore.observe(destKeyId, record);
  };

  /**
   * Reaching the outer destination and refusing the authenticated message is
   * terminal for route search. Keep the refusal in `response` so intermediate
   * engines thread it back (they intentionally retain no application semantics).
   * @param {any} result
   */
  const normalizeOpenResult = (result) => {
    const reason = result?.response?.[OPEN_REFUSAL];
    const publicReason = result?.response?.refused === true && typeof result.response.reason === "string"
      ? result.response.reason
      : null;
    const refusalReason = typeof reason === "string" ? reason : publicReason;
    if (refusalReason === null) return result;
    const duplicate = refusalReason === "replay:duplicate" || result?.response?.duplicate === true;
    return {
      ...result,
      delivered: true,
      refused: true,
      ...(duplicate ? { duplicate: true } : {}),
      response: typeof reason === "string"
        ? { received: false, refused: true, reason: refusalReason, ...(duplicate ? { duplicate: true } : {}) }
        : result.response,
    };
  };

  let inFlight = 0;
  /** @type {Map<string, number>} */
  const inFlightByCaller = new Map();
  /**
   * Reserve a recursive-search slot for the whole relay attempt. The engine awaits
   * each child sequentially, so eight active attempts mean at most eight active
   * outbound forwards from this plugin — independent of ttl/budget/fanout.
   * @param {string | null} key authenticated immediate caller, or null for a host entry
   * @param {() => Promise<any>} work
   * @param {boolean} [peerFacing]
   */
  const withRelaySlot = async (key, work, peerFacing = false) => {
    const callerActive = key === null ? 0 : (inFlightByCaller.get(key) ?? 0);
    if (inFlight >= MAX_IN_FLIGHT_RELAYS || callerActive >= MAX_IN_FLIGHT_PER_CALLER) {
      return peerFacing
        ? { [REFUSE]: true, reason: "too many relays in flight" }
        : { delivered: false, reason: "too many relays in flight", spent: 0 };
    }
    inFlight += 1;
    if (key !== null) inFlightByCaller.set(key, callerActive + 1);
    try {
      return await work();
    } finally {
      inFlight -= 1;
      if (key !== null) {
        const remaining = (inFlightByCaller.get(key) ?? 1) - 1;
        if (remaining <= 0) inFlightByCaller.delete(key);
        else inFlightByCaller.set(key, remaining);
      }
    }
  };

  /**
   * Secure incoming facade. The legacy engine's M0 `id` is unsigned and its cache
   * runs before `deliver`; preserving it would let a relay pre-inject an id with
   * junk and suppress the valid signed wrapper. Force it false at every new-plugin
   * hop and rely exclusively on the inner `(origin,messageId,blockIndex)` guard.
   * @param {any} envelope
   * @param {string | null} [from]
   */
  const relayUnchecked = async (envelope, from = null) =>
    normalizeOpenResult(
      await rawRouter.relay(
        { ...(envelope && typeof envelope === "object" ? envelope : {}), id: null },
        from,
      ),
    );

  /**
   * Host-only origin facade: sign the exact serialized body, then give the opaque
   * wrapper to the engine. The outer id is deliberately null (see `relay`).
   * @param {string} dest
   * @param {any} payload
   * @param {{ttl?: number, budget?: number}} [opts]
   */
  const sendUnchecked = async (dest, payload, opts = {}) => {
    let destinationKeyId;
    try {
      destinationKeyId = keyId(dest);
    } catch {
      return { delivered: false, reason: "invalid destination identity key", spent: 0 };
    }

    // Decide confidentiality before wrapping: Tier 0 (walk-verified) wins, Tier 1
    // (record-carried) is opt-in, and a conflict at either tier REFUSES rather than
    // sending cleartext — a relay must not be able to strip a seal by forging a dispute.
    const tier0 = deps.tier0Seal ? deps.tier0Seal(dest) : { state: /** @type {"unverified"} */ ("unverified"), key: null };
    const target = resolveRoutedSeal({
      tier0,
      tier1: { state: routedKeyStore.recordState(destinationKeyId), key: routedKeyStore.recordSealKey(destinationKeyId) },
      allowRecordCarried: deps.allowRecordCarried === true,
    });
    // F2: once Tier 0 knows this peer's sealing posture, its record-carried Tier-1 entry
    // is moot — drop it so a stale conflict cannot linger on the surface or in a resolver.
    if (tier0.state !== "unverified") routedKeyStore.forget(destinationKeyId);
    if (target.decision === "refuse") return { delivered: false, reason: `seal-refused:${target.state}`, spent: 0 };
    const sealTo = target.decision === "seal" && target.key ? { recipientKey: target.key } : undefined;

    const wrapper = wrapRoutedMessage({
      self: deps.selfRecord(),
      privateKey: deps.privateKey,
      destinationKeyId,
      body: payload,
      messageId: newMessageId(),
      now: now(),
      validityMs: messageValidityMs,
      ...(sealTo ? { sealTo } : {}),
    });
    const routeOptions = /** @type {{ttl?: number, budget?: number, id?: any}} */ ({ id: null });
    if (opts.ttl !== undefined) routeOptions.ttl = opts.ttl;
    if (opts.budget !== undefined) routeOptions.budget = opts.budget;
    const result = normalizeOpenResult(await rawRouter.send(dest, wrapper, routeOptions));
    observeDiscovery(destinationKeyId, result);
    return result;
  };

  // Public host/embedder entry points share the same plugin-wide work ceiling as
  // incoming peers. (The per-caller sub-ceiling applies only to authenticated
  // network callers, which have a stable key to charge.)
  const relay = (/** @type {any} */ envelope, /** @type {string | null} */ from = null) =>
    withRelaySlot(null, () => relayUnchecked(envelope, from));
  const send = (/** @type {string} */ dest, /** @type {any} */ payload, /** @type {{ttl?: number, budget?: number}} */ opts = {}) =>
    withRelaySlot(null, () => sendUnchecked(dest, payload, opts));

  /** The identity key id for a destination PEM, or null if it is not a usable key. */
  const destKeyId = (/** @type {string} */ dest) => {
    try {
      return keyId(dest);
    } catch {
      return null;
    }
  };

  // Expose only the secure facade. Returning `rawRouter` would leave a public path
  // that bypasses wrap/open and silently restores the unsigned Stage-1 posture. The
  // routed-key queries are the read side of M2 Tier-1 discovery; Tier-0 (walk-verified)
  // resolution belongs to the directory and always takes precedence over these.
  const router = {
    relay,
    send,
    self: rawRouter.self,
    routedSealKey: (/** @type {string} */ dest) => {
      const id = destKeyId(dest);
      return id ? routedKeyStore.recordSealKey(id) : null;
    },
    routedSealState: (/** @type {string} */ dest) => {
      const id = destKeyId(dest);
      return id ? routedKeyStore.recordState(id) : "none";
    },
    routedSealDetail: (/** @type {string} */ dest) => {
      const id = destKeyId(dest);
      return id ? routedKeyStore.recordDetail(id) : null;
    },
  };

  // Per-caller token bucket. peerhailer has no framework rate limiter — command and
  // shell each hand-roll one — so routing does too: one receipt can trigger up to
  // fanout signed callPeers, so an unbounded relay rate is an amplification lever.
  /** @type {Map<string, number[]>} */
  const relays = new Map();
  const withinLimit = (/** @type {string} */ key) => {
    const t = now();
    const recent = (relays.get(key) ?? []).filter((at) => t - at < RELAY_WINDOW_MS);
    if (recent.length >= MAX_RELAYS_PER_WINDOW) {
      relays.set(key, recent);
      return false;
    }
    recent.push(t);
    relays.set(key, recent);
    return true;
  };
  return {
    name: "route",
    description: "Relay signed cleartext messages across admitted peers (routing M1).",
    // Encrypted *arrival* (each hop's transport), like chat and files. Note this is
    // NOT payload confidentiality across the path: at M1 every relay can read the
    // signed body. Sealing to the destination is M3; do not route private content.
    requiresEncryptedArrival: true,
    capabilities: ["route"],
    routes: [
      {
        method: "POST",
        path: "/route/relay",
        capability: "route",
        /** @param {any} input */
        handler: async ({ body, caller }) => {
          if (!caller?.publicKey) return { [REFUSE]: true, reason: "no key to attribute a relay to" };
          if (!withinLimit(caller.publicKey)) return { [REFUSE]: true, reason: "relaying too fast" };
          // The neighbour that handed us this is the caller; the engine never
          // hands it straight back.
          return withRelaySlot(caller.publicKey, () => relayUnchecked(body ?? {}, caller.publicKey), true);
        },
      },
    ],
    /** Host-only: originate a routed message toward `dest`. */
    send,
    router,
  };
}
