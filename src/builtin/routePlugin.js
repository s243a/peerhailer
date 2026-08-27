/**
 * The routing plugin (Stage 1): a peer holding `route` may hand this machine a
 * message to relay onward, or to deliver if this machine is the destination. The
 * algorithm and its bounds live in `../routing.js`; this is only the surface and
 * the wiring — one route, `POST /route/relay`, carrying the fixed envelope, over an
 * encrypted arrival. See docs/routing.md.
 *
 * `route` is its own capability, distinct from `RELAY` (which carries a single
 * declared hop) and from `tunnel:*`: a peer you will relay *for* is not thereby a
 * peer that may reach your local services.
 *
 * @module builtin/routePlugin
 */
import { createRouter } from "../routing.js";
import { REFUSE } from "../plugins.js";

/** A caller may hand us at most this many relays per window before we refuse. */
export const RELAY_WINDOW_MS = 10_000;
export const MAX_RELAYS_PER_WINDOW = 60;

/**
 * @param {{
 *   self: string,
 *   neighbors: () => string[],
 *   forward: (peer: string, envelope: any) => Promise<any>,
 *   deliver: (payload: any, meta: { origin: string, via: string[] }) => any,
 *   isBlocked?: (key: string) => boolean,
 *   policy?: any,
 *   ttlMax?: number,
 *   budgetMax?: number,
 *   now?: () => number,
 * }} deps
 */
export function createRoutePlugin(deps) {
  const router = createRouter(deps);
  const now = deps.now ?? Date.now;
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
    description: "Relay and deliver multi-hop messages across admitted peers (Stage 1).",
    // Encrypted *arrival* (each hop's transport), like chat and files. Note this is
    // NOT payload confidentiality across the path: at Stage 1 every relay can read
    // the payload — sealing to the destination is a near-term prerequisite before
    // routing anything private (see src/routing.js and docs/routing.md).
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
          return router.relay(body ?? {}, caller.publicKey);
        },
      },
    ],
    /** Host-only: originate a routed message toward `dest`. */
    send: (/** @type {string} */ dest, /** @type {any} */ payload, /** @type {any} */ opts) => router.send(dest, payload, opts),
    router,
  };
}
