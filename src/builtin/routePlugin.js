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
 * }} deps
 */
export function createRoutePlugin(deps) {
  const router = createRouter(deps);
  return {
    name: "route",
    description: "Relay and deliver multi-hop messages across admitted peers (Stage 1).",
    // Sealed like chat and files: the fabric cannot see what a routed message
    // carries, so it must not carry one in the clear.
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
