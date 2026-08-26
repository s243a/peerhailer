/**
 * Advertise what this machine can *launch* for a peer, over the wire.
 *
 * `hail` tells a caller who this machine is; nothing yet tells them what it can
 * run. The session composer needs that: to offer "start Gemini on puppy" it must
 * first discover that puppy declares a launchable worker and a tunnel to reach it.
 *
 * An offer is a **service** carrying agent metadata (an operator declared it with
 * `hail services add … --agent … --role worker --tunnel …`) whose paired tunnel
 * actually exists — startable *and* reachable. The command line is never
 * advertised, only the label, agent, role and tunnel name a caller composes with.
 *
 * A second kind is a **controller** offer for T3-to-T3 remote control: when this
 * machine declares a `pair` command and a `t3` tunnel, it advertises that a caller
 * can mint a grant and drive this node's T3 — carrying those names, never the
 * command line.
 *
 * Gated by its own `offers` capability, in no built-in profile — an operator
 * grants it deliberately, the same as `service:*` and `tunnel:*`.
 *
 * @module builtin/offersPlugin
 */

export const OFFERS = "offers";

/**
 * @param {{ services?: Record<string, any>, tunnels?: Record<string, string>, commands?: Record<string, any> }} options
 */
export function createOffersPlugin({ services = {}, tunnels = {}, commands = {} } = {}) {
  const workerOffers = Object.entries(services).flatMap(([name, decl]) => {
    if (!decl || typeof decl !== "object") return []; // a bare command string carries no metadata
    const { label, agent, role, tunnel, supervisorTunnel } = decl;
    if (!agent && !role) return []; // not a launchable offer, just a plain service
    const tunnelName = typeof tunnel === "string" && tunnel ? tunnel : name;
    // Startable but unreachable is not an offer: without the paired tunnel the
    // caller could start it and never speak to it. Advertise only complete pairs.
    if (!tunnels[tunnelName]) return [];
    /** @type {{service: string, label: string, agent: string|null, role: string, tunnel: string, supervisorTunnel?: string}} */
    const offer = {
      service: name,
      label: typeof label === "string" && label ? label : name,
      agent: typeof agent === "string" ? agent : null,
      role: role === "supervisor" ? "supervisor" : "worker",
      tunnel: tunnelName,
    };
    // Advertise a supervisor seat only when its tunnel is declared too — else the
    // caller could enable supervision it cannot actually reach.
    if (typeof supervisorTunnel === "string" && supervisorTunnel && tunnels[supervisorTunnel]) {
      offer.supervisorTunnel = supervisorTunnel;
    }
    return [offer];
  });

  // A T3-to-T3 *controller* offer: this machine can mint a T3 pairing grant and
  // tunnel its T3 to a caller, so a peer can drive this node's T3 from its own.
  // By convention that is a command named `pair` and a tunnel named `t3`; the
  // offer carries both names so a caller composes with them rather than guessing.
  // The command line itself is never advertised — only that `pair` exists.
  const controllerOffers =
    commands.pair && tunnels.t3
      ? [{ role: "controller", label: "Remote T3", command: "pair", tunnel: "t3" }]
      : [];
  const offers = [...workerOffers, ...controllerOffers];

  return {
    name: "offers",
    description: "Advertises launchable agent offerings (service+tunnel pairs) to holders of `offers`.",
    // Not secret, but capability-gated and rides the encrypted-arrival floor like
    // every non-hail route.
    requiresEncryptedArrival: true,
    capabilities: [OFFERS],
    routes: [
      {
        method: "POST",
        path: "/offers",
        capability: OFFERS,
        /** @param {any} ctx */
        handler: (ctx) => {
          ctx.log?.(`[offers] advertised ${offers.length} offering(s)`);
          return { offers };
        },
      },
    ],
  };
}
