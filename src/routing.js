/**
 * Stage 1 routing: deliverable multi-hop over the trust graph, loop-free by
 * construction. See docs/routing.md for the roadmap this is the floor of.
 *
 * The engine is the **protocol**, and it is fixed and shared: a message carries a
 * `dest`, a hard `ttl` (a depth ceiling nobody may raise), a `budget` (a ceiling on
 * total forwards, so a search cannot fan out into a flood), a `visited` set (so a
 * node is never on a path twice), and an opaque sealed `payload`. The rules here —
 * decrement ttl and budget, never revisit, never step toward a blocked key —
 * are not negotiable.
 *
 * Everything *else* is **policy**, injected: which admitted neighbour to try first,
 * how many to try (`fanout`), and the distance metric that orders them. The engine
 * is deliberately metric-agnostic — greedy-toward-key, random, round-robin are all
 * just an `order()` — because the metric is exactly the thing a node gets to choose
 * (docs/routing.md, "each node picks its own approach").
 *
 * Delivery is request/response: when a message reaches `dest`, `deliver(payload)`
 * runs and its return value travels back up the call chain to the origin. Multi-hop
 * callPeer, in other words. This is a synchronous recursive relay (a bounded DFS
 * with backtracking), not asynchronous flooding — simpler, and a good fit for a
 * request/response fabric. The efficiency refinement (discover a path once, cache
 * it, then source-route without re-searching) is Stage 1.5, noted in the roadmap.
 *
 * @module routing
 */

export const DEFAULT_TTL = 16;
export const DEFAULT_BUDGET = 64;

/**
 * @param {{
 *   self: string,
 *   neighbors: () => string[],
 *   forward: (peer: string, envelope: any) => Promise<any>,
 *   deliver: (payload: any, meta: { origin: string, via: string[] }) => any,
 *   isBlocked?: (key: string) => boolean,
 *   policy?: { order?: (candidates: string[], dest: string) => string[], fanout?: number },
 *   ttlMax?: number,
 *   budgetMax?: number,
 *   normalize?: (key: string) => string,
 * }} deps
 */
export function createRouter({
  self,
  neighbors,
  forward,
  deliver,
  isBlocked = () => false,
  policy = {},
  ttlMax = DEFAULT_TTL,
  budgetMax = DEFAULT_BUDGET,
  normalize = (/** @type {string} */ k) => k,
}) {
  const N = normalize;
  self = N(self);
  const order = policy.order ?? ((candidates) => candidates);
  const fanout = typeof policy.fanout === "number" && Number.isInteger(policy.fanout) && policy.fanout > 0 ? policy.fanout : Infinity;

  /**
   * Handle a message at this node: deliver it if we are the destination, else try
   * to relay it onward within ttl and budget. `from` is the neighbour that handed
   * it to us (never tried again). Returns
   * `{ delivered, response?, via?, spent }` — `spent` is forwards consumed, so a
   * caller can hold the shared budget across siblings.
   * @param {{dest: string, ttl: number, budget: number, visited: string[], payload: any, origin?: string}} envelope
   * @param {string | null} [from]
   */
  async function relay(envelope, from = null) {
    const { payload } = envelope;
    const dest = N(envelope.dest);
    const fromKey = from == null ? null : N(from);
    const visited = (Array.isArray(envelope.visited) ? envelope.visited : []).map(N);
    const origin = N(envelope.origin ?? visited[0] ?? self);
    const path = [...visited, self];

    if (dest === self) {
      return { delivered: true, response: await deliver(payload, { origin, via: path }), via: path, spent: 0 };
    }
    const ttl = Number(envelope.ttl);
    let budget = Number(envelope.budget);
    if (!Number.isFinite(ttl) || ttl <= 0) return { delivered: false, reason: "ttl", spent: 0 };
    if (!Number.isFinite(budget) || budget <= 0) return { delivered: false, reason: "budget", spent: 0 };

    // Candidates: admitted neighbours not already on the path, not the node that
    // handed us this, and never a blocked key (the "a relay must never reach a peer
    // this machine has blocked" rule from docs/acp-tunnel.md).
    const onPath = new Set(path);
    const candidates = neighbors().map(N).filter((k) => k !== fromKey && !onPath.has(k) && !isBlocked(k));
    const ordered = order([...candidates], dest);

    let spent = 0;
    let tried = 0;
    for (const next of ordered) {
      if (tried >= fanout) break;
      if (budget - spent - 1 < 0) break; // the forward itself costs one
      tried += 1;
      const child = {
        dest,
        ttl: ttl - 1,
        budget: budget - spent - 1,
        visited: path,
        payload,
        origin,
      };
      let r;
      try {
        r = await forward(next, child);
      } catch (error) {
        r = { delivered: false, reason: String(/** @type {any} */ (error)?.message ?? error), spent: 0 };
      }
      spent += 1 + (Number(r?.spent) || 0);
      if (r?.delivered) {
        return { delivered: true, response: r.response, via: r.via ?? [...path, next], spent };
      }
    }
    return { delivered: false, reason: "no route", spent };
  }

  /**
   * Origin entry point: send a payload toward `dest` across the graph.
   * @param {string} dest
   * @param {any} payload
   * @param {{ttl?: number, budget?: number}} [opts]
   */
  async function send(dest, payload, { ttl = ttlMax, budget = budgetMax } = {}) {
    const target = N(dest);
    if (target === self) return { delivered: true, response: await deliver(payload, { origin: self, via: [self] }), via: [self] };
    return relay({ dest: target, ttl: Math.min(ttl, ttlMax), budget: Math.min(budget, budgetMax), visited: [], payload, origin: self }, null);
  }

  return { relay, send, self };
}

/**
 * A greedy policy: order candidates by a distance metric toward the destination,
 * closest first, and cap the fan-out. The metric is injected so the engine stays
 * metric-agnostic; `xorDistance` below is the usual one over identity keys.
 * @param {{ distance: (a: string, b: string) => bigint | number, fanout?: number }} opts
 */
export function greedyPolicy({ distance, fanout = 3 }) {
  return {
    fanout,
    /** @param {string[]} candidates @param {string} dest */
    order: (/** @type {string[]} */ candidates, /** @type {string} */ dest) =>
      [...candidates].sort((a, b) => {
        const da = distance(a, dest);
        const db = distance(b, dest);
        return da < db ? -1 : da > db ? 1 : 0;
      }),
  };
}

/** A flood policy: try every neighbour (bounded only by ttl and budget), unordered. */
export function floodPolicy() {
  return { fanout: Infinity, order: (/** @type {string[]} */ candidates) => candidates };
}

/**
 * XOR distance between two keys, as a BigInt over a stable hash of each key. Keys
 * are opaque strings (PEMs); hashing gives them a uniform id in a fixed space, and
 * XOR of those ids is the Kademlia metric. Pass a `hash` (e.g. a hex sha256) — kept
 * injectable so the engine and this helper carry no crypto dependency of their own.
 * @param {(key: string) => string} hashHex  key -> hex string id
 */
export function xorDistanceOver(hashHex) {
  /** @param {string} a @param {string} b */
  return (a, b) => {
    const ha = BigInt("0x" + hashHex(a));
    const hb = BigInt("0x" + hashHex(b));
    return ha ^ hb;
  };
}
