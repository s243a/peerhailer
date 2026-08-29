/**
 * The pure Stage-1 routing engine: deliverable multi-hop over the trust graph,
 * loop-free by construction. See docs/routing.md for the roadmap this is the
 * floor of. It deliberately knows no cryptography; builtin/routePlugin.js layers
 * the M1 signed wrapper and replay discipline around its opaque `payload` seam.
 *
 * The engine is the **protocol**, and it is fixed and shared: a message carries a
 * `dest`, a hard `ttl` (a depth ceiling), a `budget` (a soft ceiling on total
 * forwards), a `visited` set (so a node is never on a path twice), a `payload`, and
 * an `origin`. The hard rules — clamp ttl/budget/fanout to local maxima on receipt,
 * decrement ttl, never revisit, never step toward a blocked key — are not
 * negotiable.
 *
 * **Confidentiality, stated honestly: at M1 the `payload` is NOT sealed.** Every
 * relay on the path can read the wrapper's clear body (and log or alter the wire
 * copy, though alteration is refused at the destination). `requiresEncryptedArrival`
 * on the plugin protects each *hop's* transport, not the path — an intermediary is
 * an admitted peer, and admission is not confidentiality. Sealing the payload to the
 * destination's key is a near-term prerequisite before routing anything private (see
 * docs/routing.md); it is distinct from the Stage 5 *anonymity* (onion) work. The
 * outer `origin` field is likewise carried **unsigned** and remains advisory only;
 * the M1 plugin discards it at delivery and supplies the signed inner origin id.
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

import { randomUUID } from "node:crypto";

export const DEFAULT_TTL = 16;
export const DEFAULT_BUDGET = 64;
export const DEFAULT_FANOUT_MAX = 8;
export const DEFAULT_DEDUP_WINDOW_MS = 5 * 60_000;
export const DEFAULT_DEDUP_MAX = 4096;

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
 *   fanoutMax?: number,
 *   normalize?: (key: string) => string,
 *   now?: () => number,
 *   newId?: () => string,
 *   dedupWindowMs?: number,
 *   dedupMax?: number,
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
  fanoutMax = DEFAULT_FANOUT_MAX,
  normalize = (/** @type {string} */ k) => k,
  now = () => Date.now(),
  newId = () => randomUUID(),
  dedupWindowMs = DEFAULT_DEDUP_WINDOW_MS,
  dedupMax = DEFAULT_DEDUP_MAX,
}) {
  const N = normalize;
  self = N(self);
  // Stage-1/M0 correctness dedup, at the DESTINATION only. A raw-engine message
  // carries a unique `id`; the
  // destination delivers each id at most once within a window, so a relay re-
  // injecting an old envelope cannot make the destination act on it twice. Only the
  // destination dedups — an intermediate keeps re-forwarding, so the recursive
  // search stays complete (a node legitimately reached via a second path during
  // backtracking is not wrongly refused). Absent an id (an old or non-originated
  // envelope), delivery is not deduped. The M1 plugin intentionally forces this
  // outer id to null: it is unsigned and runs before cryptographic open, so letting
  // it reserve would let a relay poison the real signed message's slot. M1 uses its
  // inner `(origin,messageId,blockIndex)` guard instead.
  /** @type {Map<string, number>} id -> expiry */
  const seen = new Map();
  /** @param {string | undefined} id */
  const firstDelivery = (id) => {
    if (!id) return true;
    const t = now();
    for (const [k, exp] of seen) { if (exp <= t) seen.delete(k); else break; }
    if (seen.has(id)) return false;
    seen.set(id, t + dedupWindowMs);
    while (seen.size > dedupMax) { const oldest = seen.keys().next().value; if (oldest === undefined) break; seen.delete(oldest); }
    return true;
  };
  const order = policy.order ?? ((candidates) => candidates);
  // Fanout bounds the breadth a receipt imposes on *other* nodes, so — like ttl and
  // budget — it is clamped to a local maximum here, in the engine, not left to
  // policy. A policy may ask for less; it can never ask for more than fanoutMax.
  const requested =
    typeof policy.fanout === "number" && Number.isInteger(policy.fanout) && policy.fanout > 0 ? policy.fanout : fanoutMax;
  const fanout = Math.min(requested, fanoutMax);

  /**
   * Handle a message at this node: deliver it if we are the destination, else try
   * to relay it onward within ttl and budget. `from` is the neighbour that handed
   * it to us (never tried again). Returns
   * `{ delivered, response?, via?, spent }` — `spent` is forwards consumed, so a
   * caller can hold the shared budget across siblings.
   * @param {{dest: string, ttl: number, budget: number, visited: string[], payload: any, origin?: string, id?: string}} envelope
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
      if (!firstDelivery(envelope.id)) return { delivered: true, duplicate: true, via: path, spent: 0 };
      return { delivered: true, response: await deliver(payload, { origin, via: path }), via: path, spent: 0 };
    }
    // Clamp on RECEIPT to this node's own maxima. The envelope's ttl and budget
    // arrive from a peer — admitted, but not trusted — so an oversized ttl or budget
    // must never let a remote sender make this node search deeper or wider than its
    // own policy allows. NaN or negative values fall through the checks below and
    // stop the message. Because each hop re-clamps, the bound is enforced everywhere,
    // not just at the origin's send().
    const ttl = Math.min(Number(envelope.ttl), ttlMax);
    let budget = Math.min(Number(envelope.budget), budgetMax);
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
        // Propagate the origin's id so the destination dedup (firstDelivery) actually
        // fires for relayed traffic — without this the id survives only a direct
        // send, and a message that crosses a relay is delivered again on replay. This
        // is the raw-engine M0 stopgap in docs/routing-security-roadmap.md: it suppresses
        // *accidental* double-delivery (a diamond topology forwards twice under
        // fanout), NOT a malicious relay — the id is unsigned, so a dishonest relay
        // can strip or re-mint it. The M1 route plugin bypasses this field and uses
        // the authenticated inner manifest instead.
        id: envelope.id,
      };
      let r;
      try {
        r = await forward(next, child);
      } catch (error) {
        r = { delivered: false, reason: String(/** @type {any} */ (error)?.message ?? error), spent: 0 };
      }
      // `spent` came from another machine. A negative report used to *increase*
      // the budget available to later siblings; a huge/NaN report could make the
      // accounting equally meaningless. Accept only a finite non-negative claim,
      // capped by the budget that child received. An invalid claim fails closed by
      // charging the child its whole allowance.
      const reportedSpent = Number(r?.spent);
      const childSpent = Number.isFinite(reportedSpent) && reportedSpent >= 0
        ? Math.min(reportedSpent, child.budget)
        : child.budget;
      spent += 1 + childSpent;
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
   * @param {{ttl?: number, budget?: number, id?: string}} [opts]
   */
  async function send(dest, payload, { ttl = ttlMax, budget = budgetMax, id = newId() } = {}) {
    const target = N(dest);
    if (target === self) {
      if (!firstDelivery(id)) return { delivered: true, duplicate: true, via: [self] };
      return { delivered: true, response: await deliver(payload, { origin: self, via: [self] }), via: [self] };
    }
    return relay({ dest: target, ttl: Math.min(ttl, ttlMax), budget: Math.min(budget, budgetMax), visited: [], payload, origin: self, id }, null);
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
