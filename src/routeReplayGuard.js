/**
 * The destination-side replay-state discipline for routed messages — the second
 * half of milestone M1 in `docs/routing-security-roadmap.md`.
 *
 * It takes an **already-verified** manifest (the signature, origin binding, and
 * destination self-check are the caller's job) and decides whether the destination
 * should act on it: fresh-and-in-window → admit and reserve; a replay, an expired or
 * not-yet-valid envelope, or a full cache → refuse. Verification and replay state are
 * deliberately separate concerns.
 *
 * **This is a session guard, not restart-safe** (Sol's review): a signed `expiry`
 * bounds how long the state must live, so the cache is in-memory and
 * garbage-collectable, but a restart empties it and a still-unexpired envelope could
 * be replayed once. A durable variant — retained until `expiresAt` — is the
 * across-restart option; this is the stated per-process one.
 *
 * The delivery it guards is at-most-once *attempt*: a crash between the reservation
 * here and the consumer completing can lose or (durably) duplicate. A consumer that
 * needs transactional exactly-once supplies its own idempotency store.
 *
 * `check()` is the non-reserving half used after signature/origin policy but before
 * decoding a large body; `admit()` repeats the decision and reserves only after the
 * body validates. Local wall time is held to a monotonic high-water mark, so an NTP
 * rollback cannot reopen an entry already swept after a forward jump (availability
 * fails closed until the wall clock catches up).
 *
 * @module routeReplayGuard
 */

/** A signed envelope may claim at most this much validity, whatever the origin put. */
export const DEFAULT_MAX_VALIDITY_MS = 5 * 60_000;
/** Tolerance for clock disagreement between origin and destination. */
export const DEFAULT_CLOCK_SKEW_MS = 2 * 60_000;
/** Global live-entry ceiling; at capacity a new message fails closed (no eviction). */
export const DEFAULT_MAX_ENTRIES = 4096;
/** Per-origin live-entry ceiling, so one origin cannot consume the whole cache. */
export const DEFAULT_MAX_PER_ORIGIN = 512;

/**
 * @param {{
 *   now?: () => number,
 *   maxValidityMs?: number,
 *   clockSkewMs?: number,
 *   maxEntries?: number,
 *   maxPerOrigin?: number,
 * }} [options]
 */
export function createRouteReplayGuard({
  now = Date.now,
  maxValidityMs = DEFAULT_MAX_VALIDITY_MS,
  clockSkewMs = DEFAULT_CLOCK_SKEW_MS,
  maxEntries = DEFAULT_MAX_ENTRIES,
  maxPerOrigin = DEFAULT_MAX_PER_ORIGIN,
} = {}) {
  // Validate the numeric options up front. A NaN (e.g. `clockSkewMs: NaN`) would flow
  // into `exp = expiresAt + clockSkewMs` as NaN, and `existing.exp >= t` is false for
  // NaN — so identical manifests would be admitted repeatedly instead of deduped. A
  // misconfigured guard must fail loudly at construction, not silently disable replay.
  for (const [name, value] of Object.entries({ maxValidityMs, clockSkewMs, maxEntries, maxPerOrigin })) {
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
      throw new Error(`route replay guard ${name} must be a finite, non-negative number`);
    }
  }
  if (typeof now !== "function") throw new Error("route replay guard now must be a function");
  /** @type {Map<string, { exp: number, origin: string }>} dedup key -> reservation */
  const entries = new Map();
  /** @type {Map<string, number>} originKeyId -> live count */
  const perOrigin = new Map();
  // Wall clocks can move backwards (NTP correction, a manual clock change). Once
  // this process has observed a time, replay state must never reason as though it
  // were earlier: an entry swept after a forward jump must not become admissible
  // again if the clock rolls back. The availability trade-off is deliberately
  // fail-closed — a large erroneous jump may refuse traffic until time catches up.
  let timeHighWater = Number.NEGATIVE_INFINITY;
  const currentTime = () => {
    const observed = now();
    if (!Number.isFinite(observed)) throw new Error("route replay clock must return a finite number");
    timeHighWater = Math.max(timeHighWater, observed);
    return timeHighWater;
  };

  /** @param {string} origin */
  const inc = (origin) => perOrigin.set(origin, (perOrigin.get(origin) ?? 0) + 1);
  /** @param {string} origin */
  const dec = (origin) => {
    const n = (perOrigin.get(origin) ?? 0) - 1;
    if (n <= 0) perOrigin.delete(origin);
    else perOrigin.set(origin, n);
  };
  // A reservation covers exactly the interval a message with that expiry is still
  // admissible: while `t <= exp` it must dedup, and only once `t > exp` may it be
  // swept — so the duplicate test (`>=`) and the sweep test (`<`) meet at the same
  // instant the window's `expired` check flips, with no one-tick gap a replay could
  // slip through.
  /** Drop reservations whose admissibility window (with skew) has fully passed. @param {number} t */
  const sweep = (t) => {
    for (const [k, e] of entries) {
      if (e.exp < t) {
        entries.delete(k);
        dec(e.origin);
      }
    }
  };

  /**
   * Run the complete window/dedup/capacity decision. `reserve:false` is a
   * non-reserving preflight (apart from harmless expired-entry GC); the caller can
   * reject stale or duplicate signed manifests before decoding a large payload,
   * then call the reserving form only after the payload itself validates.
   *
   * @param {{ originKeyId: string, messageId: string, blockIndex: number, issuedAt: number, expiresAt: number }} manifest
   * @param {boolean} reserve
   * @returns {{ ok: true } | { ok: false, reason: "not-yet-valid" | "expired" | "validity-too-long" | "duplicate" | "at-capacity" | "origin-at-capacity" }}
   */
  const assess = (manifest, reserve) => {
    const t = currentTime();
    const { originKeyId, messageId, blockIndex, issuedAt, expiresAt } = manifest;

    // Time window, enforced locally regardless of what the origin signed.
    if (expiresAt - issuedAt > maxValidityMs) return { ok: false, reason: /** @type {const} */ ("validity-too-long") };
    if (issuedAt > t + clockSkewMs) return { ok: false, reason: /** @type {const} */ ("not-yet-valid") };
    if (expiresAt < t - clockSkewMs) return { ok: false, reason: /** @type {const} */ ("expired") };

    const key = `${originKeyId}\0${messageId}\0${blockIndex}`;
    const existing = entries.get(key);
    if (existing && existing.exp >= t) return { ok: false, reason: /** @type {const} */ ("duplicate") };

    // A genuinely new slot must fit both ceilings. Sweep only when a ceiling is
    // reached; replacing an expired same-key slot is count-neutral.
    if (existing === undefined) {
      if (entries.size >= maxEntries) {
        sweep(t);
        if (entries.size >= maxEntries) return { ok: false, reason: /** @type {const} */ ("at-capacity") };
      }
      if ((perOrigin.get(originKeyId) ?? 0) >= maxPerOrigin) {
        sweep(t);
        if ((perOrigin.get(originKeyId) ?? 0) >= maxPerOrigin) {
          return { ok: false, reason: /** @type {const} */ ("origin-at-capacity") };
        }
      }
    }

    if (!reserve) return { ok: true };

    if (existing !== undefined) {
      // A same-key reservation that has expired: replace it, keeping the count net.
      dec(existing.origin);
    }
    entries.set(key, { exp: expiresAt + clockSkewMs, origin: originKeyId });
    inc(originKeyId);
    return { ok: true };
  };

  return {
    /**
     * Check window, duplicate, and capacity policy without reserving a new entry.
     * Expired-entry garbage collection may occur, but a refusal or success here
     * never consumes a slot.
     *
     * @param {{ originKeyId: string, messageId: string, blockIndex: number, issuedAt: number, expiresAt: number }} manifest
     */
    check(manifest) {
      return assess(manifest, false);
    },

    /**
     * Decide whether to deliver `manifest` now. On `{ ok: true }` a reservation is
     * held until `expiresAt + skew`, so a subsequent identical envelope is a
     * duplicate. On refusal nothing is reserved.
     *
     * @param {{ originKeyId: string, messageId: string, blockIndex: number, issuedAt: number, expiresAt: number }} manifest
     * @returns {{ ok: true } | { ok: false, reason: "not-yet-valid" | "expired" | "validity-too-long" | "duplicate" | "at-capacity" | "origin-at-capacity" }}
     */
    admit(manifest) {
      return assess(manifest, true);
    },

    /** Live reservation count — for tests and diagnostics. */
    size: () => {
      sweep(currentTime());
      return entries.size;
    },
  };
}
