/**
 * The observation seam (M3a) — a durable, key-indexed record of *what a destination has
 * learned about a routed origin*, and the request-scoped **authenticated-origin proof** that
 * gates writing to it (`docs/routing-security-roadmap.md`).
 *
 * The first (and only) observation kind is `requireSealFrom`: once a destination has opened a
 * *sealed* message from an origin, it has learned "this origin seals to me", and that fact is
 * worth remembering across restarts so a later *clear* message claiming that origin can be
 * recognised as a possible downgrade. M3a builds and records the observation; *enforcing* it
 * (refusing the downgrade) is the load-bearing step wired on top — the mechanism is here and
 * tested, the daemon does not yet activate it.
 *
 * **The proof, and why.** A raw `observe(key, kind)` is too easy for an honest in-process
 * consumer to call with the last-hop key or an unverified field. This is not a
 * malicious-plugin sandbox — plugins are trusted in-process — but a cheap *correctness*
 * boundary: core verification (`openRoutedMessage`) mints an opaque `AuthenticatedOrigin`
 * handle from the key it just authenticated, and `observe` accepts only such a handle. A
 * plugin holding a bare key cannot record against it by accident; it must present the handle
 * verification issued this request.
 *
 * The state is **OR-floored** (a kind, once set for an origin, is never cleared — a relay must
 * not be able to shed it) and **key-indexed** (so an identity rotation, being a new key, is a
 * fresh entry — the old marker harmlessly retires with the old key). It is capped and
 * **fails closed at capacity**: a full store refuses a *new* origin's marker rather than
 * evicting an existing one, so a flood of throwaway identities cannot lever an existing
 * marker out (eviction would be a targeted downgrade tool).
 *
 * @module routedObservation
 */

/** The observation kinds this store understands. Adding one is a deliberate schema change. */
export const OBSERVATION_KINDS = /** @type {const} */ (["requireSealFrom"]);
const KIND_SET = new Set(/** @type {readonly string[]} */ (OBSERVATION_KINDS));

/** Ceiling on tracked origins; at capacity a new origin's marker is refused, never evicting
 * an existing one (a marker is a downgrade-defence a relay must not be able to shed). */
export const DEFAULT_MAX_ENTRIES = 4096;

const SHA256_B64URL_LEN = 43; // a keyId: SHA-256 of SPKI DER, base64url, unpadded
const B64URL = /^[A-Za-z0-9_-]+$/;
/** @param {unknown} v */
const isKeyId = (v) => typeof v === "string" && v.length === SHA256_B64URL_LEN && B64URL.test(v);

// The set of handles this module has issued. Membership is the proof — an object not minted by
// `authenticatedOrigin` is not a proof, however it is shaped. A WeakSet keeps it request-scoped
// (a handle is collectable once the request drops it) and unforgeable without calling the mint.
const issued = new WeakSet();

/**
 * Mint the opaque authenticated-origin handle for a key core verification has authenticated.
 * Called by `openRoutedMessage` on a verified manifest; a consumer receives it in the verified
 * result and presents it to `observe`. It carries only the normalized origin key id.
 *
 * The proof is safe to hold past its request *only because every current kind attests a
 * timeless fact* (`requireSealFrom` = "this origin proved it can seal to me", recorded
 * OR-floored, never cleared). A future kind that is time-sensitive ("origin was reachable at
 * T", "origin held capability C") must bind an epoch into the proof, or be rejected here —
 * WeakSet membership alone does not make a stashed, replayed proof stale.
 *
 * @param {string} originKeyId the authenticated origin identity key id
 * @returns {{ originKeyId: string }} an opaque, frozen handle (identity matters, not shape)
 */
export function authenticatedOrigin(originKeyId) {
  // Validate here so the correctness boundary is self-consistent, not convention-dependent —
  // the only caller passes a verified keyId, so this never fires, but the mint should not
  // brand a non-key.
  if (!isKeyId(originKeyId)) throw new Error("authenticatedOrigin requires an origin key id");
  const handle = Object.freeze({ originKeyId });
  issued.add(handle);
  return handle;
}

/** Whether `v` is a handle this module issued (the proof check). @param {unknown} v */
export function isAuthenticatedOrigin(v) {
  return typeof v === "object" && v !== null && issued.has(/** @type {object} */ (v));
}

/**
 * A tracked origin, as persisted: its identity key id and the kinds observed about it.
 * @typedef {{ id: string, kinds: string[] }} StoredObservation
 */

/**
 * @param {{
 *   maxEntries?: number,
 *   initial?: StoredObservation[],                 // a persisted snapshot to rehydrate
 *   persist?: (entries: StoredObservation[]) => void, // called after each durable change
 * }} [options]
 */
export function createRoutedObservationStore({ maxEntries = DEFAULT_MAX_ENTRIES, initial, persist } = {}) {
  /** @type {Map<string, Set<string>>} originKeyId -> observed kinds */
  const entries = new Map();

  /** @returns {StoredObservation[]} */
  const serialize = () => [...entries].map(([id, kinds]) => ({ id, kinds: [...kinds] }));
  const persistNow = () => {
    // Best-effort, like the replay guard and key store: a persist failure must not propagate
    // out of the delivery path. The in-memory marker is authoritative; durability is an add-on.
    if (!persist) return;
    try {
      persist(serialize());
    } catch {
      /* the in-memory marker stands */
    }
  };

  // Rehydrate: keep only well-formed ids and known kinds; a malformed line is skipped, never
  // fatal. The markers are self-evident (a key id + a kind enum), so there is nothing to
  // re-verify — unlike a routed sealing key, a marker grants no capability, it only ratchets
  // confidentiality upward, so the worst a hand-edit achieves is over-refusing (availability).
  if (Array.isArray(initial)) {
    for (const it of initial) {
      if (!it || !isKeyId(it.id) || !Array.isArray(it.kinds) || entries.has(it.id) || entries.size >= maxEntries) continue;
      const kinds = it.kinds.filter((k) => KIND_SET.has(k));
      if (kinds.length) entries.set(it.id, new Set(kinds));
    }
  }

  return {
    /**
     * Record that `kind` was observed about the origin the `proof` authenticates. OR-floored:
     * a kind already set is a no-op (no write). Requires a handle minted this request by
     * `authenticatedOrigin` — a bare key throws, so a consumer cannot record against an
     * unverified origin by accident.
     *
     * @param {{ originKeyId: string }} proof an AuthenticatedOrigin handle
     * @param {(typeof OBSERVATION_KINDS)[number]} kind
     * @returns {"recorded" | "already" | "at-capacity"}
     */
    observe(proof, kind) {
      if (!isAuthenticatedOrigin(proof)) throw new Error("observe requires an authenticated-origin proof");
      if (!KIND_SET.has(kind)) throw new Error(`unknown observation kind: ${kind}`);
      const id = proof.originKeyId;
      const set = entries.get(id);
      if (set) {
        if (set.has(kind)) return "already";
        set.add(kind);
        persistNow();
        return "recorded";
      }
      // A new origin: honor the ceiling by refusing, never evicting an existing marker.
      if (entries.size >= maxEntries) return "at-capacity";
      entries.set(id, new Set([kind]));
      persistNow();
      return "recorded";
    },

    /**
     * Whether `kind` has been observed about `originKeyId` — the read side an enforcement
     * policy consults. Takes a bare key (reading needs no proof; only writing does).
     * @param {string} originKeyId @param {string} kind
     */
    has(originKeyId, kind) {
      return entries.get(originKeyId)?.has(kind) === true;
    },

    /** Tracked-origin count — for tests and diagnostics. */
    size: () => entries.size,

    /** The observations in persisted form — the same snapshot `persist` receives. */
    snapshot: () => serialize(),
  };
}
