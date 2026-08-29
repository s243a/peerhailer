/**
 * Tier-1 record-carried sealing keys for routed destinations — the discovery half of
 * milestone M2 (`docs/routing-security-roadmap.md`).
 *
 * A routed destination is an identity *key*, often a peer we have never walked to and
 * hold no local record for — so its sealing key cannot come from the name-keyed
 * directory (that is Tier 0, `directory.sealKeyFor`). Instead the destination's *signed*
 * self-record rides back on a route-discovery response or an earlier authenticated
 * cleartext delivery, and this store records the sealing key it carries — but only after
 * proving the record's identity **equals the routing target** (`keyId(record.publicKey)
 * === targetKeyId`, a second-preimage-hard binding), never on raw string trust.
 *
 * The guarantee is deliberately weaker than Tier 0 and deliberately quarantined:
 *  - **Signed, but no liveness.** A relay cannot forge or substitute the record for a
 *    *different* key, but it can preserve and replay an *older* signed record of the same
 *    destination (stale addresses, a retired sealing key). So Tier 1 beats a passive
 *    relay lacking the retired private key, but has weaker freshness/revocation than a
 *    walk — the caller must treat it as opt-in, surface it before sending, and never
 *    show the Tier-0 lock. Tier 0 always wins at the call site.
 *  - **Session-scoped, in-memory.** Like the replay guard, this holds no durable state:
 *    a record re-arrives whenever routing to that destination recurs, so nothing is lost
 *    by forgetting on restart, and a stale Tier-1 key never outlives the process. A
 *    durable variant is possible but is not built. Capacity eviction is safe for an
 *    ordinary record-carried entry (it is simply re-observed), but a *conflict* is
 *    security evidence — dropping it would let a relay replaying a single old record
 *    re-establish a stale key — so conflicts are evicted last, only if every slot is
 *    disputed at once (a pathological state a relay cannot reach on its own).
 *  - **Conflict is refusal, not selection.** Two *different* sealing keys observed for
 *    one target mark it `record-conflict`, and `recordSealKey` then returns null: the
 *    store never picks a winner from ambiguous hearsay. A later Tier-0 walk resolves it
 *    (the caller prefers Tier 0, and may `forget` the moot Tier-1 entry).
 *
 * @module routedKeyStore
 */
import { keyId } from "./routeManifest.js";
import { verifyRecord } from "./peerRecord.js";
import { sameKey } from "./identity.js";

/** Ceiling on tracked destinations; the oldest non-conflicted entry is evicted when
 * full. Evicting a record-carried entry is safe (it is re-observed); conflicts are kept. */
export const DEFAULT_MAX_ENTRIES = 4096;

const SHA256_B64URL_LEN = 43; // a keyId: SHA-256 of SPKI DER, base64url, unpadded
const B64URL = /^[A-Za-z0-9_-]+$/;
/** @param {unknown} v */
const isKeyId = (v) => typeof v === "string" && v.length === SHA256_B64URL_LEN && B64URL.test(v);

/**
 * @param {{ maxEntries?: number }} [options]
 */
export function createRoutedKeyStore({ maxEntries = DEFAULT_MAX_ENTRIES } = {}) {
  /**
   * @type {Map<string, {
   *   sealKey: string | null,   // the record-carried X25519 sealing key (null once conflicted)
   *   conflict: boolean,        // two differing sealing keys seen -> refuse to pick
   *   name: string,             // the destination's self-declared name, for surfacing
   *   recordLastSeen: number | null, // the record's own freshness stamp, for age surfacing
   * }>}
   */
  const entries = new Map();

  /** Make room under the ceiling by dropping the oldest *non-conflicted* destination — a
   * conflict is security evidence and must not be silently lost (its loss would let a
   * replayed single record re-establish a stale key). Only if every slot is disputed
   * does the oldest conflict go, and a relay cannot manufacture that state itself. Map
   * iteration is insertion order, so the first match is the oldest of its kind. */
  const evictOldest = () => {
    for (const [k, e] of entries) {
      if (!e.conflict) {
        entries.delete(k);
        return;
      }
    }
    const oldest = entries.keys().next();
    if (!oldest.done) entries.delete(oldest.value);
  };

  return {
    /**
     * Classify and record the sealing key a signed self-record carries for a routed
     * destination. The record must be self-consistent (`verifyRecord(_, null)`) and its
     * identity must equal `targetKeyId`; otherwise nothing is stored.
     *
     * @param {string} targetKeyId the routing target's identity key id (`keyId(dest)`)
     * @param {any} envelope a `{record, signature}` signed self-record
     * @returns {"record-carried" | "record-conflict" | "no-seal-key" | "not-target" | "unverified"}
     */
    observe(targetKeyId, envelope) {
      if (!isKeyId(targetKeyId)) return "unverified";
      const rec = verifyRecord(envelope, null);
      if (!rec.ok) return "unverified";

      // Bind the record to the routing target: only the destination itself could have
      // signed a record whose key hashes to targetKeyId (second-preimage on SHA-256).
      let identityKeyId;
      try {
        identityKeyId = keyId(rec.key);
      } catch {
        return "unverified";
      }
      if (identityKeyId !== targetKeyId) return "not-target";

      const sealKey = rec.record.sealPublicKey ?? null;
      if (!sealKey) return "no-seal-key"; // a record with no sealing key offers no Tier-1 key

      const existing = entries.get(targetKeyId);
      if (!existing) {
        if (entries.size >= maxEntries) evictOldest();
        entries.set(targetKeyId, {
          sealKey,
          conflict: false,
          name: rec.record.name,
          recordLastSeen: rec.record.lastSeen,
        });
        return "record-carried";
      }
      if (existing.conflict) return "record-conflict"; // sticky within the session
      if (sameKey(existing.sealKey, sealKey)) {
        // A matching record adds no authority; refresh only the freshness stamp.
        if (typeof rec.record.lastSeen === "number") existing.recordLastSeen = rec.record.lastSeen;
        return "record-carried";
      }
      // A different sealing key for the same target: ambiguous hearsay, refuse to pick.
      existing.sealKey = null;
      existing.conflict = true;
      return "record-conflict";
    },

    /**
     * The Tier-1 record-carried sealing key for a destination, or null if none was
     * observed or the observations conflict. Tier-0 resolution is the caller's job and
     * always takes precedence over this.
     *
     * @param {string} targetKeyId
     * @returns {string | null}
     */
    recordSealKey(targetKeyId) {
      const e = entries.get(targetKeyId);
      return e && !e.conflict ? e.sealKey : null;
    },

    /**
     * The Tier-1 view of a destination — for policy and for the pre-send surface. Never
     * `verified`: that is a Tier-0 word and belongs to the directory, which the caller
     * consults first.
     *
     * @param {string} targetKeyId
     * @returns {"record-carried" | "record-conflict" | "none"}
     */
    recordState(targetKeyId) {
      const e = entries.get(targetKeyId);
      if (!e) return "none";
      return e.conflict ? "record-conflict" : "record-carried";
    },

    /**
     * What to show a person before a Tier-1 send: the sealing key (to fingerprint), the
     * destination's declared name, and the record's own freshness stamp (its age). Null
     * when there is no usable Tier-1 key.
     *
     * @param {string} targetKeyId
     * @returns {{ sealKey: string, name: string, recordLastSeen: number | null } | null}
     */
    recordDetail(targetKeyId) {
      const e = entries.get(targetKeyId);
      if (!e || e.conflict || !e.sealKey) return null;
      return { sealKey: e.sealKey, name: e.name, recordLastSeen: e.recordLastSeen };
    },

    /**
     * Drop a destination's Tier-1 entry — used when a Tier-0 walk supersedes it, so the
     * moot record-carried key (and any conflict) no longer lingers.
     * @param {string} targetKeyId
     */
    forget(targetKeyId) {
      entries.delete(targetKeyId);
    },

    /** Tracked-destination count — for tests and diagnostics. */
    size: () => entries.size,
  };
}
