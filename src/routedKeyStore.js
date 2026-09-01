/**
 * Discovered sealing keys for routed destinations — the Tier-1 half of routing key trust
 * (`docs/routing-security-roadmap.md`).
 *
 * A routed destination is an identity *key*, often a peer we have never walked to and
 * hold no local record for — so its sealing key cannot come from the name-keyed directory
 * (that is Tier 0, `directory.sealKeyFor`). Instead the destination's *signed* self-record
 * rides back on a **data-free discovery probe** (never on a message carrying application
 * data), and this store records the sealing key it carries — but only after proving the
 * record's identity **equals the routing target** (`keyId(record.publicKey) ===
 * targetKeyId`, a second-preimage-hard binding), never on raw string trust.
 *
 * A discovered key is held **pending** and is **not usable for sealing until a person
 * approves it** (by fingerprint) — the manual gate that makes Tier 1 safe. Approval is the
 * Tier-1 analogue of a walk: it is what turns "signed hearsay with no liveness" into "a
 * key this operator chose to trust". `recordSealKey` therefore returns a key only once it
 * is approved; the resolver refuses (never falls back to cleartext) for a merely-pending
 * or absent key.
 *
 *  - **Signed, but no liveness.** A relay cannot forge or substitute the record for a
 *    *different* key, but it can replay an *older* signed record (a retired sealing key).
 *    Approval is the human check against that; two *different* keys for one target become a
 *    sticky `record-conflict` (approval void) and the store refuses to pick a winner.
 *  - **Restart-safe when given a persistence port.** With no port the store is session-scoped
 *    (a record re-arrives on the next discovery, and a stale key never outlives the process).
 *    Pass `initial` + `persist` and its state survives a restart — so an **approved** key does
 *    not fall back to a first cleartext re-discovery on restart, and a **conflict** (security
 *    evidence) cannot be shed by a bounce. This extends Tier-1's existing no-liveness property
 *    across the restart (a pending key is still unusable until approved); the module does no
 *    I/O, the daemon wires the port to a sidecar file. Capacity eviction still drops a
 *    *pending* entry first — never an *approved* key or a *conflict*.
 *
 * @module routedKeyStore
 */
import { keyId } from "./routeManifest.js";
import { verifyRecord } from "./peerRecord.js";
import { sameKey } from "./identity.js";

/** Ceiling on tracked destinations; the oldest *pending* entry is evicted when full.
 * Approved keys and conflicts are never evicted (operator/security state). */
export const DEFAULT_MAX_ENTRIES = 4096;

const SHA256_B64URL_LEN = 43; // a keyId: SHA-256 of SPKI DER, base64url, unpadded
const B64URL = /^[A-Za-z0-9_-]+$/;
/** @param {unknown} v */
const isKeyId = (v) => typeof v === "string" && v.length === SHA256_B64URL_LEN && B64URL.test(v);

/**
 * A tracked destination, as persisted: its identity key id, the classified sealing key, and
 * the **signed self-record** the key came from (null for a conflict), so the identity→key
 * binding is re-proven on load rather than trusted — a hand-edited sidecar cannot bind an
 * attacker's key as approved.
 * @typedef {{ id: string, sealKey: string | null, approved: boolean, conflict: boolean, name: string, record: any }} StoredEntry
 */

/**
 * @param {{
 *   maxEntries?: number,
 *   initial?: StoredEntry[],                 // a persisted snapshot to rehydrate
 *   persist?: (entries: StoredEntry[]) => void, // called after each durable mutation
 * }} [options]
 */
export function createRoutedKeyStore({ maxEntries = DEFAULT_MAX_ENTRIES, initial, persist } = {}) {
  /**
   * @type {Map<string, {
   *   sealKey: string | null,   // the discovered X25519 sealing key (null once conflicted)
   *   approved: boolean,        // a person has approved this key for sealing
   *   conflict: boolean,        // two differing sealing keys seen -> refuse to pick
   *   name: string,             // the destination's self-declared name, for surfacing
   *   record: any,              // the signed self-record the key came from (null on conflict)
   * }>}
   */
  const entries = new Map();

  /** @returns {StoredEntry[]} */
  const serialize = () => [...entries].map(([id, e]) => ({ id, sealKey: e.sealKey, approved: e.approved, conflict: e.conflict, name: e.name, record: e.record ?? null }));
  const persistNow = () => {
    // Best-effort, for the same reason as the replay guard: a persist failure must not
    // propagate out of observe/approve/forget (breaking a Tier-0 handler mid-flight, or
    // failing a send() for a delivered message). The in-memory state is authoritative.
    if (!persist) return;
    try {
      persist(serialize());
    } catch {
      /* durability is best-effort; the in-memory state stands */
    }
  };

  // Rehydrate a persisted snapshot. A conflict seals to nothing (fail-closed), so it needs no
  // key to re-prove and is kept sticky as-is. Any usable/pending entry must carry the signed
  // self-record its key came from, and that record is re-verified here exactly as `observe`
  // did — only the destination could sign a record whose identity hashes to this id, so a
  // hand-edited sidecar cannot bind an *attacker's* key as approved: the key is always one the
  // destination genuinely signed. What this proves is the identity->key *binding*, not the
  // approval *decision* — a local editor can still flip `approved` on a genuine record, or
  // substitute an older genuine one (the same no-liveness gap as a replayed record, at the
  // same trust level as editing directory.json). The sealing key is taken from the re-verified
  // record, not the sibling field, so a tampered `sealKey` is ignored. A malformed or unproven
  // line is skipped, never fatal.
  if (Array.isArray(initial)) {
    for (const it of initial) {
      if (!it || !isKeyId(it.id) || entries.has(it.id) || entries.size >= maxEntries) continue;
      if (it.conflict === true) {
        entries.set(it.id, { sealKey: null, approved: false, conflict: true, name: typeof it.name === "string" ? it.name : "", record: null });
        continue;
      }
      if (!it.record) continue; // a usable/pending entry with no record to re-prove is dropped
      const rec = verifyRecord(it.record, null);
      if (!rec.ok) continue;
      let identityKeyId;
      try {
        identityKeyId = keyId(rec.key);
      } catch {
        continue;
      }
      if (identityKeyId !== it.id) continue;
      const sealKey = rec.record.sealPublicKey ?? null;
      if (!sealKey) continue;
      entries.set(it.id, { sealKey, approved: it.approved === true, conflict: false, name: rec.record.name, record: it.record });
    }
  }

  /** Make room under the ceiling by dropping the oldest *pending* destination, and report
   * whether it could. An approved key (operator-blessed) and a conflict (security evidence
   * — dropping it would let a replayed single record re-establish a stale key) are NEVER
   * evicted; if every slot is one of those, no room is made and the new observation is
   * dropped instead (retriable — it re-arrives on the next discovery). Map iteration is
   * insertion order, so the first match is the oldest pending. @returns {boolean} evicted */
  const evictOldest = () => {
    for (const [k, e] of entries) {
      if (!e.approved && !e.conflict) {
        entries.delete(k);
        return true;
      }
    }
    return false;
  };

  return {
    /**
     * Classify and record the sealing key a signed self-record carries for a routed
     * destination. The record must be self-consistent (`verifyRecord(_, null)`) and its
     * identity must equal `targetKeyId`; otherwise nothing is stored. A newly discovered
     * key is **pending** (`record-carried`) — approval is a separate, deliberate step.
     *
     * @param {string} targetKeyId the routing target's identity key id (`keyId(dest)`)
     * @param {any} envelope a `{record, signature}` signed self-record
     * @returns {"record-approved" | "record-carried" | "record-conflict" | "no-seal-key" | "not-target" | "unverified" | "at-capacity"}
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
      if (!sealKey) return "no-seal-key"; // a record with no sealing key offers no key

      const existing = entries.get(targetKeyId);
      if (!existing) {
        // At capacity, evict a pending entry to make room; if every slot is an approved
        // key or a conflict (never evicted), drop this new discovery rather than clobber
        // one — it is retriable on the next probe.
        if (entries.size >= maxEntries && !evictOldest()) return "at-capacity";
        // Keep the signed envelope so the binding is re-provable on restart, not just trusted.
        entries.set(targetKeyId, { sealKey, approved: false, conflict: false, name: rec.record.name, record: envelope });
        persistNow();
        return "record-carried";
      }
      if (existing.conflict) return "record-conflict"; // sticky — and now persisted, so sticky across restarts too
      if (sameKey(existing.sealKey, sealKey)) {
        return existing.approved ? "record-approved" : "record-carried"; // adds no authority
      }
      // A different sealing key for the same target: ambiguous hearsay. Refuse to pick,
      // and void any prior approval — a key we approved is no longer the only claim.
      existing.sealKey = null;
      existing.approved = false;
      existing.conflict = true;
      existing.record = null; // a conflict seals to nothing; it carries no key to re-prove
      persistNow();
      return "record-conflict";
    },

    /**
     * Approve the destination's currently-pending discovered key for sealing — the manual
     * Tier-1 trust gate. Optionally require it to equal `expectedSealKey` (the fingerprint
     * the operator reviewed), so an approval cannot race a key that changed underneath it.
     *
     * @param {string} targetKeyId
     * @param {string} [expectedSealKey] approve only if the held key matches this
     * @returns {{ ok: true, sealKey: string } | { ok: false, reason: "unknown" | "conflict" | "mismatch" }}
     */
    approve(targetKeyId, expectedSealKey) {
      const e = entries.get(targetKeyId);
      if (!e) return { ok: false, reason: "unknown" };
      // Conflict first: a conflicted entry has a null key, so the key check below would
      // otherwise misreport it as "unknown" rather than the real "conflict".
      if (e.conflict) return { ok: false, reason: "conflict" };
      if (!e.sealKey) return { ok: false, reason: "unknown" };
      if (expectedSealKey !== undefined && !sameKey(e.sealKey, expectedSealKey)) {
        return { ok: false, reason: "mismatch" };
      }
      if (!e.approved) {
        e.approved = true;
        persistNow(); // persist only a real transition, not an idempotent re-approval
      }
      return { ok: true, sealKey: e.sealKey };
    },

    /**
     * The **approved** sealing key for a destination, or null if none is approved (pending,
     * conflicted, or absent). This is the only key the send path may seal to at Tier 1;
     * Tier-0 resolution is the caller's job and always takes precedence.
     *
     * @param {string} targetKeyId
     * @returns {string | null}
     */
    recordSealKey(targetKeyId) {
      const e = entries.get(targetKeyId);
      return e && e.approved && !e.conflict ? e.sealKey : null;
    },

    /**
     * The Tier-1 view of a destination. `record-approved` is usable; `record-carried` is
     * discovered-but-pending (awaiting approval); the rest are self-explanatory. Never
     * `verified`: that is a Tier-0 word and belongs to the directory.
     *
     * @param {string} targetKeyId
     * @returns {"record-approved" | "record-carried" | "record-conflict" | "none"}
     */
    recordState(targetKeyId) {
      const e = entries.get(targetKeyId);
      if (!e) return "none";
      if (e.conflict) return "record-conflict";
      return e.approved ? "record-approved" : "record-carried";
    },

    /**
     * What to show a person deciding whether to approve, or before a Tier-1 send: the
     * sealing key (to fingerprint), the destination's declared name, and whether it is
     * already approved. Null on a conflict or when nothing is held. No record "age" is
     * surfaced — a relay selects which past record it replays, so age would be a value it
     * chooses wearing a freshness label.
     *
     * @param {string} targetKeyId
     * @returns {{ sealKey: string, name: string, approved: boolean } | null}
     */
    recordDetail(targetKeyId) {
      const e = entries.get(targetKeyId);
      if (!e || e.conflict || !e.sealKey) return null;
      return { sealKey: e.sealKey, name: e.name, approved: e.approved };
    },

    /**
     * Drop a destination's Tier-1 entry — used when an authoritative Tier-0 event (a walk,
     * a rotation, a forget) supersedes it, so a moot or retired key cannot linger.
     * @param {string} targetKeyId
     */
    forget(targetKeyId) {
      if (entries.delete(targetKeyId)) persistNow();
    },

    /** Tracked-destination count — for tests and diagnostics. */
    size: () => entries.size,

    /** The tracked destinations in persisted form — the same snapshot `persist` receives. */
    snapshot: () => serialize(),
  };
}
