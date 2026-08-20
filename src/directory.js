/**
 * The peers this machine knows, and the ones it has merely heard of.
 *
 * Two sets, and the distinction between them is the security model rather than
 * bookkeeping:
 *
 * **Admitted** peers are ones a person added. They can be hailed, and this
 * machine will answer them.
 *
 * **Candidates** are names other peers mentioned. They are leads. Trust does
 * not travel with a peer list — a peer naming another tells you it exists, not
 * that you should talk to it. Admitting one stays a deliberate act, because
 * gossip that also carried trust would turn one compromised peer into a way to
 * introduce arbitrary machines.
 *
 * The directory holds no credentials, only names, routes and when each was last
 * seen. See `peerRecord`.
 *
 * @module directory
 */
import { makePeerRecord, mergePeerRecord, publicRecord } from "./peerRecord.js";
import { sameKey } from "./identity.js";
import { allows, DEFAULT_PROFILE, resolveProfile } from "./profiles.js";

/**
 * @param {{ self?: any, admitted?: any[], candidates?: any[], now?: () => number }} [state]
 */
export function createDirectory(state = {}) {
  const self = makePeerRecord(state.self ?? { name: "unnamed" }) ?? {
    name: "unnamed",
    publicKey: null,
    addresses: [],
    lastSeen: null,
  };
  const now = state.now ?? (() => Date.now());
  /** @type {Map<string, import("./peerRecord.js").PeerRecord & {profile: string}>} */
  const admitted = new Map();
  /** @type {Map<string, { record: import("./peerRecord.js").PeerRecord, heardFrom: string[] }>} */
  const candidates = new Map();

  for (const peer of state.admitted ?? []) {
    const record = makePeerRecord(peer);
    if (record) {
      admitted.set(record.name, { ...record, profile: peer.profile ?? DEFAULT_PROFILE });
    }
  }
  for (const peer of state.candidates ?? []) {
    const record = makePeerRecord(peer);
    if (record) candidates.set(record.name, { record, heardFrom: peer.heardFrom ?? [] });
  }

  /**
   * Admit a peer: the deliberate act that gossip is not allowed to perform.
   *
   * A peer is admitted *into a profile*, which is what it may then ask for.
   * `trusted` unless another is named — the common case is your own machines.
   *
   * @param {any} peer
   * @param {{profile?: string}} [options]
   * @returns {(import("./peerRecord.js").PeerRecord & {profile: string}) | null}
   */
  function admit(peer, { profile } = {}) {
    const record = makePeerRecord(peer);
    if (!record) return null;
    const existing = admitted.get(record.name) ?? null;
    const merged = mergePeerRecord(existing, record) ?? record;
    const withProfile = {
      ...merged,
      profile: profile ?? peer?.profile ?? existing?.profile ?? DEFAULT_PROFILE,
    };
    admitted.set(withProfile.name, withProfile);
    candidates.delete(withProfile.name);
    return withProfile;
  }

  /**
   * Forget a peer entirely, admitted or not. Revocation has to be simple.
   *
   * @param {string} name
   */
  function forget(name) {
    return admitted.delete(name) || candidates.delete(name);
  }

  /**
   * Record what a peer told us about the others it knows.
   *
   * Names we already admitted are merged — they may have moved, and a fresh
   * route is worth having. Names we do not know become candidates, tagged with
   * who mentioned them so a person deciding later can see where a lead came
   * from. Nothing here admits anybody.
   *
   * @param {string} sourceName who told us
   * @param {any} peers what they said they know
   */
  function learnFrom(sourceName, peers) {
    /** @type {{merged: string[], candidates: string[]}} */
    const learned = { merged: [], candidates: [] };
    for (const peer of Array.isArray(peers) ? peers : []) {
      const record = makePeerRecord(peer);
      if (!record || record.name === self.name) continue;

      const known = admitted.get(record.name);
      if (known) {
        const merged = mergePeerRecord(known, record);
        // The profile is ours; nothing a peer says can change what another peer
        // is allowed to ask of us.
        if (merged) admitted.set(record.name, { ...merged, profile: known.profile });
        learned.merged.push(record.name);
        continue;
      }

      const existing = candidates.get(record.name);
      const heardFrom = new Set(existing?.heardFrom ?? []);
      if (sourceName) heardFrom.add(sourceName);
      candidates.set(record.name, {
        record: (existing ? mergePeerRecord(existing.record, record) : record) ?? record,
        heardFrom: [...heardFrom],
      });
      if (!existing) learned.candidates.push(record.name);
    }
    return learned;
  }

  /**
   * Note that a route worked. The only way an address earns its position.
   *
   * @param {string} name
   * @param {{transport: string, value: string} | undefined} address
   */
  function markReachable(name, address) {
    const record = admitted.get(name);
    if (!record) return null;
    const stamped = record.addresses.map((entry) =>
      entry.transport === address?.transport && entry.value === address?.value
        ? { ...entry, lastOk: now() }
        : entry,
    );
    // Re-made rather than merged: merging with nothing returns what it was
    // given, and the point of stamping a route is to reorder them.
    const updated = makePeerRecord({ ...record, addresses: stamped, lastSeen: now() });
    // makePeerRecord only returns null for a nameless record, which this cannot
    // be — but a silent null here would erase a peer, so it is checked.
    if (!updated) return record;
    const stampedRecord = { ...updated, profile: record.profile };
    admitted.set(name, stampedRecord);
    return stampedRecord;
  }

  /**
   * What this machine will tell a peer that asks.
   *
   * Admitted peers only. Passing on candidates would relay hearsay we never
   * checked, and would let one peer seed names across a whole network by
   * telling a single machine about them.
   */
  function hailResponse() {
    return {
      self: publicRecord({ ...self, lastSeen: now() }),
      // Peers granted nothing are still ours to know about, but telling others
      // where to find a machine we deliberately do not answer would hand out a
      // reachability we chose not to use.
      peers: [...admitted.values()]
        .filter((record) => allows(record.profile, "hail"))
        .map((record) => publicRecord(record))
        .filter(Boolean),
    };
  }

  return {
    self,
    admit,
    forget,
    learnFrom,
    markReachable,
    hailResponse,
    /** @param {string} name */
    /** @param {string} name */
    get: (name) => admitted.get(name) ?? null,
    /**
     * Find an admitted peer by the key it signs with.
     *
     * The lookup that matters when someone calls: a name is what they claim, a
     * key is what they proved.
     *
     * @param {string} publicKey
     */
    getByKey: (publicKey) =>
      [...admitted.values()].find((record) => sameKey(record.publicKey, publicKey)) ?? null,
    /**
     * @param {string} name
     * @param {string} capability
     */
    allowsCapability: (name, capability) => {
      const record = admitted.get(name);
      return record ? allows(record.profile, capability) : false;
    },
    /** @param {string} name */
    profileFor: (name) => resolveProfile(admitted.get(name)?.profile),
    listAdmitted: () => [...admitted.values()],
    listCandidates: () =>
      [...candidates.entries()].map(([name, entry]) => ({ ...entry.record, name, heardFrom: entry.heardFrom })),
    /** Everything worth writing to disk, in the shape the constructor accepts. */
    snapshot: () => ({
      self,
      admitted: [...admitted.values()],
      candidates: [...candidates.entries()].map(([name, entry]) => ({
        ...entry.record,
        name,
        heardFrom: entry.heardFrom,
      })),
    }),
  };
}
