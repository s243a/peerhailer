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
import { normalizeKey, sameKey } from "./identity.js";
import {
  allows,
  ADMIT_PROFILE,
  BLOCKED_PROFILE,
  CANDIDATE_PROFILE,
  DEFAULT_PROFILE,
  INTRODUCE,
  listProfiles,
  resolveProfile,
} from "./profiles.js";
import { profileFor } from "./trust.js";

/**
 * Profiles by name — built-ins merged with whatever was customised.
 *
 * @param {Record<string, any>} custom
 */
function asRecord(custom) {
  return Object.fromEntries(listProfiles(custom).map((profile) => [profile.name, profile]));
}

/**
 * @param {{
 *   self?: any,
 *   admitted?: any[],
 *   candidates?: any[],
 *   blocklist?: {names?: string[], keys?: string[]},
 *   profiles?: Record<string, any>,
 *   trust?: {model?: string, settings?: Record<string, unknown>, unknownProfile?: string,
 *           admitProfile?: string, candidateProfile?: string},
 *   now?: () => number,
 * }} [state]
 */
export function createDirectory(state = {}) {
  const self = makePeerRecord(state.self ?? { name: "unnamed" }) ?? {
    name: "unnamed",
    publicKey: null,
    addresses: [],
    lastSeen: null,
  };
  const now = state.now ?? (() => Date.now());
  /**
   * What a peer says about itself, plus what is ours: the profile we assigned,
   * and any competing key we have watched answer in its name.
   *
   * @typedef {import("./peerRecord.js").PeerRecord & {
   *   profile: string,
   *   conflicts?: {key: string, firstSeen: number, lastSeen: number, count: number, via?: string}[],
   * }} StoredPeer
   */
  /** @type {Map<string, StoredPeer>} */
  const admitted = new Map();
  /** @type {Map<string, { record: import("./peerRecord.js").PeerRecord, heardFrom: string[] }>} */
  const candidates = new Map();

  for (const peer of state.admitted ?? []) {
    const record = makePeerRecord(peer);
    if (record) {
      admitted.set(record.name, { ...record, profile: peer.profile ?? DEFAULT_PROFILE });
    }
  }
  const blocklist = {
    names: [...(state.blocklist?.names ?? [])],
    keys: [...(state.blocklist?.keys ?? [])],
  };
  /**
   * Profiles this directory resolves against.
   *
   * Built-ins plus whatever the user defined and any a plugin suggested. Held
   * here because a capability check that does not know about a profile silently
   * falls back to the default — a peer would appear to hold a grant it does
   * not, or be refused one it does, with nothing to say why.
   */
  let profileSet = asRecord(state.profiles ?? {});

  const trust = {
    model: state.trust?.model ?? "direct",
    settings: state.trust?.settings ?? {},
    unknownProfile: state.trust?.unknownProfile ?? "unknown",
    // Where a peer lands when nobody said otherwise. Two of them, because
    // typing an address and acting on a peer's say-so are different acts.
    admitProfile: state.trust?.admitProfile ?? ADMIT_PROFILE,
    candidateProfile: state.trust?.candidateProfile ?? CANDIDATE_PROFILE,
  };

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
    // Typing an address asserts you know the machine; acting on a name a peer
    // mentioned does not. A gossiped name promoted with an address of your own
    // is the first act, not the second — so the test is whether *this* call
    // brought one, not whether the name was ever heard of.
    const heardOf = candidates.has(record.name);
    const broughtAddress = record.addresses.length > 0;
    const fallback = heardOf && !broughtAddress ? trust.candidateProfile : trust.admitProfile;
    const withProfile = {
      ...merged,
      profile: profile ?? peer?.profile ?? existing?.profile ?? fallback ?? DEFAULT_PROFILE,
      ...(existing?.conflicts?.length ? { conflicts: existing.conflicts } : {}),
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
    const stampedRecord = keepOurs(updated, record);
    admitted.set(name, stampedRecord);
    return stampedRecord;
  }

  /**
   * Replace the key held for a peer, deliberately.
   *
   * The only path by which a held key changes. Everything else — gossip, a
   * merge, a signed reply from a stranger — leaves it alone, because a key
   * arriving over the wire is a claim and this is a decision. Clears the
   * conflicts, since whatever they were reporting has now been answered by a
   * person.
   *
   * @param {string} name
   * @param {string} publicKey
   */
  function rotateKey(name, publicKey) {
    const record = admitted.get(name);
    const key = normalizeKey(publicKey);
    if (!record || !key) return null;
    const { conflicts: _dropped, ...rest } = record;
    const rotated = { ...rest, publicKey: key };
    admitted.set(name, rotated);
    return rotated;
  }

  /**
   * Re-attach what belongs to us rather than to the peer.
   *
   * `makePeerRecord` builds a record from what a peer says about itself, which
   * is right for addresses and wrong for a profile we assigned or a conflict we
   * observed. Anything rebuilt has to carry those back or they are quietly lost
   * the next time a route is stamped.
   *
   * @param {any} rebuilt
   * @param {any} previous
   */
  function keepOurs(rebuilt, previous) {
    /** @type {any} */
    return {
      ...rebuilt,
      profile: previous?.profile,
      ...(previous?.conflicts?.length ? { conflicts: previous.conflicts } : {}),
    };
  }

  /**
   * Remember that something answered as this peer holding a different key.
   *
   * Not a decision — the key we hold keeps working, and nothing here changes
   * what is trusted. It exists because the alternative is one line of `walk`
   * output that scrolls past: run it again tomorrow and there is no sign
   * anything ever disagreed.
   *
   * The two cases this cannot tell apart are the whole reason a person has to
   * look. A machine whose key changed and a machine that is not this peer
   * produce identical evidence, and only someone who knows what they did that
   * afternoon can say which happened.
   *
   * Deliberately not part of `makePeerRecord`: a peer describing itself must
   * never be able to hand us a conflict list, only to cause one.
   *
   * @param {string} name
   * @param {string} publicKey
   * @param {{transport: string, value: string}} [via]
   */
  function noteKeyConflict(name, publicKey, via) {
    const record = admitted.get(name);
    const key = normalizeKey(publicKey);
    if (!record || !key || sameKey(key, record.publicKey)) return record ?? null;

    const seen = Array.isArray(record.conflicts) ? [...record.conflicts] : [];
    const at = now();
    const existing = seen.findIndex((entry) => sameKey(entry.key, key));
    const previous = existing >= 0 ? seen[existing] : undefined;
    if (previous) {
      seen[existing] = { ...previous, lastSeen: at, count: previous.count + 1 };
    } else {
      seen.push({ key, firstSeen: at, lastSeen: at, count: 1, ...(via ? { via: via.value } : {}) });
    }

    const updated = { ...record, conflicts: seen };
    admitted.set(name, updated);
    return updated;
  }

  /**
   * Bind a key to a peer on first verified contact.
   *
   * A peer admitted without a key is trusted on first use, and stays that way
   * until something writes the key back. Nothing did: `walk` verified a signed
   * reply and threw the key away, so every hail was another first contact and
   * the window never closed.
   *
   * A key already held is never replaced — rotation is a deliberate act, not
   * something a peer performs by answering differently tomorrow.
   *
   * @param {string} name
   * @param {string | null | undefined} publicKey
   */
  function bindKey(name, publicKey) {
    const record = admitted.get(name);
    if (!record || record.publicKey) return record ?? null;
    const bound = makePeerRecord({ ...record, publicKey });
    if (!bound || !bound.publicKey) return record;
    const kept = keepOurs(bound, record);
    admitted.set(name, kept);
    return kept;
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
        .filter((record) => profileFor({ peer: record, directory: api, blocklist }).profile !== BLOCKED_PROFILE)
        .filter((record) => allows(record.profile, "hail", profileSet))
        .map((record) => publicRecord(record))
        .filter(Boolean),
    };
  }

  const api = {
    self,
    admit,
    forget,
    learnFrom,
    markReachable,
    bindKey,
    noteKeyConflict,
    rotateKey,
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
     * The profile a peer effectively has, and why.
     *
     * Not simply what was assigned: a blocklist entry overrides it, and a peer
     * nobody assigned may still be derived a profile by the trust model. The
     * reason comes back too, because "why can this machine do that" is asked
     * when something has already gone wrong.
     *
     * @param {string} name
     */
    effectiveProfile: (name) => {
      const record = admitted.get(name);
      const candidate = candidates.get(name);
      return profileFor({
        peer: record ?? candidate?.record ?? { name },
        directory: api,
        blocklist,
        model: trust.model,
        settings: trust.settings,
        unknownProfile: trust.unknownProfile,
        vouchedBy: candidate?.heardFrom ?? [],
      });
    },
    /**
     * @param {string} name
     * @param {string} capability
     */
    allowsCapability: (name, capability) => {
      const record = admitted.get(name);
      const candidate = candidates.get(name);
      if (!record && !candidate) {
        // A caller we have never heard of still gets whatever the unknown
        // profile grants — nothing, unless someone changed that deliberately.
        return allows(trust.unknownProfile, capability, profileSet);
      }
      const { profile } = profileFor({
        peer: record ?? candidate?.record ?? { name },
        directory: api,
        blocklist,
        model: trust.model,
        settings: trust.settings,
        unknownProfile: trust.unknownProfile,
        vouchedBy: candidate?.heardFrom ?? [],
      });
      return allows(profile, capability, profileSet);
    },
    /** @param {string} name */
    profileFor: (name) => resolveProfile(admitted.get(name)?.profile, profileSet),
    /**
     * Take on state written by somebody else.
     *
     * The daemon serves from a long-lived directory while mutations are applied
     * to the file. After one lands, this brings the two back together — without
     * it the page would keep showing what was true before the change it just
     * made.
     *
     * @param {any} state
     */
    adopt: (state) => {
      admitted.clear();
      candidates.clear();
      for (const peer of state?.admitted ?? []) {
        const record = makePeerRecord(peer);
        if (record) admitted.set(record.name, keepOurs(record, { profile: peer.profile ?? DEFAULT_PROFILE, conflicts: peer.conflicts }));
      }
      for (const peer of state?.candidates ?? []) {
        const record = makePeerRecord(peer);
        if (record) candidates.set(record.name, { record, heardFrom: peer.heardFrom ?? [] });
      }
      blocklist.names = [...(state?.blocklist?.names ?? [])];
      blocklist.keys = [...(state?.blocklist?.keys ?? [])];
      // Including trust: a running daemon adopting new state was keeping its
      // old defaults, so changing where admitted peers land had no effect
      // until restart.
      if (state?.trust) {
        trust.model = state.trust.model ?? trust.model;
        trust.settings = state.trust.settings ?? trust.settings;
        trust.unknownProfile = state.trust.unknownProfile ?? trust.unknownProfile;
        trust.admitProfile = state.trust.admitProfile ?? trust.admitProfile;
        trust.candidateProfile = state.trust.candidateProfile ?? trust.candidateProfile;
      }
    },
    /**
     * Replace the profiles this directory resolves against.
     *
     * Used once plugins are loaded, since a plugin may suggest profiles and the
     * directory is built before it is known which plugins there are.
     *
     * @param {Record<string, any>} custom
     */
    useProfiles: (custom) => {
      profileSet = asRecord(custom);
    },
    /**
     * Deny a peer everything, by key where we have one.
     *
     * Blocking by name alone is defeated by renaming, so the key is what is
     * recorded when there is one — a peer cannot rename its way back in.
     *
     * @param {{name?: string, publicKey?: string | null}} peer
     */
    block: (peer) => {
      if (peer?.publicKey && !blocklist.keys.includes(peer.publicKey)) {
        blocklist.keys.push(peer.publicKey);
      } else if (peer?.name && !blocklist.names.includes(peer.name)) {
        blocklist.names.push(peer.name);
      }
      return { names: [...blocklist.names], keys: [...blocklist.keys] };
    },
    /** @param {string} name */
    unblock: (name) => {
      const record = admitted.get(name) ?? candidates.get(name)?.record ?? null;
      blocklist.names = blocklist.names.filter((entry) => entry !== name);
      if (record?.publicKey) {
        blocklist.keys = blocklist.keys.filter((key) => key !== record.publicKey);
      }
      return { names: [...blocklist.names], keys: [...blocklist.keys] };
    },
    blocklist: () => ({ names: [...blocklist.names], keys: [...blocklist.keys] }),
    trust: () => ({ ...trust }),
    listAdmitted: () => [...admitted.values()],
    listCandidates: () =>
      [...candidates.entries()].map(([name, entry]) => ({ ...entry.record, name, heardFrom: entry.heardFrom })),
    /** Everything worth writing to disk, in the shape the constructor accepts. */
    snapshot: () => ({
      self,
      blocklist: { names: [...blocklist.names], keys: [...blocklist.keys] },
      trust: { ...trust },
      admitted: [...admitted.values()],
      candidates: [...candidates.entries()].map(([name, entry]) => ({
        ...entry.record,
        name,
        heardFrom: entry.heardFrom,
      })),
    }),
  };

  // Returned after construction so a trust model can consult the directory it
  // is deciding for — `web-of-trust` has to ask which vouchers are credible.
  return api;
}
