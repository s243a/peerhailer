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
import {
  makePeerRecord,
  MAX_CONFLICTS,
  mergePeerRecord,
  publicRecord,
  TARGET_BINDING_VERSION,
} from "./peerRecord.js";
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
 * Carry the monotone sealing-key trust forward across independent writers.
 *
 * A writer snapshots the directory it loaded at startup and wholesale-replaces
 * `admitted` on disk. A verified sealing key is monotone — like `bindingSeen` —
 * so a writer that loaded *before* a walk elsewhere bound one must not erase it
 * on the way out, or the peer silently downgrades to cleartext after the write.
 * This reconciles a snapshot against current on-disk state, per peer:
 *
 * - Only when the identity key still matches — a rotated identity invalidates
 *   the old sealing binding, so its key is not resurrected onto a new identity.
 * - A verified on-disk key the snapshot lacks is carried forward (the stale
 *   writer never saw the bind).
 * - Two *different* verified keys is a genuine disagreement — kept as a
 *   conflict, not silently picked, so the send path fails closed.
 *
 * Pure and exported for direct testing; `persist()` composes it with the
 * `bindingSeen` max-merge it already does.
 *
 * @param {any[]} onDisk current on-disk admitted records
 * @param {any[]} snap this writer's admitted snapshot
 * @returns {any[]} the snapshot with sealing trust reconciled
 */
export function carryVerifiedSeal(onDisk, snap) {
  const prior = new Map((onDisk ?? []).map((p) => [p.name, p]));
  return (snap ?? []).map((p) => {
    const was = prior.get(p.name);
    if (!was?.sealSeen || !was.sealPublicKey || was.publicKey !== p.publicKey) return p;
    if (p.sealSeen && p.sealPublicKey && p.sealPublicKey !== was.sealPublicKey) {
      return { ...p, sealPublicKey: was.sealPublicKey, sealSeen: true, sealConflict: p.sealPublicKey };
    }
    if (!p.sealSeen || !p.sealPublicKey) {
      return { ...p, sealPublicKey: was.sealPublicKey, sealSeen: true, ...(was.sealConflict ? { sealConflict: was.sealConflict } : {}) };
    }
    return was.sealConflict && !p.sealConflict ? { ...p, sealConflict: was.sealConflict } : p;
  });
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
   *   profileUntil?: number,
   *   profileAfter?: string,
   *   bindingSeen?: number,
   *   sealSeen?: boolean,
   *   sealConflict?: string,
   * }} StoredPeer
   */
  /** @type {Map<string, StoredPeer>} */
  const admitted = new Map();
  /** @type {Map<string, { record: import("./peerRecord.js").PeerRecord, heardFrom: string[] }>} */
  const candidates = new Map();

  for (const peer of state.admitted ?? []) {
    const record = makePeerRecord(peer);
    if (record) {
      admitted.set(record.name, keepOurs(record, { ...peer, profile: peer.profile ?? DEFAULT_PROFILE }));
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
   * `until` raises that profile for a while and then lets it fall back to
   * whatever the peer held before — a temporary raise, not a temporary
   * existence. The clock is this machine's, checked when the question is asked,
   * which is what makes it safer than an expiry one machine writes and another
   * believes.
   *
   * @param {any} peer
   * @param {{profile?: string, until?: number}} [options]
   * @returns {(import("./peerRecord.js").PeerRecord & {profile: string}) | null}
   */
  function admit(peer, { profile, until } = {}) {
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
    // What it reverts to is captured now, while we still know what it was
    // raised from. Working it out at expiry means guessing months later.
    const elevation =
      until && profile
        ? { profileUntil: until, profileAfter: asOfNow(existing)?.profile ?? fallback ?? DEFAULT_PROFILE }
        : existing?.profileUntil
          ? { profileUntil: existing.profileUntil, ...(existing.profileAfter ? { profileAfter: existing.profileAfter } : {}) }
          : {};

    const withProfile = {
      ...merged,
      profile: profile ?? peer?.profile ?? existing?.profile ?? fallback ?? DEFAULT_PROFILE,
      ...(existing?.conflicts?.length ? { conflicts: existing.conflicts } : {}),
      // The support observation is monotone: re-attach it here, or a routine
      // address update (`hail add <known-peer> <new-address>`) would silently
      // clear the downgrade guard until the next verified walk. `merged` came
      // from `mergePeerRecord`, which does not carry this stored-only field.
      ...(existing?.bindingSeen ? { bindingSeen: existing.bindingSeen } : {}),
      // Likewise the sealing-key trust marker and any conflict: re-admitting a
      // peer (a new address, a profile change) must not drop the fact that we
      // verified its sealing key, or the next send falls back to cleartext —
      // nor silently clear a conflict a person still has to resolve.
      ...(existing?.sealSeen ? { sealSeen: existing.sealSeen } : {}),
      ...(existing?.sealConflict ? { sealConflict: existing.sealConflict } : {}),
      ...elevation,
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
        // Through `keepOurs`, like every other rebuild. Re-attaching only the
        // profile dropped the rest: a peer raised until Friday, mentioned by
        // anyone holding `introduce`, came back raised *for good* — gossip
        // deleting an expiry rather than merely reading past one — and the
        // record of a competing key went with it.
        if (merged) admitted.set(record.name, keepOurs(merged, known));
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
    // A deliberate identity rotation invalidates the sealing binding, which was
    // verified against the *old* identity. Drop it (and any conflict) so the
    // next walk re-binds the sealing key against the new identity — otherwise we
    // would keep encrypting to a key proven only against a key just replaced.
    const { conflicts: _dropped, sealPublicKey: _sk, sealSeen: _ss, sealConflict: _sc, ...rest } = record;
    const rotated = { ...rest, publicKey: key };
    admitted.set(name, rotated);
    return rotated;
  }

  /**
   * The peer as it stands *now*, with a lapsed elevation already fallen back.
   *
   * Resolved on read rather than swept on a timer: a sweep needs something
   * running, and a directory that only tells the truth while a daemon is up is
   * worse than one that computes it when asked.
   *
   * The clock is ours, which is the whole reason this is safer than an expiring
   * grant. A grant's expiry is a timestamp one machine writes and another
   * believes; this one is checked by the machine that made the decision,
   * against its own clock, at the moment of use.
   *
   * @param {any} record
   */
  function asOfNow(record) {
    if (!record?.profileUntil || record.profileUntil > now()) return record;
    // The elevation lapsed. Reverting to what it was raised *from* is the least
    // surprising answer: a temporary raise, not a temporary existence.
    const { profileUntil: _lapsed, profileAfter, ...rest } = record;
    return { ...rest, profile: profileAfter ?? trust.candidateProfile ?? DEFAULT_PROFILE };
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
      ...(previous?.profileUntil ? { profileUntil: previous.profileUntil } : {}),
      ...(previous?.profileAfter ? { profileAfter: previous.profileAfter } : {}),
      // Once seen, never un-seen: the support observation is monotone, so a
      // rebuild from any source keeps the highest version we ever verified.
      ...(previous?.bindingSeen ? { bindingSeen: previous.bindingSeen } : {}),
      // Same discipline for the sealing key: once a verified record bound it,
      // that trust is ours and monotone. A rebuild from any source keeps it, or
      // a routine route-stamp would drop the marker and silently downgrade the
      // peer to cleartext on the next send. The conflict flag rides along too,
      // or a rebuild would clear a fail-closed state a person has to resolve.
      ...(previous?.sealSeen ? { sealSeen: previous.sealSeen } : {}),
      ...(previous?.sealConflict ? { sealConflict: previous.sealConflict } : {}),
    };
  }

  /**
   * Bind this peer's sealing key from a *verified* record — the only path by
   * which a sealing key becomes trusted enough to encrypt to.
   *
   * The sealing key rides the signed record, so `verifyRecord` on a walk hands
   * us one that genuinely belongs to the admitted identity. Everything before
   * that — a gossip mention, a candidate an introducer described — is a claim we
   * do not seal to, because a malicious introducer can staple its own X25519 key
   * beside the victim's real identity key. Adopting it here, after the identity
   * signature checked out, is what makes "bound to the identity" true across the
   * directory's life and not merely on the wire.
   *
   * Once bound, a *different* verified key is a rotation or an attack — a
   * deliberate act, like the identity key — so it is never silently replaced.
   * Instead it raises a **conflict**: the held key is kept, the disagreeing key
   * recorded, and the peer's seal state becomes `conflict`, which fails sends
   * closed rather than encrypting to a key that may be stale or compromised. An
   * unverified key sitting on the record (no `sealSeen`) is not trusted and is
   * replaced freely.
   *
   * `expectedIdentity` is the identity key the sealing key was verified against.
   * A walk captures the peer, does network I/O, then mutates the *current*
   * record by name — so if a concurrent rotation changed the identity in the
   * meantime, the proof no longer applies to who this record is now, and the
   * bind is refused. Callers that just bound a fresh identity (TOFU) pass it.
   *
   * @param {string} name
   * @param {string} sealPublicKey
   * @param {string} [expectedIdentity] identity key the sealing key was verified against
   */
  function bindSealKey(name, sealPublicKey, expectedIdentity) {
    const record = admitted.get(name);
    const key = normalizeKey(sealPublicKey);
    if (!record || !key) return record ?? null;
    const expected = normalizeKey(expectedIdentity);
    if (expected && record.publicKey && record.publicKey !== expected) return record;
    if (record.sealSeen && record.sealPublicKey && record.sealPublicKey !== key) {
      if (record.sealConflict === key) return record;
      const updated = { ...record, sealConflict: key };
      admitted.set(name, updated);
      return updated;
    }
    if (record.sealSeen && record.sealPublicKey === key) {
      // Re-confirming the held key answers any prior disagreement.
      if (record.sealConflict) {
        const { sealConflict: _cleared, ...rest } = record;
        admitted.set(name, rest);
        return rest;
      }
      return record;
    }
    const updated = { ...record, sealPublicKey: key, sealSeen: true };
    admitted.set(name, updated);
    return updated;
  }

  /**
   * The peer's sealing key, but only once a verified record bound it and no
   * conflict is outstanding. A key that merely rode in on gossip (`sealSeen`
   * absent), or one under dispute (`sealConflict` set), is not returned. This is
   * the accessor a sender consults; reading `record.sealPublicKey` directly
   * would trust an unverified — or contested — claim.
   *
   * @param {string} name
   */
  function sealKeyFor(name) {
    const record = admitted.get(name);
    if (!record || record.sealConflict) return null;
    return record.sealSeen && record.sealPublicKey ? record.sealPublicKey : null;
  }

  /**
   * The peer's sealing trust as a tri-state a sender acts on:
   * - `verified`  — a walk bound the key; encrypt to it.
   * - `conflict`  — two verified keys disagree; fail the send closed, do not
   *   fall back to cleartext (that would hide a rotation or an attack).
   * - `unverified`— no key bound yet (an older peer); cleartext is the legacy
   *   fallback until the first walk.
   *
   * @param {string} name
   * @returns {"verified" | "conflict" | "unverified"}
   */
  function sealState(name) {
    const record = admitted.get(name);
    if (!record) return "unverified";
    if (record.sealConflict) return "conflict";
    return record.sealSeen && record.sealPublicKey ? "verified" : "unverified";
  }

  /**
   * Record that this peer's *signed* record advertised a hail-format version —
   * the "supports target-binding" observation the downgrade guard consults.
   *
   * Monotone by `max`, deliberately. Records carry no expiry and every one a
   * peer ever signed stays valid, so a rollback — presenting an older,
   * genuinely-signed, support-absent record — could otherwise clear the guard
   * without forging anything. Keeping the highest version ever seen means once a
   * caller is known to bind, a stale record cannot make us accept a `to`-less
   * hail from it again. See docs/hail-target-binding.md.
   *
   * @param {string} name
   * @param {number | undefined} version
   */
  function noteBinding(name, version) {
    const record = admitted.get(name);
    if (!record || !Number.isInteger(version) || !version || version <= 0) return record ?? null;
    if ((record.bindingSeen ?? 0) >= version) return record;
    const updated = { ...record, bindingSeen: version };
    admitted.set(name, updated);
    return updated;
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
      // Where it was *first* seen, and not updated after: an address is a hint
      // about which route carried it, not a claim about where it lives now.
      seen.push({ key, firstSeen: at, lastSeen: at, count: 1, ...(via ? { via: via.value } : {}) });
    }

    // Newest first, capped. Warning fatigue is the failure mode: a list nobody
    // can read is a list nobody reads.
    seen.sort((a, b) => b.lastSeen - a.lastSeen);
    const updated = { ...record, conflicts: seen.slice(0, MAX_CONFLICTS) };
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
      // Our own record is where we advertise the hail-format version we speak,
      // so a caller learns from our *signed* self-record that we bind targets.
      // Stamped here, not in `publicRecord`, so gossiping another peer carries
      // *their* version, never ours.
      self: publicRecord({ ...self, v: TARGET_BINDING_VERSION, lastSeen: now() }),
      // Peers granted nothing are still ours to know about, but telling others
      // where to find a machine we deliberately do not answer would hand out a
      // reachability we chose not to use.
      // Through `asOfNow`, like every other question about a peer's profile.
      // Reading the stored field meant a raise that had expired went on being
      // gossiped: `effectiveProfile` said the peer had fallen back, and this
      // went on telling the fabric it was hail-able. A lapse has to be resolved
      // wherever the profile is consulted, not only where it is displayed.
      peers: [...admitted.values()]
        .map(asOfNow)
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
    bindSealKey,
    sealKeyFor,
    sealState,
    noteBinding,
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
      const record = asOfNow(admitted.get(name));
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
      const record = asOfNow(admitted.get(name));
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
    profileFor: (name) => resolveProfile(asOfNow(admitted.get(name))?.profile, profileSet),
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
        // The whole stored record as `previous`, so keepOurs decides what is ours.
        // Enumerating fields at each call site meant every new one had to be added
        // in several places, and an elevation was dropped on load.
        if (record) admitted.set(record.name, keepOurs(record, { ...peer, profile: peer.profile ?? DEFAULT_PROFILE }));
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
