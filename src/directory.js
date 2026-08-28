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
import { fingerprint, normalizeKey, sameKey } from "./identity.js";

/**
 * What `blockPeer` did, honest about what it blocked and why — so a caller can
 * tell the operator the truth rather than assert an unverified binding.
 *
 * @typedef {{
 *   mode: "verified-key" | "name" | "candidate-name" | "candidate-name+key",
 *   name: string,
 *   blockedKey: string | null,
 *   reportedKey: string | null,
 *   fingerprint: string | null,
 *   heardFrom: string[],
 *   blocklist: { names: string[], keys: string[] },
 * }} BlockOutcome
 */
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
 * Reconcile a CLI writer's mutated state against current disk, writing back only
 * what *this* command changed from the state it first read (`baseline`).
 *
 * A CLI process reads state at startup, mutates a long-lived directory (and some
 * stored keys in place), then writes. Spreading its whole snapshot over disk
 * would silently revert whatever a daemon or another terminal committed since —
 * a `block`, a `trust` change, a `gate` rotation the slow writer never saw. So
 * each top-level key is taken from disk unless this command changed it from the
 * baseline, and admitted peers are revision-merged with deletions as tombstones.
 *
 * Pure and exported for testing.
 *
 * @param {any} onDisk state read inside the write lock (current truth)
 * @param {any} baseline state this process read at startup
 * @param {any} current this process's state now (stored keys + directory snapshot)
 * @returns {any} the state to write
 */
export function reconcilePersist(onDisk, baseline, current) {
  /** @type {any} */
  const result = { ...onDisk };
  // Presence is part of the comparison, not only value: a key this command
  // *removed* (present at baseline, absent now) is a change, and must not read
  // as "untouched" just because its value was null. Distinguishing absent from
  // null is what lets a deliberate key removal win over a concurrent write.
  const has = (/** @type {any} */ o, /** @type {string} */ k) => Object.prototype.hasOwnProperty.call(o ?? {}, k);
  for (const key of new Set([...Object.keys(baseline ?? {}), ...Object.keys(current ?? {})])) {
    if (key === "admitted") continue; // reconciled below, not diffed wholesale
    const inCur = has(current, key);
    if (inCur === has(baseline, key) && JSON.stringify(current?.[key]) === JSON.stringify(baseline?.[key])) continue;
    if (inCur) result[key] = current[key];
    else delete result[key]; // this command removed the key
  }
  const baselineNames = new Set((baseline?.admitted ?? []).map((/** @type {any} */ p) => p.name));
  const currentNames = new Set((current?.admitted ?? []).map((/** @type {any} */ p) => p.name));
  const forgotten = new Set([...baselineNames].filter((n) => !currentNames.has(n)));
  const admitted = mergeByRevision(onDisk?.admitted ?? [], current?.admitted ?? [], { forgotten, baselineNames });
  // Only materialise `admitted` if any side actually had it, so a state that
  // never carried the key round-trips unchanged rather than gaining an empty [].
  if (admitted.length || has(onDisk, "admitted") || has(current, "admitted") || has(baseline, "admitted")) {
    result.admitted = admitted;
  }
  return result;
}

/**
 * The baseline `reconcilePersist` diffs a command's `current` state against.
 *
 * It must be built the *same way* as `current` (`{ ...stored, ...snapshot }`), or
 * the directory constructor merely **materialising defaults** on a legacy file —
 * an absent `blocklist` becoming `{names:[],keys:[]}`, an absent `trust` becoming
 * the default policy — reads as a change this command made. It isn't: nobody
 * touched it. Treated as a change, it would overwrite whatever a concurrent writer
 * committed to that key (a `block`, a `trust` edit) between this process's startup
 * and its write. Taking the directory-managed keys through the startup `snapshot`
 * on *both* sides makes a pure materialisation a no-op, so only a real edit is
 * written and a concurrent one on an untouched key survives.
 *
 * `self` is the deliberate exception: it stays the raw stored value, because
 * stamping this machine's identity (its keys) onto a legacy or empty `self` *is* a
 * change worth persisting on first sight — normalising it away would stop a brand
 * new machine ever saving its own identity.
 *
 * @param {any} stored raw state as first read from disk
 * @param {any} snapshot `directory.snapshot()` taken at startup, before any mutation
 * @returns {any} a deep clone, safe to diff against later
 */
export function reconcileBaseline(stored, snapshot) {
  return JSON.parse(JSON.stringify({ ...stored, ...snapshot, self: stored?.self }));
}

/**
 * Merge two views of the admitted set by per-record revision.
 *
 * Every mutation bumps a monotone `rev` (see `commit`), so the higher `rev` wins
 * per peer and a stale snapshot cannot overwrite newer state. `bindingSeen`
 * (max) and `sealRequired` (or) are monotone floors that never regress even if a
 * concurrent edit wins the revision; the sealing key and any conflict follow
 * `rev`, so a deliberate rotation or `acceptSealKey` (both higher-rev) can change
 * them. A revision tie resolves to disk — the merging process is the staler
 * reader, so it does not overwrite a concurrent committed edit it happens to
 * match. Fails closed for sealing (back to the floor), never open.
 *
 * Deletion is a *tombstone*, not absence: a one-sided peer is kept by default
 * (so a stale writer cannot drop a peer another added), which would otherwise
 * refuse every revocation. `forgotten` is the peers this writer deleted (in its
 * baseline, gone from its snapshot) — removed even though on disk. `baselineNames`
 * is what it saw at startup, so a snapshot-only peer is kept when this writer
 * *added* it but dropped when another writer *forgot* it while this one ran
 * (otherwise a slow walk resurrects a just-revoked peer).
 *
 * Pure and exported for direct testing.
 *
 * @param {any[]} onDisk current on-disk admitted records
 * @param {any[]} snap this writer's admitted snapshot
 * @param {{forgotten?: Set<string>, baselineNames?: Set<string>}} [intent]
 * @returns {any[]} the reconciled admitted set
 */
export function mergeByRevision(onDisk, snap, { forgotten = new Set(), baselineNames = new Set() } = {}) {
  /** @type {Map<string, any>} */
  const byName = new Map();
  for (const p of onDisk ?? []) {
    if (forgotten.has(p.name)) continue; // this writer revoked it — a tombstone, not a drop
    byName.set(p.name, p);
  }
  for (const p of snap ?? []) {
    const was = byName.get(p.name);
    if (!was) {
      // In the snapshot but not (or no longer) on disk. Kept only if this writer
      // added it; a peer it saw at startup that is now gone from disk was
      // forgotten by someone else while this writer ran — do not resurrect it.
      if (!baselineNames.has(p.name)) byName.set(p.name, p);
      continue;
    }
    const winner = (Number(p.rev) || 0) > (Number(was.rev) || 0) ? p : was;
    const loser = winner === p ? was : p;
    // Floors are raised from the loser too, so even a disk-winning tie can differ
    // from the disk record if the snapshot carried a higher floor — that is the
    // floor doing its job (never regress), not a merge instability. In practice a
    // floor change bumps `rev`, so the winner already holds it.
    const bindingSeen = Math.max(Number(winner.bindingSeen) || 0, Number(loser.bindingSeen) || 0);
    const sealRequired = Boolean(winner.sealRequired || loser.sealRequired);
    byName.set(p.name, {
      ...winner,
      ...(bindingSeen > 0 ? { bindingSeen } : {}),
      ...(sealRequired ? { sealRequired: true } : {}),
    });
  }
  return [...byName.values()];
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
   *   sealRequired?: boolean,
   *   rev?: number,
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
   * Store a record after a deliberate mutation, bumping its per-record revision.
   *
   * `persist()` merges two views of the admitted set by this revision (see
   * `mergeByRevision`), so a writer that snapshotted stale state cannot roll a
   * peer back over a change another writer already committed to disk — the
   * failure the sealing review turned up, where a slow walk overwrote a
   * concurrent rotation. The load paths (construction, `adopt`) use
   * `admitted.set` directly, preserving the revision a record was stored with;
   * only genuine mutations pass through here.
   *
   * @param {string} name
   * @param {any} record
   * @returns {any}
   */
  const commit = (name, record) => {
    const base = Math.max(admitted.get(name)?.rev ?? 0, Number(record.rev) || 0);
    const next = { ...record, rev: base + 1 };
    admitted.set(name, next);
    return next;
  };

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
   * Contract on the profile name: a name that resolves to nothing is **stored
   * and surfaced as `parked`, not refused**. The full profile set is not known
   * at admission time — the directory is built before plugins load, and a
   * persisted record must load whatever plugin set is present — so refusing here
   * would reject legitimately plugin-contributed profiles and make replay
   * conditional on the current plugins. Validation is the operator surfaces'
   * job (`hail add`, `POST /api/peers`, `--reassign`); the library stays
   * permissive and the resolver fails such a name closed at read.
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
    // A profile can arrive either as an option or on the peer record itself, and
    // both forms are a deliberate set — resolve one value and use it for both the
    // assignment and the elevation decision, or the `peer.profile` form changes
    // the profile while silently keeping a stale expiry. Only a *string* counts:
    // a non-string profile (`false`, `0`, a number) is not a name, and would
    // otherwise be stored verbatim and resolve down the no-name branch to the
    // trusted default instead of the arrival-based fallback below.
    const asName = (/** @type {any} */ value) => (typeof value === "string" ? value : undefined);
    const requestedProfile = asName(profile) ?? asName(peer?.profile);
    // What it reverts to is captured now, while we still know what it was
    // raised from. Working it out at expiry means guessing months later. When the
    // peer is *already* elevated (a live, unlapsed raise), the base to revert to
    // is the one it would have fallen back to — `existing.profileAfter` — not its
    // currently-elevated profile: re-elevating or extending a raise must not turn
    // it permanent by capturing the raised profile as the revert target.
    const revertBase =
      existing?.profileUntil && existing.profileUntil > now()
        ? existing.profileAfter
        : asOfNow(existing)?.profile;
    const elevation =
      until && requestedProfile
        ? { profileUntil: until, profileAfter: revertBase ?? fallback ?? DEFAULT_PROFILE }
        : // An explicit permanent profile (a profile with no `until`) is a
          // deliberate set, so it clears any temporary elevation — otherwise the
          // peer would later revert off a profile a person just chose for good.
          // Only an address-only re-admission (no explicit profile) preserves a
          // running elevation.
          requestedProfile
          ? {}
          : existing?.profileUntil
            ? { profileUntil: existing.profileUntil, ...(existing.profileAfter ? { profileAfter: existing.profileAfter } : {}) }
            : {};

    const withProfile = {
      ...merged,
      profile: requestedProfile ?? existing?.profile ?? fallback ?? DEFAULT_PROFILE,
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
      // The seal *requirement* is a monotone safety floor: once a peer has been
      // sealed to, re-admitting it must not let it drop back to cleartext. It
      // survives here (and a rotation), unlike the key itself.
      ...(existing?.sealRequired ? { sealRequired: existing.sealRequired } : {}),
      ...elevation,
    };
    const stored = commit(withProfile.name, withProfile);
    candidates.delete(withProfile.name);
    return stored;
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
        if (merged) commit(record.name, keepOurs(merged, known));
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
    return commit(name, stampedRecord);
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
    // verified against the *old* identity. Drop the key and any conflict so the
    // next walk re-binds against the new identity. `sealRequired` deliberately
    // stays (it is in `rest`): the peer must not silently drop to cleartext in
    // the window before that walk — its seal state becomes `reverify`, which
    // fails sends closed until a key is verified again.
    const { conflicts: _dropped, sealPublicKey: _sk, sealSeen: _ss, sealConflict: _sc, ...rest } = record;
    return commit(name, { ...rest, publicKey: key });
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
      ...(previous?.sealRequired ? { sealRequired: previous.sealRequired } : {}),
      // The per-record revision is ours too: carried so a rebuild (a route
      // stamp, a gossip merge) does not reset it and let a stale writer win the
      // `mergeByRevision` comparison. `commit` bumps from whatever is carried.
      ...(previous?.rev ? { rev: previous.rev } : {}),
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
   * closed. Crucially the conflict is *not* auto-resolved by the held key
   * reappearing on a later walk: a signed record carries no freshness, so an
   * attacker on an unpinned route can replay an old one, and letting that clear
   * the conflict would resume encryption to a key a person may have distrusted.
   * A conflict is cleared only by a deliberate `acceptSealKey`, a `rotateKey`,
   * or forgetting the peer. An unverified key sitting on the record (no
   * `sealSeen`) is not trusted and is replaced freely.
   *
   * `expectedIdentity` is the identity key the sealing key was verified against.
   * A walk captures the peer, does network I/O, then mutates the *current*
   * record by name — so if a concurrent rotation changed the identity (or
   * cleared it) in the meantime, the proof no longer applies to who this record
   * is now, and the bind is refused. When it is supplied, the current record
   * must still hold *exactly* that identity — a null current key is refused too,
   * or an ABA rotation-to-keyless would bind a key onto the wrong peer.
   *
   * @param {string} name
   * @param {string} sealPublicKey
   * @param {string} [expectedIdentity] identity key the sealing key was verified against
   */
  function bindSealKey(name, sealPublicKey, expectedIdentity) {
    const record = admitted.get(name);
    const key = normalizeKey(sealPublicKey);
    if (!record || !key) return record ?? null;
    if (expectedIdentity !== undefined) {
      const expected = normalizeKey(expectedIdentity);
      if (!expected || !record.publicKey || !sameKey(record.publicKey, expected)) return record;
    }
    if (record.sealSeen && record.sealPublicKey && !sameKey(record.sealPublicKey, key)) {
      // Keep the first disagreeing key as the pending one. A later, *different*
      // disagreeing key does not replace it — an attacker alternating two
      // replayed old keys must not be able to flip what an operator would accept.
      if (record.sealConflict) return record;
      return commit(name, { ...record, sealConflict: key });
    }
    if (record.sealSeen && sameKey(record.sealPublicKey, key)) return record;
    // First verified key for this peer. `sealRequired` is set for good here: a
    // peer we have ever sealed to must never silently drop to cleartext again,
    // even if the key is later lost or a stale writer rolls it back.
    return commit(name, { ...record, sealPublicKey: key, sealSeen: true, sealRequired: true });
  }

  /**
   * Resolve a sealing conflict (or set a peer's sealing key) deliberately — the
   * operator act a replayable re-walk is not allowed to perform. With no key it
   * accepts the conflicting one the last walk presented; a key can also be named
   * explicitly. Clears the conflict and marks the peer verified and seal-required.
   *
   * @param {string} name
   * @param {string} [sealPublicKey] the key to accept; defaults to the conflicting one
   */
  function acceptSealKey(name, sealPublicKey) {
    const record = admitted.get(name);
    if (!record) return null;
    const chosen = normalizeKey(sealPublicKey) ?? normalizeKey(record.sealConflict) ?? normalizeKey(record.sealPublicKey);
    if (!chosen) return record;
    const { sealConflict: _resolved, ...rest } = record;
    return commit(name, { ...rest, sealPublicKey: chosen, sealSeen: true, sealRequired: true });
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
   * The peer's sealing trust as a state a sender acts on:
   * - `verified`  — a walk bound the key; encrypt to it (`sealKeyFor`).
   * - `conflict`  — two verified keys disagree; **fail the send closed**, and a
   *   person resolves it (`acceptSealKey`). Never fall back to cleartext.
   * - `reverify`  — the peer has been sealed to before (`sealRequired`) but the
   *   key is currently absent (a rotation, or a stale writer rolled it back).
   *   **Fail the send closed** until the next walk re-verifies — do not
   *   downgrade a peer we know can seal.
   * - `unverified`— never sealed to (an older peer); cleartext is the legacy
   *   fallback until the first walk.
   *
   * @param {string} name
   * @returns {"verified" | "conflict" | "reverify" | "unverified"}
   */
  function sealState(name) {
    const record = admitted.get(name);
    if (!record) return "unverified";
    if (record.sealConflict) return "conflict";
    if (record.sealSeen && record.sealPublicKey) return "verified";
    if (record.sealRequired) return "reverify";
    return "unverified";
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
    return commit(name, { ...record, bindingSeen: version });
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
    return commit(name, { ...record, conflicts: seen.slice(0, MAX_CONFLICTS) });
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
    return commit(name, keepOurs(bound, record));
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
    acceptSealKey,
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
     * The resolvable profile set, as it stands now — the single source the daemon
     * reads for listing, assignment validation, and rejection style, so those
     * never lag behind resolution after a `useProfiles` refresh. A shallow copy,
     * so a caller can't mutate the live set.
     */
    currentProfiles: () => ({ ...profileSet }),
    /**
     * A peer's assigned profile, and whether it still names a real one. `parked`
     * is true when a name was assigned but no longer resolves (a removed or
     * renamed profile, a hand-edited record) — the peer is granted nothing until
     * reassigned, and this is what a surface renders so the demotion is visible
     * rather than silent. `blocked` is never parked (it comes from the blocklist).
     *
     * @param {string} name
     */
    profileStatus: (name) => {
      const assigned = asOfNow(admitted.get(name))?.profile ?? null;
      const parked = Boolean(assigned && assigned !== BLOCKED_PROFILE && !profileSet[assigned]);
      return { assigned, parked, effective: resolveProfile(assigned, profileSet).name };
    },
    /**
     * The admitted peers who hold `name` now *or are scheduled to revert to it*.
     * Used before removing a profile, so its holders are named rather than
     * silently parked. Three clauses cover: currently effective (`asOfNow`),
     * scheduled-to-revert (a peer elevated *away* from it, `profileAfter`), and
     * the stored-but-lapsed remnant (`profile`). The scheduled case is the one
     * that would otherwise escape and park at lapse.
     *
     * @param {string} name
     */
    holdersOf: (name) =>
      [...admitted.values()].filter(
        (record) => record.profile === name || record.profileAfter === name || asOfNow(record).profile === name,
      ),
    /**
     * Take on state written by somebody else.
     *
     * The daemon serves from a long-lived directory while mutations are applied
     * to the file. After one lands, this brings the two back together — without
     * it the page would keep showing what was true before the change it just
     * made.
     *
     * Deliberately does *not* touch the profile set: the resolvable profiles are
     * built-ins + plugin-suggested + stored, and the plugin half is only known to
     * the host, not here. The caller (`applyChange`/`reload`) re-applies the
     * merged set via `useProfiles` after adopting — see the note there.
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
     * The low-level block: deny exactly the record handed in, key-first.
     *
     * For a caller that already holds a key it trusts — an admitted record, a key
     * lifted from a grant — and wants it blocked as a stable identity. It takes the
     * record's key on faith, so it must **not** be fed a name an operator typed:
     * that path may resolve to a candidate's *hearsay* key, and blocking that would
     * deny whoever really holds it. Operator/name-driven blocking goes through
     * `blockPeer`, which decides verified-vs-hearsay before any key is touched.
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
    /**
     * Deny a peer everything by name — by key only when the key is one we can trust.
     *
     * A **verified** key (an admitted peer's bound key) is blocked key-first: a
     * stable identity a rename cannot shed. A **hearsay** key (a candidate's
     * gossiped `name → key` binding) is *not* promoted to a key block on its own:
     * a peer naming N→K is evidence of a claim, not that K is N, so key-blocking it
     * could deny an innocent third party who actually holds K while leaving the
     * real N free to rename in. So a candidate blocks by name — rename-evadable,
     * but it lands on the intended target — unless the operator explicitly confirms
     * the key with `{ includeKey: true }`. The mode is chosen from what we hold
     * (admitted vs candidate), never inferred from the bare presence of a key, so
     * an unverified key is never blocked by accident.
     *
     * Returns the mode actually taken plus the key involved and its provenance, so
     * the caller can tell the operator exactly what happened rather than assert a
     * binding nobody verified.
     *
     * @param {string} name
     * @param {{ includeKey?: boolean }} [options]
     * @returns {{
     *   mode: "verified-key" | "name" | "candidate-name" | "candidate-name+key",
     *   name: string,
     *   blockedKey: string | null,
     *   reportedKey: string | null,
     *   fingerprint: string | null,
     *   heardFrom: string[],
     *   blocklist: { names: string[], keys: string[] },
     * }}
     */
    blockPeer: (name, { includeKey = false } = {}) => {
      const admittedRecord = admitted.get(name) ?? null;
      const candidate = candidates.get(name) ?? null;
      const pushName = () => {
        if (name && !blocklist.names.includes(name)) blocklist.names.push(name);
      };
      const pushKey = (/** @type {string} */ key) => {
        if (key && !blocklist.keys.includes(key)) blocklist.keys.push(key);
      };
      /**
       * @param {"verified-key" | "name" | "candidate-name" | "candidate-name+key"} mode
       * @param {{ blockedKey?: string | null, reportedKey?: string | null, heardFrom?: string[] }} [extra]
       */
      const result = (mode, { blockedKey = null, reportedKey = null, heardFrom = [] } = {}) => ({
        mode,
        name,
        blockedKey,
        reportedKey,
        fingerprint: blockedKey || reportedKey ? fingerprint(blockedKey ?? reportedKey ?? "") : null,
        // A copy: the source is the candidate map's own array, and a caller must
        // not be able to mutate directory state by editing the outcome it got back.
        heardFrom: [...heardFrom],
        blocklist: { names: [...blocklist.names], keys: [...blocklist.keys] },
      });

      // Verified: an admitted peer's key is one we bound. Key-first, name stays
      // reusable by a different identity later.
      if (admittedRecord?.publicKey) {
        pushKey(admittedRecord.publicKey);
        return result("verified-key", { blockedKey: admittedRecord.publicKey });
      }
      // Candidate: the key is hearsay. Name always; the key only on explicit
      // confirmation, and even then disclosed as unverified.
      if (candidate?.record?.publicKey) {
        pushName();
        if (includeKey) {
          pushKey(candidate.record.publicKey);
          return result("candidate-name+key", {
            blockedKey: candidate.record.publicKey,
            heardFrom: candidate.heardFrom,
          });
        }
        return result("candidate-name", {
          reportedKey: candidate.record.publicKey,
          heardFrom: candidate.heardFrom,
        });
      }
      // No key anywhere — an unknown name, or a keyless record: name only.
      pushName();
      return result("name");
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
    /**
     * Lift a key block directly, by PEM or by fingerprint.
     *
     * The escape hatch for a key that outlived the record it came from: a candidate
     * blocked by key and then forgotten (or aged out of gossip) leaves the key in
     * the blocklist with no name to resolve it, so `unblock(name)` can no longer
     * reach it. Matches a stored block on the normalized key *or* its fingerprint,
     * so the operator can undo with whichever they can see.
     *
     * @param {string} keyOrFingerprint
     */
    unblockKey: (keyOrFingerprint) => {
      const before = blocklist.keys.length;
      blocklist.keys = blocklist.keys.filter(
        (key) => !sameKey(key, keyOrFingerprint) && fingerprint(key) !== keyOrFingerprint,
      );
      return {
        removed: before - blocklist.keys.length,
        names: [...blocklist.names],
        keys: [...blocklist.keys],
      };
    },
    blocklist: () => ({ names: [...blocklist.names], keys: [...blocklist.keys] }),
    trust: () => ({ ...trust }),
    /**
     * Change the trust policy through the directory, so a `snapshot()` reflects
     * it. A caller that mutated a stored copy instead would have the change
     * diffed away at persist time — the snapshot, being authoritative for
     * directory state, would overwrite it.
     *
     * @param {{model?: string, settings?: Record<string, unknown>, unknownProfile?: string}} patch
     */
    setTrust: (patch) => {
      if (typeof patch?.model === "string") trust.model = patch.model;
      if (patch?.settings) trust.settings = patch.settings;
      if (typeof patch?.unknownProfile === "string") trust.unknownProfile = patch.unknownProfile;
      return { ...trust };
    },
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
