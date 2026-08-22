/**
 * What an admitted peer is allowed to ask for.
 *
 * Admission is not one thing. "I know this machine exists" and "this machine
 * may use my services" are different grants, and collapsing them means every
 * peer you can name is a peer that can act. So a peer is admitted *into a
 * profile*, and the profile says which capabilities it carries.
 *
 * `trusted` is the default and the one most peers will ever have: your own
 * machines, allowed the things this fabric exists to do. The others are there
 * because the interesting cases are the edges — a machine you want to find but
 * not answer, or one you are still deciding about.
 *
 * Capabilities are named strings rather than an enum. A service added later
 * should be grantable without a schema change here, and a profile that does not
 * mention a capability simply does not have it.
 *
 * @module profiles
 */

/** Answer this peer's hails, and tell it about the peers we know. */
export const HAIL = "hail";
/** Let this peer see our directory in full, not just what a hail returns. */
export const DIRECTORY = "directory";

/**
 * May tell this machine about peers it has not met.
 *
 * `DIRECTORY` governs what we hand out; this governs what we take in, and the
 * two were the same permission by omission — any peer we could reach could put
 * names, addresses and keys into our candidate list. Whose leads are worth
 * following is a judgement about that peer, so it is a capability.
 */
export const INTRODUCE = "introduce";
/** Reserved for the covert channel: may enrol a transport with us. */
export const ENROL = "enrol";
/** Reserved for relaying: may ask us to carry traffic for it. */
export const RELAY = "relay";
/**
 * May issue grants this machine will honour.
 *
 * Off by default, like relaying. A peer that can delegate can introduce
 * capability to machines you never admitted — bounded by what it holds, which
 * is a real bound and still a wider one than being able to act itself.
 */
export const DELEGATE = "delegate";
/**
 * May ask why things are failing — and only while this node is in debug mode.
 *
 * Held apart from every default profile on purpose. Diagnostics answer the
 * question every other refusal deliberately refuses to answer: *which* rule
 * turned you away. That is exactly the oracle withheld from a refusal, so it
 * takes two keys to open — the grant, and a window an operator opened.
 */
export const DIAGNOSTICS = "diagnostics";

/**
 * How a peer in this profile is turned away.
 *
 * `deny` answers, which is honest and lets an operator on the other end see
 * that they were refused rather than that something broke. `drop` closes
 * without a reply, for peers that should not learn anything at all.
 *
 * @typedef {"deny" | "drop"} RejectionStyle
 */

/**
 * @typedef {{
 *   name: string,
 *   allows: string[],
 *   description: string,
 *   onReject?: RejectionStyle,
 *   pinned?: boolean,
 *   builtIn?: boolean,
 * }} CapabilityProfile
 */

/** Answering is the default: a silent refusal is indistinguishable from a fault. */
export const DEFAULT_REJECTION = "deny";

/** The always-present fallback, so resolution can never yield nothing. */
const TRUSTED = {
  name: "trusted",
  // Deliberately not everything. Relaying spends this machine's bandwidth and
  // exposure on someone else's traffic, and enrolment changes how it is
  // reachable — both are grants worth making on purpose rather than
  // inheriting by being a peer at all.
  allows: [HAIL, DIRECTORY, INTRODUCE],
  description: "Your own machines. May hail, see who else you know, and introduce peers.",
  // Pinned because it is the answer nearly every time, and a list whose common
  // case is buried gets scrolled past. Pinning is presentation only — see
  // listProfiles for why that still matters.
  pinned: true,
  builtIn: true,
};

/** @type {Record<string, CapabilityProfile>} */
export const BUILT_IN_PROFILES = {
  trusted: TRUSTED,
  known: {
    name: "known",
    builtIn: true,
    // Findable, but not answered. For a machine you want in your directory
    // without opening anything to it — a phone you hail from, never to.
    allows: [],
    description: "Recorded, but granted nothing. Useful for one-way reachability.",
  },
  unknown: {
    name: "unknown",
    builtIn: true,
    // What a peer gets when nobody has said anything about it. Empty by
    // default, and a real profile rather than a special case so that a fabric
    // wanting to answer strangers can grant it something without new machinery.
    allows: [],
    description: "Peers you hold no opinion about. Granted nothing by default.",
  },
  blocked: {
    name: "blocked",
    builtIn: true,
    // Dropped rather than answered. A peer you blocked is one you have already
    // decided to stop talking to, and telling it so is a reply it can act on.
    onReject: "drop",
    // Not assignable; produced by the blocklist. Present so a peer's effective
    // profile always names something a person can look up.
    allows: [],
    description: "Denied everything, whatever else says otherwise.",
  },
  carrier: {
    name: "carrier",
    builtIn: true,
    allows: [HAIL, DIRECTORY, INTRODUCE, RELAY],
    description: "A trusted peer that may also ask this machine to relay for it.",
  },
  operator: {
    name: "operator",
    builtIn: true,
    // The machine you debug from. Diagnostics are not in `trusted` because
    // most trusted peers have no business asking why others were refused.
    allows: [HAIL, DIRECTORY, INTRODUCE, DIAGNOSTICS],
    description: "A trusted peer that may also read diagnostics, in debug mode.",
  },
};

export const DEFAULT_PROFILE = "trusted";

/**
 * The one profile that means "no". Named, because comparing against the string
 * by substring lets a profile called `unblocked` match it.
 */
export const BLOCKED_PROFILE = "blocked";

/**
 * Where a peer lands when nobody said otherwise, by *how* it arrived.
 *
 * Typing an address is an assertion that you know the machine. Clicking admit
 * on a name a peer mentioned is acting on someone else's say-so about a machine
 * you have never contacted, and the two deserve different answers — the GUI
 * warns that a lead is not trust, then used to grant `trusted` anyway.
 */
export const ADMIT_PROFILE = "trusted";
export const CANDIDATE_PROFILE = "known";

/**
 * Resolve a profile by name, falling back to the default.
 *
 * An unknown profile name resolves to `trusted` rather than to nothing, because
 * the alternative is a peer that silently stops working after a config edit or
 * a version change — a failure that looks exactly like a network problem.
 *
 * @param {string | undefined} name
 * @param {Record<string, CapabilityProfile>} [profiles]
 * @returns {CapabilityProfile}
 */
export function resolveProfile(name, profiles = BUILT_IN_PROFILES) {
  const found = name ? profiles[name] : undefined;
  return found ?? profiles[DEFAULT_PROFILE] ?? TRUSTED;
}

/**
 * @param {string | undefined} profileName
 * @param {string} capability
 * @param {Record<string, CapabilityProfile>} [profiles]
 */
export function allows(profileName, capability, profiles = BUILT_IN_PROFILES) {
  return resolveProfile(profileName, profiles).allows.includes(capability);
}

/**
 * Profiles as a list, in the order they should be offered.
 *
 * Pinned first, then alphabetical. `trusted` is pinned out of the box because
 * it is the answer nearly every time.
 *
 * Ordering grants nothing, and is still worth thinking about: whatever sits at
 * the top of a list is what gets chosen when someone is moving quickly. Pin the
 * profile you want applied without thought, and be wary of pinning a permissive
 * one — the risk is not that pinning grants anything, but that it decides what
 * people pick.
 *
 * @param {Record<string, Partial<CapabilityProfile>>} [custom] user profiles, merged over the built-ins
 * @returns {CapabilityProfile[]}
 */
export function listProfiles(custom = {}) {
  /** @type {Record<string, CapabilityProfile>} */
  const merged = {};
  for (const [name, profile] of Object.entries(BUILT_IN_PROFILES)) {
    merged[name] = { ...profile };
  }
  for (const [name, profile] of Object.entries(custom ?? {})) {
    const base = merged[name];
    merged[name] = {
      name,
      allows: profile.allows ?? base?.allows ?? [],
      description: profile.description ?? base?.description ?? "",
      ...(profile.onReject ?? base?.onReject
        ? { onReject: profile.onReject ?? base?.onReject ?? DEFAULT_REJECTION }
        : {}),
      ...(profile.pinned ?? base?.pinned ?? false ? { pinned: true } : {}),
      ...(base?.builtIn ? { builtIn: true } : {}),
    };
  }

  return Object.values(merged).sort((left, right) => {
    if (Boolean(left.pinned) !== Boolean(right.pinned)) return left.pinned ? -1 : 1;
    return left.name < right.name ? -1 : left.name > right.name ? 1 : 0;
  });
}

/**
 * Change which profiles are offered first.
 *
 * Returns the custom-profile map to store. A built-in is not modified in place
 * — the override is recorded alongside it, so an upgrade that changes what
 * `trusted` grants still reaches a user who only ever repinned it.
 *
 * @param {Record<string, Partial<CapabilityProfile>>} custom
 * @param {string} name
 * @param {boolean} pinned
 */
/**
 * Define a profile, or change what an existing one grants.
 *
 * The library has always taken custom profiles; nothing exposed making one, so
 * the only way to say "my phone may use the tunnel and nothing else" was to
 * edit the state file. That gap is why an indefinite *grant* looked like the
 * available answer to a question a profile should have answered.
 *
 * Built-ins are not editable. Renaming what `trusted` means underneath a person
 * who assigned it would change every peer holding it at once, silently.
 *
 * @param {Record<string, any> | undefined} custom
 * @param {string} name
 * @param {{allows: string[], description?: string}} definition
 */
export function setProfile(custom, name, definition) {
  if (name in BUILT_IN_PROFILES) {
    throw new Error(`${name} is built in; choose another name`);
  }
  const allows = [...new Set((definition?.allows ?? []).filter((c) => typeof c === "string" && c))];
  return {
    ...custom,
    [name]: {
      ...(custom?.[name] ?? {}),
      name,
      allows,
      ...(definition?.description ? { description: definition.description } : {}),
    },
  };
}

/**
 * Remove a profile someone defined. Built-ins stay.
 *
 * @param {Record<string, any> | undefined} custom
 * @param {string} name
 */
export function removeProfile(custom, name) {
  if (!custom || !(name in custom)) return custom ?? {};
  const { [name]: _gone, ...rest } = custom;
  return rest;
}

/**
 * Move a profile to the top of the list, or let it fall back.
 *
 * @param {Record<string, any> | undefined} custom
 * @param {string} name
 * @param {boolean} pinned
 */
export function setPinned(custom, name, pinned) {
  const existing = custom?.[name] ?? {};
  return { ...custom, [name]: { ...existing, pinned } };
}

/**
 * How to turn away a peer in this profile.
 *
 * @param {string | undefined} profileName
 * @param {Record<string, Partial<CapabilityProfile>>} [custom]
 * @returns {RejectionStyle}
 */
export function rejectionFor(profileName, custom = {}) {
  const merged = listProfiles(custom).find((profile) => profile.name === profileName);
  return merged?.onReject ?? DEFAULT_REJECTION;
}

/**
 * @param {Record<string, Partial<CapabilityProfile>>} custom
 * @param {string} name
 * @param {RejectionStyle} style
 */
export function setRejection(custom, name, style) {
  return { ...custom, [name]: { ...(custom?.[name] ?? {}), onReject: style } };
}
