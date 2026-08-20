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
/** Reserved for the covert channel: may enrol a transport with us. */
export const ENROL = "enrol";
/** Reserved for relaying: may ask us to carry traffic for it. */
export const RELAY = "relay";

/**
 * @typedef {{ name: string, allows: string[], description: string }} CapabilityProfile
 */

/** The always-present fallback, so resolution can never yield nothing. */
const TRUSTED = {
  name: "trusted",
  // Deliberately not everything. Relaying spends this machine's bandwidth and
  // exposure on someone else's traffic, and enrolment changes how it is
  // reachable — both are grants worth making on purpose rather than
  // inheriting by being a peer at all.
  allows: [HAIL, DIRECTORY],
  description: "Your own machines. May hail, and see who else you know.",
};

/** @type {Record<string, CapabilityProfile>} */
export const BUILT_IN_PROFILES = {
  trusted: TRUSTED,
  known: {
    name: "known",
    // Findable, but not answered. For a machine you want in your directory
    // without opening anything to it — a phone you hail from, never to.
    allows: [],
    description: "Recorded, but granted nothing. Useful for one-way reachability.",
  },
  carrier: {
    name: "carrier",
    allows: [HAIL, DIRECTORY, RELAY],
    description: "A trusted peer that may also ask this machine to relay for it.",
  },
};

export const DEFAULT_PROFILE = "trusted";

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
