/**
 * How a peer ends up with a profile, and what beats what.
 *
 * A profile says which capabilities a peer has. This decides *which profile a
 * peer gets*, which is a separate question and the one that grows: assigned by
 * hand today, derived from who vouched for whom tomorrow, and overridden by a
 * blocklist in any case.
 *
 * The order is fixed and worth stating plainly, because an authorization
 * decision nobody can predict is one nobody can audit:
 *
 *   1. **Blocked** — denied everything, whatever else says otherwise.
 *   2. **Assigned** — a profile a person chose for this peer.
 *   3. **Derived** — what the trust model concludes, for peers nobody assigned.
 *   4. **Unknown** — the default for peers we hold no opinion about.
 *
 * Deny wins outright and is checked first, so blocking is never something that
 * has to out-argue another rule. Assignment beats derivation because a person
 * deciding should not be quietly overruled by a heuristic; derivation only
 * fills the silence.
 *
 * @module trust
 */
import { sameKey } from "./identity.js";
import { DEFAULT_PROFILE } from "./profiles.js";

/** Granted nothing, and not a profile anyone can assign. */
export const BLOCKED_PROFILE = "blocked";
/** What a peer gets when nobody has said anything about it. */
export const UNKNOWN_PROFILE = "unknown";

/**
 * @typedef {{
 *   name: string,
 *   describe: string,
 *   derive: (input: {
 *     peer: any,
 *     vouchedBy: string[],
 *     directory: any,
 *     settings: Record<string, unknown>,
 *   }) => string | null,
 * }} TrustModel
 */

/** The always-present fallback, so resolution can never yield nothing. */
const DIRECT = {
  name: "direct",
  describe: "Only what you assigned. A peer you did not decide about gets nothing.",
  derive: () => null,
};

/**
 * Trust models, which differ only in how a peer nobody assigned is treated.
 *
 * `direct` is the default and the honest one: if you did not say, the answer is
 * no. The other exists because a fabric of any size makes assigning every peer
 * by hand the reason people stop assigning at all.
 *
 * @type {Record<string, TrustModel>}
 */
export const TRUST_MODELS = {
  direct: DIRECT,
  "web-of-trust": {
    name: "web-of-trust",
    describe:
      "A peer vouched for by enough peers you already trust inherits a profile. Introductions carry weight; they never carry your decision.",
    derive: ({ vouchedBy, directory, settings }) => {
      const needed = Number(settings.vouchesRequired ?? 2);
      // Only peers that can hail us count as vouchers. A peer we granted
      // nothing to is one whose opinion we already decided not to act on.
      const credible = vouchedBy.filter((name) => directory.allowsCapability(name, "hail"));
      if (credible.length < needed) return null;
      // Never the full profile the voucher holds: an introduction is grounds for
      // a smaller grant, or trust becomes transitive by arithmetic.
      return typeof settings.vouchedProfile === "string" ? settings.vouchedProfile : "known";
    },
  },
};

export const DEFAULT_TRUST_MODEL = "direct";

/**
 * @param {string | undefined} name
 * @returns {TrustModel}
 */
export function resolveTrustModel(name) {
  return TRUST_MODELS[name ?? ""] ?? DIRECT;
}

/**
 * Is this peer blocked?
 *
 * Matched on the key first, because that is the identity: blocking a name alone
 * is defeated by the peer choosing another one. A name entry still works for
 * peers we hold no key for, which is the only case where it is all we have.
 *
 * @param {{names?: string[], keys?: string[]}} blocklist
 * @param {{name?: string, publicKey?: string | null}} peer
 */
export function isBlocked(blocklist, peer) {
  if (!peer) return false;
  if (peer.publicKey && (blocklist?.keys ?? []).some((key) => sameKey(key, peer.publicKey))) {
    return true;
  }
  return typeof peer.name === "string" && (blocklist?.names ?? []).includes(peer.name);
}

/**
 * Decide which profile a peer gets, and say why.
 *
 * The reason travels with the answer because "why can this machine do that" is
 * the question asked when something has gone wrong, and reconstructing it later
 * from four sources is how authorization becomes folklore.
 *
 * @param {{
 *   peer: any,
 *   directory: any,
 *   blocklist?: {names?: string[], keys?: string[]},
 *   model?: string,
 *   settings?: Record<string, unknown>,
 *   unknownProfile?: string,
 *   vouchedBy?: string[],
 * }} input
 * @returns {{profile: string, reason: string}}
 */
export function profileFor({
  peer,
  directory,
  blocklist = {},
  model = DEFAULT_TRUST_MODEL,
  settings = {},
  unknownProfile = UNKNOWN_PROFILE,
  vouchedBy = [],
}) {
  if (isBlocked(blocklist, peer)) {
    return { profile: BLOCKED_PROFILE, reason: "blocked" };
  }

  if (typeof peer?.profile === "string" && peer.profile.length > 0) {
    return { profile: peer.profile, reason: "assigned" };
  }

  const derived = resolveTrustModel(model).derive({ peer, vouchedBy, directory, settings });
  if (derived) {
    return { profile: derived, reason: `derived by ${model} from ${vouchedBy.length} vouches` };
  }

  return { profile: unknownProfile, reason: "no opinion held" };
}
