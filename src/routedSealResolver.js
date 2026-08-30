/**
 * Resolve whether — and to which key — a routed message is sealed, the send-decision
 * linchpin of the confidentiality milestone (`docs/routing-security-roadmap.md`).
 *
 * It composes the two key sources into ONE decision so no call site can consult Tier 1
 * while a Tier-0 key exists: **Tier 0 (walk-verified, from the directory) always wins**;
 * Tier 1 (from the routed key store) is used only for a key a person has **approved**.
 *
 * **Application data is confidential by default.** When there is no usable key — none
 * approved/verified, or a conflict, or a merely-discovered-but-pending key — the send is
 * **refused**, never quietly sent in the clear. Cleartext is reached only for a caller
 * that explicitly marks the payload public (`publicOk`) and there is no key to seal to.
 * This is what makes confidentiality *monotone*: no relay action (forging a conflict,
 * evicting a key, replaying a stale record) can turn a confidential send into a clear one
 * — the worst it can do is cause a refusal.
 *
 * Every ambiguous or incoherent input fails closed (refuse), including states this
 * function does not recognise or a "usable" state paired with a null key — a wiring bug at
 * the one place that decides confidentiality must never fall through to cleartext.
 *
 * @module routedSealResolver
 */

/** The exact states each tier reports; anything else is a wiring bug and fails closed. */
const TIER0_STATES = new Set(["verified", "conflict", "reverify", "unverified"]);
const TIER1_STATES = new Set(["record-approved", "record-carried", "record-conflict", "none"]);

/**
 * @param {{
 *   tier0: { state: "verified" | "conflict" | "reverify" | "unverified", key: string | null },
 *   tier1: { state: "record-approved" | "record-carried" | "record-conflict" | "none", key: string | null },
 *   publicOk?: boolean,
 * }} input
 * @returns {{
 *   decision: "seal" | "refuse" | "cleartext",
 *   tier: 0 | 1 | null,
 *   key: string | null,
 *   state: "verified" | "record-approved" | "tier0-conflict" | "tier0-reverify"
 *     | "tier1-conflict" | "tier1-pending" | "no-key" | "public" | "resolver-unknown" | "resolver-incoherent",
 * }}
 */
export function resolveRoutedSeal({ tier0, tier1, publicOk = false }) {
  // An explicit public payload is the caller's informed opt-out: send it cleartext,
  // whatever the tiers say. This is not a relay-forced downgrade (the caller chose it),
  // and it is how a data-free discovery probe elicits the destination's record.
  if (publicOk) return { decision: "cleartext", tier: null, key: null, state: "public" };

  if (!TIER0_STATES.has(tier0?.state)) {
    return { decision: "refuse", tier: null, key: null, state: "resolver-unknown" };
  }

  // Tier 0 is authoritative and handled first, so Tier 1 is never consulted while a
  // Tier-0 posture exists.
  if (tier0.state === "verified") {
    if (!tier0.key) return { decision: "refuse", tier: null, key: null, state: "resolver-incoherent" };
    return { decision: "seal", tier: 0, key: tier0.key, state: "verified" };
  }
  if (tier0.state === "conflict") return { decision: "refuse", tier: null, key: null, state: "tier0-conflict" };
  if (tier0.state === "reverify") return { decision: "refuse", tier: null, key: null, state: "tier0-reverify" };

  // Tier 0 is unverified (or the destination is not an admitted peer). Consider Tier 1.
  if (!TIER1_STATES.has(tier1?.state)) {
    return { decision: "refuse", tier: null, key: null, state: "resolver-unknown" };
  }
  if (tier1.state === "record-approved") {
    if (!tier1.key) return { decision: "refuse", tier: null, key: null, state: "resolver-incoherent" };
    return { decision: "seal", tier: 1, key: tier1.key, state: "record-approved" };
  }
  if (tier1.state === "record-conflict") return { decision: "refuse", tier: null, key: null, state: "tier1-conflict" };
  // Discovered but not yet approved: a person must approve the key before we seal to it —
  // and confidential data is not sent in the clear in the meantime.
  if (tier1.state === "record-carried") return { decision: "refuse", tier: null, key: null, state: "tier1-pending" };

  // No key at all. Confidential by default: refuse. Cleartext only for explicitly-public
  // data (and even then the destination's own floor may still reject it).
  if (publicOk) return { decision: "cleartext", tier: null, key: null, state: "public" };
  return { decision: "refuse", tier: null, key: null, state: "no-key" };
}
