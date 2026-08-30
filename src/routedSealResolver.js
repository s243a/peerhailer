/**
 * Resolve which key a routed message seals to, and at what tier — the send-decision
 * linchpin of milestone M3b (`docs/routing-security-roadmap.md`).
 *
 * It composes the two key sources into ONE decision so no call site can consult Tier 1
 * while a Tier-0 key exists (Kimi's M2 review, F2/resolver): **Tier 0 (walk-verified,
 * from the directory) always wins**; Tier 1 (record-carried, from the routed key store)
 * is considered only when the operator opted in *and* Tier 0 has no key.
 *
 * The rule that actually protects confidentiality (Kimi's F1): **a conflict at either
 * tier fails closed — it never degrades to cleartext.** A relay that replays an older
 * signed record manufactures a Tier-1 conflict; a `reverify` is a Tier-0 key that
 * rotated or was rolled back. If either quietly fell through to a cleartext send, the
 * relay would have a downgrade lever. So a conflict is a `refuse`, not a `cleartext`.
 * Cleartext is reached only when there is genuinely no key and no dispute — and even then
 * the destination's own floor (enforced there) may still reject it.
 *
 * Availability vs confidentiality, stated honestly (also Kimi's F1): refusing on a
 * conflict costs *availability* when the origin never had a Tier-0 key — the message was
 * not going to be sealed anyway. The confidentiality loss the rule prevents is the case
 * where a manufactured conflict *displaces a key the origin already held*. Both collapse
 * to the same safe action here: refuse, surface, let a person resolve it.
 *
 * @module routedSealResolver
 */

/** The exact states each tier reports; anything else is a wiring bug and fails closed. */
const TIER0_STATES = new Set(["verified", "conflict", "reverify", "unverified"]);
const TIER1_STATES = new Set(["record-carried", "record-conflict", "none"]);

/**
 * @param {{
 *   tier0: { state: "verified" | "conflict" | "reverify" | "unverified", key: string | null },
 *   tier1: { state: "record-carried" | "record-conflict" | "none", key: string | null },
 *   allowRecordCarried?: boolean,
 * }} input
 * @returns {{
 *   decision: "seal" | "refuse" | "cleartext",
 *   tier: 0 | 1 | null,
 *   key: string | null,
 *   state: "verified" | "record-carried" | "tier0-conflict" | "tier0-reverify" | "tier1-conflict" | "unverified" | "resolver-unknown",
 * }}
 */
export function resolveRoutedSeal({ tier0, tier1, allowRecordCarried = false }) {
  // Fail closed on any state this function does not recognise. Unreachable today
  // (`sealState`/the store return exactly the known sets), but a future wiring bug at the
  // one place that decides confidentiality must refuse, never fall through to cleartext.
  if (!TIER0_STATES.has(tier0?.state)) {
    return { decision: "refuse", tier: null, key: null, state: "resolver-unknown" };
  }
  // Tier 0 wins outright when it holds a verified key.
  if (tier0.state === "verified" && tier0.key) {
    return { decision: "seal", tier: 0, key: tier0.key, state: "verified" };
  }
  // A Tier-0 dispute is authoritative and fails closed regardless of Tier 1: a peer we
  // have sealed to before must never silently downgrade (matches `directory.sealState`).
  if (tier0.state === "conflict") {
    return { decision: "refuse", tier: null, key: null, state: "tier0-conflict" };
  }
  if (tier0.state === "reverify") {
    return { decision: "refuse", tier: null, key: null, state: "tier0-reverify" };
  }

  // Tier 0 is unverified (or the destination is not an admitted peer at all). Tier 1 is
  // consulted only on an explicit opt-in — a weaker, no-liveness key is never used by
  // default, and it never overrides Tier 0 (which we already handled above).
  if (allowRecordCarried) {
    if (!TIER1_STATES.has(tier1?.state)) {
      return { decision: "refuse", tier: null, key: null, state: "resolver-unknown" };
    }
    if (tier1.state === "record-carried" && tier1.key) {
      return { decision: "seal", tier: 1, key: tier1.key, state: "record-carried" };
    }
    // A Tier-1 conflict fails closed too: a relay replaying a stale record must not be
    // able to turn "we could seal" into a cleartext send.
    if (tier1.state === "record-conflict") {
      return { decision: "refuse", tier: null, key: null, state: "tier1-conflict" };
    }
  }

  // No key, no dispute: cleartext is permissible here, but the destination's local floor
  // (checked at delivery, never here) may still reject it.
  return { decision: "cleartext", tier: null, key: null, state: "unverified" };
}
