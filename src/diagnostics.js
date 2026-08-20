/**
 * Why things are failing, for the one peer allowed to ask.
 *
 * Every refusal elsewhere is deliberately uninformative: unknown peer, bad
 * signature, wrong key, missing capability and blocked all read alike, so the
 * reply cannot be used to work out which one to attack. That is right, and it
 * makes a genuine failure miserable to diagnose — the operator sees `denied`
 * and has to guess, usually from the wrong machine.
 *
 * So the oracle exists, behind two locks rather than one:
 *
 *   1. the caller holds the `diagnostics` capability, and
 *   2. this node is in a debug window an operator opened.
 *
 * Two, because either alone rots. A grant left on a peer would answer forever;
 * a mode with no grant would answer anyone. Both together mean a deliberate act
 * on this machine plus a decision already made about that peer — and the window
 * closes itself, since a debug mode nobody remembers to turn off is a permanent
 * one.
 *
 * @module diagnostics
 */

/** Long enough to reproduce a problem, short enough to be forgotten safely. */
export const DEFAULT_WINDOW_MS = 15 * 60_000;
/** Refusals worth keeping. Bounded: this is a debugging aid, not an audit log. */
const HISTORY = 50;

/**
 * A debug window, and the record of what has been refused while open.
 *
 * @param {{now?: () => number}} [options]
 */
export function createDiagnostics({ now = () => Date.now() } = {}) {
  /** @type {{at: number, claimed: string, reason: string}[]} */
  const refusals = [];
  let openUntil = 0;

  return {
    /** @param {number} [forMs] */
    open(forMs = DEFAULT_WINDOW_MS) {
      openUntil = now() + forMs;
      return openUntil;
    },
    close() {
      openUntil = 0;
    },
    isOpen: () => openUntil > now(),
    openUntil: () => (openUntil > now() ? openUntil : null),

    /**
     * Record a refusal, whether or not anyone is watching.
     *
     * Kept even with the window shut, because the useful question is almost
     * always "why did that fail a minute ago" — asked after the failure, which
     * is too late to have turned recording on.
     *
     * @param {string} claimed
     * @param {string} reason
     */
    refused(claimed, reason) {
      refusals.push({ at: now(), claimed, reason });
      if (refusals.length > HISTORY) refusals.shift();
    },

    /**
     * What to tell a caller that has passed both locks.
     *
     * Includes this node's clock, because a hail refused as stale is usually
     * two machines disagreeing about the time — invisible from either end, and
     * the first thing to check once it can be seen.
     *
     * @param {{self: any, directory: any, caller: string}} input
     */
    report({ self, directory, caller }) {
      return {
        self: { name: self.name, publicKey: self.publicKey },
        now: now(),
        window: { open: openUntil > now(), until: openUntil > now() ? openUntil : null },
        you: { name: caller, ...directory.effectiveProfile(caller) },
        trust: directory.trust(),
        peers: directory.listAdmitted().map((/** @type {any} */ peer) => ({
          name: peer.name,
          ...directory.effectiveProfile(peer.name),
          hasKey: Boolean(peer.publicKey),
          addresses: peer.addresses.length,
          lastSeen: peer.lastSeen,
        })),
        refusals: [...refusals],
      };
    },
  };
}
