/**
 * The routed seal-target resolver (M3b send decision). What matters: Tier 0 always wins;
 * a conflict at EITHER tier fails closed and never becomes a cleartext send (Kimi F1);
 * Tier 1 is used only on explicit opt-in and never overrides Tier 0; and a genuine
 * no-key/no-dispute case is the only path to cleartext.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { resolveRoutedSeal } from "../src/routedSealResolver.js";

const t0 = (state, key = null) => ({ state, key });
const t1 = (state, key = null) => ({ state, key });

test("a Tier-0 verified key wins and is sealed to", () => {
  assert.deepEqual(
    resolveRoutedSeal({ tier0: t0("verified", "K0"), tier1: t1("record-carried", "K1"), allowRecordCarried: true }),
    { decision: "seal", tier: 0, key: "K0", state: "verified" },
  );
});

test("a Tier-0 conflict or reverify fails closed — never Tier 1, never cleartext", () => {
  for (const [state, expected] of [["conflict", "tier0-conflict"], ["reverify", "tier0-reverify"]]) {
    // Even with a usable Tier-1 key and opt-in on, a Tier-0 dispute refuses the send.
    assert.deepEqual(
      resolveRoutedSeal({ tier0: t0(state), tier1: t1("record-carried", "K1"), allowRecordCarried: true }),
      { decision: "refuse", tier: null, key: null, state: expected },
    );
  }
});

test("Tier 1 is used only when opted in and Tier 0 has no key", () => {
  const tier1 = t1("record-carried", "K1");
  // Opt-in off: a record-carried key is ignored, and with no Tier-0 key it is cleartext.
  assert.deepEqual(
    resolveRoutedSeal({ tier0: t0("unverified"), tier1, allowRecordCarried: false }),
    { decision: "cleartext", tier: null, key: null, state: "unverified" },
  );
  // Opt-in on: it is sealed at Tier 1.
  assert.deepEqual(
    resolveRoutedSeal({ tier0: t0("unverified"), tier1, allowRecordCarried: true }),
    { decision: "seal", tier: 1, key: "K1", state: "record-carried" },
  );
});

test("a Tier-1 conflict fails closed under opt-in, but is inert without it", () => {
  const conflicted = t1("record-conflict");
  // Opted in: a manufactured Tier-1 conflict refuses rather than falling to cleartext (F1).
  assert.deepEqual(
    resolveRoutedSeal({ tier0: t0("unverified"), tier1: conflicted, allowRecordCarried: true }),
    { decision: "refuse", tier: null, key: null, state: "tier1-conflict" },
  );
  // Never opted into Tier 1: its conflict is irrelevant — cleartext (the floor may still refuse).
  assert.deepEqual(
    resolveRoutedSeal({ tier0: t0("unverified"), tier1: conflicted, allowRecordCarried: false }),
    { decision: "cleartext", tier: null, key: null, state: "unverified" },
  );
});

test("no key and no dispute is the only path to cleartext", () => {
  assert.deepEqual(
    resolveRoutedSeal({ tier0: t0("unverified"), tier1: t1("none"), allowRecordCarried: true }),
    { decision: "cleartext", tier: null, key: null, state: "unverified" },
  );
});

test("Tier 0 wins even when Tier 1 also holds a (different) key — no consult past Tier 0", () => {
  // The point of the single resolver: Tier 0 verified short-circuits before Tier 1 is read.
  const r = resolveRoutedSeal({
    tier0: t0("verified", "K0"),
    tier1: t1("record-conflict"), // would refuse if it were ever consulted
    allowRecordCarried: true,
  });
  assert.equal(r.decision, "seal");
  assert.equal(r.key, "K0");
});
