/**
 * The routed seal-target resolver — the confidential-by-default send decision. What
 * matters: Tier 0 always wins; Tier 1 seals only to an APPROVED key; a conflict, a
 * merely-pending key, or no key at all REFUSES rather than leaking; cleartext is reached
 * only for explicitly-public data with no key; and every incoherent input fails closed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { resolveRoutedSeal } from "../src/routedSealResolver.js";

const t0 = (state, key = null) => ({ state, key });
const t1 = (state, key = null) => ({ state, key });

test("a Tier-0 verified key wins and is sealed to", () => {
  assert.deepEqual(
    resolveRoutedSeal({ tier0: t0("verified", "K0"), tier1: t1("record-approved", "K1") }),
    { decision: "seal", tier: 0, key: "K0", state: "verified" },
  );
});

test("a Tier-0 conflict or reverify fails closed on a confidential send — never Tier 1, never cleartext", () => {
  for (const [state, expected] of [["conflict", "tier0-conflict"], ["reverify", "tier0-reverify"]]) {
    assert.deepEqual(
      resolveRoutedSeal({ tier0: t0(state), tier1: t1("record-approved", "K1") }),
      { decision: "refuse", tier: null, key: null, state: expected },
    );
  }
});

test("an explicit public payload goes cleartext regardless of the tiers (the caller's opt-out)", () => {
  for (const [tier0, tier1] of [
    [t0("conflict"), t1("record-conflict")],
    [t0("unverified"), t1("record-carried")],
    [t0("verified", "K0"), t1("none")],
  ]) {
    assert.deepEqual(
      resolveRoutedSeal({ tier0, tier1, publicOk: true }),
      { decision: "cleartext", tier: null, key: null, state: "public" },
    );
  }
});

test("Tier 1 seals only to an approved key; a pending key refuses (never cleartext)", () => {
  // Approved -> sealed at Tier 1.
  assert.deepEqual(
    resolveRoutedSeal({ tier0: t0("unverified"), tier1: t1("record-approved", "K1") }),
    { decision: "seal", tier: 1, key: "K1", state: "record-approved" },
  );
  // Discovered but not yet approved -> refuse, even for a caller that would allow public.
  assert.deepEqual(
    resolveRoutedSeal({ tier0: t0("unverified"), tier1: t1("record-carried"), publicOk: false }),
    { decision: "refuse", tier: null, key: null, state: "tier1-pending" },
  );
});

test("a Tier-1 conflict fails closed", () => {
  assert.deepEqual(
    resolveRoutedSeal({ tier0: t0("unverified"), tier1: t1("record-conflict") }),
    { decision: "refuse", tier: null, key: null, state: "tier1-conflict" },
  );
});

test("no key: confidential data refuses; only explicitly-public data goes cleartext", () => {
  assert.deepEqual(
    resolveRoutedSeal({ tier0: t0("unverified"), tier1: t1("none") }),
    { decision: "refuse", tier: null, key: null, state: "no-key" },
  );
  assert.deepEqual(
    resolveRoutedSeal({ tier0: t0("unverified"), tier1: t1("none"), publicOk: true }),
    { decision: "cleartext", tier: null, key: null, state: "public" },
  );
});

test("an unrecognised or incoherent state fails closed — never cleartext", () => {
  assert.equal(resolveRoutedSeal({ tier0: t0("bogus"), tier1: t1("none") }).state, "resolver-unknown");
  assert.equal(resolveRoutedSeal({ tier0: {}, tier1: t1("none") }).decision, "refuse");
  assert.equal(resolveRoutedSeal({ tier0: t0("unverified"), tier1: t1("weird") }).state, "resolver-unknown");
  // A "usable" state with a null key is a wiring bug — refuse, do not fall through.
  assert.equal(resolveRoutedSeal({ tier0: t0("verified", null), tier1: t1("none") }).state, "resolver-incoherent");
  assert.equal(
    resolveRoutedSeal({ tier0: t0("unverified"), tier1: t1("record-approved", null) }).state,
    "resolver-incoherent",
  );
});

test("Tier 0 wins even when Tier 1 also holds an approved key — no consult past Tier 0", () => {
  const r = resolveRoutedSeal({ tier0: t0("verified", "K0"), tier1: t1("record-conflict") });
  assert.equal(r.decision, "seal");
  assert.equal(r.key, "K0");
});
