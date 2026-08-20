/**
 * Diagnostics, and the two locks on them.
 *
 * This endpoint answers the question every other refusal refuses to answer:
 * *which* rule turned you away. So the tests here are mostly about it staying
 * shut — a grant alone must not open it, and neither must a window alone.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { createDiagnostics } from "../src/diagnostics.js";
import { createDirectory } from "../src/directory.js";
import { generateIdentity } from "../src/identity.js";
import { allows } from "../src/profiles.js";

test("a window closes itself", () => {
  let clock = 1_000;
  const diagnostics = createDiagnostics({ now: () => clock });

  assert.equal(diagnostics.isOpen(), false, "shut until an operator opens it");
  diagnostics.open(60_000);
  assert.equal(diagnostics.isOpen(), true);

  clock += 59_000;
  assert.equal(diagnostics.isOpen(), true);
  clock += 2_000;
  // A debug mode nobody remembers to turn off is a permanent one.
  assert.equal(diagnostics.isOpen(), false);
});

test("closing early works too", () => {
  const diagnostics = createDiagnostics();
  diagnostics.open(60_000);
  diagnostics.close();
  assert.equal(diagnostics.isOpen(), false);
});

test("refusals are recorded whether or not anyone is watching", () => {
  // The useful question is "why did that fail a minute ago", asked after the
  // failure — too late to have turned recording on.
  const diagnostics = createDiagnostics();
  diagnostics.refused("sol", "no hail capability");

  const directory = createDirectory({ self: { name: "here" } });
  const report = diagnostics.report({ self: directory.self, directory, caller: "ops" });
  assert.equal(report.refusals.length, 1);
  assert.equal(report.refusals[0].claimed, "sol");
});

test("the history is bounded", () => {
  const diagnostics = createDiagnostics();
  for (let i = 0; i < 200; i += 1) diagnostics.refused(`peer-${i}`, "nope");

  const directory = createDirectory({ self: { name: "here" } });
  const { refusals } = diagnostics.report({ self: directory.self, directory, caller: "ops" });
  assert.ok(refusals.length <= 50, "a debugging aid, not an audit log");
  assert.equal(refusals.at(-1).claimed, "peer-199", "the newest are the ones kept");
});

test("the report carries this node's clock", () => {
  // A hail refused as stale is usually two machines disagreeing about the time,
  // which is invisible from either end until something says so.
  const diagnostics = createDiagnostics({ now: () => 12_345 });
  const directory = createDirectory({ self: { name: "here" } });
  assert.equal(diagnostics.report({ self: directory.self, directory, caller: "ops" }).now, 12_345);
});

test("the report explains the caller's own standing", () => {
  const sol = generateIdentity();
  const directory = createDirectory({ self: { name: "here" } });
  directory.admit({ name: "sol", publicKey: sol.publicKey, profile: "known" });

  const report = createDiagnostics().report({ self: directory.self, directory, caller: "sol" });
  assert.equal(report.you.profile, "known");
  assert.match(report.you.reason, /assigned/);
});

test("diagnostics are not granted by the everyday profiles", () => {
  // Most trusted peers have no business asking why others were refused.
  assert.equal(allows("trusted", "diagnostics"), false);
  assert.equal(allows("carrier", "diagnostics"), false);
  assert.equal(allows("known", "diagnostics"), false);
  assert.equal(allows("operator", "diagnostics"), true);
});
