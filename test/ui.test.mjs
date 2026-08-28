/**
 * The page's inline browser script must actually parse. It lives inside a
 * String.raw template, and a cooked template would silently eat its backslash
 * escapes (a regex `\/` collapses to `/`, a string `\n` becomes a raw newline),
 * leaving a <script> the browser cannot run — with no server-side error. This
 * renders the page, extracts the script, and parses it, so that regression
 * cannot land unseen again.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { renderPage } from "../src/ui.js";

test("the served inline browser script parses", () => {
  const html = renderPage({ name: "tester" });
  const m = html.match(/<script type="module">([\s\S]*?)<\/script>/);
  assert.ok(m, "the page has an inline module script");
  const script = m[1];
  assert.ok(script.length > 1000, "the script is the real payload, not a stub");
  // Throws a SyntaxError if the escapes were eaten by a cooked template.
  assert.doesNotThrow(() => new Function(script), "the browser script is valid JavaScript");
  // The path-normalising regex must survive as a regex, not become a comment.
  assert.ok(script.includes("replace(/\\/+$/"), "the `\\/` regex escape reached the browser intact");
});

test("interpolated self values still land in the page", () => {
  const html = renderPage({ name: "my-node" });
  assert.ok(html.includes("my-node"), "String.raw still interpolates ${...}");
});

test("the served fetch helpers surface the server's error message, not a bare status", () => {
  const html = renderPage({ name: "tester" });
  const script = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];
  // Both api() and cxPost() must prefer the server's `error` field over "HTTP <n>",
  // or a 409 sealing explanation / "a name is required" reaches the operator as a
  // meaningless status code. Guards the regression at the served-page level, since
  // this browser code (fetch + DOM) can't be unit-executed here.
  const occurrences = script.split("data.error ?? (path").length - 1;
  assert.ok(occurrences >= 2, "both api() and cxPost() carry the data.error fallback");
});
