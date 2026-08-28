# Backlog

A triaged list of known issues and follow-ups, with a plan to work through them. Built from
several review passes (Kimi, Sol, Fable 5) over the sealing and UI work, plus feature work
deliberately deferred, and refined by a Sol review of this plan itself. Kept here so the
roadmap is shared, not scattered across PR threads.

**Status:** `TODO` · `IN PROGRESS` · `DONE (#PR)`. Source tags: `[fable]` `[sol]` `[kimi]`
= who surfaced it; `[deferred]` = a feature follow-up we chose to postpone.

## Done

- **DONE (#22)** — `[sol]` UI async-staleness: stale download status, upload generation/ABA,
  chat-send ABA, compose in-flight-stop repaint. Tied every async op to the state that started it.
- **DONE (#23)** — `[fable]` Malformed request-target crashed the daemon (`new URL` above the
  handler's `try`) — an unauthenticated remote crash. Moved inside the try; regression test.
- **DONE (#24)** — `[kimi]` Profile fail-open **security core**: `resolveProfile` now fails
  closed (named-but-missing → `unknown`, absence → default `trusted`); assignment validated at
  the CLI/API/`hail trust` door via `isAssignableProfile`; removal copy corrected. The honesty
  layer is the follow-up below.

---

## Phase 1 — security & robustness (do first)

- **TODO** — `[kimi/sol]` **Profile fail-closed: honesty layer** (follow-up to #24). Fail-closed
  without surfacing recreates the "looks like a network fault" fear, so pair it with:
  - **Validate at the library boundary** (`directory.admit`), not only CLI/API — a future caller
    must not silently store an unassignable profile. (Security itself is already caller-independent:
    the resolver fails closed at every reader; this is the loud-at-the-door half.)
  - **Removal semantics:** `hail profiles remove` should **refuse while the profile is still
    assigned** (list holders), with `--force` demoting holders to `unknown` (never `trusted`) and
    `--reassign <name>` moving them. Mirrors the existing refuse-to-edit-built-ins rule.
  - **Surface a parked peer:** `profileFor`/`effectiveProfile` carry an "assigned profile 'X' no
    longer exists" reason; render it in `hail peers` and the page like a seal conflict.
  - **Migration/startup warning** for state files already naming a missing profile (a renamed
    built-in ships a one-line migration map; a dropped one parks with the surfaced reason).
  - Note: this **reverses a documented availability choice** — missing profiles used to preserve
    connectivity; they now revoke capabilities, visibly.
  Ships as one trust-semantics PR (validation + resolution + removal + migration + tests).
- **DONE (#28)** — `[kimi, from #26 review; extended per fable]` **A profile removal/rename
  never reached a running daemon.** `adopt()` refreshed admitted/candidates/blocklist/trust but
  not `profileSet`. Fixed: `applyChange` re-applies the **merged** (built-ins + plugin-suggested
  + stored) set via `useProfiles` after `adopt`. A Fable confirm caught two divergences the
  one-liner left, both closed here: (A) `applyChange` collected from the *startup* plugin list
  while `rebuild` used a fresh one — the closure's plugin list is now a `let` rebound on reload,
  so the merge uses the current set; (B) the server kept a *separate* `profiles` copy feeding
  `/api/profiles` and page assignment-validation, which lagged resolution — the server now reads
  the profile set from the directory (single source, `directory.currentProfiles()`), so the
  page's offered/accepted set tracks resolution. Note: this is a down-payment on the
  `buildRuntime` extraction (Phase 4), which should absorb the whole plugin+profile build so the
  three sites can't diverge again. Tests: adopt-leaves-profileSet contract, and page
  listing/validation track the live set.
- **TODO** — `[kimi, from #26 review]` **CLI parked markers are false for plugin-suggested
  profiles.** The CLI never loads plugins, so its `profileSet` = built-ins + stored custom; a
  peer on a plugin-suggested profile shows `⚠ parked` in `hail peers` and its `--reassign` is
  falsely refused. A false parked marker trains the operator to ignore the marker. Load
  plugin-suggested profiles in the CLI like the daemon, or footnote that the set is partial.
  `bin/hail.js`.
- **TODO (release-gated)** — `[kimi]` **Renamed-built-in migration map.** A startup warning is
  enough until a built-in is actually renamed; the day one is, every record holding the old
  name parks at upgrade. Any release that renames a built-in must ship a one-line migration
  map applied on load. Checklist item, gated on "a built-in is renamed".
- **DONE (#27)** — `[sol]` **Resource lifecycle.** `close()` never called plugin `stop()`,
  orphaning `shell`/`service`/`tunnel` child processes and tunnels on shutdown. Fixed:
  `close()` stops listeners first, then plugins (`Promise.allSettled`, best-effort), then
  composer/mounts; `reload()` builds the replacement routes into a temporary, swaps
  synchronously, then tears down the replaced plugins fire-and-forget (`allSettled`). Note
  from implementation: `collectRoutes` degrades gracefully (logs-and-skips, never throws) and
  `reload` is synchronous, so the reload restaging is defensive hardening — the definite bug
  was `close()`. Tests: close stops plugins, a throwing stop() doesn't block the rest, reload
  swaps and stops the old set.
- **TODO** — `[fable, moved from Phase 2]` **Blocking a candidate ignores its key** — a security
  *bypass* (a gossiped-key candidate blocked by name renames back in), so Phase 1. Fix: resolve the
  admitted-or-candidate record and pass it to `directory.block()`, which is already key-first with a
  name fallback. Do **not** record both name and key — that changes the documented key-first
  semantics and would stop a different identity legitimately reusing the name later.
- **TODO (late Phase 1)** — `[fable]` `reconcilePersist` marks `trust` as changed on the first load
  of a legacy state file (constructor materialised defaults), which could overwrite a concurrent
  trust-policy edit in that first-load window. Not "or comment": either **classify as accepted debt**
  (documented) or **fix** — normalise legacy state consistently before both baseline capture and the
  locked re-read, with a regression test. Late in Phase 1 because it can lose a trust edit.

## Phase 2 — correctness

- **TODO** — `[fable]` **`adopt()` ignores `state.self`**, so `hail name` + reload keeps signing the
  old name. Note the reference trap: making `self` a `let` and reassigning it leaves `api.self`
  pointing at the old object — **mutate the existing `self` in place, or use an internal `let` + an
  API getter.** Adopt name/address changes, but **runtime identity stamping (signing + sealing public
  keys) must win** over the persisted `state.self` copies. `directory.js`.
- **TODO** — `[fable]` **Reload rebuilds the command plugin without its history settings.** One-line
  fix now; subsumed by the `buildRuntime` extraction later. Its own concern — **do not bundle with
  `adopt(self)`** (different cause and invariants). `bin/hail.js`.
- **TODO** — `[sol, split from #12]` **Atomic validate-before-adopt.** `adopt()` clears live maps
  before validating the incoming shape — normalise into temporaries and swap only once valid. (The
  general immutable-read-views part is Phase 4.) `directory.js`.

## Phase 3 — UX (separate concerns — not one "UI batch")

- **TODO** — `[fable]` **New incoming conversations never appear in the chat UI.** Careful: polling
  `chLoad()` every 4s would *worsen* the open-`<select>` churn below. Fix shape: **replace** the
  `chOpen()` poll with a single state refresh that updates peer options **only when their model
  changed**, preserves the current selection, opens the selected thread once, and does **not** replace
  options while the chat selector is actively in use. `ui.js`.
- **TODO** — `[fable]` **`api()` discards the server's error message** — the 409 sealing explanations
  and "a name is required" are unreachable. Give `api()` `cxPost`'s `data.error ??` fallback (or merge
  the two). `ui.js`.
- **TODO** — `[fable]` `refresh()` replaces `#peers` innerHTML every 5s, closing a profile `<select>`
  open mid-choice. Skip the repaint when `document.activeElement` is inside the table — the focus
  check must run **immediately before** the replacement. `ui.js`.
- **TODO** — `[fable]` `/api/chat/send` doesn't pre-check `MAX_MESSAGE`; an oversized non-UI send
  round-trips and returns a generic error. Check locally and say why. `server.js`.

## Phase 4 — structural refactors (larger; each its own PR)

- **TODO** — `[sol]` **One `buildRuntime(state)`** for startup and reload (subsumes the reload-history
  fix). `bin/hail.js`, `server.js`.
- **TODO** — `[sol]` **Typed request errors — scope-sensitive.** A shared `readJson(request)` throws
  typed errors; map them **by scope**: control API → 400 malformed / 413 oversize / 500 unexpected;
  hail/plugin routes **preserve** the existing 404/drop concealment (they deliberately conceal route
  and refusal information). Not a universal "return 400/413". `server.js`.
- **TODO** — `[sol]` **CLI arg parsing** — `node:util.parseArgs` or a per-command schema. `bin/hail.js`.
- **TODO** — `[sol, split from #12]` **Immutable read views** — getters/snapshots hand out mutable
  records that bypass `commit`. Return **deeply** cloned/frozen views (a shallow spread or a top-level
  `Object.freeze` still exposes nested `addresses`/`conflicts`). `directory.js`.

## Phase 5 — deferred feature work

- **TODO** — `[kimi/sol, deferred]` **Sealing: receiver-side downgrade refusal.** A receiver still
  accepts cleartext from a peer whose sealing key it holds; add an inbound `requireSealFrom` marker
  set after the first sealed message. Reasonably Phase 5 today (direct cleartext still comes from the
  authenticated peer itself, not a network attacker), but **mandatory before any relayed/routed
  consumer**. `chatPlugin.js`, `directory.js`. See `docs/sealing.md`.
- **TODO** — `[sol, deferred]` **Routing replay hole — pick a plan; the doc previously promised the
  wrong one.** `send()` mints an envelope id but `relay()`'s child envelope drops it. The *authenticated*
  fix (id/seq/expiry/origin signed and sealed) needs Stage 1.5 primitives that **do not exist at
  Stage 1** (Stage 1 has no sealed block and an unsigned origin). Choose:
  - **Now (mechanical):** propagate the same id through every child envelope and keep destination
    dedup — documenting that an admitted malicious relay can still alter/replace it; **or**
  - **Stage 1.5 (authenticated):** fold it in where immutable origin/id/expiry can be signed and
    covered by destination sealing.
  See `docs/routing.md`.
- **TODO** — `[deferred]` **Routing Stage 1.5** — chunked, route-caching, end-to-end-sealed relay:
  identity-key-indexed sealing-key discovery for routed destinations, and origin-from-payload auth
  (not the direct-chat `from === caller` binding). See `docs/routing.md`.

## Minor / taste (batch opportunistically)

- `[fable]` `server.js` finds the chat plugin by duck-typing but the route plugin by name — one convention.
- `[fable]` `bin/hail.js` calls `publicKeyFromFlags()` twice — hoist.
- `[fable]` `directory.js` `profileFor` computes the resolved profile then feeds raw `record.profile`
  to `allows` — reuse the resolved one.
- `[fable]` `unblock` can't remove the key of a *forgotten* peer — accept a key/fingerprint argument.
- `[fable]` `admit` with `until` but no profile silently produces no elevation — guard in the library.
- `[fable]` `MAX_MESSAGE` is documented as 4 KB but compared against UTF-16 `.length` — note it.
- `[sol]` an invalid file op silently becomes `list`; `block()` isn't idempotent; a few overview
  comments have drifted (`ui.js` "read-mostly", `directory.js` "only names/routes/timestamps",
  `server.js` "every refusal is a 404").
- `[fable, from #27 review]` `composer.closeAll` does `void stop(id)` on async teardown; the one
  unguarded call inside (`entry.gate?.close()`, `composer.js:294`) could surface as an unhandled
  rejection (process-fatal under default Node) on shutdown. Guard it. Marginal.

## Test gaps to pin

- `resolveProfile` named-but-missing semantics (landed with #24); removal + migration + parked-reason
  with the honesty PR.
- A reload round-trip preserving command-plugin options (Phase 2).
- `adopt` picking up a changed `self` while keeping runtime identity keys (Phase 2).
- Blocking a candidate records its key, key-first (Phase 1).
- `close()` calls `stop()` on a plugin that defines it; a reload whose new route table fails leaves
  the old plugins serving (Phase 1 lifecycle).

---

## How we work these

1. **Order:** Phase 1 → 5, pulling anything security-shaped forward. Security/trust-semantics changes
   get a **broad review pass (Kimi or Sol) first**, then implement, then a **narrow Fable 5 confirming
   pass** on the changed functions.
2. **One concern per PR** — and *don't* over-bundle: the two lifecycle changes are one PR; the profile
   validation/resolution/removal/migration/tests are one PR; but `adopt(self)` and reload-history are
   separate, and the UX items (chat discovery, api errors, table focus, message size) are each their own.
3. Every behaviour fix ships with a focused test; UI fixes keep `test/ui.test.mjs` green (the served
   script must parse) since there's no DOM harness for the async races.
</content>
