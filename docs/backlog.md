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
- **DONE** — `[fable, moved from Phase 2; refined by kimi + sol]` **Blocking a candidate ignores its
  key** — a security *bypass* (a gossiped-key candidate blocked by name renames back in), so Phase 1.
  The first cut (`recordFor` → `block`, key-first on any resolved key) was reviewed and *rejected*: a
  candidate's key is **hearsay** (a gossiper's `name → key` claim, unverified), so key-blocking it on
  a bare `block N` could silently deny an innocent third party who holds that key while the real peer
  renames free — *and* the confirmation message asserted a binding nobody verified. **Revised rule
  (supersedes the old "never dual-record"): never key-block hearsay implicitly.** New
  `directory.blockPeer(name, {includeKey})`: an *admitted* (verified) key blocks key-first, name
  reusable; a *candidate* blocks by **name** by default and only also blocks its reported key on an
  explicit `--include-key` / `includeKey:true`, disclosing the fingerprint + `heardFrom` provenance;
  an unknown name blocks by name. Returns a `BlockOutcome` the CLI and `/api/block` render honestly.
  Low-level `directory.block(peer)` kept for callers holding a key they already trust (grants, admitted
  records). Reversibility: added `directory.unblockKey(pemOrFingerprint)` + `hail unblock --key <..>`
  for a key that outlived its record (candidate blocked then forgotten). Tests in
  `test/blockCandidate.test.mjs`. Deferred follow-up: a web-UI affordance for the `--include-key`
  confirm (the UI block button correctly does the safe name-only default today).
- **DONE** — `[fable]` `reconcilePersist` marked `trust` (and any default-materialised key: an empty
  `blocklist`, `candidates`) as changed on the first load of a legacy state file, because the baseline
  was the *raw* stored file while `current` came through the constructor-materialised snapshot — so a
  pure default filled in by the constructor read as an edit and clobbered a concurrent writer's real
  edit to that key. **Fixed** by building the baseline the same way `current` is built: new exported
  `directory.reconcileBaseline(stored, snapshot)` takes the directory-managed keys through the startup
  snapshot on both sides, so materialisation is a no-op and only a real edit is written. `self` is the
  deliberate exception (kept raw) so identity stamping is still persisted on first sight — verified a
  brand-new machine still saves its identity and a legacy file gains no spurious `trust` key.
  Regression tests in `test/sealPersistence.test.mjs` (incl. an assertion documenting the pre-fix clobber).

## Phase 2 — correctness

- **DONE** — `[fable]` **`adopt()` ignores `state.self`**, so `hail name` + reload kept signing the
  old name. Fixed: `adopt` now `Object.assign(self, makePeerRecord(state.self), {publicKey, sealPublicKey})`
  — adopting the renamed name/addresses while the running daemon's signing + sealing public keys win
  over any persisted copy. `self` is mutated **in place** (not reassigned), avoiding the reference
  trap: it is handed out by reference via `api.self` and `snapshot().self`, so a new object would
  strand every existing reader on the old name. Regression tests in `test/directory.test.mjs` (rename
  adopted, identity keys preserved, same object reference, and no-self leaves self untouched).
- **DONE (#29, via buildRuntime)** — `[fable]` Reload rebuilt the command plugin without its
  history settings. `buildRuntime` now reads `maxHistory`/`historyMs` from the supplied
  `state.history`, so a reload preserves the operator's audit limits.
- **DONE** — `[sol, split from #12]` **Atomic validate-before-adopt.** `adopt()` cleared the live
  `admitted`/`candidates` maps *before* building the incoming records, so a malformed reload (a
  non-iterable `admitted`, a record that won't build) left the daemon serving an emptied directory.
  Fixed: normalise everything (admitted, candidates, blocklist, self) into locals first — the throw
  now happens before anything live is touched — then apply in a tail section that cannot throw, so the
  directory moves between consistent states atomically. Regression test in `test/directory.test.mjs`
  (a malformed adopt leaves admitted peers, the blocklist, and self intact). (The general
  immutable-read-views part remains Phase 4.)

## Phase 3 — UX (separate concerns — not one "UI batch")

- **TODO** — `[fable]` **New incoming conversations never appear in the chat UI.** Careful: polling
  `chLoad()` every 4s would *worsen* the open-`<select>` churn below. Fix shape: **replace** the
  `chOpen()` poll with a single state refresh that updates peer options **only when their model
  changed**, preserves the current selection, opens the selected thread once, and does **not** replace
  options while the chat selector is actively in use. `ui.js`.
- **DONE** — `[fable]` **`api()` discards the server's error message** — the 409 sealing explanations
  and "a name is required" were unreachable; `api()` threw a bare `HTTP <n>`. Fixed: `api()` now reads
  the body and throws `data.error ?? "HTTP <n>"`, mirroring `cxPost` (the server sends `{error}` on 20
  error paths). Guarded in `test/ui.test.mjs` at the served-page level (browser fetch/DOM code can't be
  unit-executed here). `ui.js`.
- **DONE** — `[fable]` `refresh()` replaced `#peers` innerHTML every 5s, closing a profile `<select>`
  open mid-choice. Fixed: guard the `#peers` repaint with `!peersEl.contains(document.activeElement)`,
  evaluated immediately before the write (after the async fetch), so the 5s refresh yields to an
  in-progress interaction. Clock, candidates, and error still update. Served-page guard in
  `test/ui.test.mjs`; visual pass deferred. `ui.js`.
- **DONE** — `[fable]` `/api/chat/send` didn't pre-check `MAX_MESSAGE`; an oversized non-UI send
  round-tripped and came back as a concealed generic 502. Fixed: the route now imports the receiver's
  `MAX_MESSAGE` and rejects `text.length > MAX_MESSAGE` locally with a 400 naming the limit (same `>`
  boundary as the peer, so parity is exact). Test in `test/chatSealed.test.mjs` (400-with-limit, not a
  502 round-trip; the boundary length itself passes). `server.js`.

## Phase 4 — structural refactors (larger; each its own PR)

- **DONE (#29)** — `[sol, extended by kimi]` **One `buildRuntime(state)`** for startup and reload.
  Extracted to `src/runtime.js` (testable): builds `{plugins, profiles}` from state, one canonical
  plugin order, command-history from `state.history`, `mergeProfiles` shared with `applyChange`.
  `rebuild()` is pure; `onReload` commits after `daemon.reload` accepts and **re-derives profiles
  from a fresh state read at commit** (closes a fail-open race Kimi found where a profile removed
  during the async build would resurrect). Removes the plugin-order + history + profile-copy drift.
  Follow-ups: (a) **fingerprint-keep** — reload preserves plugin instances whose config is unchanged,
  so a `tunnels add` reload doesn't wipe the chat replay-guard nonce cache or command history
  (Kimi's Q5; the reload now *logs* that reset in the meantime); (b) the CLI's profile set still
  lacks *external* plugin suggestions (bundled ones are all built-ins, so no false parked marker
  today) — the deferred CLI-visibility item.
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
- `[fable, from #29 review]` `loadState` returns `{}` on a read failure (never throws), so a
  transiently-unreadable state file at a reload's commit degrades to a near-empty runtime and
  `adopt({})` clears the admitted peers — fail-closed and near-unreachable (atomic-rename writes +
  lock), but "failed read keeps the old runtime" isn't literally true. Guard the reload commit
  against an empty re-read. Related: the `try/catch` around `loadState` in `gateConfig`
  (`bin/hail.js`) is dead code (loadState can't throw). Both pre-existing.
- `[kimi #26 / fable #29]` The CLI builds its profile set from `stored.profiles` + built-ins only
  (no plugin suggestions), so a profile suggested *only by an external plugin* is unassignable via
  the CLI while the daemon/page accept it. Fail-closed (refuses, never grants) and bundled profiles
  are all built-ins, so no false parked marker today. The deferred CLI-visibility item.

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
