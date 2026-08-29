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

- **DONE (across #24/#26/#28 + CLI-visibility PR)** — `[kimi/sol]` **Profile fail-closed: honesty
  layer** (follow-up to #24). Delivered by *surfacing*, which is what keeps fail-closed from reading
  as a network fault:
  - **Removal semantics:** `hail profiles remove` refuses while the profile is still assigned (lists
    holders), `--force` demotes to `unknown` (never `trusted`), `--reassign <name>` moves them. ✓
  - **Surface a parked peer:** `profileStatus` carries `parked` + the "assigned 'X' no longer exists"
    reason, rendered in `hail peers`, the page, and a `[daemon]` startup warning. ✓ (The CLI's markers
    were false for *external* plugin profiles until the CLI-visibility PR below — now fixed.)
  - **Startup warning** for state files naming a missing profile: the daemon logs parked peers at
    boot. ✓
  - **Validate at the library boundary (`directory.admit`):** deliberately **not** done as a *refusal*
    — admit's contract is park-don't-refuse (it can't know the plugin-suggested set at construction,
    and refusing would break replay/reload of a record naming a since-removed profile), and
    `createDirectory` takes no log to warn through. The "must not *silently* store" goal is met by the
    parked surfacing above (it is never silent). A boundary *warning* (not refusal) would need a log
    threaded through `createDirectory` — deferred as low value given the surfacing already lands
    everywhere a reader looks.
  - Note: this reverses a documented availability choice — missing profiles used to preserve
    connectivity; they now revoke capabilities, **visibly**.
- **DONE** — `[kimi, from #26 review]` **CLI parked markers were false for external plugin
  profiles.** The CLI never loaded plugins, so its resolvable set was built-ins + stored custom; a
  peer on an *external* plugin's suggested profile falsely read `⚠ parked` in `hail peers` and its
  `--profile`/`--reassign` were falsely refused (bundled plugins add only built-ins, so no false
  marker there). Fixed: `bin/hail.js` gains a memoised `resolvableProfiles()` that loads the
  configured external plugins (like `hail plugins` does) and folds their suggestions in; used by
  `hail peers` (via `useProfiles`) and the `add`/`trust`/`profiles --reassign` assignability checks.
  `loadPlugins([])` is instant, so a config with no external plugins pays nothing; fail-closed intact
  (a genuinely-unknown profile is still refused/parked). Test in `test/cli.test.mjs` with a fixture
  plugin.
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
<!-- CLI parked-marker visibility: DONE — folded into the "Profile fail-closed: honesty layer" entry
     above (resolvableProfiles() in bin/hail.js loads external plugins so the CLI resolves the daemon's set). -->

- **CHECKLIST (release-gated, no code now)** — `[kimi]` **Renamed-built-in migration map.** The
  interim measure is shipped: the daemon logs parked peers at boot, so a record naming a missing
  profile is surfaced, not silent. Nothing to build until a built-in is actually renamed — building a
  map speculatively is YAGNI. **Release checklist:** any release that renames a built-in profile must
  ship a one-line `old → new` migration map applied on load, or every record holding the old name
  parks at upgrade.
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

- **DONE** — `[fable]` **New incoming conversations never appear in the chat UI.** The 4s poll only
  called `chOpen()` (the open thread's messages), never rebuilding the peer `<option>` list, so a peer
  who messaged first never showed in the dropdown. Fixed: the poll now runs `chPoll()`, which rebuilds
  the list from `/api/chat/state` and writes it **only when it changed** (`html !== chLastOpts`) **and**
  the selector isn't the focused element — so an open dropdown / mid-choice selection is never churned
  (same guard as the peer table). Selection preserved; the open thread still refreshes each tick.
  Option-building extracted to `chOptions`/`chApplyOptions` (shared by `chLoad`). Served-page guard in
  `test/ui.test.mjs`; visual pass deferred. `ui.js`.
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
- **DONE** — `[sol]` **Typed request errors — scope-sensitive.** Added `readJson(request)` throwing
  typed `RequestTooLarge` / `MalformedRequest`, replacing the ~13 inline
  `JSON.parse((await readBody) || "{}")` sites. Mapped **by scope** in the handler's outer catch:
  control API → **400** malformed / **413** oversize / **500** unexpected (a loopback management
  surface — a script/page deserves a status it can act on, not a blank 404); hail scope → concealed
  (`nothingHere`) as before. **Plugin routes conceal on either listener** (their body-read is wrapped
  to `nothingHere` inline), preserving the deliberate route/refusal concealment. `readBody` also gained
  a `content-length` pre-check so an over-declared body is refused *and answered* (413) rather than the
  socket being destroyed; the streaming guard still drops an under-declared flood. Tests in
  `test/malformedRequest.test.mjs` (control 400 + 413, hail plugin-route concealment). `server.js`.
- **IN PROGRESS (Candidate A landed)** — `[sol]` **CLI arg parsing** — the local typed parser
  (`docs/cli-arg-parsing.md` Candidate A) is built in `src/cliArgs.js` (typed + tested, out of the
  un-checked `bin/`): per-leaf schemas with `boolean`/`string`/`optional` kinds, `--` pass-through,
  unknown-option rejection, and positional-arity checks. Proven against the 13 assertable contract-
  matrix points in `test/cliArgs.test.mjs` (point 14, help generated from the schemas, is future
  work). Wired into `bin/hail.js`, replacing the ad-hoc parser; commands **without** a schema fall
  back to the legacy lenient parse, so migration proceeds leaf by leaf with zero regression. Migrated
  so far: `block`, `unblock`, `add`, `daemon`, `commands`, `profiles`. **Remaining (follow-ups):**
  schema the rest (`tunnels`, `services`, `shells`, `shares`, `files`, `gate`, `seal`, `rotate`,
  `walk`, `trust`, `chat`, compose…), then generated `--help` from the schemas. Optional future
  robustness: the Commander/Babashka dev-only differential+fuzz oracle (RFC "Future work"). Survey below:
- **DESIGN** — `[sol]` **CLI arg parsing** — surveyed in `docs/cli-arg-parsing.md`. The audit found
  several real bugs: booleans can consume positionals, forwarded flags disappear (there is no `--`
  terminator), unknown flags are ignored, and missing string values behave inconsistently. The
  documented `--debug [minutes]` is genuinely boolean-or-valued, which `node:util.parseArgs` cannot
  express directly. The revised design compares a local typed parser, stdlib, Commander,
  Lisp-origin `@babashka/cli`, CAC, Yargs, and Citty. Any runtime package would reverse the documented
  source-clone/no-`npm install` deployment promise unless vendored or bundled. If that policy changes,
  Commander 14 and `@babashka/cli` are the two package finalists and should face the same contract
  proof before handlers change; otherwise use a local typed schema. `bin/hail.js`.
- **DONE** — `[sol, split from #12]` **Immutable read views** — `get`/`getByKey`/`listAdmitted`/
  `listCandidates`/`holdersOf`/`snapshot`/`currentProfiles` handed out live records, so a caller
  mutating one (e.g. `record.addresses.push(...)`) corrupted directory state behind `commit`'s back
  (no revision bump). Fixed with a `readView(value)` = `deepFreeze(structuredClone(value))` applied to
  each getter: a deep clone (the nested `addresses`/`conflicts` arrays are copied, not shared) that is
  also deeply frozen, so a stray mutation is *loud* (throws in strict mode) rather than silently lost.
  `deepFreeze` only ever touches a fresh clone — never a live record, which `commit` still mutates.
  `mergeByRevision` is pure, so a frozen snapshot flows through the persist path untouched; the whole
  suite passed unchanged, confirming no consumer mutated a read view. `trust()`/`setTrust()` (a Fable
  follow-up — their `{...trust}` left `settings` live) now return read views too. Test in
  `test/directory.test.mjs`. (Mutator returns like `admit`'s are out of scope — the item is read
  getters.) `directory.js`.

## Phase 5 — deferred feature work

- **DONE (per-session; durable is a follow-up)** — `[kimi/sol, deferred]` **Sealing: receiver-side
  downgrade refusal.** A receiver accepted cleartext even from a peer it had received *sealed* messages
  from — a silent confidentiality downgrade, the missing receiver half of the sender's already-closed
  door. Fixed in `chatPlugin.js`: a per-instance `sealedFrom` set records the keys of peers that have
  sent a validated sealed message; a later cleartext from such a peer is refused (`REFUSE`, "no
  downgrade"), while an unrelated peer's cleartext and the peer's own continued sealing are unaffected.
  Kept in the plugin instance, in the same spirit as its nonce cache (a reload resets it and the next
  sealed message re-establishes it; the hail layer authenticates every caller regardless), so it is a
  **per-session** ratchet. Kimi (PR #49) approved and confirmed the arming is post-validation and the
  keying fail-closed. **Follow-up — durable marker: DEFERRED after a Sol design review** (see
  `docs/durable-seal-ratchet.md`). Verdict: do not build as proposed — the correctness cost
  (cross-process merge semantics, failure ordering, identity-rotation policy, an override state
  machine, mixed-version behaviour) presently outweighs closing a small operator-only restart window.
  Sol found real gaps the corrected design records: the persist seam must be a **caller-bound host
  capability applied before the message's side effects and failing the request on persist error** (not
  a post-return result directive, which arms too late); a revision-based `sealCleartextOk` **override
  is unsound** (a stale writer resurrects it past an operator clear — needs a field-level register, or
  no persistent override); the first draft's **lost-keypair recovery premise was wrong** (a peer needs
  only *our* sealing key + its Ed25519 identity to seal *to us*); and the receiver floor should
  **reset on identity rotation** (keyed by signing key), unlike the sender-side `sealRequired`.
  Revisit when routing adds a second seal consumer, and build **one general origin-keyed durable
  seal-observation seam** then. The `requireSealFrom` OR-floor design itself is sound and kept for that
  day. Tests for the shipped per-session ratchet in `test/chatSealed.test.mjs`. Relayed caveat
  (key on the in-payload origin, never `caller`) remains a hard requirement — see the NOTE in
  `chatPlugin.js`.
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
