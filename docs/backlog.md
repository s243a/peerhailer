# Backlog

A triaged list of known issues and follow-ups, with a plan to work through them. Built from
several review passes (Kimi, Sol, Fable 5) over the sealing and UI work, plus feature work
deliberately deferred. Kept here so the roadmap is shared, not scattered across PR threads.

**Status:** `TODO` · `IN PROGRESS` · `DONE` (PR #). Source tags: `[fable]` `[sol]` `[kimi]`
= who surfaced it; `[deferred]` = a feature follow-up we chose to postpone.

---

## Phase 1 — security & robustness (do first)

- **DONE (#23)** — `[fable]` Malformed request-target crashes the daemon. `new URL` was
  built above the handler's `try`; a target Node accepts but `new URL` rejects (`GET //[`)
  was an unauthenticated remote crash. Fixed + regression test.
- **TODO** — `[fable]` **Profile fails open to `trusted`.** `resolveProfile(name)` returns
  the default (`trusted`) both for "no name" *and* "named but unknown", and neither
  `hail add --profile X` nor `POST /api/peers` validates that `X` exists. A typo grants a
  peer everything; `hail profiles remove <n>` promotes every holder to `trusted`. Fix:
  validate the profile name at assignment (CLI + API); in `resolveProfile`, distinguish
  "no name" (→ default) from "named but missing" (→ `unknown`, fail-closed). `profiles.js`,
  `bin/hail.js` (add), `server.js` (`POST /api/peers`). **Security — wants a broad review
  pass on the fail-open→fail-closed semantics before implementing.**
- **TODO** — `[sol]` **Resource lifecycle.** `close()` never calls plugin `stop()`, so a
  daemon shutdown orphans `shell`/`service`/`tunnel` child processes and tunnels; and
  `reload()` stops old plugins *before* the new route table is built, so a build failure
  leaves a half-stopped daemon. Fix: `close()` stops listeners first, then `plugin.stop?.()`
  (best-effort), then composer/mounts; `reload()` stages+swaps synchronously, then stops the
  old plugins. `server.js`. (Plan sketched.)

## Phase 2 — correctness

- **TODO** — `[fable]` **`adopt()` ignores `state.self`**, so `hail name` + reload keeps
  signing and gossiping the old name until restart. Make `self` a mutable internal reference
  and fold `state.self` into `adopt`, keeping the identity-key stamping. `directory.js`.
- **TODO** — `[fable]` **Reload rebuilds the command plugin without its history settings**
  (a concrete case of the startup-vs-reload divergence below). One-line fix now; folded into
  the `buildRuntime` extraction later. `bin/hail.js`.
- **TODO** — `[fable]` **Blocking a candidate ignores its key** — `block` reads admitted
  peers only, so a gossiped-key candidate is blocked by name and renames back in (and the CLI
  falsely prints "no key held"). Make `block` consult candidates like `unblock` does, and
  record name+key when both exist. `bin/hail.js`, `server.js`, `directory.js`.
- **TODO** — `[fable]` `reconcilePersist` marks `trust` as changed on the first load of a
  legacy state file (no `trust` key) because the constructor materialised defaults — could
  overwrite a concurrent trust edit in that window. One-time, low-stakes; normalise shape on
  load or comment. `directory.js`.

## Phase 3 — UX

- **TODO** — `[fable]` **New incoming conversations never appear in the chat UI.** `chLoad()`
  runs once at page load; the 4s timer only refreshes the *selected* thread, so a first
  message from an unselected peer is invisible until reload — the headline use case. Poll
  `chLoad()` (it preserves the selection) alongside/instead of `chOpen()`. `ui.js`.
- **TODO** — `[fable]` **`api()` discards the server's error message** (throws `"HTTP 400"`),
  so the 409 sealing explanations and messages like "a name is required" are unreachable for
  admit/forget/block/profile/reload calls. Give `api()` `cxPost`'s `data.error ??` fallback,
  or merge the two helpers. `ui.js`.
- **TODO** — `[fable]` `refresh()` replaces `#peers` innerHTML every 5s, closing a profile
  `<select>` open mid-choice. Skip the repaint when `document.activeElement` is inside the
  table. `ui.js`.
- **TODO** — `[fable]` `/api/chat/send` doesn't pre-check `MAX_MESSAGE`; an oversized non-UI
  send round-trips and returns a generic error. Check locally and say why. `server.js`.

## Phase 4 — structural refactors (larger; each its own PR)

- **TODO** — `[sol]` **One `buildRuntime(state)`** for startup and reload, so plugin/profile
  construction can't diverge (subsumes the reload-history fix above). `bin/hail.js`, `server.js`.
- **TODO** — `[sol]` **Typed request errors** — a shared `readJson(request)` that returns
  400 on malformed / 413 on oversize, and mapping unexpected control-route failures to 500
  instead of the current 404. Replaces ~12 inline `JSON.parse((await readBody())||"{}")`.
  `server.js`.
- **TODO** — `[sol]` **CLI arg parsing** — `node:util.parseArgs` or a per-command schema; a
  bare `--port` becomes `1`, invalid ports fall back silently, booleans can eat positionals.
  `bin/hail.js`.
- **TODO** — `[sol]` **State-boundary encapsulation** — `adopt()` clears live maps before
  validating incoming shape; getters/snapshots hand out mutable records that bypass `commit`.
  Normalise into temporaries before swapping; return cloned/frozen read views. `directory.js`.

## Phase 5 — deferred feature work

- **TODO** — `[kimi/sol, deferred]` **Sealing: receiver-side downgrade refusal.** A receiver
  still accepts a cleartext message from a peer whose sealing key it holds; it must not gate
  on `sealKeyFor(sender)` (holding the sender's recipient key doesn't prove the sender
  verified ours). Add an inbound `requireSealFrom` marker set after the first sealed message,
  after which cleartext from that peer is refused. **Mandatory before any relayed consumer.**
  `chatPlugin.js`, `directory.js`. See `docs/sealing.md`.
- **TODO** — `[sol, deferred]` **Routing Stage-1 replay hole** — `send` mints an envelope id
  but forwarding drops it, so replaying the same id through a relay delivered it twice at the
  destination. The id/sequence/count/expiry/origin must be signature-covered inside the
  sealed block. Fix in the routing forwarding path. See `docs/routing.md`.
- **TODO** — `[deferred]` **Routing Stage 1.5** — chunked, route-caching, end-to-end-sealed
  relay. Needs identity-key-indexed sealing-key discovery for routed destinations (not the
  neighbour-only `sealKeyFor`) and origin-from-payload auth (not the direct-chat
  `from === caller` binding). See `docs/routing.md`.

## Minor / taste (batch opportunistically)

- `[fable]` `server.js` finds the chat plugin by duck-typing (`conversations`+`say`) but the
  route plugin by `name === "route"` — pick one convention.
- `[fable]` `bin/hail.js` calls `publicKeyFromFlags()` twice (condition and value) — hoist.
- `[fable]` `directory.js` `hailResponse`/`profileFor` computes the resolved profile then
  feeds the *raw* `record.profile` to `allows` — reuse the resolved one.
- `[fable]` `unblock` can't remove the key of a *forgotten* peer (one-way door) — accept a
  key/fingerprint argument.
- `[fable]` `admit` with `until` but no profile silently produces no elevation — guard in the
  library (the CLI already guards; the API never passes `until`).
- `[fable]` `MAX_MESSAGE` is documented as 4 KB but compared against UTF-16 `.length`
  everywhere — consistent, just not bytes; note it.
- `[sol]` an invalid file op silently becomes `list`; `block()` isn't idempotent (double-block
  adds a duplicate name); a few overview comments have drifted (`ui.js` "read-mostly",
  `directory.js` "only names/routes/timestamps", `server.js` "every refusal is a 404").

## Test gaps to pin

- `resolveProfile` semantics for a named-but-missing profile (with the Phase 1 fix).
- A reload round-trip preserving command-plugin options (Phase 2).
- `adopt` picking up a changed `self` (Phase 2).
- Blocking a candidate records its key (Phase 2).
- `close()` calls `stop()` on a plugin that defines it; a reload whose new route table fails
  leaves the old plugins serving (Phase 1 lifecycle).

---

## How we work these

1. **Order:** Phase 1 → 5, but pull anything security-shaped forward. Security/trust-semantics
   changes (profile fail-open) get a **broad review pass (Kimi or Sol) first**, then implement,
   then a **narrow Fable 5 confirming pass** on the changed functions.
2. **One concern per PR.** Group only tightly-related fixes (e.g. the two reload/self
   correctness items, or the UI batch).
3. Every behaviour fix ships with a focused test; UI fixes keep `test/ui.test.mjs` green
   (the served script must parse) since there's no DOM harness for the async races.
</content>
