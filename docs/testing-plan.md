# Testing plan

A lot has been built quickly. This says what is actually covered, what is not,
and who should look at each thing — in an order where the cheap checks happen
before the expensive ones and a human sees anything visual before a reviewer
does.

## What is covered now

| Repo | Automated | Live-exercised |
| --- | --- | --- |
| peerhailer | 72 tests, strict typecheck | two daemons hailing, signature auth, profile gating, diagnostics gates, plugin routes, grants across three machines, GUI via HTTP |
| mcp-acp-bridge | 93 tests | dual mode, cancel, model switching, gated execution, workspace confinement |
| t3code (ACP driver) | 12 tests, typecheck | turns, cancel, model switching through the bridge |

One caveat worth stating plainly: **every one of those tests was written by the
same author as the code**, so they share its blind spots. That is the argument
for stage 2 rather than for more tests.

## Stage 0 — gaps only automation can close (me)

Cheap, and they are the failures a person would hit by accident rather than by
looking.

| What | Why it matters |
| --- | --- |
| **Concurrent writes** | Confirmed broken: a peer added by the CLI while the daemon runs is erased by the daemon's next write. Data loss, silent, trivially reachable. |
| State file corruption | Truncated or malformed JSON should cost the directory, not the daemon. |
| Address roaming | A peer that moves should be re-found via another peer, and the stale address retired. |
| npm packaging | Install from a tarball, confirm `hail` runs and the exports resolve. |
| Windows paths | `~` expansion, the mode-600 identity file, and the state directory. |

## Stage 1 — things a person has to look at (you)

Before any reviewer sees them, because a reviewer reading a half-polished
interface spends its attention on the polish.

| What | What to look for |
| --- | --- |
| **The GUI in a real browser** | It has only ever been fetched with `curl`. Does it render, does the profile picker work, does blocking update, does it survive a daemon restart, does it look sane in dark mode? |
| **Two real machines** | Everything so far is loopback. Two boxes on a LAN, then one over Tailscale: do addresses get learned, does the right route win, does a laptop that moved get found again? |
| **The old PuppyLinux box** | The machine this is meant to serve. Does it install and run at all? |
| **T3 `agy-dual-gated`** | Verified at the bridge, never through T3's UI. Do the approval cards appear with the command text? |

## Stage 2 — review (Kimi)

The highest-value stage, because peerhailer has had **no external review at
all**, and the last review of the ACP driver found seven real defects including
one that made the permission flow entirely non-functional.

| Target | Ask for |
| --- | --- |
| **peerhailer — the security model** | Trust precedence, blocklist by key, grant verification, the plugin capability gate. Where can a peer get a capability it was not granted? |
| **peerhailer — the daemon** | Auth path, the freshness window, resource handling, anything reachable before authentication. |
| **mcp-acp-bridge** | Never reviewed. Point it at `docs/design.md` first, or it will re-propose approaches already tested and rejected. |

Send it the design docs alongside the code. Both repositories record reasoning
that a diff alone does not show, and a reviewer without it will spend its budget
rediscovering settled questions.

## Stage 3 — design review (Sol, later)

Once the design has stopped moving. The peer fabric, plugin GUIs and trust
levels are still being revised in conversation, and a design review of something
mid-revision mostly produces comments on the parts about to change.

Worth its cost on: whether the trust model holds together across peerhailer and
T3, whether the plugin trust levels are the right cuts, and whether the covert
and relay designs are sound before either is built.

## Not worth testing yet

- **Covert mode, relaying, transports beyond HTTP** — designed, not built.
- **The T3 plugin manager** — designed only.
- **Load and scale** — a fabric of personally-owned machines is tens of peers.
  A performance question here would be a distraction from a correctness one.
