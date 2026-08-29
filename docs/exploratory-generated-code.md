# Exploratory: generated code, Prolog, and the language-target question

**Status: exploratory / non-core / experimental.** This is a place to think, not a
commitment. Nothing here changes the project ethos, the zero-runtime-dependency
stance, or the current hand-written code. It records a thread of ideas — a Prolog
grammar as a parser oracle, and what language a *generated* parser should target —
so they are not lost, framed against the constraints that actually apply. Treat any
of it as an experiment behind an opt-in, never as a replacement for what ships
today.

## The reframing that decides everything else

We have mostly justified "no dependencies" as a *security* property — code loaded
by the CLI runs beside the identity key, and a lockfile does not make a compromised
publisher harmless. That is true, but it is not the load-bearing reason, and
`decisions.md` says so first: the daemon's failure mode is silence, and diagnosing
it means being on the machine, opening the file, changing something, and
restarting. **A compile step is a step in the wrong place in that loop.** "The file
you edit is the file that runs," "the npm release is the source," "what someone
reads is what executed" — the deepest benefit is *dynamic debuggability*, and
security rides along with it.

This matters here because it changes what "acceptable" means for **generated**
code. The question is not "is it a dependency?" — generated code you commit is not
a dependency. The question is: **does the shipped artifact stay the file you read,
edit, and debug on the machine?** If yes, generation is compatible with the ethos.
If the shipped thing is opaque, or a build step stands between the source and what
runs, it is not — however good the source language.

## The target-language question, for *generated* code

Annotated JavaScript (JSDoc, `tsc`-checked) is what we write today, so it is not an
"alternative" in the usual sense — but a *generator* that emits it is very much an
alternative to writing it by hand, and it is the alternative that fits best. The
three candidates, ranked against the reframed criterion above (debuggability of the
shipped artifact), not against security alone:

| Target | Debuggable shipped artifact? | `tsc`-checked | Build step to run? | Fit |
| --- | --- | --- | --- | --- |
| **Annotated JS (JSDoc), generated** | Yes — plain JS you can open and edit | Yes | No | **Best** |
| **TypeScript, generated** | Only after emit; the run artifact is generated *from* the generated source | Yes | **Yes** (`tsc` emit) | Close, but the emit step fights "the file you edit is the file that runs" |
| **ClojureScript (via Squint), generated** | Weakest — generated JS, less direct traces, a Squint runtime | No | Effectively yes | Furthest from the debugging ethos |

The pull the other way is real and worth naming: **Prolog compiles more *naturally*
to a Lisp substrate than to typed imperative JS.** Unification, backtracking, DCGs,
immutable and homoiconic data are ClojureScript's home turf — the semantic gap from
Prolog is smaller. So there is a genuine tension: CLJS is the easier thing to *emit
from* Prolog; annotated JS is the better thing to *live in* here. TypeScript sits
between — typed (good) but needing an emit step (bad for this repo). For peerhailer
specifically the deployment fit wins, so the target to aim a generator at is
**annotated JS**; CLJS earns its place where the no-build constraint does not apply
(a standalone `bb`/Node tool, not code embedded in what peerhailer ships).

## Prolog as a parser oracle

The strongest near-term idea, and the cheapest. Parsers are Prolog's home turf:
**DCGs** (definite clause grammars) are declarative grammars that are directly
executable, and they parse *and* generate. Two modes, and the first needs no
compilation at all:

1. **Oracle, uncompiled (dev-only).** Write the CLI grammar as a DCG and run it in a
   Prolog engine (SWI, Scryer, or tau-prolog in Node) *during tests*, differentially
   against the hand-written parser over the same contract matrix
   (`test/cliArgs.test.mjs`). This is the RFC's "differential oracle" pattern with
   Prolog as the reference implementation instead of Commander — a dev-only check,
   no shipped artifact, guarded so `node --test` with no install still runs the core
   suite. It does **not** require transpilation to be useful.
2. **Transpiled to annotated JS.** If UnifyWeaver can emit JSDoc-JS, the generated
   DCG parser becomes a *shippable* artifact that fits the ethos — and if it ever
   beats the hand-written parser on clarity, it could graduate from oracle to
   implementation. The DCG parse=generate duality is a bonus: the same grammar that
   validates `--debug [minutes]` can run backwards to emit the usage string, which
   is exactly the "help from the same schema" open point (contract-matrix #14).

The CLI parser is the ideal *first* target for either: a well-understood problem, a
ready-made acceptance test in the contract matrix, and low stakes because the
hand-written parser is the fallback.

## The wider synergy (further out)

- **UnifyWeaver.** A Prolog → (WAM) → targets compiler already in the author's
  hands; the parser is a natural first backend to exercise, with the contract matrix
  as its oracle. Emitting annotated JS keeps it inside the ethos; the CLJS backend
  serves other hosts.
- **A `bb`-backed shell plugin.** `bb` (Babashka proper — the fast native Clojure
  scripting runtime, *not* the tiny `@babashka/cli` args library) is an **external
  binary** like `bash`, so a `shell:bb` plugin adds no npm dependency and gives
  structured, safer remote scripting. The most tractable of the plugin ideas.
- **A Prolog policy/rules plugin.** peerhailer's trust model and routing policy are
  already pluggable; a declarative Prolog policy compiled to inspectable JS is an
  elegant fit — powerful, and the biggest sidequest.

## What would let any of this graduate from experiment to core

- The shipped artifact stays the file you read, edit, and debug on the machine (the
  reframed criterion) — for a generator, that means emitting committed, inspectable
  JS, not an opaque bundle or a build-on-target step.
- No runtime npm dependency. A dev-only toolchain (a Prolog engine for the oracle, a
  transpiler at authoring time) is acceptable; a runtime one is not.
- It has to *win* — a generated parser must beat the hand-written one on clarity or
  maintainability to replace it, which is a high bar given the plain-JS version is
  zero-build, `tsc`-checked, and traces to lines you can read.

Until something clears that bar it stays here: opt-in, experimental, and not a
change to how peerhailer is built or shipped.
