# CLI argument parsing

**Status: design / proposed.** A survey of ways to parse `hail`'s arguments and a
staged recommendation. Nothing here is decided yet; this exists so the choice is
made once, with the reasoning written down (see `decisions.md` for the format this
graduates into once picked).

## Where we are

`bin/hail.js` parses with a hand-rolled `parseArgs` — about 25 lines. It splits
`argv` into `{ positional, flags }`, understanding `--flag value`, `--flag=value`,
a trailing `--flag` (as `true`), and bare positionals. It has no dependencies, it
is easy to read, and every command runs on it today.

It has **one real defect** and a few soft edges.

**The defect — a boolean flag before a positional is misparsed.** The parser is
greedy: any non-flag token after `--flag` becomes that flag's *value*. So a
boolean flag works only at the end of the line. `hail block bob --include-key`
parses correctly; `hail block --include-key bob` does not — `bob` is swallowed as
the value of `--include-key`, and the command then fails on the now-missing name.
The same trap sits behind `--force`, `--debug`, `--raw`, `--ui`, `--route`, and
every other flag whose presence *is* its value. In practice we place these last
and never hit it, but "hold the arguments in one order or the tool misreads you"
is a real sharp edge on a tool people drive all day.

**Soft edges** (not bugs, but what a better parser would also buy):

- **No unknown-flag rejection.** `hail add bob --porfile trusted` silently ignores
  the typo and admits `bob` on the default profile. The mistake is invisible.
- **No per-command shape.** Which flags a command takes, whether a value is
  required, and what it means live only in that command's imperative code, so
  there is no single place to generate `--help` from or to validate against.
- **Type is positional, not declared.** Whether `--x` is boolean or string is
  decided by what follows it at the call site, not by what `--x` *is*.

Semantic validation that already lives in command logic — `--key` must be a PEM
(`publicKeyFromFlags`), `--until` must be a date or duration (`untilFromFlag`) — is
**not** the parser's job and stays where it is under every option below. The parser
tokenizes and types; the command decides what a value has to mean.

## What actually picks the answer

- **Zero dependencies is a hard constraint**, not a preference. `decisions.md` is
  explicit: nothing to install before the daemon runs, and the npm release *is* the
  source. That removes `yargs` / `commander` / `minimist` from the table entirely,
  and it makes `node:util.parseArgs` — in the standard library since Node 18.3,
  stable since 20 — the natural engine: it is already present on every machine the
  floor `engines` promises.
- **The shape is subcommands + a global flag.** `hail <command> …`, where `--state`
  (and a few like `--home-dir`) apply to every command and the rest are
  per-command. Any schema approach has to account for the global ones — see the
  wrinkle in the appendix.
- **The ethos is the smallest model that makes the behaviour unsurprising.** The
  file you edit is the file that runs; a parser rewrite that touches every command
  for a defect that bites rarely is machinery in the wrong place. Whatever we pick
  should be paid for by what it fixes.

## The approaches

### A — Keep the parser, teach it which flags are boolean (light touch)

`parseArgs(argv, booleanFlags)` takes a set of names that never consume a value.
When the parser meets `--include-key`, it records `true` and does **not** eat the
next token, so `hail block --include-key bob` keeps `bob` as the positional. The
set can be global (a handful of names) or, more precisely, per-command.

- **Fixes:** the boolean-before-positional defect — the only actual bug.
- **Leaves:** typo rejection, per-command validation, generated help.
- **Cost/risk:** ~5–10 lines, no migration, no behaviour change for any existing
  invocation (they all put booleans last already). Trivially testable.

### B — `node:util.parseArgs` with a per-command option schema

Parse the subcommand, then hand the rest to `parseArgs` with that command's
options:

```js
const { values, positionals } = parseArgs({
  args, allowPositionals: true, strict: true,
  options: { profile: { type: "string" }, "include-key": { type: "boolean" }, /* … */ },
});
```

- **Fixes:** boolean typing (declared, not positional), and with `strict: true`,
  **unknown-flag rejection** — the typo becomes an error, not a silent no-op.
- **Buys toward:** the option map is a machine-readable description of each
  command, which a `--help` generator can read.
- **Cost/risk:** every command needs its options declared, and `strict: true` is a
  behaviour change — an unrecognised flag now throws where it used to be ignored
  (mostly an improvement, but it must be rolled out per command, not flag-day). The
  global `--state` has to appear in every command's options or be parsed in a first
  pass (appendix). Larger surface, in a file `tsc` does not check.

### C — A declarative per-command schema layer

Define, per command, a small record: each flag's type, whether it is required, and
a one-line description; drive parsing, validation, *and* `--help` from it. The
engine underneath is B's `parseArgs`; the addition is the schema being the single
source the command, its validation, and its help all read.

- **Fixes:** everything above, plus required-flag enforcement and self-documenting
  help — the schema *is* the manual.
- **Cost/risk:** the most code and the widest migration; a genuine subsystem. Only
  worth it if we want generated help and uniform validation across a still-growing
  command set.

### D — A third-party parser

Rejected on sight: it breaks the zero-dependency rule that `decisions.md` treats as
load-bearing. Noted only so the question is not reopened.

## Comparison

| | A: boolean set | B: parseArgs + schema | C: schema layer |
|---|---|---|---|
| Fixes the boolean defect | ✅ | ✅ | ✅ |
| Rejects unknown flags (typos) | ❌ | ✅ | ✅ |
| Generated `--help` / validation | ❌ | foundation | ✅ |
| Zero-dependency | ✅ | ✅ (stdlib) | ✅ (stdlib) |
| Migration surface | ~1 function | every command | every command + a layer |
| Risk in un-typechecked `bin/` | negligible | moderate | higher |

## Recommendation

**Staged, smallest-first.**

1. **Now: A.** It closes the one defect that is actually a bug, in a handful of
   lines, with no migration and no risk to a working CLI. This is the "smallest
   model that makes the correct behaviour unsurprising."
2. **Later, if and when we want it: C, realised via B.** The trigger is a concrete
   want — typo rejection biting a user, or a command set large enough that
   hand-written help drifts from reality. At that point `node:util.parseArgs` is the
   engine (zero-dep, standard, already handles the boolean typing and `--`), and a
   per-command schema is migrated command-by-command with `strict` turned on as each
   is converted, never flag-day.

This keeps the change proportional to the problem today while naming the path the
day the problem is bigger — and it commits, in advance, to the stdlib over a
dependency when that day comes.

## Appendix

**The boolean-gap repro.** With the current parser:

```
hail block --include-key bob   # bob is read as --include-key's value; "usage: hail block <name>"
hail block bob --include-key    # correct
```

**The global-flags wrinkle.** `--state` applies to every command and is read before
dispatch. Under a strict per-command schema (B/C), an unknown flag throws — so
`--state` must either be listed in every command's options, or stripped in a first
pass that parses the global flags, with the remainder handed to the per-command
schema. The two-pass shape (globals, then command) is the cleaner of the two and is
what a migration should adopt.

**`parseArgs` notes.** `type` is `"string"` or `"boolean"`; a string option accepts
both `--x v` and `--x=v`. `multiple: true` collects repeats into an array (useful if
a flag is ever allowed more than once). `strict: true` throws on unknown options and
on a value given to a boolean; `allowPositionals: true` keeps bare tokens. `tokens:
true` yields the raw token stream if a command ever needs to interpret order itself.
