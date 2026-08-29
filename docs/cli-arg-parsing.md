# CLI argument parsing

**Status: design / proposed.** Revised 2026-08-28 after auditing every flag and
running preliminary smoke checks against the leading candidates. No parser has
been selected, the full contract proof is still pending, and no CLI behaviour has
been migrated yet.

## Decision to make

`hail` needs typed, command-specific argument parsing. The open question is which
engine should sit under that schema:

1. a small parser owned here;
2. Node's `node:util.parseArgs`;
3. a focused JavaScript CLI package such as Commander; or
4. a Lisp-origin parser compiled to JavaScript, specifically `@babashka/cli`.

The earlier version of this document treated zero runtime dependencies as a hard
veto and recommended the stdlib path. That conclusion was premature. Dependencies
are a cost to inspect and control, not automatically a design failure, and the
stdlib parser cannot directly express one of `hail`'s documented options.

## What `hail` actually requires

`bin/hail.js` currently parses the entire command line before dispatch with a
roughly 25-line ad-hoc parser. The audit found 44 distinct options explicitly
read from `flags`:

- 32 string-valued options;
- 11 booleans: `chat`, `force`, `raw`, `route`, `ui`, `writable`,
  `include-key`, `keep-sessions`, `reports-port`,
  `require-target-binding`, and `trust-forwarded`; and
- one genuinely optional-valued option: `debug`.

`hail daemon --debug` opens the default diagnostics window, while
`hail daemon --debug 15` opens it for 15 minutes. This is a useful public
contract, not a forgotten parser accident. Any replacement should preserve it
unless a separate CLI design explicitly replaces it.

Optional-valued switches may also be useful for future commands. Choosing an
engine that structurally forbids them would turn each such addition into another
shim or CLI redesign, so this is both a compatibility requirement and an
expressiveness consideration.

Three apparent mixed-type cases are less fundamental:

- `reports-port` is semantically boolean. Its string branch only recovers the
  service command swallowed by the current greedy parser.
- `ui` and `force` accept bare `true` or the string `"true"`; preserving
  `--ui=true` and `--force=true` is a compatibility choice.
- `key === true` means a required value was omitted; `key` itself is a string
  option.

The actual cross-command options are `--state` and the undocumented `--name`. The
old document mentioned `--home-dir`, but no such option exists. `--name` is read
and persisted before dispatch, so it can currently rename the local peer during
any command. A migration must either preserve that surprising behaviour or
deprecate it in favour of `hail name`.

### Demonstrated defects in the current parser

The boolean-before-positional bug is real, but it is not the only real defect.

1. **Booleans consume positionals.** `hail block --include-key bob` reads `bob`
   as the flag's value and then reports a missing name.
2. **Forwarded flags disappear.** `hail commands add deploy ./run.sh --env prod`
   stores only `./run.sh`. The same class affects `shells add` and `services add`.
   The current parser does not implement `--`, so there is no unquoted escape.
3. **Unknown options are silently accepted.** A typo such as `--porfile` can
   quietly select default behaviour.
4. **Missing string values are inconsistent.** For example, bare daemon `--port`
   becomes boolean `true`, and `Number(true)` selects port 1 rather than reporting
   the missing value.
5. **Option validity is global rather than leaf-specific.** A valid flag for one
   action can be silently ignored on an unrelated action.

This means a replacement is justified by behaviour, not merely style.

## Required contract for any replacement

The implementation should be accepted only if tests establish all of these:

- boolean flags work before or after positionals;
- string options reject a missing value;
- bare and valued `--debug` retain their meanings;
- unknown options fail against the exact command/action schema;
- extra positionals fail unless that leaf deliberately accepts them;
- `--` ends option parsing and preserves the remaining token values and order,
  without treating them as `hail` options;
- `commands add`, `shells add`, and `services add` can store command lines that
  contain their own flags;
- `--state` preserves the currently accepted before- and after-command forms,
  while a post-`--` `--state` is payload rather than a global option;
- dash-leading required values have a defined compatibility story. In
  particular, the current parser deliberately accepts an inline PEM after
  `--key`;
- errors remain short, actionable, and prefixed with `hail:` rather than exposing
  a library stack trace; and
- the currently tested root `--help` behaviour remains available, with leaf help
  added from the same schemas if the selected engine supports it.

Generated per-command help and shell completion are valuable secondary outcomes.
They should come from the same schema as validation rather than from another
hand-maintained list.

## How to judge a dependency

Peerhailer has good reasons for its present zero-dependency policy. Code loaded by
the CLI runs beside the identity key, a lockfile does not make a compromised
publisher harmless, and minimal machines are important deployment targets.

This is also a documented deployment contract, not just a security preference.
`docs/deploy-minimal-linux.md` promises that a source clone runs directly with
`node bin/hail.js`, with no `npm install`, build, or package manager on the target;
the README repeats the zero-dependency promise. Adding Commander, Babashka CLI, or
any other runtime package breaks that workflow unless its required JavaScript is
vendored or bundled. Selecting a package therefore requires an explicit policy
reversal and corresponding updates to those deployment documents.

That does not make every dependency worse than locally maintained parsing code.
The relevant questions are more concrete:

- Does it solve the actual grammar without compatibility shims?
- Does it require a native addon, compilation on the target, an install hook, or a
  separately installed toolchain?
- How much code is imported at runtime, and how much unrelated code is merely
  installed?
- Can the exact published JavaScript be reviewed and pinned by integrity hash?
- Is the source understandable when a production parse differs from expectation?
- Does its Node support match `peerhailer`'s published `>=20` floor?
- How stable is its API and maintenance policy?

If the source-clone/no-install policy is deliberately reversed and a package is
selected, use an exact version initially, commit the lockfile, review dependency
and lifecycle-script changes on upgrades, and maintain a parser-contract test
suite independent of that package. A lockfile does not by itself preserve the
existing deployment workflow.

Package metadata below was checked on 2026-08-28. Sizes are npm unpacked sizes,
except where the installed tree is explicitly named.

## Candidate A — a small typed parser owned here

Replace the untyped global parser with a per-leaf schema whose option kinds are
`boolean`, `string`, and a deliberately constrained optional value for `debug`.
Add `--`, unknown-option rejection, and positional arity checks.

### For

- Exact preservation of `hail`'s current contracts, including optional values,
  inline PEMs, and error wording.
- No external trusted code or release cadence.
- The tokenizer can remain small because `hail` has long options only.
- A plain data schema could still drive help.

### Against

- We own every edge case: `--x=y`, repeats, missing values, terminators,
  dash-leading values, action selection, and error diagnostics.
- Optional values are inherently ambiguous next to positionals. A local parser
  does not remove that ambiguity; it only lets us choose a project-specific rule.
- Parser and help generation can grow into a small framework that duplicates
  mature, better-tested work.
- `bin/hail.js` is not currently covered by `tsc`, increasing the cost of owning
  more parsing machinery there.

This remains viable if the dependency trust boundary outweighs all maintenance
benefits, but it should be compared to packages rather than assumed safest.

## Candidate B — `node:util.parseArgs`

Node's parser is stable at the project's Node floor and declares options as
strict `boolean` or `string` values. It handles `--`, `--x=y`, repeated options,
and token reporting. See the
[Node `parseArgs` documentation](https://nodejs.org/api/util.html#utilparseargsconfig).

### For

- No package or additional trusted publisher.
- Correct core tokenization and useful error messages.
- Strict unknown-option rejection and a solid base for per-leaf schemas.
- Already present everywhere `peerhailer` promises to run.

### Against

- An option must be `boolean` xor `string`. It cannot represent
  `--debug [minutes]` directly.
- A strict string option rejects a separated value beginning with `-` as
  ambiguous, so the currently accepted `--key "-----BEGIN ..."` form needs
  `--key=...`, `--key-file`, or a compatibility shim.
- Strict booleans reject currently accepted `--ui=true` / `--force=true`
  spellings.
- Boolean parsing alone does not reject `--flag yes` when positionals are
  allowed; every leaf still needs positional arity validation.
- Global-first permissive parsing is unsafe because an unknown value option can
  distort command discovery. A staged migration still needs careful full-argv
  reparsing against each leaf.

`parseArgs` remains a good tokenizer, but the exceptions erase much of the
claimed simplicity. It should not be chosen solely because it is stdlib.

## Candidate C — Commander 14

[Commander 14.0.3](https://github.com/tj/commander.js/tree/v14.0.3) is the
conservative package candidate. It is MIT-licensed, about 209 KB unpacked, has no
runtime dependencies, and declares Node `>=20`. Commander 15 requires Node
22.12 or newer, so 14 is the compatible line; its maintainers state that 14
receives security updates through May 2027 in the
[Commander 15 release notes](https://github.com/tj/commander.js/releases/tag/v15.0.0).

### For

- Optional option values are first-class: `--debug [minutes]` produces `true`
  when bare and the supplied string when valued.
- Nested commands, required and variadic positionals, command-specific options,
  strict unknown checking, generated help, `--`, and pass-through modes are
  established features. See the
  [Commander 14 documentation](https://github.com/tj/commander.js/blob/v14.0.3/Readme.md)
  and its
  [optional-value discussion](https://github.com/tj/commander.js/blob/v14.0.3/docs/options-in-depth.md).
- A preliminary local smoke check preserved `block --include-key bob`, a
  dash-leading PEM required value, `--debug`, `--debug 15`, `--debug=15`, and
  post-`--` command flags. This is not the full contract proof proposed below.
- One plain-JavaScript package is a small, direct audit surface. It also ships
  type declarations.

### Against

- It still expands peerhailer's trusted runtime beyond this repository.
- Its builder API is more imperative than a plain data table. Keeping the current
  switch while gaining generated help may require an adapter or a broader command
  dispatch refactor.
- Version 14 is already the maintenance line. After May 2027, remaining on v14
  goes beyond its stated security-update window; the project must raise its Node
  floor for Commander 15+, accept that exposure, or migrate again.
- Commander's optional-value rule remains ambiguous beside a positional.
  `--debug=15` is the clearest documented spelling even if `--debug 15` remains
  supported.

This is the lowest-risk default if an external dependency is acceptable.

## Candidate D — `@babashka/cli` (Lisp-origin, compiled to JavaScript)

[`@babashka/cli` 0.12.86](https://www.npmjs.com/package/@babashka/cli) is written
in Clojure/CLJC and published as ESM compiled by
[Squint](https://github.com/squint-cljs/squint). Consumers use a normal
JavaScript API: no compilation step, JVM, native binary, or separately installed
toolchain is required. The installed dependency tree nevertheless contains the
Squint compiler package. Its
[JavaScript and command-tree documentation](https://github.com/babashka/cli#javascript)
shows the same parser and dispatcher used from JS.

The Lisp origin is relevant without being decisive. Code-as-data, macros,
immutable data, and REPL-driven development are natural tools for parsers,
compilers, AST transformations, and declarative DSLs. Those strengths plausibly
shape a good command-schema API, and also explain Lisp's recurring role in AI and
symbolic-programming tools. They do not, by themselves, prove that a particular
npm artifact is safer or easier to maintain.

### For

- A data-shaped command tree supports nested and multi-word commands, inherited
  globals, per-command restriction, positional restriction, validation,
  generated help, and `--` without building that framework here.
- Bare options naturally become `true`, while an adjacent value is retained, so
  the documented `--debug [minutes]` contract fits.
- A preliminary local Node smoke check confirmed the important shapes: typed
  booleans before positionals, bare and valued `--debug`, unknown-option
  rejection, `--ui=true`, and post-`--` forwarding. This is not the full contract
  proof proposed below.
- The installed implementation is pure JavaScript. The tested tree required no
  native addon and declared no install lifecycle hook.
- The exact generated JavaScript can be pinned, inspected, fuzzed, and reviewed
  by a person or an AI reviewer even if the reviewer does not write Clojure.

### Against

- The npm package has a runtime dependency on `squint-cljs`; its generated module
  imports Squint core, string, and EDN helpers. Squint installs `chokidar`, which
  installs `readdirp`. The audited tree was four packages and about 2.5 MB
  installed, not merely the 318 KB top-level package.
- `chokidar` and `readdirp` were not reachable from the parser's runtime imports
  in the audit, but they are still lockfile and installation baggage.
- The authoritative source is CLJC and the shipped parser is generated JavaScript.
  A deep upstream fix is less direct for a JavaScript-only maintainer, and stack
  traces may lead through Squint helpers.
- The package is pre-1.0, declares no Node engine, and currently ships no visible
  TypeScript declaration file. Node 20 compatibility therefore has to be enforced
  in peerhailer's own CI rather than delegated to package metadata.
- Its default value coercion turns `--debug 15` into number `15`, so the current
  string-only handler needs a small normalization. Declaring `debug` as a string
  instead would make the value mandatory and lose the bare form.
- It rejects a separated PEM that begins with dashes under strict parsing, so
  `--key-file`, `--key=...`, or a narrow compatibility normalizer is still needed.
- Clojure-style `:option value` syntax is enabled by default; `hail` should set
  `no-keyword-opts` so the migration does not silently add a second CLI dialect.

### Could it be bundled?

Bundling only the imported Babashka/Squint modules could remove the compiler and
watcher baggage from the installed tree. That would trade runtime dependencies
for a generated vendored artifact and a release build step. It is a separate
decision: the npm package as published does **not** provide a self-contained
bundle, and peerhailer's current principle is that the file shipped is the file
read and debugged. Do not count hypothetical bundling as an advantage unless the
project explicitly accepts that build/review workflow.

Babashka CLI is a credible finalist, not a novelty. Its command model has to win
enough clarity over Commander to justify the larger and less direct runtime.

## Other parsers considered

### CAC 7

[CAC 7](https://github.com/cacjs/cac) is an attractive small option: roughly
41 KB unpacked, zero dependencies, generated help, strict unknown checking, and
native optional values written as `--debug [minutes]`.

It is not a finalist yet. It requires Node 20.19+, which is narrower than the
published `>=20` floor, and its command dispatcher is flat rather than a nested
command tree. It remains a reasonable fallback if those constraints are accepted.

### Yargs 18

[Yargs 18](https://github.com/yargs/yargs/tree/v18.1.0) has excellent command,
validation, strictness, help, and parser-configuration features. It is the broadest
option here, but `hail` does not need most of that breadth. The current release
requires Node 20.19+ on the 20.x line, 22.12+ on 22.x, or Node 23+, excluding
Node 21 and Node 22.0–22.11. It has six direct runtime dependencies (roughly
thirteen unique packages / fifteen installed package instances in the audited
tree), and models optional values only loosely through an untyped option plus
validation. It offers less precise fit than Commander at greater runtime cost.

### Citty 0.2

[Citty](https://github.com/unjs/citty) is a compact, zero-runtime-dependency,
data-shaped command builder with nested commands and generated usage. Its declared
argument kinds are positional, string, boolean, and enum. It does not directly
represent a boolean-or-valued `--debug`, so the decisive stdlib limitation remains.

### Minimal tokenizers

Packages such as `arg`, `mri`, and `minimist` are smaller still, but they do not
provide the per-leaf command schema and generated help that justify adopting a
parser framework. Rebuilding those layers on a tokenizer merely moves the local
maintenance burden.

## Comparison

| Candidate | `--debug [minutes]` | Nested leaf schemas/help | Runtime tree | Node floor | No-install clone | Main concern |
| --- | --- | --- | --- | --- | --- | --- |
| Local typed parser | Yes, by design | We build it | none | current | Yes | We own the grammar |
| `node:util.parseArgs` | No, needs shim/syntax change | We build it | none | `>=20` | Yes | Exceptions erode simplicity |
| Commander 14.0.3 | Yes, first-class | Yes | 1 package, 0 deps | `>=20` | No, unless vendored | v14 support horizon / imperative API |
| `@babashka/cli` 0.12.86 | Yes, then normalize | Yes | 4 packages, ~2.5 MB installed | undeclared; test `>=20` | No, unless bundled | generated runtime / pre-1.0 API |
| CAC 7.0.0 | Yes, first-class | Flat command model | 1 package, 0 deps | `>=20.19` | No, unless vendored | floor / flat dispatcher |
| Yargs 18.1.0 | Loosely, with validation | Yes | 6 direct, 13 unique | `20.19+`, `22.12+`, or `>=23` | No, unless bundled | unnecessary breadth |
| Citty 0.2.2 | No | Yes | 1 package, 0 deps | undeclared | No, unless vendored | same mixed-type limit |

## Recommendation

Do not commit to `node:util.parseArgs` on the claim that it limits nothing; that
claim is false for the documented diagnostics option. Do not select a Lisp-origin
package merely because Lisp is associated with compilers or AI, either.

First decide whether the source-clone/no-install promise is still binding. If it
is, implement the local typed schema; the stdlib route does not justify its
compatibility shims merely to keep the engine in core.

If the project is willing to reverse that deployment policy, run the same small
proof against the two serious package finalists:

1. **Commander 14.0.3** — the conservative default: exact Node-floor match,
   optional values, plain JavaScript, zero transitive dependencies.
2. **`@babashka/cli` 0.12.86** — the declarative alternative: a richer data-shaped
   multi-command model whose installed/runtime and generated-source costs are now
   explicit.

The proof should define only schemas and return the parsed shape; it should not
rewrite command handlers. Judge both with the contract tests below, generated
help snapshots, Node 20 and 22, startup time, error quality, and an audit of the
exact packed files. Choose Babashka only if its command tree is materially clearer
for hail's grouped actions. Otherwise choose Commander.

If neither dependency earns that policy change, keep the local typed-schema
choice rather than forcing `parseArgs` through increasingly project-specific
shims.

## Contract test matrix for the proof

1. `block --include-key bob` succeeds and targets `bob`.
2. `block bob --include-key` remains valid.
3. `block bob --include-keey` fails as an unknown option.
4. `block bob --include-key=yes` follows an explicitly chosen boolean-value rule.
5. `block bob --include-key yes` fails as an extra positional.
6. `--state PATH block bob` and `block bob --state PATH` select the same state.
7. `commands add deploy -- ./run.sh --env prod` preserves the complete command.
8. After `--`, `--state child.json` remains payload.
9. `add bob --key <PEM>` retains its current form, or the migration documents and
   tests the intentional `--key-file` / `--key=<PEM>` replacement.
10. Bare `daemon --debug`, `daemon --debug 2`, and `daemon --debug=2` all retain
    their intended meanings.
11. `daemon --require-target-binding yes` fails loudly.
12. `profiles pin trusted --force` fails because `--force` belongs to
    `profiles remove`, not the `profiles` group globally.
13. Every string-valued option fails when its value is missing.
14. Root and leaf `--help` are generated from the same schemas used to validate.
