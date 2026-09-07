/**
 * The contract matrix from docs/cli-arg-parsing.md, proven at the parser level.
 * (Point 14 — help generated from the same schemas — is a separate feature, not
 * yet built, so it is not asserted here.)
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { parseArgs, CliError } from "../src/cliArgs.js";

const of = (line) => parseArgs(line.split(" ").filter(Boolean));

test("1 & 2: a boolean flag works before or after the positional", () => {
  for (const line of ["block --include-key bob", "block bob --include-key"]) {
    const { positional, flags } = of(line);
    assert.deepEqual(positional, ["block", "bob"], line);
    assert.equal(flags["include-key"], true, line);
  }
});

test("3: an unknown option is refused against the command schema", () => {
  assert.throws(() => of("block bob --include-keey"), CliError);
});

test("4: --include-key=false is off; =anything-else is on", () => {
  assert.equal(of("block bob --include-key=false").flags["include-key"], false);
  assert.equal(of("block bob --include-key=yes").flags["include-key"], true);
});

test("5: a value given to a boolean flag lands as an extra positional and fails", () => {
  assert.throws(() => of("block bob --include-key yes"), /extra argument: yes/);
});

test("6: --state selects the same state before or after the command", () => {
  assert.equal(of("--state P block bob").flags.state, "P");
  assert.equal(of("block bob --state P").flags.state, "P");
});

test("7: `--` preserves a forwarded command with its own flags", () => {
  const { positional } = of("commands add deploy -- ./run.sh --env prod");
  // The handler reads rest.slice(2).join(" "); rest is positional after the command.
  assert.deepEqual(positional.slice(3), ["./run.sh", "--env", "prod"]);
});

test("8: after `--`, a --state token is payload, not the global option", () => {
  const { flags, positional } = of("commands add deploy -- ./run.sh --state child.json");
  assert.equal(flags.state, undefined, "not swallowed as the global");
  assert.ok(positional.includes("--state") && positional.includes("child.json"), "kept as payload");
});

test("9: --key keeps an inline dash-leading PEM as its value", () => {
  const pem = "-----BEGIN-PUBLIC-KEY-----";
  const { flags } = parseArgs(["add", "bob", "--key", pem]);
  assert.equal(flags.key, pem);
});

test("10: --debug is bare-true, spaced, or =valued", () => {
  assert.equal(of("daemon --debug").flags.debug, true);
  assert.equal(of("daemon --debug 2").flags.debug, "2");
  assert.equal(of("daemon --debug=2").flags.debug, "2");
});

test("11: a value handed to a boolean daemon flag fails loudly", () => {
  assert.throws(() => of("daemon --require-target-binding yes"), /extra argument: yes/);
});

test("12: --force is refused on `profiles pin` — it belongs to `profiles remove`", () => {
  assert.throws(() => of("profiles pin trusted --force"), /unknown option --force/);
  // ...and is accepted on remove.
  assert.equal(of("profiles remove temp --force").flags.force, true);
});

test("13: a string option with no value fails", () => {
  assert.throws(() => of("add bob --profile"), /--profile needs a value/);
});

test("a missing required positional fails with the argument name", () => {
  assert.throws(() => of("block"), /missing argument: name/);
});

test("an unmigrated command falls back to the lenient parse (no schema, no error)", () => {
  // A command with no schema entry accepts unknown flags and stays greedy — exactly the
  // legacy behaviour. Every real `hail` command is now migrated, so this uses a synthetic
  // name to exercise the fallback mechanism itself.
  const { positional, flags } = of("frobnicate add mymod --anything here");
  assert.equal(positional[0], "frobnicate");
  assert.equal(flags.anything, "here");
});

test("regression: daemon accepts --hail-on-encrypted / --hail-on-tls (Fable)", () => {
  assert.equal(of("daemon --hail-on-encrypted tailscale0").flags["hail-on-encrypted"], "tailscale0");
  assert.equal(of("daemon --hail-on-tls eth0").flags["hail-on-tls"], "eth0");
});

test("regression: unblock --key with no name is valid (Fable)", () => {
  const { flags, positional } = of("unblock --key ABCDEF12");
  assert.equal(flags.key, "ABCDEF12");
  assert.deepEqual(positional, ["unblock"], "no name required");
  // ...and the name form still works.
  assert.deepEqual(of("unblock bob").positional, ["unblock", "bob"]);
});

test("the lenient fallback is verbatim: --a --b=c keeps the old greedy reading", () => {
  // A command with no schema must behave exactly as before: the old parser read
  // `--b=c` (which is not a bare --word) as the value of --a.
  const { flags } = of("frobnicate --a --b=c");
  assert.equal(flags.a, "--b=c", "unchanged legacy behaviour on an unschemed command");
});

// --- Security-shaped commands: seal, rotate, trust, gate ---

test("seal: status is an action with no positional; accept takes a name + key options", () => {
  assert.deepEqual(of("seal status").positional, ["seal", "status"]);
  const accept = of("seal accept bob --seal-key-file b.pub");
  assert.deepEqual(accept.positional, ["seal", "accept", "bob"]);
  assert.equal(accept.flags["seal-key-file"], "b.pub");
  // A bare/unknown action falls to the lenient parse (the handler prints usage/status).
  assert.deepEqual(of("seal").positional, ["seal"]);
  assert.throws(() => of("seal accept"), /missing argument: name/);
  assert.throws(() => of("seal accept bob --seal-keyy x"), /unknown option/);
});

test("rotate: name is required, key/key-file are typed, unknown options refused", () => {
  const r = of("rotate bob --key-file new.pub");
  assert.deepEqual(r.positional, ["rotate", "bob"]);
  assert.equal(r.flags["key-file"], "new.pub");
  assert.throws(() => of("rotate"), /missing argument: name/);
  assert.throws(() => of("rotate bob --bogus"), /unknown option/);
  // A dash-leading inline PEM is kept as --key's value (isLongFlag exempts a PEM).
  const pem = "-----BEGIN-PUBLIC-KEY-----";
  assert.equal(parseArgs(["rotate", "bob", "--key", pem]).flags.key, pem);
});

test("trust: bare shows status (no model); a model is one positional; options typed", () => {
  assert.deepEqual(of("trust").positional, ["trust"]);
  assert.deepEqual(of("trust web-of-trust").positional, ["trust", "web-of-trust"]);
  assert.equal(of("trust --unknown known").flags.unknown, "known");
  assert.equal(of("trust web-of-trust --vouches 2").flags.vouches, "2");
  assert.throws(() => of("trust a b"), /unexpected extra argument: b/);
});

test("gate: set-password/serve are actions; keep-sessions/trust-forwarded are booleans", () => {
  assert.equal(of("gate set-password --keep-sessions").flags["keep-sessions"], true);
  const serve = of("gate serve --target http://127.0.0.1:3000 --port 8443 --trust-forwarded");
  assert.deepEqual(serve.positional, ["gate", "serve"]);
  assert.equal(serve.flags.target, "http://127.0.0.1:3000");
  assert.equal(serve.flags["trust-forwarded"], true);
  assert.deepEqual(of("gate").positional, ["gate"]); // bare → status via lenient
  assert.throws(() => of("gate serve --targett x"), /unknown option/);
});

// --- Declared-capability commands: walk, shells, services, shares, tunnels, files ---

test("walk: no options, no positionals; an unknown option is refused", () => {
  assert.deepEqual(of("walk").positional, ["walk"]);
  assert.throws(() => of("walk --deep"), /unknown option --deep/);
});

test("shells: add takes name + a variadic command line; bare lists via lenient", () => {
  // A real shell line is quoted (one argv token); the handler joins the variadic tail either way.
  const { positional } = of("shells add sandboxed firejail bash");
  assert.deepEqual(positional, ["shells", "add", "sandboxed", "firejail", "bash"]);
  // A line carrying its own flags is passed after `--`, kept verbatim as payload.
  assert.deepEqual(of("shells add sandboxed -- firejail --net=none bash").positional.slice(3), ["firejail", "--net=none", "bash"]);
  assert.deepEqual(of("shells").positional, ["shells"]); // bare → lenient listing
  assert.throws(() => of("shells add"), /missing argument: name/);
});

test("services: add carries offer metadata + optional --reports-port; remove needs a name", () => {
  const add = of("services add web node-srv --label My --role worker --reports-port");
  assert.deepEqual(add.positional, ["services", "add", "web", "node-srv"]);
  assert.equal(add.flags.label, "My");
  assert.equal(add.flags.role, "worker");
  assert.equal(add.flags["reports-port"], true);
  assert.throws(() => of("services add web x --bogus"), /unknown option --bogus/);
  assert.throws(() => of("services remove"), /missing argument: name/);
});

test("shares: add takes name + optional root and backend options; http omits the root", () => {
  const local = of("shares add drop /srv/drop --writable");
  assert.deepEqual(local.positional, ["shares", "add", "drop", "/srv/drop"]);
  assert.equal(local.flags.writable, true);
  const http = of("shares add repo --backend http --base https://h/f/");
  assert.deepEqual(http.positional, ["shares", "add", "repo"]); // root omitted for http
  assert.equal(http.flags.base, "https://h/f/");
  assert.throws(() => of("shares add drop /srv --nope"), /unknown option --nope/);
});

test("tunnels: add takes name + address; --exit-token is a valued string", () => {
  const add = of("tunnels add acp 127.0.0.1:9100 --exit-token sekret-token");
  assert.deepEqual(add.positional, ["tunnels", "add", "acp", "127.0.0.1:9100"]);
  assert.equal(add.flags["exit-token"], "sekret-token");
  assert.deepEqual(of("tunnels").positional, ["tunnels"]); // bare → lenient listing
  assert.throws(() => of("tunnels add acp 127.0.0.1:9100 --bogus"), /unknown option --bogus/);
  assert.throws(() => of("tunnels add acp"), /missing argument: address/);
});

test("files: flat positionals peer/share/action + optional path/localfile; no options", () => {
  const get = of("files bob docs get a/b.txt out.txt");
  assert.deepEqual(get.positional, ["files", "bob", "docs", "get", "a/b.txt", "out.txt"]);
  assert.deepEqual(of("files bob docs list").positional, ["files", "bob", "docs", "list"]);
  assert.throws(() => of("files bob docs"), /missing argument: action/);
  assert.throws(() => of("files bob docs get a b c"), /unexpected extra argument: c/);
  assert.throws(() => of("files bob docs list --json"), /unknown option --json/);
});

// --- The last leaves: name, id, forget, status, peers, shell, tunnel, plugins ---

test("name: one required positional (the new name); extras and unknown options refused", () => {
  assert.deepEqual(of("name sol").positional, ["name", "sol"]);
  assert.throws(() => of("name"), /missing argument: newname/);
  assert.throws(() => of("name a b"), /unexpected extra argument: b/);
  assert.throws(() => of("name sol --force"), /unknown option --force/);
});

test("id / status / peers: no positionals, no options", () => {
  for (const cmd of ["id", "status", "peers"]) {
    assert.deepEqual(of(cmd).positional, [cmd], cmd);
    assert.throws(() => of(`${cmd} extra`), /unexpected extra argument: extra/, cmd);
    assert.throws(() => of(`${cmd} --deep`), /unknown option --deep/, cmd);
  }
});

test("forget: one required positional (the peer name)", () => {
  assert.deepEqual(of("forget bob").positional, ["forget", "bob"]);
  assert.throws(() => of("forget"), /missing argument: name/);
  assert.throws(() => of("forget bob --hard"), /unknown option --hard/);
});

test("shell: flat peer/name/action + variadic args; --raw is a boolean; payload flags go after --", () => {
  const send = of("shell bob mysh send S1 hello world");
  assert.deepEqual(send.positional, ["shell", "bob", "mysh", "send", "S1", "hello", "world"]);
  assert.equal(of("shell bob mysh send S1 hi --raw").flags.raw, true);
  // A payload carrying its own --flags is preserved verbatim after `--`.
  assert.deepEqual(of("shell bob mysh exec -- ls --color").positional.slice(4), ["ls", "--color"]);
  assert.throws(() => of("shell bob mysh"), /missing argument: action/);
  assert.throws(() => of("shell bob mysh exec ls --color"), /unknown option --color/);
});

test("tunnel: flat peer/name/action + variadic args; no options", () => {
  const send = of("tunnel bob acp send T1 payload");
  assert.deepEqual(send.positional, ["tunnel", "bob", "acp", "send", "T1", "payload"]);
  assert.deepEqual(of("tunnel bob acp forward 9100").positional, ["tunnel", "bob", "acp", "forward", "9100"]);
  assert.throws(() => of("tunnel bob acp"), /missing argument: action/);
  assert.throws(() => of("tunnel bob acp send T1 hi --extra"), /unknown option --extra/);
});

test("plugins: add/remove take a module; bare/unknown action lists via the lenient fallback", () => {
  assert.deepEqual(of("plugins add ./mod.js").positional, ["plugins", "add", "./mod.js"]);
  assert.deepEqual(of("plugins remove ./mod.js").positional, ["plugins", "remove", "./mod.js"]);
  assert.deepEqual(of("plugins").positional, ["plugins"]); // bare → lenient listing
  assert.deepEqual(of("plugins list").positional, ["plugins", "list"]); // unknown action → lenient
  assert.throws(() => of("plugins add"), /missing argument: module/);
  assert.throws(() => of("plugins add ./mod.js --anything"), /unknown option --anything/);
});
