#!/usr/bin/env node
/**
 * hail — the command line for peerhailer.
 *
 * Deliberately usable with no daemon running: every command operates on the
 * stored directory directly. A tool for reaching machines that has to be
 * running before you can ask it anything is a tool that fails exactly when you
 * need it.
 *
 *   hail status                    what this machine is, and who it knows
 *   hail peers                     admitted peers and candidates
 *   hail add <name> <address>      admit a peer, deliberately
 *   hail forget <name>             remove one, admitted or not
 *   hail walk                      ask known peers who else they know
 *   hail id                        print this machine's public key
 *   hail daemon [--port N]         answer hails from other machines
 */
import { readFileSync } from "node:fs";
import { createServer as createHttpsServer } from "node:https";
import { networkInterfaces } from "node:os";
import { hostname } from "node:os";

import { createDirectory } from "../src/directory.js";
import { defaultIdentityPath, fingerprint, loadIdentity, normalizeKey } from "../src/identity.js";
import { listProfiles, removeProfile, setPinned, setProfile, setRejection } from "../src/profiles.js";
import { createDiagnostics, DEFAULT_WINDOW_MS } from "../src/diagnostics.js";
import { createDiagnosticsPlugin } from "../src/builtin/diagnosticsPlugin.js";
import hailPlugin from "../src/builtin/hailPlugin.js";
import { createTunnelPlugin } from "../src/builtin/tunnelPlugin.js";
import { createCommandPlugin } from "../src/builtin/commandPlugin.js";
import { createChatPlugin } from "../src/builtin/chatPlugin.js";
import { createServicePlugin } from "../src/builtin/servicePlugin.js";
import { createShellPlugin } from "../src/builtin/shellPlugin.js";
import { openShell, sendShell, pollShell, closeShell, execShell } from "../src/shellClient.js";
import { collectProfiles, collectRoutes, loadPlugins } from "../src/plugins.js";
import { TRUST_MODELS } from "../src/trust.js";
import { walk, callPeer } from "../src/hail.js";
import { createGate, hashPassword, newSecret } from "../src/gate.js";
import { selfSignedCert } from "../src/cert.js";
import { createDaemon } from "../src/server.js";
import { defaultStatePath, loadState, updateState } from "../src/state.js";

const log = (message) => process.stdout.write(`${message}\n`);
const fail = (message) => {
  process.stderr.write(`hail: ${message}\n`);
  process.exit(1);
};

/**
 * Flags, values, and one trap worth avoiding.
 *
 * `--flag value` is convenient until the value is a PEM, which begins with
 * `-----BEGIN` and looks exactly like another flag. So a value is only refused
 * when it starts with `--` *and* reads like a flag name; anything else is taken
 * as the value it plainly is. `--flag=value` always works and is what to use
 * when the value could be anything at all.
 */
function parseArgs(argv) {
  const positional = [];
  /** @type {Record<string, string | true>} */
  const flags = {};
  const looksLikeFlag = (token) => /^--[a-z][a-z0-9-]*$/i.test(token);

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) {
      positional.push(token);
      continue;
    }
    const equals = token.indexOf("=");
    if (equals !== -1) {
      flags[token.slice(2, equals)] = token.slice(equals + 1);
      continue;
    }
    const key = token.slice(2);
    const next = argv[i + 1];
    if (next === undefined || looksLikeFlag(next)) flags[key] = true;
    else {
      flags[key] = next;
      i += 1;
    }
  }
  return { positional, flags };
}

const { positional, flags } = parseArgs(process.argv.slice(2));
const [command, ...rest] = positional;
const statePath = typeof flags.state === "string" ? flags.state : defaultStatePath();
const stored = loadState(statePath, { log: (m) => process.stderr.write(`${m}\n`) });
const identity = loadIdentity(defaultIdentityPath(statePath), {
  log: (m) => process.stderr.write(`${m}\n`),
});

const directory = createDirectory({
  ...stored,
  profiles: stored.profiles ?? {},
  self: {
    // The hostname is a better default than a placeholder: it is already the
    // name a person calls this machine, and a fabric full of peers called
    // "unnamed" cannot be reasoned about at all.
    ...(stored.self ?? { name: flags.name ?? hostname(), addresses: [] }),
    ...(typeof flags.name === "string" ? { name: flags.name } : {}),
    // The key is this machine's identity, so the record always carries it —
    // a peer cannot check a claim it was never given a key for.
    publicKey: identity.publicKey,
  },
});
// Profiles ride alongside the directory: they are configuration about peers,
// and splitting them into another file would mean two things to keep in step.
/**
 * Write the directory back, keeping everything else in the file.
 *
 * Two things are being protected here. Configuration this command knows nothing
 * about survives, because the file read inside the lock is spread first —
 * rebuilding from the directory alone once erased the plugin list. And the read
 * happens *inside* the lock, so a change lands on top of whatever a daemon or
 * another terminal wrote a moment ago rather than replacing it.
 *
 * The peers this process knows still win for peer data: they are what the
 * command was about. Anything else on disk is left alone.
 */
const persist = () =>
  updateState(
    statePath,
    (onDisk) => {
      const snap = directory.snapshot();
      // Carry the monotone target-binding signal forward across writers. This
      // process's directory may have loaded before a running daemon learned a
      // peer binds (passively, from a hail), and `snapshot()` wholesale-replaces
      // `admitted`, which would drop it — making a field the whole design treats
      // as never-lowered lowerable by an unrelated CLI command. Only this one
      // field is merged by `max`; the rest stays "this command's peers win".
      const priorBinding = new Map((onDisk.admitted ?? []).map((p) => [p.name, p.bindingSeen]));
      const admitted = (snap.admitted ?? []).map((p) => {
        const seen = Math.max(Number(p.bindingSeen) || 0, Number(priorBinding.get(p.name)) || 0);
        return seen > 0 ? { ...p, bindingSeen: seen } : p;
      });
      return { ...onDisk, ...stored, ...snap, admitted };
    },
    { log: (m) => process.stderr.write(`${m}\n`) },
  );

// The identity and the name have to survive the process, or every hail
// introduces a machine nobody has heard of. Written on first sight rather than
// waiting for a command that happens to save.
if (!stored.self || stored.self.name !== directory.self.name || !stored.self.publicKey) persist();

/** A key given inline, or read from a file — PEMs are easier to hand over as files. */
/**
 * When an elevation should lapse: an ISO date, or a duration like `7d`, `2h`.
 *
 * @param {unknown} value
 * @returns {number | null}
 */
function untilFromFlag(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  const text = value.trim();
  const duration = /^(\d+)\s*(m|h|d|w)$/i.exec(text);
  if (duration) {
    const units = { m: 60_000, h: 3_600_000, d: 86_400_000, w: 604_800_000 };
    return Date.now() + Number(duration[1]) * units[duration[2].toLowerCase()];
  }
  const parsed = Date.parse(text);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * Turn what a person wrote into addresses a socket can bind.
 *
 * Interface names, because they are the stable half: `wlan0` outlives the
 * address DHCP hands it, and a daemon bound to yesterday's address answers
 * nothing while looking healthy. A literal address is taken as written, for the
 * cases where that is what you meant.
 *
 * @param {string} spec
 * @returns {string[]}
 */
function addressesFor(spec) {
  const wanted = spec.trim();
  if (!wanted) return [];
  // Already an address, or the wildcard.
  if (/^[0-9.]+$/.test(wanted) || wanted.includes(":") || wanted === "0.0.0.0") return [wanted];

  const iface = networkInterfaces()[wanted];
  if (!iface) return [];
  return iface.filter((entry) => entry.family === "IPv4" && !entry.internal).map((entry) => entry.address);
}

const publicKeyFromFlags = () => {
  // `--key` with nothing after it parses as boolean `true`, which is not a
  // string and so used to read as "no key flag given" — silently admitting on
  // trust-on-first-use, the exact thing this function exists to refuse.
  if (flags.key === true) fail("--key needs a PEM; --key-file <path> is easier");
  if (flags["key-file"] === true) fail("--key-file needs a path");

  const source = typeof flags["key-file"] === "string" ? "key-file" : typeof flags.key === "string" ? "key" : null;
  if (!source) return null;

  let raw;
  if (source === "key-file") {
    try {
      raw = readFileSync(String(flags["key-file"]), "utf8");
    } catch {
      fail(`--key-file could not be read: ${flags["key-file"]}`);
    }
  } else {
    raw = String(flags.key);
  }

  // Asking for a key and getting nothing usable is a failed hand-off, not a
  // request to trust on first use. `--key "$(cat missing.pub)"` yields an empty
  // string, and admitting keyless there silently grants less checking than was
  // asked for — the peer reads `no key` in a line nobody re-reads.
  const key = normalizeKey(raw);
  if (!key) fail(`--${source} did not contain a usable public key`);
  return key;
};

const describe = (peer) => {
  const effective = directory.effectiveProfile(peer.name);
  const routes = peer.addresses.map((a) => `${a.transport}:${a.value}`).join(", ") || "no address";
  const seen = peer.lastSeen ? new Date(peer.lastSeen).toISOString() : "never";
  const lapses =
    peer.profileUntil && peer.profileUntil > Date.now()
      ? ` until ${new Date(peer.profileUntil).toISOString()}`
      : "";
  const profile = `[${effective.profile}${lapses}]`;
  const key = peer.publicKey ? fingerprint(peer.publicKey).slice(0, 14) : "no key";
  const line = `${peer.name.padEnd(16)} ${profile.padEnd(10)} ${key}  ${routes}  (last seen ${seen})`;
  // A competing key is the one thing here a person must not scroll past: the
  // key held keeps working, so nothing breaks to make them look.
  const conflicts = Array.isArray(peer.conflicts) ? peer.conflicts : [];
  if (conflicts.length === 0) return line;
  return [
    line,
    ...conflicts.map(
      (c) =>
        `    ! also answered as ${peer.name} holding ${fingerprint(c.key).slice(0, 14)}` +
        ` (${c.count}x, first ${new Date(c.firstSeen).toISOString()})`,
    ),
    `    ! the key above is still the trusted one. If this machine's key changed,`,
    `    !   hail rotate ${peer.name} --key-file <new.pub>`,
  ].join("\n");
};

/**
 * Read a password without it landing in argv or shell history. In order of
 * preference: a `--password-file`, then piped stdin, then a hidden interactive
 * prompt. Never a command-line flag — an argument is visible in `ps` and saved
 * by the shell.
 *
 * @param {string} prompt
 * @returns {Promise<string>}
 */
async function readPassword(prompt) {
  if (typeof flags["password-file"] === "string") {
    return readFileSync(flags["password-file"], "utf8").replace(/\r?\n+$/, "");
  }
  if (!process.stdin.isTTY) {
    let data = "";
    for await (const chunk of process.stdin) data += chunk;
    return data.replace(/\r?\n+$/, "");
  }
  process.stderr.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  let pw = "";
  for await (const chunk of process.stdin) {
    for (const ch of chunk.toString()) {
      const code = ch.charCodeAt(0);
      if (code === 10 || code === 13 || code === 4) {
        // Enter (\n / \r) or Ctrl-D: done.
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stderr.write("\n");
        return pw;
      }
      if (code === 3) {
        // Ctrl-C: abort.
        process.stdin.setRawMode(false);
        process.stderr.write("\n");
        process.exit(1);
      }
      if (code === 127 || code === 8) pw = pw.slice(0, -1); // backspace / delete
      else pw += ch;
    }
  }
  return pw;
}

switch (command) {
  case "status": {
    log(`name:    ${directory.self.name}`);
    log(`key:     ${fingerprint(identity.publicKey)}`);
    log(`state:   ${statePath}`);
    log(`admitted: ${directory.listAdmitted().length}`);
    log(`candidates: ${directory.listCandidates().length}`);
    break;
  }

  case "peers": {
    const admitted = directory.listAdmitted();
    log(admitted.length ? "admitted:" : "admitted: none");
    for (const peer of admitted) log(`  ${describe(peer)}`);

    const candidates = directory.listCandidates();
    if (candidates.length) {
      // Named separately because they are leads, not peers: a name someone
      // mentioned is not a machine anyone agreed to talk to.
      log("\ncandidates (heard of, not admitted):");
      for (const peer of candidates) {
        log(`  ${peer.name.padEnd(20)} heard from ${peer.heardFrom.join(", ") || "unknown"}`);
      }
      log("\n  admit one with: hail add <name> <address>");
    }
    break;
  }

  case "add": {
    const [name, address] = rest;
    if (!name) fail("usage: hail add <name> [address]");
    const transport = typeof flags.transport === "string" ? flags.transport : "other";
    // An elevation without a profile to raise to is a no-op the user meant as
    // something; say so rather than admitting them and quietly ignoring it.
    const until = "until" in flags ? untilFromFlag(flags.until) : null;
    if ("until" in flags && until === null) fail("--until wants a date, or a duration like 7d or 2h");
    if (until && typeof flags.profile !== "string") fail("--until raises a profile: say which with --profile");

    const admitted = directory.admit(
      {
        name,
        addresses: address ? [{ transport, value: address, lastOk: null }] : [],
        ...(publicKeyFromFlags() ? { publicKey: publicKeyFromFlags() } : {}),
      },
      ...(typeof flags.profile === "string"
        ? [{ profile: flags.profile, ...(until ? { until } : {}) }]
        : []),
    );
    if (!admitted) fail("a name is required");
    persist();
    log(`admitted ${describe(admitted)}`);
    break;
  }

  case "block": {
    const [name] = rest;
    if (!name) fail("usage: hail block <name>");
    const peer = directory.get(name) ?? { name };
    directory.block(peer);
    persist();
    log(
      peer.publicKey
        ? `blocked ${name} by key — renaming will not get it back in`
        : `blocked ${name} by name (no key held for it, so a rename would)`,
    );
    break;
  }

  case "unblock": {
    const [name] = rest;
    if (!name) fail("usage: hail unblock <name>");
    directory.unblock(name);
    persist();
    log(`unblocked ${name}`);
    break;
  }

  case "trust": {
    const [model] = rest;
    if (!model) {
      const current = directory.trust();
      log(`model: ${current.model}`);
      log(`unknown peers: ${current.unknownProfile}`);
      log("");
      for (const entry of Object.values(TRUST_MODELS)) {
        log(`  ${entry.name.padEnd(14)} ${entry.describe}`);
      }
      break;
    }
    if (!TRUST_MODELS[model]) fail(`unknown trust model: ${model}`);
    stored.trust = {
      ...(stored.trust ?? {}),
      model,
      ...(typeof flags.vouches === "string" ? { settings: { vouchesRequired: Number(flags.vouches) } } : {}),
      ...(typeof flags.unknown === "string" ? { unknownProfile: flags.unknown } : {}),
    };
    persist();
    log(`trust model is now ${model}`);
    break;
  }

  case "rotate": {
    // Separate from `add` on purpose. Adding merges and never replaces a key,
    // which is what stops a peer talking us out of the identity we hold for it;
    // this is the door a person opens, and it takes the new key explicitly so
    // it cannot be done by accident.
    const [name] = rest;
    if (!name) fail("usage: hail rotate <name> --key-file <new.pub>");
    const key = publicKeyFromFlags();
    if (!key) fail("hail rotate needs the new key: --key-file <new.pub> or --key <pem>");
    const existing = directory.get(name);
    if (!existing) fail(`no peer called ${name}`);
    if (existing.publicKey) {
      log(`replacing ${fingerprint(existing.publicKey).slice(0, 14)} with ${fingerprint(key).slice(0, 14)} for ${name}`);
    }
    const rotated = directory.rotateKey(name, key);
    if (!rotated) fail(`could not rotate ${name}`);
    persist();
    log(`rotated ${describe(rotated)}`);
    break;
  }

  case "forget": {
    const [name] = rest;
    if (!name) fail("usage: hail forget <name>");
    const forgotten = directory.forget(name);
    persist();
    log(forgotten ? `forgot ${name}` : `${name} was not known`);
    break;
  }

  case "walk": {
    const result = await walk(directory, {
      as: { name: directory.self.name, publicKey: identity.publicKey, privateKey: identity.privateKey },
    });
    persist();
    for (const peer of result.reached) log(`reached ${peer.name} via ${peer.via.value}`);
    for (const peer of result.unreachable) log(`unreachable ${peer.name}: ${peer.error}`);
    if (result.candidates.length) {
      log(`\nheard of ${result.candidates.length}, none admitted:`);
      for (const peer of result.candidates) {
        log(`  ${peer.name} (from ${peer.heardFrom.join(", ") || "unknown"})`);
      }
    }
    break;
  }

  case "daemon": {
    // Named in the directory file, so a machine's services are part of its
    // recorded configuration rather than an argument someone has to remember.
    const diagnostics = createDiagnostics();
    // The CLI is opinionated where the library is not: a daemon that answers no
    // hails is not a daemon. Someone composing their own host loads whichever
    // of these they want, and opens no endpoints by default.
    // Declared endpoints become a tunnel plugin; declare none and the routes do
    // not exist, which is the difference between a service being refused and a
    // service not being there.
    const tunnels = stored.tunnels ?? {};
    const declaredCommands = stored.commands ?? {};
    const declaredServices = stored.services ?? {};
    const declaredShells = stored.shells ?? {};
    // An inbox is opt-in: someone running a headless relay should not inherit
    // one, same principle as the page.
    const wantsChat = flags.chat === true || stored.chat === true;
    const plugins = [
      hailPlugin,
      createDiagnosticsPlugin(diagnostics),
      ...(Object.keys(tunnels).length
        ? [createTunnelPlugin({ endpoints: tunnels, ownPorts: [Number.isFinite(port) ? port : 8787] })]
        : []),
      ...(wantsChat ? [createChatPlugin()] : []),
      ...(Object.keys(declaredServices).length ? [createServicePlugin({ services: declaredServices })] : []),
      ...(Object.keys(declaredShells).length ? [createShellPlugin({ shells: declaredShells })] : []),
      ...(Object.keys(declaredCommands).length
        ? [
            createCommandPlugin({
              commands: declaredCommands,
              // How much to remember, and for how long. In memory, so both are
              // bounded — and settings, because how much you want to know
              // afterwards is not this project's decision.
              ...(Number.isFinite(stored.history?.max) ? { maxHistory: stored.history.max } : {}),
              ...(Number.isFinite(stored.history?.ageMs) ? { historyMs: stored.history.ageMs } : {}),
            }),
          ]
        : []),
      ...(await loadPlugins(stored.plugins ?? [], { log })),
    ];
    for (const [name, address] of Object.entries(tunnels)) {
      log(`[tunnel] ${name} -> ${address} (needs tunnel:${name})`);
    }
    for (const name of Object.keys(declaredCommands)) {
      log(`[command] ${name} (needs command:${name})`);
    }
    for (const name of Object.keys(declaredServices)) {
      log(`[service] ${name} (needs service:${name})`);
    }
    for (const name of Object.keys(declaredShells)) {
      log(`[shell] ${name} (needs shell:${name}) — remote shell access; encrypted arrival only`);
    }
    if (wantsChat) log(`[chat] on (needs chat)`);
    // Profiles a plugin suggests have to be known before anyone is asked
    // whether they hold one — bundled plugins included, which is where the
    // `operator` profile comes from.
    const profiles = { ...collectProfiles(plugins), ...(stored.profiles ?? {}) };
    directory.useProfiles(profiles);
    // A window opened at launch still closes itself. `--debug` is for starting
    // a daemon you are about to debug, not for leaving one open.
    if (flags.debug) {
      const forMs = typeof flags.debug === "string" ? Number(flags.debug) * 60_000 : DEFAULT_WINDOW_MS;
      const until = diagnostics.open(Number.isFinite(forMs) ? forMs : DEFAULT_WINDOW_MS);
      log(`[diagnostics] window open until ${new Date(until).toISOString()}`);
    }
    // A bare boolean flag that swallowed a following token would read as a
    // string and, being `!== true`, silently disable the fully-closed state the
    // operator meant to turn on — the wrong direction for a security posture
    // flag. Fail loudly instead of enforcing less than was asked.
    if (typeof flags["require-target-binding"] === "string") {
      fail("--require-target-binding takes no value — write it bare to refuse every un-targeted hail");
    }

    // Off unless named: a page you did not write should not be able to admit
    // peers, and the page this daemon serves is same-origin anyway.
    const allowedOrigins =
      typeof flags["allow-origin"] === "string"
        ? flags["allow-origin"].split(",").map((entry) => entry.trim()).filter(Boolean)
        : [];
    if (allowedOrigins.length) log(`[api] also answering ${allowedOrigins.join(", ")}`);

    /**
     * Rebuild what the daemon serves from the state file as it is now.
     *
     * The daemon cannot do this itself: only here knows that `stored.tunnels`
     * becomes a tunnel plugin and `stored.commands` becomes a command plugin.
     */
    const rebuild = async () => {
      const fresh = loadState(statePath);
      const nextTunnels = fresh.tunnels ?? {};
      const nextCommands = fresh.commands ?? {};
      const nextServices = fresh.services ?? {};
      const nextShells = fresh.shells ?? {};
      const nextChat = flags.chat === true || fresh.chat === true;
      const nextPlugins = [
        hailPlugin,
        createDiagnosticsPlugin(diagnostics),
        ...(nextChat ? [createChatPlugin()] : []),
        ...(Object.keys(nextTunnels).length
          ? [createTunnelPlugin({ endpoints: nextTunnels, ownPorts: [Number.isFinite(port) ? port : 8787] })]
          : []),
        ...(Object.keys(nextServices).length ? [createServicePlugin({ services: nextServices })] : []),
        ...(Object.keys(nextShells).length ? [createShellPlugin({ shells: nextShells })] : []),
        ...(Object.keys(nextCommands).length ? [createCommandPlugin({ commands: nextCommands })] : []),
        // The externally-loaded ones too. Dropping them silently on reload
        // vanishes the profiles they declare, so a peer holding a capability one
        // of them contributed is refused with nothing said — an operator adding
        // a tunnel and watching their T3 integration stop answering.
        ...(await loadPlugins(fresh.plugins ?? [], { log })),
      ];
      return {
        plugins: nextPlugins,
        profiles: { ...collectProfiles(nextPlugins), ...(fresh.profiles ?? {}) },
        state: fresh,
      };
    };

    const port = Number(flags.port ?? 8787);
    const daemon = createDaemon({
      directory,
      identity,
      profiles,
      diagnostics,
      plugins,
      // The fully-closed target-binding state: refuse every hail that does not
      // name its target. Off by default (a mixed fleet still interoperates);
      // turn it on once every peer that hails this machine sends `to`. See
      // docs/hail-target-binding.md.
      requireTargetBinding: flags["require-target-binding"] === true,
      onReload: async () => daemon.reload(await rebuild()),
      // The page can admit and block, so those changes reach disk the same way
      // the CLI's do — applied to what is on disk now, then adopted in memory,
      // so a change made at a terminal is not discarded by the next save here.
      applyChange: (mutate) => {
        let result;
        const next = updateState(
          statePath,
          (onDisk) => {
            const fresh = createDirectory({ ...onDisk, profiles: onDisk.profiles ?? {} });
            fresh.useProfiles({ ...collectProfiles(plugins), ...(onDisk.profiles ?? {}) });
            result = mutate(fresh);
            return { ...onDisk, ...fresh.snapshot() };
          },
          { log },
        );
        directory.adopt(next);
        return result;
      },
      log,
    });
    // Two doors, and the first one is optional.
    //
    // The control listener exists only for the page: the CLI reads the state
    // file directly and never speaks HTTP. So no page means no port a browser
    // can reach, which removes the whole cross-origin class rather than
    // defending against it — see "The page is surface" in docs/decisions.md.
    //
    // Opt-in, but said out loud when it is off. A safe default that hides the
    // feature only produces people who cannot find it.
    const wantsUi = flags.ui === true || flags.ui === "true";
    const host = typeof flags.host === "string" ? flags.host : "127.0.0.1";
    if (wantsUi) {
      const listening = await daemon.listen({ port: Number.isFinite(port) ? port : 8787, host });
      log(`[ui] http://${listening.host}:${listening.port}`);
      if (host !== "127.0.0.1" && host !== "localhost") {
        log(`[daemon] warning: the page and /api/* are on ${host} and hold no authentication`);
      }
    } else {
      log(`[ui] not served — add --ui for a page at http://127.0.0.1:${Number.isFinite(port) ? port : 8787}`);
    }

    // `--hail-on wlan0,tailscale0` — interface names, resolved now, because the
    // name is the stable half and the address is not. The encrypted assertion is
    // per interface, not per invocation: `--hail-on` is plaintext arrival,
    // `--hail-on-encrypted` asserts the arrival is encrypted (a tainet, pinned
    // TLS later). Two flags rather than one boolean over a mixed list, so
    // asserting the tailnet cannot silently vouch for wifi in the same breath.
    const resolveHosts = (spec) => {
      const parts = typeof spec === "string" ? spec.split(",") : [];
      for (const part of parts) {
        if (addressesFor(part).length === 0) log(`[daemon] ${part.trim()} has no address to bind`);
      }
      return [...new Set(parts.flatMap(addressesFor))];
    };
    const plainHosts = resolveHosts(flags["hail-on"]);
    const encryptedHosts = resolveHosts(flags["hail-on-encrypted"]);
    // `--hail-on-tls` serves pinned TLS: the handshake makes the arrival
    // encrypted, so the operator never asserts it — this is how a shell or
    // tunnel runs on a LAN off any tailnet.
    const tlsHosts = resolveHosts(flags["hail-on-tls"]);
    const hosts = [...plainHosts, ...encryptedHosts, ...tlsHosts];

    // Any plugin whose routes require an encrypted arrival is not served on a
    // plaintext interface. Derived from the loaded plugins themselves rather than
    // a hardcoded set of families, so a module-specifier plugin (`hail plugins
    // add …`) that gates its routes is warned about too — otherwise the operator
    // is left exactly where the warning exists to prevent them being: wondering
    // why a declared capability is not answered.
    // Derived from the *resolved* routes, not the plugin objects: arrival is
    // encrypted by default now, so a plugin can be gated without carrying a
    // marker of its own (`collectRoutes` applies the default). A plugin is named
    // here if any of its routes ends up requiring encryption.
    const gatedPlugins = [
      ...new Set(
        [...collectRoutes(plugins, { log: () => {} }).values()]
          .filter((r) => r.requiresEncryptedArrival)
          .map((r) => r.plugin),
      ),
    ];
    if (plainHosts.length && gatedPlugins.length) {
      log(`[daemon] WARNING: ${gatedPlugins.join(", ")} require an encrypted arrival, but --hail-on interfaces are`);
      log("[daemon]          plaintext — those routes are NOT served there. Use --hail-on-tls to serve them over");
      log("[daemon]          pinned TLS, or --hail-on-encrypted for a tailnet. They are never offered in cleartext.");
    }
    const hailPort = Number.isFinite(port) ? port : 8787;
    if (plainHosts.length) await daemon.listenHail({ port: hailPort, hosts: plainHosts, encrypted: false });
    if (encryptedHosts.length) await daemon.listenHail({ port: hailPort, hosts: encryptedHosts, encrypted: true });
    // A provided (real / Let's Encrypt) cert overrides the self-signed one on the
    // TLS listeners — for clients that validate against a CA, e.g. a browser.
    const providedCert = typeof flags["tls-cert"] === "string" ? readFileSync(flags["tls-cert"], "utf8") : undefined;
    const providedKey = typeof flags["tls-key"] === "string" ? readFileSync(flags["tls-key"], "utf8") : undefined;
    if (tlsHosts.length) {
      await daemon.listenHail({
        port: hailPort,
        hosts: tlsHosts,
        tls: true,
        ...(providedCert && providedKey ? { cert: providedCert, key: providedKey } : {}),
      });
    }
    if (!wantsUi && hosts.length === 0) {
      log("[daemon] nothing is being served: --ui for the page, --hail-on to answer peers");
    }
    // Deliberately no persist() here. Every change the daemon makes already
    // went to disk through applyChange, which writes and then re-reads, so its
    // in-memory copy holds nothing newer than the file. What it *can* hold is
    // something older: it never re-reads changes made behind it, so a `hail add`
    // run at another terminal while this was up would be overwritten on the way
    // out. Serving a hail mutates nothing, so there is nothing here to lose.
    const stop = async () => {
      await daemon.close();
      process.exit(0);
    };
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
    break;
  }

  case "name": {
    const [next] = rest;
    if (!next) fail("usage: hail name <name>");
    // Renaming does not change identity — peers that hold the key still
    // recognise this machine, which is the point of keys being the identity.
    directory.self.name = next;
    persist();
    log(`this machine is now ${next} (${fingerprint(identity.publicKey)})`);
    break;
  }

  case "id": {
    // For handing to another machine: `hail id > sol.pub`.
    process.stdout.write(identity.publicKey.endsWith("\n") ? identity.publicKey : `${identity.publicKey}\n`);
    break;
  }

  case "shell": {
    // Drive a shell on *another* peer (client side), distinct from `shells`
    // which declares one on this machine. Low-level open/send/poll/close so a
    // session survives across separate invocations — hold the id, drive it a
    // call at a time — plus `exec` for a one-shot command.
    const [peerName, name, action, ...more] = rest;
    if (!peerName || !name || !action) {
      fail("usage: hail shell <peer> <name> <open|send|poll|close|exec> [args]");
    }
    const record = directory.get(peerName);
    if (!record) fail(`unknown peer ${peerName} — see hail peers`);
    const as = { name: directory.self.name, publicKey: identity.publicKey, privateKey: identity.privateKey };
    const call = (path, body) => callPeer(record, path, body, { as });
    const need = (result) => {
      if (!result.ok) fail(result.error);
      return result.response;
    };

    if (action === "open") {
      const res = need(await openShell(call, name));
      log(`id: ${res.id}`);
      log(`then: hail shell ${peerName} ${name} send ${res.id} "<command>"`);
      log(`      hail shell ${peerName} ${name} poll ${res.id}`);
      log(`      hail shell ${peerName} ${name} close ${res.id}`);
      break;
    }
    const id = more[0];
    if (action === "send") {
      if (!id) fail(`usage: hail shell ${peerName} ${name} send <id> <text...>`);
      // A trailing newline runs the line; --raw sends the bytes untouched, for
      // control characters and partial input.
      const text = more.slice(1).join(" ") + (flags.raw === true ? "" : "\n");
      need(await sendShell(call, name, id, text));
      log("sent");
      break;
    }
    if (action === "poll") {
      if (!id) fail(`usage: hail shell ${peerName} ${name} poll <id>`);
      const res = need(await pollShell(call, name, id));
      if (res.data) process.stdout.write(Buffer.from(res.data, "base64").toString());
      if (res.closed) log(`\n[shell closed${res.error ? `: ${res.error}` : ""}]`);
      break;
    }
    if (action === "close") {
      if (!id) fail(`usage: hail shell ${peerName} ${name} close <id>`);
      need(await closeShell(call, name, id));
      log("closed");
      break;
    }
    if (action === "exec") {
      const command = more.join(" ");
      if (!command) fail(`usage: hail shell ${peerName} ${name} exec <command...>`);
      const res = await execShell(call, name, command);
      if (!res.ok) fail(res.error);
      process.stdout.write(res.output.endsWith("\n") ? res.output : res.output + "\n");
      if (!res.complete) log("[did not finish within the poll window — the session was closed]");
      break;
    }
    fail(`unknown shell action ${action} — open|send|poll|close|exec`);
    break;
  }

  case "shells": {
    const [action, name] = rest;
    const declared = stored.shells ?? {};

    if (action === "add") {
      const line = rest.slice(2).join(" ").trim();
      if (!name || !line) fail('usage: hail shells add <name> "<shell command>"');
      if (!/^[a-z0-9][a-z0-9-]*$/i.test(name)) fail("a shell name is letters, digits and dashes");
      stored.shells = { ...declared, [name]: line };
      persist();
      log(`shell ${name} runs: ${line}`);
      log(`peers need shell:${name}; it is in no profile — grant it deliberately`);
      log("this is remote shell access, run as " + (process.env.USER ?? "this user") + ". To restrict it, declare a sandbox:");
      log('  hail shells add ' + name + ' "firejail --net=none bash"   (or bwrap / unshare / a container)');
      break;
    }
    if (action === "remove") {
      if (!name) fail("usage: hail shells remove <name>");
      const { [name]: _gone, ...rest2 } = declared;
      stored.shells = rest2;
      persist();
      log(`shell ${name} removed`);
      break;
    }
    const names = Object.keys(declared);
    if (names.length === 0) {
      log('no shells declared. hail shells add <name> "<shell command>"');
      break;
    }
    for (const entry of names) log(`  ${entry.padEnd(12)} runs: ${declared[entry]}   needs shell:${entry}`);
    break;
  }

  case "services": {
    const [action, name] = rest;
    const declared = stored.services ?? {};

    if (action === "add") {
      // --reports-port: the child binds its own port and prints `{"port":N}` to
      // stdout, and that announced port is what a caller gets — a fact, not the
      // claim `{port}` substitution makes. Prefer it for anything tunnelled to.
      // The global parser lifts `--reports-port` into `flags`; when it precedes
      // the command it swallows it as its value, so recover the line from either.
      const rp = flags["reports-port"];
      const reportsPort = rp !== undefined;
      const line = (typeof rp === "string" ? rp : rest.slice(2).join(" ")).trim();
      if (!name || !line) fail('usage: hail services add <name> "<command line, {port} unless --reports-port>" [--reports-port]');
      if (!/^[a-z0-9][a-z0-9-]*$/i.test(name)) fail("a service name is letters, digits and dashes");
      if (!reportsPort && !line.includes("{port}")) {
        fail('a claim-mode service needs {port} in its line, or pass --reports-port if the child announces its own');
      }
      stored.services = { ...declared, [name]: reportsPort ? { command: line, reportsPort: true } : line };
      persist();
      log(`service ${name} runs: ${line}`);
      log(reportsPort ? 'port: read from the child\'s announced {"port":N}' : "port: allocated and substituted for {port} (a routing hint, not proof)");
      log(`peers need service:${name}; no profile grants it yet`);
      log(`this runs as ${process.env.USER ?? "this user"}, and stays running — declare only what you mean`);
      break;
    }
    if (action === "remove") {
      if (!name) fail("usage: hail services remove <name>");
      const { [name]: _gone, ...rest2 } = declared;
      stored.services = rest2;
      persist();
      log(`service ${name} removed`);
      break;
    }
    const names = Object.keys(declared);
    if (names.length === 0) {
      log('no services declared. hail services add <name> "<command line with {port}>"');
      break;
    }
    for (const entry of names) {
      const decl = declared[entry];
      const cmd = typeof decl === "string" ? decl : decl.command;
      const mode = typeof decl === "object" && decl.reportsPort ? " (reports its port)" : "";
      log(`  ${entry.padEnd(12)} runs: ${cmd}${mode}   needs service:${entry}`);
    }
    break;
  }

  case "commands": {
    const [action, name] = rest;
    const declared = stored.commands ?? {};

    if (action === "add") {
      const line = rest.slice(2).join(" ").trim();
      if (!name || !line) fail('usage: hail commands add <name> "<command line>"');
      if (!/^[a-z0-9][a-z0-9-]*$/i.test(name)) fail("a command name is letters, digits and dashes");
      // The operator writes the whole line, and a caller only ever names it.
      // Nothing a peer sends is interpolated into it — a command that must vary
      // is two declared commands, because validating a caller's value is the
      // defence this project has refused twice already.
      stored.commands = { ...declared, [name]: line };
      persist();
      log(`command ${name} runs: ${line}`);
      log(`peers need command:${name}; no profile grants it yet`);
      log(`this runs as ${process.env.USER ?? "this user"} — declare only what you mean`);
      break;
    }

    if (action === "remove") {
      if (!name) fail("usage: hail commands remove <name>");
      const { [name]: _gone, ...rest2 } = declared;
      stored.commands = rest2;
      persist();
      log(`command ${name} removed`);
      break;
    }

    const names = Object.keys(declared);
    if (names.length === 0) {
      log('no commands declared. hail commands add <name> "<command line>"');
      break;
    }
    for (const entry of names) log(`  ${entry.padEnd(12)} runs: ${declared[entry]}   needs command:${entry}`);
    break;
  }

  case "tunnels": {
    const [action, name, address] = rest;
    const tunnels = stored.tunnels ?? {};

    if (action === "add") {
      if (!name || !address) fail("usage: hail tunnels add <name> <host:port>");
      if (!/^[a-z0-9][a-z0-9-]*$/i.test(name)) fail("a tunnel name is letters, digits and dashes");
      // Written down here, and named by callers. A peer says `acp`; it never
      // says an address, or this is a port forward into whatever trusts
      // localhost for the reason that nothing remote should reach it.
      stored.tunnels = { ...tunnels, [name]: address };
      persist();
      log(`tunnel ${name} -> ${address}`);
      log(`peers need the ${`tunnel:${name}`} capability; no profile grants it yet`);
      break;
    }

    if (action === "remove") {
      if (!name) fail("usage: hail tunnels remove <name>");
      const { [name]: _gone, ...rest2 } = tunnels;
      stored.tunnels = rest2;
      persist();
      log(`tunnel ${name} removed`);
      break;
    }

    const names = Object.keys(tunnels);
    if (names.length === 0) {
      log("no tunnels declared. hail tunnels add <name> <host:port>");
      break;
    }
    for (const entry of names) log(`  ${entry.padEnd(12)} -> ${tunnels[entry]}   needs tunnel:${entry}`);
    break;
  }

  case "plugins": {
    const [action, specifier] = rest;
    if (action === "add" || action === "remove") {
      if (!specifier) fail(`usage: hail plugins ${action} <module>`);
      const current = stored.plugins ?? [];
      stored.plugins =
        action === "add"
          ? [...new Set([...current, specifier])]
          : current.filter((entry) => entry !== specifier);
      persist();
      log(`${action === "add" ? "added" : "removed"} ${specifier}`);
      break;
    }

    const configured = stored.plugins ?? [];
    if (configured.length === 0) {
      log("no plugins configured.  hail plugins add <module>");
      break;
    }
    // Loaded to report them, so what is listed is what would actually run.
    for (const plugin of await loadPlugins(configured, { log: () => {} })) {
      const routes = (plugin.routes ?? []).map((r) => `${r.method} ${r.path} [${r.capability}]`);
      log(`${plugin.name.padEnd(12)} ${plugin.description ?? ""}`);
      for (const route of routes) log(`  ${route}`);
    }
    break;
  }

  case "gate": {
    // A password door in front of a local web app — a bastion for serving
    // something like T3 to a browser without exposing it directly. Not a plugin
    // (a browser holds no key to authenticate as a peer); its own door, in
    // src/gate.js. See docs/gate.md.
    const [action] = rest;

    if (action === "set-password") {
      const pw = await readPassword("New gate password: ");
      if (!pw) fail("no password given");
      // Rotate the cookie-signing secret by default, which invalidates every live
      // session: a password change usually means the old one may be compromised,
      // and a stateless token minted under the old secret would otherwise keep
      // working until it expired. `--keep-sessions` makes survival the opt-in.
      const keepSessions = flags["keep-sessions"] === true;
      const secret = keepSessions && stored.gate?.secret ? stored.gate.secret : newSecret();
      stored.gate = { passwordHash: hashPassword(pw), secret };
      persist();
      log("gate password set (stored hashed, never in the clear).");
      log(keepSessions ? "existing sessions kept (--keep-sessions)." : "all existing sessions were revoked.");
      log("serve it with:  hail gate serve --target http://127.0.0.1:<app-port> --port <n>");
      break;
    }

    if (action === "serve") {
      const target = typeof flags.target === "string" ? flags.target : null;
      if (!target) fail("usage: hail gate serve --target http://127.0.0.1:<app-port> [--port N] [--host H] [--tls-cert C --tls-key K]");
      let targetUrl;
      try {
        // Validate early with a clear message rather than an opaque throw later.
        targetUrl = new URL(target);
      } catch {
        fail(`--target is not a URL: ${target}`);
      }
      if (!stored.gate?.passwordHash) fail("no gate password set — run: hail gate set-password");

      // The intended target is a local app. A non-local one is allowed (an
      // operator may front an internal service on another host — the tunnel's
      // "operator declares" trust), but say so out loud: an authenticated proxy
      // to a remote host is a bigger thing than a bastion for a local port.
      const targetHost = targetUrl.hostname;
      const localTarget = /^(127\.|::1$|\[::1\]$|localhost$|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(targetHost);
      if (!localTarget) log(`[gate] note: --target ${targetHost} is not local — this gates an authenticated proxy to a remote host`);

      const gate = createGate({
        target,
        passwordHash: stored.gate.passwordHash,
        secret: stored.gate.secret,
        trustForwarded: flags["trust-forwarded"] === true,
        log,
      });

      // Provided (Let's Encrypt) cert for a clean browser load, else the
      // identity's self-signed one — which works but warns, since a browser
      // cannot pin the way a peer does.
      const providedCert = typeof flags["tls-cert"] === "string" ? readFileSync(flags["tls-cert"], "utf8") : undefined;
      const providedKey = typeof flags["tls-key"] === "string" ? readFileSync(flags["tls-key"], "utf8") : undefined;
      const tlsOptions = providedCert && providedKey ? { cert: providedCert, key: providedKey } : selfSignedCert(identity);

      const server = createHttpsServer(tlsOptions, gate.onRequest);
      server.on("upgrade", gate.onUpgrade);
      const host = typeof flags.host === "string" ? flags.host : "127.0.0.1";
      const gatePort = typeof flags.port === "string" && /^\d+$/.test(flags.port) ? Number(flags.port) : 8443;
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(gatePort, host, () => resolve(undefined));
      });
      const bound = /** @type {import("node:net").AddressInfo} */ (server.address());
      log(`[gate] ${target} is now behind a password at https://${host}:${bound.port}`);
      if (!providedCert) {
        log("[gate] using a self-signed cert — a browser will warn. For a clean load pass --tls-cert/--tls-key");
        log("[gate] (e.g. a Let's Encrypt cert fronted by `tailscale serve`).");
      }
      const stop = () => server.close(() => process.exit(0));
      process.on("SIGINT", stop);
      process.on("SIGTERM", stop);
      break;
    }

    log(
      stored.gate?.passwordHash
        ? "gate password is set. Serve it with: hail gate serve --target http://127.0.0.1:<app-port> --port <n>"
        : "no gate password set. Run: hail gate set-password",
    );
    break;
  }

  case "profiles": {
    const [action, target] = rest;
    if (action === "add") {
      if (!target) fail("usage: hail profiles add <name> --allows hail,directory");
      const allows = typeof flags.allows === "string" ? flags.allows.split(",").map((c) => c.trim()) : [];
      if (allows.length === 0) fail("a profile that grants nothing is `known`; use --allows");
      try {
        stored.profiles = setProfile(stored.profiles ?? {}, target, {
          allows,
          ...(typeof flags.description === "string" ? { description: flags.description } : {}),
        });
      } catch (error) {
        fail(String(error instanceof Error ? error.message : error));
      }
      directory.useProfiles({ ...collectProfiles([hailPlugin]), ...stored.profiles });
      persist();
      log(`profile ${target} grants ${allows.join(", ")}`);
      break;
    }
    if (action === "remove") {
      if (!target) fail("usage: hail profiles remove <name>");
      stored.profiles = removeProfile(stored.profiles ?? {}, target);
      persist();
      log(`profile ${target} removed; peers holding it fall back to the default`);
      break;
    }
    if (action === "reject") {
      const [, name, style] = rest;
      if (!name || (style !== "deny" && style !== "drop")) {
        fail("usage: hail profiles reject <name> deny|drop");
      }
      stored.profiles = setRejection(stored.profiles ?? {}, name, style);
      persist();
      log(
        style === "drop"
          ? `${name} peers are now closed on without a reply`
          : `${name} peers are now told they were denied`,
      );
      break;
    }

    if (action === "pin" || action === "unpin") {
      if (!target) fail(`usage: hail profiles ${action} <name>`);
      stored.profiles = setPinned(stored.profiles ?? {}, target, action === "pin");
      persist();
      log(`${target} is ${action === "pin" ? "pinned to the top" : "unpinned"}`);
      break;
    }

    for (const profile of listProfiles(stored.profiles)) {
      const mark = profile.pinned ? "*" : " ";
      const reject = (profile.onReject ?? "deny") === "drop" ? "drop" : "deny";
      log(
        `${mark} ${profile.name.padEnd(10)} ${(profile.allows.join(", ") || "nothing").padEnd(22)} ${reject.padEnd(5)} ${profile.description}`,
      );
    }
    log("\n  * offered first.  hail profiles pin|unpin <name>");
    log("  deny|drop is how a refused peer is answered.  hail profiles reject <name> deny|drop");
    break;
  }

  default:
    log(
      [
        "hail — peer presence and discovery",
        "",
        "  hail status                  what this machine is, and who it knows",
        "  hail peers                   admitted peers, and candidates heard of",
        "  hail add <name> [address]    admit a peer  (--transport lan|tailscale|... --profile trusted --key <pem>)",
        "    ... --until 7d | <date>    raise its profile for a while, then fall back",
        "  hail name <name>             set this machine's name",
        "  hail id                      print this machine's public key",
        "  hail tunnels [add|remove]    endpoints a peer may reach, by name",
        "  hail commands [add|remove]   commands a peer may run, by name",
        "  hail services [add|remove]   long-running processes a peer may start",
        "  hail shells [add|remove]     an interactive shell a peer may open (remote shell access)",
        "  hail gate set-password       gate a local web app behind a password, for a browser",
        "  hail gate serve --target U   serve that app over TLS at --port N (a bastion for e.g. T3)",
        "  hail shell <peer> <name> ...  drive a shell on a peer (open|send|poll|close|exec)",
        "  hail plugins [add|remove M]  services this machine offers beyond the core",
        "  hail profiles                what each profile grants, and how it refuses",
        "    ... add <name> --allows a,b   define one",
        "    ... remove <name>          and remove it",
        "    ... pin|unpin <name>       change which profile is offered first",
        "    ... reject <name> deny|drop  answer a refused peer, or close on it",
        "  hail rotate <name> --key-file F  replace the key held for a peer",
        "  hail forget <name>           remove a peer, admitted or not",
        "  hail block|unblock <name>    deny a peer everything, by key where we hold one",
        "  hail trust [model]           how peers you have not assigned are treated",
        "  hail walk                    ask known peers who else they know",
        "  hail daemon [--port N]       answer hails from other machines",
        "    ... --ui                   also serve the page (off by default; it is the only",
        "                                  reason a browser can reach this daemon at all)",
        "    ... --hail-on wlan0,tailscale0  answer hails there too; the page stays local",
        "    ... --hail-on-encrypted tailscale0  hails on an interface whose arrival is encrypted (serves shells)",
        "    ... --hail-on-tls eth0        hails over pinned TLS on a LAN interface (serves shells, no assertion)",
        "    ... --tls-cert C --tls-key K  serve a provided (Let's Encrypt) cert on --hail-on-tls, for browsers/CA clients",
        "    ... --require-target-binding  refuse any hail that does not name its target (fully-closed; once every peer sends `to`)",
        "    ... --chat                 accept short messages from peers holding `chat`",
        "    ... --allow-origin URL    let another page use the local API (off by default)",
        "    ... --debug [minutes]      open a diagnostics window that closes itself",
        "",
        "  --state <path>               use a different directory file",
      ].join("\n"),
    );
}
