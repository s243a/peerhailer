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
import { hostname } from "node:os";

import { createDirectory } from "../src/directory.js";
import { defaultIdentityPath, fingerprint, loadIdentity } from "../src/identity.js";
import { BUILT_IN_PROFILES } from "../src/profiles.js";
import { walk } from "../src/hail.js";
import { createDaemon } from "../src/server.js";
import { defaultStatePath, loadState, saveState } from "../src/state.js";

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
const persist = () => saveState(directory.snapshot(), statePath);

// The identity and the name have to survive the process, or every hail
// introduces a machine nobody has heard of. Written on first sight rather than
// waiting for a command that happens to save.
if (!stored.self || stored.self.name !== directory.self.name || !stored.self.publicKey) persist();

/** A key given inline, or read from a file — PEMs are easier to hand over as files. */
const publicKeyFromFlags = () => {
  if (typeof flags["key-file"] === "string") return readFileSync(flags["key-file"], "utf8").trim();
  return typeof flags.key === "string" ? flags.key : null;
};

const describe = (peer) => {
  const routes = peer.addresses.map((a) => `${a.transport}:${a.value}`).join(", ") || "no address";
  const seen = peer.lastSeen ? new Date(peer.lastSeen).toISOString() : "never";
  const profile = peer.profile ? `[${peer.profile}]` : "";
  const key = peer.publicKey ? fingerprint(peer.publicKey).slice(0, 14) : "no key";
  return `${peer.name.padEnd(16)} ${profile.padEnd(10)} ${key}  ${routes}  (last seen ${seen})`;
};

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
    const admitted = directory.admit(
      {
        name,
        addresses: address ? [{ transport, value: address, lastOk: null }] : [],
        ...(publicKeyFromFlags() ? { publicKey: publicKeyFromFlags() } : {}),
      },
      ...(typeof flags.profile === "string" ? [{ profile: flags.profile }] : []),
    );
    if (!admitted) fail("a name is required");
    persist();
    log(`admitted ${describe(admitted)}`);
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
      as: { name: directory.self.name, privateKey: identity.privateKey },
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
    const daemon = createDaemon({ directory, identity, log });
    const port = Number(flags.port ?? 8787);
    // Binding beyond loopback exposes an API that can admit peers, so it has to
    // be asked for by name rather than arrived at by default.
    const host = typeof flags.host === "string" ? flags.host : "127.0.0.1";
    await daemon.listen({ port: Number.isFinite(port) ? port : 8787, host });
    const stop = async () => {
      persist();
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

  case "profiles": {
    for (const profile of Object.values(BUILT_IN_PROFILES)) {
      log(`${profile.name.padEnd(10)} ${(profile.allows.join(", ") || "nothing").padEnd(22)} ${profile.description}`);
    }
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
        "  hail name <name>             set this machine's name",
        "  hail id                      print this machine's public key",
        "  hail profiles                what each capability profile grants",
        "  hail forget <name>           remove a peer, admitted or not",
        "  hail walk                    ask known peers who else they know",
        "  hail daemon [--port N]       answer hails from other machines",
        "",
        "  --state <path>               use a different directory file",
      ].join("\n"),
    );
}
