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
 *   hail daemon [--port N]         answer hails from other machines
 */
import { createDirectory } from "../src/directory.js";
import { walk } from "../src/hail.js";
import { createDaemon } from "../src/server.js";
import { defaultStatePath, loadState, saveState } from "../src/state.js";

const log = (message) => process.stdout.write(`${message}\n`);
const fail = (message) => {
  process.stderr.write(`hail: ${message}\n`);
  process.exit(1);
};

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i].startsWith("--")) {
      const key = argv[i].slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) flags[key] = true;
      else {
        flags[key] = next;
        i += 1;
      }
    } else positional.push(argv[i]);
  }
  return { positional, flags };
}

const { positional, flags } = parseArgs(process.argv.slice(2));
const [command, ...rest] = positional;
const statePath = typeof flags.state === "string" ? flags.state : defaultStatePath();
const stored = loadState(statePath, { log: (m) => process.stderr.write(`${m}\n`) });

const directory = createDirectory({
  ...stored,
  self: stored.self ?? { name: flags.name ?? "unnamed", addresses: [] },
});
const persist = () => saveState(directory.snapshot(), statePath);

const describe = (peer) => {
  const routes = peer.addresses.map((a) => `${a.transport}:${a.value}`).join(", ") || "no address";
  const seen = peer.lastSeen ? new Date(peer.lastSeen).toISOString() : "never";
  return `${peer.name.padEnd(20)} ${routes}  (last seen ${seen})`;
};

switch (command) {
  case "status": {
    log(`name:    ${directory.self.name}`);
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
    const admitted = directory.admit({
      name,
      addresses: address ? [{ transport, value: address, lastOk: null }] : [],
    });
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
    const result = await walk(directory);
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
    const daemon = createDaemon({
      directory,
      ...(typeof flags.token === "string" ? { token: flags.token } : {}),
      log,
    });
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

  default:
    log(
      [
        "hail — peer presence and discovery",
        "",
        "  hail status                  what this machine is, and who it knows",
        "  hail peers                   admitted peers, and candidates heard of",
        "  hail add <name> [address]    admit a peer  (--transport lan|tailscale|tinc|relay)",
        "  hail forget <name>           remove a peer, admitted or not",
        "  hail walk                    ask known peers who else they know",
        "  hail daemon [--port N]       answer hails from other machines",
        "",
        "  --state <path>               use a different directory file",
      ].join("\n"),
    );
}
