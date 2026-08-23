/**
 * Starting a long-running process the operator wrote down.
 *
 * The third plugin shape, after tunnels and commands. A tunnel connects to
 * something already listening; a command runs and finishes. Neither can start a
 * thing that *keeps running* — which is what spawning `bridge --listen` on a
 * machine, so a peer can drive an agent there, requires.
 *
 * The rule is the tunnel's and the command's, a third time: **the operator
 * declares the service; the caller names it.** A peer asks to start `agent` and
 * gets whatever `agent` was declared to be. It cannot pass a different command,
 * choose the agent, or supply arguments.
 *
 * `{port}` is the one substitution, and the *machine* chooses it — an integer it
 * allocated, never a value from the caller — so this is not a way to make the
 * service bind where the caller wants. The caller receives the chosen port; it
 * does not send one.
 *
 * A started service is a local listener and nothing more until a tunnel carries
 * bytes to it. This plugin starts and bounds and reaps; reaching the port is a
 * separate tunnel capability, by design — `service:agent` starts it, a tunnel
 * capability reaches it, rather than folding a byte-carrier in here.
 *
 * This is the top of the capability ladder: a declared service can be an agent
 * that runs arbitrary commands, so `service:<name>` is its own capability in no
 * built-in profile, and everything below is about not leaking or leaving one
 * running.
 *
 * @module builtin/servicePlugin
 */
import { createServer } from "node:net";
import { spawn } from "node:child_process";

import { sameKey } from "../identity.js";
import { REFUSE } from "../plugins.js";

/** How many services may run at once, in total and per peer — each a process. */
export const MAX_SERVICES = 16;
export const MAX_PER_PEER = 4;

/** A service nobody has touched in this long is one its peer walked away from. */
export const IDLE_MS = 30 * 60_000;

/** A service never lives past this, touched or not — a backstop on a leak. */
export const MAX_LIFETIME_MS = 12 * 60 * 60_000;

/**
 * The capability a declared service requires.
 *
 * @param {string} name
 */
export function capabilityFor(name) {
  return `service:${name}`;
}

/** A free loopback port, chosen by the OS and released for the child to take. */
function allocatePort() {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const address = /** @type {import("node:net").AddressInfo} */ (probe.address());
      const port = address.port;
      probe.close(() => resolve(port));
    });
  });
}

/**
 * @param {{
 *   services?: Record<string, string>,
 *   now?: () => number,
 *   spawnImpl?: typeof spawn,
 *   allocatePortImpl?: () => Promise<number>,
 *   sweepMs?: number,
 * }} [options]
 */
export function createServicePlugin({
  services = {},
  now = Date.now,
  spawnImpl = spawn,
  allocatePortImpl = allocatePort,
  sweepMs = 30_000,
} = {}) {
  /**
   * id -> a running service.
   * @type {Map<string, {name: string, peerKey: string, port: number, child: any,
   *   startedAt: number, touched: number}>}
   */
  const running = new Map();

  /**
   * What was started, kept for a person to read — a process spawned on a peer's
   * say-so while nobody watched is exactly what an operator wants afterwards.
   * @type {{name: string, peerKey: string, port: number, at: number, event: string}[]}
   */
  const log = [];

  /** @param {any} entry */
  const record = (entry) => {
    log.push({ ...entry, at: now() });
    while (log.length > 200) log.shift();
  };

  /** @param {{child: any}} service */
  const kill = (service) => {
    try {
      // The group, not just the shell — a declared line is one `&` from leaving
      // grandchildren behind, and killing the shell alone strands them. Reached
      // only for entries still in `running`, and the exit handler removes dead
      // children — so the racy path (child dies, pid recycled, we signal a fresh
      // group on the same number) is a milliseconds-wide window that also needs
      // the whole group gone and a new one to land on that exact number. Accepted
      // rather than engineered against; the on-device Termux test confirmed the
      // group-kill mechanism itself is sound.
      if (service.child?.pid) process.kill(-service.child.pid, "SIGKILL");
      else service.child?.kill?.("SIGKILL");
    } catch {
      service.child?.kill?.("SIGKILL");
    }
  };

  /** @param {string} [reason] */
  const reap = (reason) => {
    for (const [id, service] of running) {
      const idle = now() - service.touched > IDLE_MS;
      const old = now() - service.startedAt > MAX_LIFETIME_MS;
      if (idle || old) {
        kill(service);
        running.delete(id);
        record({ name: service.name, peerKey: service.peerKey, port: service.port, event: reason ?? (old ? "reaped: max lifetime" : "reaped: idle") });
      }
    }
  };

  // On a timer as well as on start, so a service whose peer vanished does not
  // wait for the next start to be noticed. Unref'd — never holds a process open.
  const sweep = setInterval(() => reap(), sweepMs);
  sweep.unref?.();

  /**
   * @param {unknown} id
   * @param {any} caller
   */
  const ownedBy = (id, caller) => {
    const service = running.get(String(id ?? ""));
    if (!service) return null;
    // Looked up in the global table by id, not scoped to the route's service
    // name: a peer reaching /service/a/stop can manage any service *it owns*,
    // even one it started under name `b`. That namespace crossing is deliberate.
    // The gate is ownership by key below, and stop/status on your own service
    // only ever reduces what runs — so it cannot widen access even if the grant
    // for `b` has since lapsed. You may always reap what you spawned.
    //
    // By key, never `===`: a PEM tolerates whitespace, so a key can be unequal
    // to itself and lock its owner out. `sameKey` is why that does not happen.
    return service.peerKey && sameKey(caller?.publicKey, service.peerKey) ? service : null;
  };

  return {
    name: "service",
    description: "Starts long-running processes this machine's operator declared, for peers holding their capability.",
    capabilities: Object.keys(services).map(capabilityFor),

    /** For a host that discards the plugin without ending the process. */
    stop: () => {
      clearInterval(sweep);
      for (const service of running.values()) kill(service);
      running.clear();
    },

    /** What is running now, and what has run — host-only, no route exposes it. */
    history: () => log.map((entry) => ({ ...entry })),
    listRunning: () =>
      [...running.values()].map((s) => ({ name: s.name, port: s.port, peerKey: s.peerKey, startedAt: s.startedAt })),

    routes: Object.entries(services).map(([name, line]) => {
      const capability = capabilityFor(name);
      return [
        {
          method: "POST",
          path: `/service/${name}/start`,
          capability,
          /** @param {any} input */
          handler: async ({ caller, log: hostLog }) => {
            reap();
            if (!caller?.publicKey) return { [REFUSE]: true, reason: "no key to own a service" };

            if (running.size >= MAX_SERVICES) {
              return { [REFUSE]: true, reason: "this machine is running as many services as it will" };
            }
            const mine = [...running.values()].filter((s) => sameKey(s.peerKey, caller.publicKey));
            if (mine.length >= MAX_PER_PEER) {
              return { [REFUSE]: true, reason: "you are running as many services as you may" };
            }

            // Reserve the slot *before* the first await. The cap checks above are
            // synchronous and `allocatePort` yields the event loop, so without a
            // reservation N concurrent starts each pass the caps before any of
            // them registers — one peer clears MAX_PER_PEER in a single tick. The
            // placeholder makes `running.size` and the per-peer count honest
            // across the allocate window; port and child fill in once they exist.
            const id = `${name}-${now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
            /** @type {{name: string, peerKey: string, port: number, child: any, startedAt: number, touched: number}} */
            const service = { name, peerKey: caller.publicKey, port: 0, child: null, startedAt: now(), touched: now() };
            running.set(id, service);

            let port;
            try {
              // The machine picks the port; the caller never sends one. A real
              // allocated integer, so substituting it into the declared line
              // cannot inject — it is a number, not caller text.
              port = await allocatePortImpl();
            } catch {
              running.delete(id);
              return { [REFUSE]: true, reason: "could not allocate a port for the service" };
            }
            service.port = port;
            const command = String(line).replaceAll("{port}", String(port));

            // Detached so the child leads its own group and the whole tree can be
            // killed; the declared line goes to a shell because the operator
            // wrote it and may want a pipe — their machine, their decision.
            const child = spawnImpl(command, { shell: true, detached: true });
            service.child = child;

            // A service that dies on its own is gone from the table, not a
            // phantom the caller thinks is up. Both handlers guard on identity:
            // a late event from a child whose slot was already reused — stopped,
            // reaped, replaced — must not delete the newcomer or record a phantom
            // event against it. The `error` guard is the one round 7 review found
            // missing; without it a child erroring after `stop` wrote a spurious
            // "failed to start" into the audit log for a deliberately-stopped
            // service.
            child.on("exit", () => {
              if (running.get(id) === service) {
                running.delete(id);
                record({ name, peerKey: caller.publicKey, port, event: "exited" });
              }
            });
            child.on("error", () => {
              if (running.get(id) === service) {
                running.delete(id);
                record({ name, peerKey: caller.publicKey, port, event: "failed to start" });
              }
            });

            record({ name, peerKey: caller.publicKey, port, event: "started" });
            hostLog(`[service] ${caller.name} started ${name} on port ${port}`);
            // The port is where the child was *told* to bind and what a caller
            // tunnels to — this machine's loopback port. It is a claim, not a
            // fact: `allocatePort` frees the port before the child takes it, so a
            // response carrying a port says the child was asked to bind it, not
            // that it did, and `status` reports the service running, not what is
            // listening. On a shared box a foreign process can win the freed port
            // in that window, leaving the caller's tunnel pointed at it. Closing
            // the gap needs the child to report its own bound port back — see
            // docs/services.md; until then the port is a routing hint, not proof.
            return { id, name, port };
          },
        },
        {
          method: "POST",
          path: `/service/${name}/stop`,
          capability,
          /** @param {any} input */
          handler: ({ body, caller }) => {
            const service = ownedBy(body?.id, caller);
            if (!service) return { [REFUSE]: true, reason: "not your service" };
            kill(service);
            running.delete(String(body.id));
            record({ name: service.name, peerKey: service.peerKey, port: service.port, event: "stopped" });
            return { stopped: true };
          },
        },
        {
          method: "POST",
          path: `/service/${name}/status`,
          capability,
          /** @param {any} input */
          handler: ({ body, caller }) => {
            const service = ownedBy(body?.id, caller);
            if (!service) return { [REFUSE]: true, reason: "not your service" };
            // Polling status is how a caller says "still using it" — the same
            // touch model tunnels use, so an active service is not reaped.
            service.touched = now();
            return { running: true, name: service.name, port: service.port, startedAt: service.startedAt };
          },
        },
      ];
    }).flat(),
  };
}
