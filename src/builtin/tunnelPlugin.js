/**
 * Carrying bytes to a service this machine already runs.
 *
 * The fabric's job is deciding *who*. This plugin is what a peer that passed
 * that decision can actually do: open a connection to one endpoint named in
 * local configuration, push bytes at it, and read what comes back.
 *
 * It never parses what it carries. That is the point rather than a shortcut — a
 * tunnel that understood its payload would need a second one for the next
 * protocol, and a machine relaying traffic it can read has acquired knowledge,
 * and responsibility, about what crossed it.
 *
 * Three rules, and each closes a way this becomes a general-purpose door:
 *
 * **The endpoint is named, never addressed.** A caller says `acp`; it does not
 * say `127.0.0.1:9000`. An unknown name is refused. Otherwise this is a port
 * forward into services that trust localhost precisely because they assume
 * nothing remote can reach them.
 *
 * **One capability per endpoint.** `tunnel:acp` says nothing about
 * `tunnel:database`. A single "may tunnel" permission would mean granting one
 * endpoint grants every endpoint a later version adds.
 *
 * **A tunnel belongs to the peer that opened it.** Every later call is checked
 * against the same key, so knowing an id is not a way in.
 *
 * @module builtin/tunnelPlugin
 */
import { connect } from "node:net";

import { sameKey } from "../identity.js";
import { REFUSE } from "../plugins.js";

/** Read from a socket without waiting: what has arrived by now, or nothing. */
const MAX_BUFFERED = 1024 * 1024;

/**
 * A tunnel nobody has touched in this long is somebody's forgotten window.
 *
 * Measured from the *peer's* last call, not from socket activity: an endpoint
 * that streams for six minutes while nobody polls is reaped. That is the right
 * default for a request-shaped transport and a surprising one for a long-lived
 * session, which is worth knowing before the first ACP client arrives.
 */
export const IDLE_MS = 5 * 60_000;

/**
 * How many tunnels may exist at once, in total and per peer.
 *
 * Each is a real socket and a file descriptor, so without a cap one capability
 * holder can exhaust the daemon's descriptors and take down everything else it
 * does — hails included. A peer authorised to reach one endpoint must not be
 * able to deny service to the rest of the machine, and it does not take malice:
 * a client with a reconnect loop and a bug does it by accident.
 */
export const MAX_TUNNELS = 64;
export const MAX_TUNNELS_PER_PEER = 8;

/**
 * The capability a named endpoint requires.
 *
 * @param {string} name
 */
export function capabilityFor(name) {
  return `tunnel:${name}`;
}

/**
 * @param {{
 *   endpoints?: Record<string, string>,
 *   now?: () => number,
 *   connectImpl?: typeof connect,
 *   sweepMs?: number,
 *   ownPorts?: number[],
 * }} [options]
 */
export function createTunnelPlugin({
  endpoints = {},
  now = Date.now,
  connectImpl = connect,
  sweepMs = 30_000,
  ownPorts = [],
} = {}) {
  // A tunnel is a port forward, and the most dangerous target it can have is
  // this daemon's own control port: reaching it hands a remote peer the local
  // API, which trusts loopback precisely because nothing remote should reach it.
  // Refused at declaration, so a self-pointing endpoint never becomes a route.
  const reserved = new Set(ownPorts.map(Number));
  for (const [name, address] of Object.entries(endpoints)) {
    const port = Number(String(address).split(":").pop());
    if (reserved.has(port)) {
      throw new Error(
        `peerhailer: tunnel '${name}' points at this daemon's own port ${port} — that forwards the local API to peers`,
      );
    }
  }
  /** id -> {socket, chunks, closed, error, peerKey, endpoint, touched} */
  const open = new Map();

  const reap = () => {
    for (const [id, tunnel] of open) {
      if (now() - tunnel.touched > IDLE_MS) {
        tunnel.socket.destroy();
        open.delete(id);
      }
    }
  };

  // On a timer as well as on `open`. Reaping only when a new tunnel arrives
  // means a peer that opens one and vanishes holds a socket until somebody else
  // happens to connect — and an attacker keeping tunnels warm with polls makes
  // `open` reap nothing at all. Unref'd, so it never keeps a process alive.
  const sweep = setInterval(reap, sweepMs);
  sweep.unref?.();

  /**
   * The tunnel this caller is asking about, if it is theirs.
   *
   * Ownership is by key rather than by name: a name is a label, and a tunnel is
   * a live connection into a local service — the strongest thing this plugin
   * hands out, and not something to attach to the weaker identifier.
   */
  /**
   * @param {unknown} id
   * @param {any} caller
   */
  const ownedBy = (id, caller) => {
    const tunnel = open.get(String(id ?? ""));
    if (!tunnel) return null;
    // `sameKey`, never `===`. A PEM carries whitespace that is not part of the
    // key, so a key can compare unequal to itself and lock its owner out of
    // their own tunnel. This project has made that mistake before, which is why
    // the helper exists.
    return tunnel.peerKey && sameKey(caller?.publicKey, tunnel.peerKey) ? tunnel : null;
  };

  /** @param {any} tunnel */
  const drain = (tunnel) => {
    const data = Buffer.concat(tunnel.chunks).toString("base64");
    tunnel.chunks = [];
    tunnel.buffered = 0;
    return data;
  };

  return {
    name: "tunnel",
    /** For a host that discards a plugin without ending the process. */
    stop: () => {
      clearInterval(sweep);
      for (const tunnel of open.values()) tunnel.socket.destroy();
      open.clear();
    },
    description: "Carries bytes to a locally declared endpoint, for peers holding its capability.",
    capabilities: Object.keys(endpoints).map(capabilityFor),

    routes: Object.entries(endpoints).flatMap(([name, address]) => {
      const capability = capabilityFor(name);
      return [
        {
          method: "POST",
          path: `/tunnel/${name}/open`,
          capability,
          /** @param {any} input */
          handler: ({ caller, log }) => {
            reap();
            if (!caller?.publicKey) return { [REFUSE]: true, reason: "no key to own a tunnel" };

            if (open.size >= MAX_TUNNELS) {
              return { [REFUSE]: true, reason: "this machine is holding as many tunnels as it will" };
            }
            const mine = [...open.values()].filter((entry) => sameKey(entry.peerKey, caller.publicKey));
            if (mine.length >= MAX_TUNNELS_PER_PEER) {
              // Per peer as well as in total, so one peer cannot spend the whole
              // allowance and lock everyone else out of a machine they were also
              // authorised to reach.
              return { [REFUSE]: true, reason: "you are holding as many tunnels as you may" };
            }

            const [host, port] = String(address).split(":");
            const id = `${name}-${now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
            const socket = connectImpl({ host, port: Number(port) });
            /** @type {{socket: import("node:net").Socket, chunks: Buffer[], buffered: number,
             *   closed: boolean, error: string | null, peerKey: string, endpoint: string,
             *   touched: number}} */
            const tunnel = {
              socket,
              chunks: [],
              buffered: 0,
              closed: false,
              error: null,
              peerKey: caller.publicKey,
              endpoint: name,
              touched: now(),
            };

            socket.on("data", (/** @type {Buffer} */ chunk) => {
              // Bounded: a service that talks faster than the peer polls must
              // not be a way to spend this machine's memory.
              if (tunnel.buffered + chunk.length > MAX_BUFFERED) {
                tunnel.error = "endpoint produced more than the tunnel will hold";
                socket.destroy();
                return;
              }
              tunnel.chunks.push(chunk);
              tunnel.buffered += chunk.length;
            });
            socket.on("error", (error) => {
              tunnel.error = String(error?.message ?? error);
              tunnel.closed = true;
            });
            socket.on("close", () => {
              tunnel.closed = true;
            });

            open.set(id, tunnel);
            log(`[tunnel] ${caller.name} opened ${name}`);
            return { id, endpoint: name };
          },
        },
        {
          method: "POST",
          path: `/tunnel/${name}/send`,
          capability,
          /** @param {any} input */
          handler: ({ body, caller }) => {
            const tunnel = ownedBy(body?.id, caller);
            if (!tunnel) return { [REFUSE]: true, reason: "not your tunnel" };
            tunnel.touched = now();
            if (tunnel.closed) return { closed: true, ...(tunnel.error ? { error: tunnel.error } : {}) };

            if (typeof body?.data === "string" && body.data) {
              tunnel.socket.write(Buffer.from(body.data, "base64"));
            }
            return { sent: true };
          },
        },
        {
          method: "POST",
          path: `/tunnel/${name}/poll`,
          capability,
          /** @param {any} input */
          handler: ({ body, caller }) => {
            const tunnel = ownedBy(body?.id, caller);
            if (!tunnel) return { [REFUSE]: true, reason: "not your tunnel" };
            tunnel.touched = now();
            return {
              data: drain(tunnel),
              closed: tunnel.closed,
              ...(tunnel.error ? { error: tunnel.error } : {}),
            };
          },
        },
        {
          method: "POST",
          path: `/tunnel/${name}/close`,
          capability,
          /** @param {any} input */
          handler: ({ body, caller }) => {
            const tunnel = ownedBy(body?.id, caller);
            if (!tunnel) return { [REFUSE]: true, reason: "not your tunnel" };
            tunnel.socket.destroy();
            open.delete(String(body.id));
            return { closed: true };
          },
        },
      ];
    }),
  };
}
