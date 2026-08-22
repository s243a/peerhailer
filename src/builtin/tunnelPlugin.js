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

import { REFUSE } from "../plugins.js";

/** Read from a socket without waiting: what has arrived by now, or nothing. */
const MAX_BUFFERED = 1024 * 1024;

/** A tunnel nobody has touched in this long is somebody's forgotten window. */
export const IDLE_MS = 5 * 60_000;

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
 * }} [options]
 */
export function createTunnelPlugin({ endpoints = {}, now = Date.now, connectImpl = connect } = {}) {
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
    return tunnel.peerKey && caller?.publicKey === tunnel.peerKey ? tunnel : null;
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
