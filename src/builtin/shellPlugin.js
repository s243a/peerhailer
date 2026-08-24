/**
 * A shell a peer can open on this machine.
 *
 * Say it plainly: this is remote shell access — SSH, reached through the peer
 * fabric instead of `sshd`. Every other plugin holds a rule this one cannot —
 * *nothing a caller sends reaches a shell* — because this plugin's whole purpose
 * is to let a peer type what runs. So it does not reuse that safety argument; it
 * stands on the ones below.
 *
 * The gate is the capability, not a filter on the bytes. This project learned
 * twice — for shell strings, for URLs — that you cannot decide safety by parsing
 * what a shell will do; a plugin that allowed `ls` and blocked `rm` is one
 * `ls; rm -rf ~` from being wrong and, worse, *implies* a safety it cannot give.
 * So this screens nothing. If you do not trust a peer with an unfiltered shell,
 * do not grant `shell:<name>` — grant a `command:` for the specific thing.
 *
 * Two ways to *restrict* a shell, and both compose without this plugin knowing:
 *
 *   - **Declare a sandboxed shell.** The operator writes the command, so the
 *     command can be the sandbox: `firejail --net=none bash`, `bwrap …`,
 *     `unshare -Urn bash`, a container, or on Termux the Android app sandbox.
 *     Restriction is the operator's choice of what to declare, not machinery here.
 *   - **A supervisor.** Optional, not required. The `send` handler is the single
 *     choke point for input, so a reviewer could sit there — the seam is noted
 *     where it would attach. It is a nice-to-have, not a precondition.
 *
 * What this plugin *does* own, whatever is declared: the capability gate, a
 * scrubbed spawn environment (so even a bare shell reaches no control port and
 * no auth material — allowlist, not denylist, so nothing leaks by omission), the
 * bounds (one session per peer, idle when no bytes flow either way, a max
 * lifetime, a session cap), a recorded session *existence* (who and when and how
 * long — never the bytes, which a PTY makes unauditable anyway), and a
 * process-group teardown that leaves nothing stranded.
 *
 * Transport is the tunnel's, deliberately: open / send / poll / close, bytes
 * base64 over the same request-shaped carrier, so a shell is one more thing the
 * existing client already knows how to drive. This first cut pipes stdio (no
 * PTY); a real terminal is a stdio swap on-device, the route surface unchanged.
 *
 * **A mutual arrival is non-negotiable** and is the listener's to enforce: the
 * shell is served only where the caller's identity is bound to the socket —
 * mutual TLS, or a trusted-local (loopback) arrival — never on a merely-
 * encrypted-but-unbound door (a provided-cert listener a browser reaches, or a
 * tailnet address bound directly), where a captured hail could replay. The
 * marker `requiresEncryptedArrival: "mutual"` says so to a host that honours it.
 *
 * @module builtin/shellPlugin
 */
import { spawn } from "node:child_process";

import { sameKey } from "../identity.js";
import { REFUSE } from "../plugins.js";

/** One session per peer by default — a shell is the strongest grant here. */
export const MAX_PER_PEER = 1;

/** How many shells may run at once across all peers — each a process tree. */
export const MAX_SHELLS = 8;

/** No bytes either way for this long is an abandoned prompt; close it. */
export const IDLE_MS = 10 * 60_000;

/** A shell never lives past this, busy or not — a backstop on a forgotten one. */
export const MAX_LIFETIME_MS = 4 * 60 * 60_000;

/** As much unread output as a session will hold before it is a memory leak. */
export const MAX_BUFFERED = 1024 * 1024;

/**
 * The environment a shell inherits: an *allowlist* of benign variables, so no
 * control-port address and no auth material this daemon holds can leak into a
 * process a peer types into. Denylists miss the next secret added; an allowlist
 * cannot. An operator who needs more sets it in the declared command itself.
 *
 * `PREFIX` is here for Termux, where it names the install root
 * (`/data/data/com.termux/files/usr`) and countless scripts read it; without it
 * a Termux shell comes back with an empty `$PREFIX` and those scripts break. It
 * is a plain path, not a loader directive like `LD_PRELOAD` — nothing in libc
 * interprets it — and its value comes from this daemon's own environment, never
 * the caller, so it needs no value check beyond being on the list.
 */
export const SAFE_ENV_KEYS = ["PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "TERM", "TMPDIR", "TZ", "COLUMNS", "LINES", "PREFIX"];

/**
 * @param {NodeJS.ProcessEnv} source
 * @returns {Record<string, string>}
 */
export function scrubEnv(source) {
  /** @type {Record<string, string>} */
  const env = {};
  for (const key of SAFE_ENV_KEYS) {
    if (typeof source[key] === "string") env[key] = String(source[key]);
  }
  // Locale category vars (LC_ALL, LC_CTYPE, …) are benign and make a terminal
  // usable; pass them through, still by an allowlist prefix rather than wholesale.
  for (const [key, value] of Object.entries(source)) {
    if (key.startsWith("LC_") && typeof value === "string") env[key] = value;
  }
  // Termux (Android) execs every binary through a shim it carries in
  // LD_PRELOAD; strip it and `shell: true` — which goes through /bin/sh, then
  // execve — cannot even start the shell (exit 126, "Permission denied"), so a
  // session opens and dies at once. Preserve *only* that shim, matched by name,
  // so this stays an allowlist and never becomes a way to preload an arbitrary
  // .so into a shell a peer typed into. LD_PRELOAD is empty off Termux.
  if (typeof source.LD_PRELOAD === "string" && /(^|\/)libtermux-exec\.so$/.test(source.LD_PRELOAD)) {
    env.LD_PRELOAD = source.LD_PRELOAD;
  }
  return env;
}

/**
 * The capability a named shell requires. Per-name, like the rest of the family,
 * so an operator can declare a bare shell and a sandboxed one as separate
 * grants — and never under the tunnel namespace: a person granting this must see
 * "a shell", not "one more endpoint".
 *
 * @param {string} name
 */
export function capabilityFor(name) {
  return `shell:${name}`;
}

/**
 * @param {{
 *   shells?: Record<string, string>,
 *   now?: () => number,
 *   spawnImpl?: typeof spawn,
 *   spawnEnv?: Record<string, string>,
 *   sweepMs?: number,
 * }} [options]
 */
export function createShellPlugin({
  shells = {},
  now = Date.now,
  spawnImpl = spawn,
  spawnEnv = scrubEnv(process.env),
  sweepMs = 30_000,
} = {}) {
  /**
   * id -> an open shell session.
   * @type {Map<string, {name: string, peerKey: string, child: any, chunks: Buffer[],
   *   buffered: number, closed: boolean, error: string | null, openedAt: number,
   *   lastByte: number}>}
   */
  const open = new Map();

  /**
   * That a session happened — who, when, how long — kept for a person to read.
   * Not the bytes: a PTY stream is not an audit trail, and pretending a byte log
   * is one is the failure this deliberately avoids.
   * @type {{name: string, peerKey: string, at: number, event: string, ms?: number}[]}
   */
  const log = [];

  /** @param {any} entry */
  const record = (entry) => {
    log.push({ ...entry, at: now() });
    while (log.length > 200) log.shift();
  };

  /** @param {{child: any}} session */
  const kill = (session) => {
    try {
      // The group, not the shell alone — a session is one `&` from leaving
      // grandchildren behind. Verified on Termux that the group signal reaches
      // the whole tree.
      if (session.child?.pid) process.kill(-session.child.pid, "SIGKILL");
      else session.child?.kill?.("SIGKILL");
    } catch {
      session.child?.kill?.("SIGKILL");
    }
  };

  /** @param {string} id @param {any} session @param {string} event */
  const forget = (id, session, event) => {
    if (open.get(id) !== session) return;
    open.delete(id);
    // Idempotent record: the overflow path records the real reason before the
    // kill's `exit` event would log a plain "closed: exited" over it, so guard
    // against the second write rather than losing why the session ended.
    if (!session.recorded) {
      session.recorded = true;
      record({ name: session.name, peerKey: session.peerKey, event, ms: now() - session.openedAt });
    }
  };

  const reap = () => {
    for (const [id, session] of open) {
      // Idle means *no bytes either way*, not "the peer stopped polling": a long
      // build that prints output nobody typed at is alive, and a peer keeping an
      // abandoned prompt warm with empty polls is not. Plus a hard lifetime cap.
      const idle = now() - session.lastByte > IDLE_MS;
      const old = now() - session.openedAt > MAX_LIFETIME_MS;
      if (idle || old) {
        kill(session);
        forget(id, session, old ? "closed: max lifetime" : "closed: idle");
      }
    }
  };

  // On a timer as well as on open, so an abandoned prompt does not wait for the
  // next open to be noticed. Unref'd — never holds the process alive.
  const sweep = setInterval(reap, sweepMs);
  sweep.unref?.();

  /**
   * The session this caller is asking about, if it is theirs. By key, never
   * `===`: a PEM carries whitespace, so a key can compare unequal to itself and
   * lock its owner out — `sameKey` is why that does not happen.
   * @param {unknown} id @param {any} caller
   */
  const ownedBy = (id, caller) => {
    const session = open.get(String(id ?? ""));
    if (!session) return null;
    return session.peerKey && sameKey(caller?.publicKey, session.peerKey) ? session : null;
  };

  /** @param {any} session */
  const drain = (session) => {
    const data = Buffer.concat(session.chunks).toString("base64");
    session.chunks = [];
    session.buffered = 0;
    return data;
  };

  return {
    name: "shell",
    description: "Opens an interactive shell the operator declared, for peers holding its capability. Remote shell access — grant it as such.",
    capabilities: Object.keys(shells).map(capabilityFor),
    // A host that honours this serves these routes only where arrival is
    // encrypted. Stated as data so it need not be re-derived from prose.
    requiresEncryptedArrival: "mutual",

    /** For a host that discards the plugin without ending the process. */
    stop: () => {
      clearInterval(sweep);
      for (const session of open.values()) kill(session);
      open.clear();
    },

    /** What sessions have run — host-only, no route exposes it. */
    history: () => log.map((entry) => ({ ...entry })),
    listOpen: () =>
      [...open.values()].map((s) => ({ name: s.name, peerKey: s.peerKey, openedAt: s.openedAt })),

    routes: Object.entries(shells).flatMap(([name, command]) => {
      const capability = capabilityFor(name);
      return [
        {
          method: "POST",
          path: `/shell/${name}/open`,
          capability,
          /** @param {any} input */
          handler: ({ caller, log: hostLog }) => {
            reap();
            if (!caller?.publicKey) return { [REFUSE]: true, reason: "no key to own a shell" };

            if (open.size >= MAX_SHELLS) {
              return { [REFUSE]: true, reason: "this machine is holding as many shells as it will" };
            }
            const mine = [...open.values()].filter((s) => sameKey(s.peerKey, caller.publicKey));
            if (mine.length >= MAX_PER_PEER) {
              return { [REFUSE]: true, reason: "you already hold a shell on this machine" };
            }

            const id = `${name}-${now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
            // Detached so the child leads its own group and the whole tree is
            // killable. `shell: true` because the operator wrote the line and may
            // want a pipe or a sandbox wrapper. The env is scrubbed to an
            // allowlist — the one non-negotiable that keeps even a bare shell
            // from reaching the control port or this daemon's secrets.
            const child = spawnImpl(command, {
              shell: true,
              detached: true,
              env: spawnEnv,
              stdio: ["pipe", "pipe", "pipe"],
            });
            /** @type {any} */
            const session = {
              name,
              peerKey: caller.publicKey,
              child,
              chunks: [],
              buffered: 0,
              closed: false,
              error: null,
              recorded: false,
              openedAt: now(),
              lastByte: now(),
            };

            // stdout and stderr merge into one stream, as a terminal shows them.
            // Any output is a byte in one direction — it keeps the session live
            // and is what `poll` drains.
            const onOutput = (/** @type {Buffer} */ chunk) => {
              if (session.buffered + chunk.length > MAX_BUFFERED) {
                session.error = "the shell produced more output than the session will hold";
                session.closed = true;
                // Record the real reason now — the kill below fires `exit`,
                // whose `forget` would otherwise log this as "closed: exited"
                // and lose why. `recorded` makes that second write a no-op.
                session.recorded = true;
                record({ name, peerKey: session.peerKey, event: "closed: output limit", ms: now() - session.openedAt });
                kill(session);
                return;
              }
              session.chunks.push(chunk);
              session.buffered += chunk.length;
              session.lastByte = now();
            };
            child.stdout?.on("data", onOutput);
            child.stderr?.on("data", onOutput);
            child.on("exit", () => {
              session.closed = true;
              forget(id, session, "closed: exited");
            });
            child.on("error", () => {
              session.error = "the shell failed to start";
              session.closed = true;
              forget(id, session, "closed: failed to start");
            });

            open.set(id, session);
            record({ name, peerKey: caller.publicKey, event: "opened" });
            hostLog(`[shell] ${caller.name} opened ${name}`);
            return { id, name };
          },
        },
        {
          method: "POST",
          path: `/shell/${name}/send`,
          capability,
          /** @param {any} input */
          handler: ({ body, caller }) => {
            const session = ownedBy(body?.id, caller);
            if (!session) return { [REFUSE]: true, reason: "not your shell" };
            if (session.closed) return { closed: true, ...(session.error ? { error: session.error } : {}) };

            // The single choke point for input — where an optional supervisor
            // would review keystrokes before they reach the shell. Input bytes
            // count as activity, so typing keeps a session alive.
            if (typeof body?.data === "string" && body.data) {
              session.child.stdin?.write(Buffer.from(body.data, "base64"));
              session.lastByte = now();
            }
            return { sent: true };
          },
        },
        {
          method: "POST",
          path: `/shell/${name}/poll`,
          capability,
          /** @param {any} input */
          handler: ({ body, caller }) => {
            const session = ownedBy(body?.id, caller);
            if (!session) return { [REFUSE]: true, reason: "not your shell" };
            // A poll is not activity: draining output the shell already produced
            // must not, by itself, keep an idle session from being reaped.
            return {
              data: drain(session),
              closed: session.closed,
              ...(session.error ? { error: session.error } : {}),
            };
          },
        },
        {
          method: "POST",
          path: `/shell/${name}/close`,
          capability,
          /** @param {any} input */
          handler: ({ body, caller }) => {
            const session = ownedBy(body?.id, caller);
            if (!session) return { [REFUSE]: true, reason: "not your shell" };
            kill(session);
            forget(String(body.id), session, "closed");
            return { closed: true };
          },
        },
      ];
    }),
  };
}
