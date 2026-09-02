/**
 * Where the directory lives between runs.
 *
 * Plain JSON in the user's config directory. Small enough to read, edit and
 * diff by hand, which matters for a tool whose failure mode is "nothing
 * answers and I cannot tell why" — the file is the thing you look at first.
 *
 * Unreadable state yields an empty directory rather than a crash. A daemon that
 * will not start because one field went bad is a machine that has removed
 * itself from the network for a reason nobody can see.
 *
 * @module state
 */
import { mkdirSync, openSync, closeSync, fsyncSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

/** @param {NodeJS.ProcessEnv} [env] */
export function defaultStatePath(env = process.env) {
  const base =
    env.PEERHAILER_HOME ??
    env.XDG_CONFIG_HOME ??
    // Windows keeps per-user application data in APPDATA; a dotted directory in
    // the profile root works but is not where anything else on that system
    // looks, which matters when somebody has to find this file to fix it.
    env.APPDATA ??
    join(env.HOME ?? env.USERPROFILE ?? homedir(), ".config");
  return join(base, "peerhailer", "directory.json");
}

/**
 * Sidecar files beside the directory, for the daemon's durable *runtime* state — the routed
 * replay reservations and Tier-1 key store. Kept out of `directory.json` deliberately: they
 * are daemon-owned (the CLI never writes them — it reaches Tier-1 through the control API), so
 * they need no cross-writer lock, and the replay guard's write-per-delivery must not contend
 * with the directory lock the CLI and page share.
 * @param {string} name
 * @param {string} [statePath]
 */
export function sidecarPath(name, statePath = defaultStatePath()) {
  return join(dirname(statePath), name);
}

/**
 * @param {string} [path]
 * @param {{log?: (message: string) => void}} [options]
 * @returns {any}
 */
export function loadState(path = defaultStatePath(), { log = () => {} } = {}) {
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    // A state file must be a JSON object; anything else (a literal `null`, an array, a
    // scalar — from corruption or a hand-edit) is treated as absent, so a caller's
    // `state.field` access cannot throw. A daemon that will not start over a bad file is a
    // machine that has removed itself from the network for a reason nobody can see.
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch (cause) {
    const code = /** @type {NodeJS.ErrnoException} */ (cause)?.code;
    if (code !== "ENOENT") {
      log(`[state] ignoring unreadable ${path}: ${cause instanceof Error ? cause.message : String(cause)}`);
    }
    return {};
  }
}

/**
 * Write through a temporary file, then rename.
 *
 * A directory truncated by a crash mid-write is a machine that has quietly
 * forgotten every peer it knew; rename is atomic on the platforms this runs on.
 *
 * With `durable`, the write also survives *power loss* and is not reordered
 * against a later write: the temp file's contents are `fsync`'d before the
 * rename, and the parent directory is `fsync`'d after (best-effort — directory
 * fsync is unsupported on some platforms/filesystems, e.g. Windows, so it
 * degrades silently there). Reserved for the rare key-RESTRICTING writes (a
 * conflict void, a forget's startup reconcile) where a lost or reordered write
 * could resurrect a revoked key; the best-effort adding hot path never asks for
 * it (the extra fsyncs are not free).
 *
 * @param {unknown} state
 * @param {string} [path]
 * @param {{durable?: boolean}} [options]
 */
export function saveState(state, path = defaultStatePath(), { durable = false } = {}) {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}`;
  const body = `${JSON.stringify(state, null, 2)}\n`;
  if (!durable) {
    writeFileSync(temporary, body, "utf8");
    renameSync(temporary, path);
    return path;
  }
  // Durable: the contents must be on the platter before the rename makes them the file, or a
  // power loss between write and rename could leave the rename pointing at unflushed garbage.
  const fd = openSync(temporary, "w");
  try {
    writeFileSync(fd, body, "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(temporary, path);
  // And the rename itself must be durable, or the file could revert to the old contents after
  // a crash — an fsync of the parent directory does that. Best-effort: some filesystems refuse
  // to open a directory for fsync; degrading there is better than failing the write outright.
  try {
    const dirFd = openSync(dirname(path), "r");
    try {
      fsyncSync(dirFd);
    } finally {
      closeSync(dirFd);
    }
  } catch {
    /* directory fsync unsupported here; the content fsync above is the part that matters most */
  }
  return path;
}

/** Long enough for any honest write, short enough that a crash is not permanent. */
const LOCK_STALE_MS = 10_000;
const LOCK_RETRY_MS = 25;

/**
 * Hold an exclusive lock on the directory file while something changes it.
 *
 * Two writers is not a theoretical problem here: the daemon persists what the
 * page did, the CLI persists what a person typed, and both write the whole
 * file. Without this, a peer added at the terminal disappears the next time the
 * daemon saves — silently, and with nothing to suggest where it went.
 *
 * An exclusive create is the lock, because it is atomic on every filesystem
 * this runs on and needs no dependency. A lock older than a few seconds is
 * assumed to belong to a process that died holding it, since the alternative is
 * a tool that stays broken until somebody finds a file they have never heard
 * of.
 *
 * Both loss-of-exclusivity paths are LOGGED, not silent: stealing a stale lock, and giving up
 * after sustained contention and writing lock-less. Downstream this file's write serialises
 * `routeGen` allocation (the routed Tier-1 causal-invalidation generation), so a lock-less
 * write is exactly where its gen-uniqueness guarantee degrades to best-effort — that must not
 * pass unrecorded, even though proceeding (over refusing forever) is the deliberate tradeoff.
 *
 * @template T
 * @param {string} path
 * @param {() => T} change
 * @param {{log?: (message: string) => void}} [options]
 * @returns {T}
 */
export function withStateLock(path, change, { log = () => {} } = {}) {
  const lockPath = `${path}.lock`;
  mkdirSync(dirname(path), { recursive: true });

  const deadline = Date.now() + LOCK_STALE_MS * 2;
  for (;;) {
    try {
      closeSync(openSync(lockPath, "wx"));
      break;
    } catch (cause) {
      if (/** @type {NodeJS.ErrnoException} */ (cause)?.code !== "EEXIST") throw cause;
      let age = 0;
      try {
        age = Date.now() - statSync(lockPath).mtimeMs;
      } catch {
        continue; // it went away between failing and asking; try again
      }
      if (age > LOCK_STALE_MS) {
        // The holder looks dead (its lock aged past the stale window). Steal it, but say so —
        // if it was actually alive, two writers are now inside the critical section.
        log(`[state] stole a stale lock on ${path} (age ${Math.round(age)}ms > ${LOCK_STALE_MS}ms) — a live holder would make this write concurrent`);
        rmSync(lockPath, { force: true });
        continue;
      }
      if (Date.now() > deadline) {
        // Better to write and risk a lost update than to refuse forever over a lock this
        // process cannot explain. Loud, because this is where routeGen gen-uniqueness (and a
        // clean read-modify-write) becomes best-effort — a concurrent writer here can collide.
        log(`[state] SECURITY: gave up waiting for the lock on ${path} after sustained contention — writing WITHOUT the lock; a concurrent write can now collide (routeGen uniqueness and this update are best-effort)`);
        break;
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, LOCK_RETRY_MS);
    }
  }

  try {
    return change();
  } finally {
    rmSync(lockPath, { force: true });
  }
}

/**
 * Apply a change to whatever is on disk *now*.
 *
 * The read happens inside the lock, so a mutation is applied to current state
 * rather than to whatever this process happened to load minutes ago. That is
 * the difference between two writers cooperating and the last one winning.
 *
 * @param {string} path
 * @param {(state: any) => any} mutate
 * @param {{log?: (message: string) => void}} [options]
 */
export function updateState(path, mutate, { log = () => {} } = {}) {
  return withStateLock(
    path,
    () => {
      const current = loadState(path, { log });
      const next = mutate(current);
      saveState(next, path);
      return next;
    },
    { log },
  );
}
