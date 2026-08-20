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
import { mkdirSync, openSync, closeSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

/** @param {NodeJS.ProcessEnv} [env] */
export function defaultStatePath(env = process.env) {
  const base =
    env.PEERHAILER_HOME ??
    env.XDG_CONFIG_HOME ??
    join(env.HOME ?? env.USERPROFILE ?? homedir(), ".config");
  return join(base, "peerhailer", "directory.json");
}

/**
 * @param {string} [path]
 * @param {{log?: (message: string) => void}} [options]
 * @returns {any}
 */
export function loadState(path = defaultStatePath(), { log = () => {} } = {}) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
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
 * @param {unknown} state
 * @param {string} [path]
 */
export function saveState(state, path = defaultStatePath()) {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}`;
  writeFileSync(temporary, `${JSON.stringify(state, null, 2)}\n`, "utf8");
  renameSync(temporary, path);
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
 * @template T
 * @param {string} path
 * @param {() => T} change
 * @returns {T}
 */
export function withStateLock(path, change) {
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
        rmSync(lockPath, { force: true });
        continue;
      }
      if (Date.now() > deadline) {
        // Better to write and risk a lost update than to refuse forever over a
        // lock this process cannot explain.
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
  return withStateLock(path, () => {
    const current = loadState(path, { log });
    const next = mutate(current);
    saveState(next, path);
    return next;
  });
}
