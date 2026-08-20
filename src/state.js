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
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
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
