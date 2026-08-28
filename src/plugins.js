/**
 * Everything this does not need to do itself.
 *
 * The core is a directory, a hello protocol, and who may ask for what. Tunnels,
 * file transfer, and whatever else people want are worth having and are not
 * worth inheriting: a project embedding this to find its own machines should
 * not acquire a file-transfer service because someone else wanted one.
 *
 * So they are plugins, and the split is deliberate. What lives in the core is
 * what every peer must agree on to talk at all. What lives in a plugin is a
 * service some peers offer and others have never heard of — a peer that does
 * not load the tunnel plugin simply has no tunnel capability to grant, and says
 * the same nothing it says to any other request it will not serve.
 *
 * ## The rule that makes this safe
 *
 * **A plugin never sees an unauthenticated request.** Every route declares the
 * capability it requires, and the daemon checks identity and capability before
 * the handler is reached. A plugin cannot opt out of that, cannot grant itself
 * a capability, and cannot be reached by a peer nobody admitted. The core stays
 * responsible for who you are; the plugin decides only what to do about it.
 *
 * A plugin that wants to be reachable by anyone can ask for a capability the
 * `unknown` profile happens to grant — which is a decision the operator makes
 * by editing that profile, in the open, and not something a plugin can arrange
 * for itself.
 *
 * ## Loading
 *
 * Explicitly, by module specifier, from configuration. Never by scanning a
 * directory: a tool whose job is deciding who may talk to your machines should
 * not execute code because it appeared on disk.
 *
 * @module plugins
 */

/**
 * @typedef {{
 *   method: string,
 *   path: string,
 *   capability: string,
 *   handler: (input: {
 *     body: any,
 *     caller: any,
 *     directory: any,
 *     identity: {publicKey: string, privateKey: string},
 *     log: (message: string) => void,
 *   }) => Promise<any> | any,
 *   requiresEncryptedArrival?: boolean | "mutual", // omit = encrypted by default; set false to allow plaintext
 * }} PluginRoute
 */

/**
 * @typedef {{
 *   name: string,
 *   description?: string,
 *   capabilities?: string[],
 *   profiles?: Record<string, {allows: string[], description: string}>,
 *   routes?: PluginRoute[],
 *   commands?: Record<string, {
 *     describe: string,
 *     run: (input: {args: string[], flags: Record<string, string | true>, directory: any, log: (message: string) => void}) => unknown,
 *   }>,
 *   init?: (input: {directory: any, identity: any, log: (message: string) => void}) => void,
 *   history?: () => Array<{capability: string, peerKey: string, at: number, outcome: string}>,
 *   requiresEncryptedArrival?: boolean | "mutual", // omit = encrypted by default; set false to allow plaintext
 *   stop?: () => void,
 * }} Plugin
 */

import { pathToFileURL } from "node:url";

/**
 * What a handler returns to refuse rather than answer.
 *
 * A plugin cannot write the response itself — the host owns that, so a refusal
 * looks identical whether it came from the core or from here, and a plugin
 * cannot accidentally reveal which rule refused.
 */
export const REFUSE = Symbol.for("peerhailer.refuse");

/** @param {string} [reason] recorded here, never sent */
export const refuse = (reason) => ({ [REFUSE]: true, reason });

const METHODS = new Set(["GET", "POST", "PUT", "DELETE", "PATCH"]);

/**
 * Resolve a route's arrival requirement from its own and its plugin's markers.
 *
 * **Encrypted by default.** When *neither* the route nor the plugin declares
 * anything, the answer is `true` (encrypted required) — a capability that
 * carries content and forgets to say so fails *safe*, refused on a plaintext
 * listener rather than silently served in the clear. Serving plaintext is
 * therefore a deliberate opt-out: a plugin (or route) must set
 * `requiresEncryptedArrival: false` on purpose, which is what the discovery
 * layer (`hail`/`directory`) does, since it carries no secrets and must bootstrap
 * over plaintext.
 *
 * Where both are declared, the *stricter* wins — ordered `false` < `true` <
 * `"mutual"` — so a route can tighten one endpoint above its plugin's floor but
 * never loosen below it. `undefined` on one side does not lower the other.
 *
 * @param {boolean | "mutual" | undefined} routeLevel
 * @param {boolean | "mutual" | undefined} pluginLevel
 * @returns {boolean | "mutual"}
 */
function resolveArrival(routeLevel, pluginLevel) {
  // -1 marks "not declared", distinct from an explicit `false` (0) which is the
  // deliberate plaintext opt-out and must be honored, not defaulted over.
  const rank = (/** @type {boolean | "mutual" | undefined} */ v) =>
    v === "mutual" ? 2 : v === true ? 1 : v === false ? 0 : -1;
  const declared = Math.max(rank(routeLevel), rank(pluginLevel));
  if (declared < 0) return true; // nothing declared → encrypted by default
  return declared === 2 ? "mutual" : declared === 1 ? true : false;
}

/**
 * Check a plugin before letting it near anything.
 *
 * Refusing a malformed plugin loudly beats loading half of it: a route with no
 * capability would otherwise be an unauthenticated endpoint, which is the one
 * mistake this whole arrangement exists to prevent.
 *
 * @param {any} plugin
 * @returns {{ok: true, plugin: Plugin} | {ok: false, error: string}}
 */
export function validatePlugin(plugin) {
  if (!plugin || typeof plugin.name !== "string" || plugin.name.trim().length === 0) {
    return { ok: false, error: "a plugin needs a name" };
  }
  for (const route of plugin.routes ?? []) {
    if (!METHODS.has(String(route?.method).toUpperCase())) {
      return { ok: false, error: `${plugin.name}: route has no usable method` };
    }
    if (typeof route?.path !== "string" || !route.path.startsWith("/")) {
      return { ok: false, error: `${plugin.name}: route path must start with /` };
    }
    // Reserved for the core. Plugin routes are matched before the scope and
    // origin checks — that is right for `/hail`, which authenticates every
    // caller itself — but it means a plugin claiming `/api/peers` would both
    // shadow the control endpoint and answer outside the cross-origin guard.
    // Refused at load rather than left to whoever writes the first plugin that
    // wants a nice-looking path.
    if (route.path === "/" || route.path === "/api" || route.path.startsWith("/api/")) {
      return { ok: false, error: `${plugin.name}: ${route.path} is reserved for the core API` };
    }
    if (typeof route?.capability !== "string" || route.capability.length === 0) {
      // The load-bearing check. A route without a capability is a route with no
      // gate, and this is the last place that can be noticed.
      return { ok: false, error: `${plugin.name}: route ${route.path} declares no capability` };
    }
    if (typeof route?.handler !== "function") {
      return { ok: false, error: `${plugin.name}: route ${route.path} has no handler` };
    }
  }
  return { ok: true, plugin };
}

/**
 * Load plugins named in configuration.
 *
 * A plugin that fails to load is reported and skipped rather than taken as
 * fatal: a broken tunnel plugin should not stop a machine answering hails,
 * which is the job it had before any plugin existed.
 *
 * @param {string[]} specifiers
 * @param {{
 *   log?: (message: string) => void,
 *   importImpl?: (specifier: string) => Promise<any>,
 *   from?: string,
 * }} [options]
 * @returns {Promise<Plugin[]>}
 */
export async function loadPlugins(specifiers, { log = () => {}, importImpl, from } = {}) {
  // A relative path means relative to where the user is, not to this file.
  // Resolving against the module would make `./my-plugin.js` mean something
  // inside the installed package, which is never what anybody meant.
  const base = from ?? pathToFileURL(`${process.cwd()}/`).href;
  const load =
    importImpl ??
    ((specifier) => import(specifier.startsWith(".") ? new URL(specifier, base).href : specifier));
  /** @type {Plugin[]} */
  const loaded = [];

  for (const specifier of specifiers ?? []) {
    try {
      const module = await load(specifier);
      const checked = validatePlugin(module?.default ?? module);
      if (!checked.ok) {
        log(`[plugin] refused ${specifier}: ${checked.error}`);
        continue;
      }
      loaded.push(checked.plugin);
      log(`[plugin] loaded ${checked.plugin.name}`);
    } catch (cause) {
      log(`[plugin] could not load ${specifier}: ${cause instanceof Error ? cause.message : cause}`);
    }
  }
  return loaded;
}

/**
 * Routes from every plugin, keyed for lookup, with conflicts refused.
 *
 * Two plugins claiming one path is not something to resolve by ordering — the
 * one that wins would depend on configuration order, which nobody would think
 * to check.
 *
 * @param {Plugin[]} plugins
 * @param {{log?: (message: string) => void}} [options]
 */
export function collectRoutes(plugins, { log = () => {} } = {}) {
  /** @type {Map<string, PluginRoute & {plugin: string}>} */
  const routes = new Map();
  for (const plugin of plugins) {
    // Validated here rather than only where plugins are loaded from disk. The
    // CLI goes through `loadPlugins`, which checks; an embedder passing plugin
    // objects to `createDaemon` directly did not, and that is the documented
    // way to use this library. The load-bearing check is the capability one: a
    // route declaring none reaches `verifyGrant` with `capability: undefined`,
    // which skips the capability test, so any valid grant opens it.
    const verdict = validatePlugin(plugin);
    if (!verdict.ok) {
      log(`[plugin] ${verdict.error} — refused`);
      continue;
    }
    for (const route of plugin.routes ?? []) {
      const key = `${String(route.method).toUpperCase()} ${route.path}`;
      const existing = routes.get(key);
      if (existing) {
        log(`[plugin] ${plugin.name} wants ${key}, already served by ${existing.plugin} — refused`);
        continue;
      }
      // The encrypted-arrival requirement, resolved and carried onto each route
      // so a listener can refuse to serve one where arrival is not encrypted.
      // Encrypted by default (see resolveArrival): a plugin that declares nothing
      // is treated as requiring encryption, so plaintext is a deliberate opt-out.
      // A route may also carry its own
      // marker to *tighten* one sensitive endpoint; the stricter of the two wins,
      // so a plugin-level floor can never be silently loosened by a route, nor a
      // route's tightening silently dropped.
      routes.set(key, {
        ...route,
        plugin: plugin.name,
        requiresEncryptedArrival: resolveArrival(route.requiresEncryptedArrival, plugin.requiresEncryptedArrival),
      });
    }
  }
  return routes;
}

/**
 * Profiles plugins suggest. Suggestions only: nothing is granted by loading.
 *
 * @param {Plugin[]} plugins
 */
export function collectProfiles(plugins) {
  /** @type {Record<string, any>} */
  const profiles = {};
  for (const plugin of plugins) {
    for (const [name, profile] of Object.entries(plugin.profiles ?? {})) {
      if (!profiles[name]) profiles[name] = { ...profile, fromPlugin: plugin.name };
    }
  }
  return profiles;
}

/**
 * The resolvable custom profile set: what the plugins suggest, overlaid by the
 * operator's stored profiles (operator config always wins). One recipe for this
 * precedence, shared by every site that builds it (startup, reload commit, and
 * the per-mutation refresh) so they cannot drift. Synchronous, so the reload
 * commit section — which must not `await` — can call it.
 *
 * @param {import("./plugins.js").Plugin[]} plugins
 * @param {{ profiles?: Record<string, any> } | undefined | null} state
 */
export function mergeProfiles(plugins, state) {
  return { ...collectProfiles(plugins), ...(state?.profiles ?? {}) };
}
