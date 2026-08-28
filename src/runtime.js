/**
 * One place that turns state into the daemon's runtime: the plugin array and the
 * merged profile set. Startup and reload both call this, so their construction
 * cannot drift — the divergences it removes (a different plugin order after the
 * first reload, command-history options dropped on reload, three copies of the
 * profile set) were exactly the kind that fail silently.
 *
 * Pure with respect to the running daemon: it constructs, it never installs. The
 * caller (startup, or the reload commit section) decides when to make the result
 * active. Every runtime-affecting input is read from `state` or the passed
 * `flags`/`deps` — never from ambient process state — so the same inputs always
 * produce the same runtime, which is what makes it testable.
 *
 * @module runtime
 */
import { createDiagnosticsPlugin } from "./builtin/diagnosticsPlugin.js";
import hailPlugin from "./builtin/hailPlugin.js";
import { createTunnelPlugin } from "./builtin/tunnelPlugin.js";
import { createCommandPlugin } from "./builtin/commandPlugin.js";
import { createChatPlugin } from "./builtin/chatPlugin.js";
import { createFilesPlugin } from "./builtin/filesPlugin.js";
import { createRoutePlugin } from "./builtin/routePlugin.js";
import { createServicePlugin } from "./builtin/servicePlugin.js";
import { createOffersPlugin } from "./builtin/offersPlugin.js";
import { createShellPlugin } from "./builtin/shellPlugin.js";
import { loadPlugins, mergeProfiles } from "./plugins.js";

/**
 * True when any declared service is a launchable offer with a matching tunnel.
 * @param {any} services
 * @param {any} tunnels
 */
export function hasLaunchableOffer(services, tunnels) {
  return Object.entries(services ?? {}).some(
    ([name, decl]) =>
      decl && typeof decl === "object" && (decl.agent || decl.role) && (tunnels ?? {})[decl.tunnel ?? name] !== undefined,
  );
}

/**
 * A T3-to-T3 controller offer: a `pair` command and a `t3` tunnel, by convention.
 * @param {any} commands
 * @param {any} tunnels
 */
export function hasControllerOffer(commands, tunnels) {
  return Boolean((commands ?? {}).pair && (tunnels ?? {}).t3);
}

/**
 * Build `{ plugins, profiles }` from state.
 *
 * Canonical plugin order (the pre-existing startup order): hail, diagnostics,
 * tunnel, chat, files, route, service, offers, shell, command, then externally
 * loaded. Order is behaviour — `collectRoutes` and `collectProfiles` are
 * first-in-array-wins on a collision, and externals stay last so a bundled route
 * or profile always wins over one an external plugin claims.
 *
 * `--chat` / `--route` are process flags, not state, so they arrive in `flags`
 * (captured once at startup) and can only turn a feature *on*: `flags.x ||
 * state.x`, so a cold start with the flag keeps chat/route across a reload even
 * if the state file never recorded it.
 *
 * @param {any} state the loaded state (its `tunnels`/`commands`/… and `history`/`profiles`)
 * @param {{
 *   identity: any,
 *   diagnostics: any,
 *   port?: number,
 *   routeDeps: () => any,
 *   flags?: { chat?: boolean, route?: boolean },
 *   log?: (message: string) => void,
 * }} deps
 * @returns {Promise<{ plugins: import("./plugins.js").Plugin[], profiles: Record<string, any> }>}
 */
export async function buildRuntime(state, { identity, diagnostics, port, routeDeps, flags = {}, log = () => {} }) {
  const tunnels = state?.tunnels ?? {};
  const services = state?.services ?? {};
  const shells = state?.shells ?? {};
  const shares = state?.shares ?? {};
  const commands = state?.commands ?? {};
  const chat = flags.chat === true || state?.chat === true;
  const route = flags.route === true || state?.routing === true;
  const ownPort = Number.isFinite(port) ? Number(port) : 8787;
  // The factories return structurally-varied plugin objects; they are all valid
  // plugins at runtime, so cast once to the interface rather than annotate each.
  const plugins = /** @type {import("./plugins.js").Plugin[]} */ ([
    hailPlugin,
    createDiagnosticsPlugin(diagnostics),
    ...(Object.keys(tunnels).length ? [createTunnelPlugin({ endpoints: tunnels, ownPorts: [ownPort] })] : []),
    ...(chat ? [createChatPlugin({ identity })] : []),
    ...(Object.keys(shares).length ? [createFilesPlugin({ shares })] : []),
    ...(route ? [createRoutePlugin(routeDeps())] : []),
    ...(Object.keys(services).length ? [createServicePlugin({ services })] : []),
    ...(hasLaunchableOffer(services, tunnels) || hasControllerOffer(commands, tunnels)
      ? [createOffersPlugin({ services, tunnels, commands })]
      : []),
    ...(Object.keys(shells).length ? [createShellPlugin({ shells })] : []),
    ...(Object.keys(commands).length
      ? [
          createCommandPlugin({
            commands,
            // From the *supplied* state, always — dropping these on reload
            // silently reverted the audit history the operator sized.
            ...(Number.isFinite(state?.history?.max) ? { maxHistory: state.history.max } : {}),
            ...(Number.isFinite(state?.history?.ageMs) ? { historyMs: state.history.ageMs } : {}),
          }),
        ]
      : []),
    ...(await loadPlugins(state?.plugins ?? [], { log })),
  ]);
  return { plugins, profiles: mergeProfiles(plugins, state) };
}
