/**
 * Why things are failing, as a plugin.
 *
 * Separate from the core for the same reason as everything else here: a project
 * embedding the directory has no use for an endpoint that explains this
 * machine's refusals, and should not have to disable one.
 *
 * Two locks, unchanged by being a plugin — the `diagnostics` capability, which
 * no everyday profile grants, and a debug window an operator opened. The
 * capability is enforced by the host before this runs; the window is checked
 * here, because it is this plugin's own state.
 *
 * @module builtin/diagnosticsPlugin
 */
import { refuse } from "../plugins.js";
import { DIAGNOSTICS } from "../profiles.js";

/**
 * @param {ReturnType<typeof import("../diagnostics.js").createDiagnostics>} diagnostics
 * @returns {import("../plugins.js").Plugin}
 */
export function createDiagnosticsPlugin(diagnostics) {
  return {
    name: "diagnostics",
    description: "Explains refusals, to a peer holding `diagnostics`, while a debug window is open.",
    capabilities: [DIAGNOSTICS],
    profiles: {
      operator: {
        allows: ["hail", "directory", DIAGNOSTICS],
        description: "A trusted peer that may also read diagnostics, in debug mode.",
      },
    },
    routes: [
      {
        method: "POST",
        path: "/diagnostics",
        capability: DIAGNOSTICS,
        /** @param {any} input */
        handler: ({ caller, directory, log }) => {
          if (!diagnostics.isOpen()) {
            // Refused the same way anything else is: the caller learns that it
            // was denied, never that the window in particular was shut.
            diagnostics.refused(caller.name, "asked for diagnostics while the window was shut");
            return refuse("the diagnostics window is shut");
          }
          log(`[diagnostics] answered ${caller.name}`);
          return diagnostics.report({ self: directory.self, directory, caller: caller.name });
        },
      },
    ],
  };
}
