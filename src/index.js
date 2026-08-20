/**
 * peerhailer — peer presence and discovery.
 *
 * Embedding entry point. Everything here works with no daemon running; the
 * daemon in `server.js` is one way to expose it, not a prerequisite.
 *
 * @module peerhailer
 */
export { createDirectory } from "./directory.js";
export { hailPeer, walk } from "./hail.js";
export { createDaemon } from "./server.js";
export { collectProfiles, collectRoutes, loadPlugins, refuse, validatePlugin } from "./plugins.js";
export { default as hailPlugin } from "./builtin/hailPlugin.js";
export { createDiagnosticsPlugin } from "./builtin/diagnosticsPlugin.js";
export { createDiagnostics } from "./diagnostics.js";
export { attenuate, mintGrant, verifyGrant } from "./grants.js";
export {
  makePeerRecord,
  mergePeerRecord,
  normalizeAddresses,
  publicRecord,
  TRANSPORTS,
} from "./peerRecord.js";
export { loadState, saveState, defaultStatePath } from "./state.js";
