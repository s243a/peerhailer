/**
 * The smallest plugin that does anything, as a worked example.
 *
 * It exists to show the shape and the guarantee: `echo` is a capability nobody
 * holds by default, so this route is unreachable until an operator grants it —
 * loading the plugin changes what this machine *can* offer, never who may use
 * it.
 */
export default {
  name: "echo",
  description: "Returns what you sent. Useful only for proving the path works.",
  capabilities: ["echo"],
  profiles: {
    echoer: { allows: ["hail", "echo"], description: "May use the echo service." },
  },
  routes: [
    {
      method: "POST",
      path: "/echo",
      capability: "echo",
      // `caller` is already authenticated and already holds `echo`. A plugin
      // never has to check, and cannot forget to.
      handler: ({ body, caller }) => ({ said: body?.say ?? null, to: caller.name }),
    },
  ],
};
