/**
 * The hello protocol, as a plugin.
 *
 * This is the thing peerhailer is for, and it is still a plugin — because
 * *answering* is a service, and a project that embeds the directory to keep
 * track of its own machines should not start answering strangers by importing a
 * library. Loading this is what makes a machine reachable.
 *
 * The `hail` capability gates it, so who gets an answer is the same question as
 * every other permission here.
 *
 * @module builtin/hailPlugin
 */
import { signRecord } from "../peerRecord.js";
import { HAIL } from "../profiles.js";

export default {
  name: "hail",
  description: "Answers hails: who I am, and which peers I have admitted.",
  capabilities: [HAIL],
  routes: [
    {
      method: "POST",
      path: "/hail",
      capability: HAIL,
      /** @param {any} input */
      handler: ({ caller, directory, identity, log }) => {
        const answer = directory.hailResponse();
        log(`[hail] ${caller.name} answered with ${answer.peers.length} peers`);
        // Signed, so the addresses in it are a claim only this machine's key
        // could have made rather than whatever the network delivered.
        return { ...answer, signed: signRecord(directory.self, identity.privateKey) };
      },
    },
  ],
};
