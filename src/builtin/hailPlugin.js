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
import { DIRECTORY, HAIL } from "../profiles.js";

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
        // Two gates, not one. `hail` says you may ask who this machine is;
        // `directory` says you may also learn who it knows. They were one gate
        // until now — anything that could hail got the peer list, which is not
        // what `trusted` describing them separately implies, and a custom
        // profile granting only `hail` would have leaked the directory in
        // silence.
        //
        // A caller admitted on a grant rather than a profile gets the identity
        // and not the list: what a grant carries cannot be re-checked here, and
        // withholding is the safe direction.
        const maySeePeers = directory.allowsCapability(caller.name, DIRECTORY);
        if (!maySeePeers) answer.peers = [];
        log(`[hail] ${caller.name} answered with ${answer.peers.length} peers`);
        // Signed, so the addresses in it are a claim only this machine's key
        // could have made rather than whatever the network delivered.
        return { ...answer, signed: signRecord(directory.self, identity.privateKey) };
      },
    },
  ],
};
