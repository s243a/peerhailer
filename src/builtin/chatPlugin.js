/**
 * A message from one machine to a person at another.
 *
 * The one thing this project reached for that nothing else provided. Tailscale
 * carries files and T3 mints tokens; a short note — *hand this to the build box*,
 * *the server is going down* — had nowhere to go. Small, and the kind of small
 * people use.
 *
 * This is the peer-to-peer half only. A message is accepted from an admitted
 * peer holding `chat`, shown by that peer's name, and kept in memory. The
 * designed second half — a relay carrying a message from something that is *not*
 * a peer, sealed so the relay cannot read it — is deliberately not here: it is
 * where the danger is, and it waits for the sealing key and a review. See
 * `docs/chat.md`.
 *
 * @module builtin/chatPlugin
 */
import { sameKey } from "../identity.js";
import { REFUSE } from "../plugins.js";

/** A message longer than this is a payload, not a note. */
export const MAX_MESSAGE = 4 * 1024;

/** How many to keep per peer. A chat is not a log; older ones fall off. */
export const MAX_PER_PEER = 100;

/** And how long. Memory only, so nothing lives forever by default. */
export const MESSAGE_MS = 24 * 60 * 60_000;

/**
 * A ceiling across *all* conversations, not just each one.
 *
 * The per-peer cap bounds one thread; nothing bounds the number of threads. That
 * is fine while `chat` is granted one peer at a time, and stops being fine the
 * day a profile hands it to a class of callers — distinct keys are only scarce
 * while capabilities are. A total cap costs nothing and does not wait for that
 * day to arrive.
 */
export const MAX_CONVERSATIONS = 500;

/**
 * @param {{
 *   now?: () => number,
 *   maxPerPeer?: number,
 *   messageMs?: number,
 *   maxConversations?: number,
 * }} [options]
 */
export function createChatPlugin({
  now = Date.now,
  maxPerPeer = MAX_PER_PEER,
  messageMs = MESSAGE_MS,
  maxConversations = MAX_CONVERSATIONS,
} = {}) {
  /**
   * Peer fingerprint -> their messages, newest last.
   *
   * Keyed by key rather than by name: a name is a label a rename changes, and a
   * conversation should follow the machine, not the label. Bounded on write in
   * both directions, because this is memory that a peer can add to.
   *
   * @type {Map<string, {from: string, text: string, at: number, mine: boolean}[]>}
   */
  const threads = new Map();

  /**
   * @param {string} peerKey
   * @param {{from: string, text: string, at: number, mine: boolean}} message
   */
  const append = (peerKey, message) => {
    const thread = threads.get(peerKey) ?? [];
    thread.push(message);
    const oldest = now() - messageMs;
    while (thread.length && (thread.length > maxPerPeer || (thread[0]?.at ?? oldest) < oldest)) thread.shift();
    threads.set(peerKey, thread);

    // Evict the least-recently-touched whole conversation past the ceiling. A
    // Map preserves insertion order and `set` above moved this key to the end,
    // so the front is the coldest.
    while (threads.size > maxConversations) {
      const coldest = threads.keys().next().value;
      if (coldest === undefined || coldest === peerKey) break;
      threads.delete(coldest);
    }
  };

  return {
    name: "chat",
    description: "Short messages to and from admitted peers, kept in memory.",
    // Encrypted arrival, refused on plaintext. This is the default now, but
    // stated explicitly because chat is the reason for it: the fabric cannot know
    // what a message carries, so it must not decide the content is safe in the
    // clear — a chat could hold a secret, and a plaintext one can be read or
    // forged on the wire. Encrypted, not "mutual": fine over a direct tailnet.
    requiresEncryptedArrival: true,
    capabilities: ["chat"],

    routes: [
      {
        method: "POST",
        path: "/chat/send",
        capability: "chat",
        /**
         * A peer sends this machine a message.
         *
         * @param {any} input
         */
        handler: ({ body, caller }) => {
          if (!caller?.publicKey) return { [REFUSE]: true, reason: "no key to attribute a message to" };
          const text = typeof body?.text === "string" ? body.text : "";
          if (!text.trim()) return { [REFUSE]: true, reason: "an empty message is not a message" };
          if (text.length > MAX_MESSAGE) return { [REFUSE]: true, reason: "that is longer than a note" };

          // `mine: false` — it came from them. Stored verbatim, and this is the
          // one place to be clear about it: the text is attacker-chosen and the
          // storage does not sanitise it. Whatever renders a thread MUST escape
          // it and MUST NOT make it actionable — a link, a command — or this is
          // the stored-XSS plugin. The claim lives here as a requirement because
          // the renderer that has to honour it does not exist yet.
          append(caller.publicKey, { from: caller.name, text, at: now(), mine: false });
          return { received: true };
        },
      },
    ],

    /**
     * The conversation with one peer, oldest first. Host-only — no route reads
     * another peer's thread, so one peer cannot read what another said.
     *
     * @param {string} peerKey
     */
    thread: (peerKey) => [...(threads.get(peerKey) ?? [])],

    /** Every conversation, for a page that lists them. */
    conversations: () =>
      [...threads.entries()].map(([peerKey, messages]) => ({
        peerKey,
        count: messages.length,
        last: messages[messages.length - 1]?.at ?? null,
      })),

    /**
     * This machine says something to a peer. Recorded on our side; delivery is
     * the caller's job, since only the host holds the peer's address and key.
     *
     * @param {string} peerKey
     * @param {string} text
     */
    say: (peerKey, text) => {
      const trimmed = String(text ?? "").slice(0, MAX_MESSAGE);
      if (!trimmed.trim()) return null;
      const message = { from: "me", text: trimmed, at: now(), mine: true };
      append(peerKey, message);
      return message;
    },

    /** @param {string} peerKey */
    forget: (peerKey) => {
      for (const key of [...threads.keys()]) {
        if (sameKey(key, peerKey)) threads.delete(key);
      }
    },
  };
}
