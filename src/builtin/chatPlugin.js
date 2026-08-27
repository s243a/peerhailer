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
import { openSigned } from "../sealing.js";

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
 *   identity?: { publicKey: string, privateKey: string, sealPublicKey?: string, sealPrivateKey?: string },
 * }} [options]
 */
export function createChatPlugin({
  now = Date.now,
  maxPerPeer = MAX_PER_PEER,
  messageMs = MESSAGE_MS,
  maxConversations = MAX_CONVERSATIONS,
  identity,
} = {}) {
  // Replay guard for sealed messages: a sealed block is a bearer artifact, so a
  // relay could re-deliver it. Each sealed message carries a nonce; a repeat is
  // ignored. Bounded, time-windowed. (docs/sealing.md, consumer contract.)
  /** @type {Map<string, number>} nonce -> expiry */
  const seenNonces = new Map();
  /** @param {string} nonce a non-empty, length-bounded nonce (caller enforces) */
  const freshNonce = (nonce) => {
    const t = now();
    for (const [k, exp] of seenNonces) { if (exp <= t) seenNonces.delete(k); else break; }
    if (seenNonces.has(nonce)) return false;
    seenNonces.set(nonce, t + messageMs);
    // The window is bounded by count as well as time. Eviction is by insertion
    // order, which is expiry order (every entry shares `messageMs`), so this
    // drops the oldest — but an authenticated peer flooding >4096 distinct
    // nonces inside the window could evict a *seen* one and replay it. Bounded,
    // requires an admitted peer, and the replay is a duplicate line; the
    // freshness in the sealed payload and the hail layer are the real defence.
    while (seenNonces.size > 4096) { const oldest = seenNonces.keys().next().value; if (oldest === undefined) break; seenNonces.delete(oldest); }
    return true;
  };
  /**
   * Peer fingerprint -> their messages, newest last.
   *
   * Keyed by key rather than by name: a name is a label a rename changes, and a
   * conversation should follow the machine, not the label. Bounded on write in
   * both directions, because this is memory that a peer can add to.
   *
   * @type {Map<string, {from: string, text: string, at: number, mine: boolean, sealed?: boolean}[]>}
   */
  const threads = new Map();

  /**
   * @param {string} peerKey
   * @param {{from: string, text: string, at: number, mine: boolean, sealed?: boolean}} message
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
          let text;
          let at = now();
          let sealed = false;
          if (body?.sealed) {
            // End-to-end sealed: only this machine can read it, and it is
            // authenticated. Consumer-contract obligations, all here: require a
            // signature (openSigned), bind the sealed sender to the transport-
            // authenticated caller, and dedup the nonce against replay.
            if (!identity?.sealPrivateKey) return { [REFUSE]: true, reason: "this machine cannot open sealed messages" };
            let opened;
            try {
              opened = openSigned(body.sealed, identity.sealPrivateKey);
            } catch {
              return { [REFUSE]: true, reason: "sealed message did not open or verify" };
            }
            // Bind the sealed sender to the transport-authenticated caller. NOTE
            // for future consumers: this couples the seal's signer to the DIRECT
            // caller, which is right for direct chat but wrong for a relayed
            // consumer (e.g. routing) — there the caller is the last hop, not the
            // origin, so authenticate the origin from INSIDE the sealed payload,
            // not from `caller`. Do not copy this check into a relayed path.
            if (!sameKey(opened.from, caller.publicKey)) return { [REFUSE]: true, reason: "sealed sender is not the caller" };
            let payload;
            try {
              payload = JSON.parse(opened.plaintext.toString("utf8"));
            } catch {
              return { [REFUSE]: true, reason: "sealed payload is malformed" };
            }
            // The nonce is the replay guard's whole basis, so a sealed message
            // without a bounded one is refused rather than waved through — the
            // sender is always this codebase, which always sets a UUID.
            const nonce = String(payload?.nonce ?? "");
            if (!nonce || nonce.length > 128) return { [REFUSE]: true, reason: "sealed message needs a bounded nonce" };
            if (!freshNonce(nonce)) return { received: true, duplicate: true };
            text = typeof payload?.text === "string" ? payload.text : "";
            // The timestamp is when WE received it. The sender's claimed `at` is
            // attacker-controlled (inside the sealed payload it signed), so it is
            // not trusted to order or date a message in our thread.
            at = now();
            sealed = true;
          } else {
            text = typeof body?.text === "string" ? body.text : "";
          }
          if (!text.trim()) return { [REFUSE]: true, reason: "an empty message is not a message" };
          if (text.length > MAX_MESSAGE) return { [REFUSE]: true, reason: "that is longer than a note" };

          // `mine: false` — it came from them. Stored verbatim, and this is the
          // one place to be clear about it: the text is attacker-chosen and the
          // storage does not sanitise it. Whatever renders a thread MUST escape
          // it and MUST NOT make it actionable — a link, a command — or this is
          // the stored-XSS plugin. The claim lives here as a requirement because
          // the renderer that has to honour it does not exist yet.
          append(caller.publicKey, { from: caller.name, text, at, mine: false, sealed });
          return { received: true, sealed };
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
     * @param {{sealed?: boolean}} [opts] whether the delivery went sealed, so
     *   our own copy carries the 🔒 (and its absence flags a cleartext send).
     */
    say: (peerKey, text, { sealed = false } = {}) => {
      const trimmed = String(text ?? "").slice(0, MAX_MESSAGE);
      if (!trimmed.trim()) return null;
      const message = { from: "me", text: trimmed, at: now(), mine: true, sealed };
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
