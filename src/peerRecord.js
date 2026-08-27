/**
 * What one peer knows about another.
 *
 * A record is a *name*, some places that name was last reachable, and when it
 * was last seen. Names are the identity; addresses are cache. A laptop that
 * moves between home, office and a tether is the same laptop, and anything a
 * person named or scripted against has to survive the address changing
 * underneath it.
 *
 * Two rules hold this shape, and both are easy to lose one field at a time:
 *
 * **No credentials.** A record travels to every peer that asks. Anything
 * secret in it is replicated to all of them, and a bearer credential that can
 * open a shell is the worst possible passenger. Records say a peer exists and
 * where it answered; proving you may talk to it happens elsewhere, per
 * connection.
 *
 * **Nothing second-hand is a fact.** A peer's view of a third machine is as old
 * as their last exchange. Status is a hint to verify on connect, never a claim
 * to render as truth, which is why `lastSeen` travels with it — a hint whose
 * age you cannot see is worse than no hint.
 *
 * @module peerRecord
 */

import { normalizeKey, sameKey, signPayload, verifyPayload } from "./identity.js";

/**
 * How many routes to keep for one peer, and how to choose.
 *
 * Addresses are cache, and an unbounded cache is not free: every route is tried
 * before a peer is declared unreachable, so a laptop that has joined fifty
 * networks turns a dead peer into a long wait.
 *
 * But "unreachable now" is not "wrong". A machine that moves between home and
 * office is reachable at each, alternately and indefinitely, and evicting the
 * one it is not currently using guarantees a slow rediscovery every time it
 * moves back. So eviction keeps **diversity** rather than only recency: a few
 * routes per transport, so a tailnet address is never crowded out by a dozen
 * café DHCP leases, and the least recently useful within a transport goes
 * first.
 *
 * A stale address is safe to try, which is what makes keeping them tolerable.
 * A DHCP lease expires and the address may belong to a stranger, but a hail is
 * only believed when the reply is signed by the key held for that peer — so an
 * inherited address costs a timeout, not a wrong answer.
 */
export const MAX_ADDRESSES_PER_TRANSPORT = 3;
export const MAX_ADDRESSES = 12;

/**
 * The hail wire-format version this build speaks, advertised in the signed
 * record a peer returns about itself.
 *
 * Version 1 is the first that binds a hail to its target — `from` carries `to`,
 * the fingerprint of the peer the hail was meant for, and a verifier at v1
 * refuses a hail addressed elsewhere. A caller learns "peer X binds targets"
 * from X's *signed* record (this field), not from a per-hail claim a
 * man-in-the-middle could strip: removing it breaks the record signature. The
 * value is an integer, not a boolean, so the observation is monotone by
 * `max(seen)` — an older, genuinely-signed record cannot roll the support back.
 * See docs/hail-target-binding.md.
 */
export const TARGET_BINDING_VERSION = 1;

/**
 * How many competing keys to remember for one peer.
 *
 * Each entry costs whoever produced it one signature, and this list is evidence
 * for a person rather than a log. Unbounded, somebody sitting on a stale address
 * — an inherited DHCP lease is enough — can append until the one conflict that
 * matters is buried under three hundred that do not. Newest kept.
 *
 * Be honest about what that buys: it bounds memory, and it does **not** promise
 * the truest entry survives. An attacker refreshing ten junk keys just after
 * each walk can hold a real rotation at position eleven for as long as they keep
 * it up — they cannot forge the real key, only crowd it, and a list pinned at
 * ten fresh entries is itself worth noticing. If that stops being an acceptable
 * trade, evict by ascending `count` rather than by age: a rotation seen forty
 * times should outlive junk seen three.
 */
export const MAX_CONFLICTS = 10;

/**
 * How long a dynamically assigned address is presumed current.
 *
 * Twenty-four hours, because that is the common DHCP lease and because a peer
 * frequently cannot find out the real one — a phone, or anything in a
 * restricted environment, does not get to ask the network what its lease is.
 * So this is a guess, and it is used only where a guess is safe.
 *
 * It ranks; it never deletes. Two reasons. Leases are often sticky, so the
 * address a machine had at home last week is usually the address it gets when
 * it goes home again — deleting it buys a slow rediscovery every time. And a
 * wrong guess that reorders costs a timeout, while a wrong guess that deletes
 * costs the only route to a machine.
 */
export const PRESUMED_LEASE_MS = 24 * 60 * 60_000;
/** Overlay addresses are assigned per node and outlive any DHCP lease. */
export const PRESUMED_OVERLAY_MS = 30 * 24 * 60 * 60_000;

/**
 * How long an address is presumed to still mean this machine.
 *
 * The peer advertising it knows best and may say so; a `stability` of
 * `"dynamic"` or `"stable"` on the address is taken at face value, since it is
 * a claim about its own network and it can only mislead us into trying a route
 * in the wrong order.
 *
 * Where it does not say — a phone, or anything that cannot ask its network what
 * lease it holds — the shape is the only evidence. RFC1918 addresses are where
 * DHCP lives, so they are presumed to turn over daily. Overlay transports
 * assign an address per node and keep it until the node is removed, which is a
 * lease in principle and effectively permanent in practice; Tailscale's
 * `100.64/10` is the same story wearing a public-looking range.
 *
 * @param {{transport?: string, value?: string, stability?: string}} address
 */
export function presumedLifetime(address) {
  if (address?.stability === "stable") return PRESUMED_OVERLAY_MS;
  if (address?.stability === "dynamic") return PRESUMED_LEASE_MS;

  const transport = address?.transport ?? "";
  if (transport === "tailscale" || transport === "tinc" || transport === "relay") {
    return PRESUMED_OVERLAY_MS;
  }
  const host = String(address?.value ?? "").replace(/^\w+:\/\//, "");
  if (/^127\.|^\[?::1\]?/.test(host)) return PRESUMED_OVERLAY_MS;
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(host)) return PRESUMED_OVERLAY_MS;
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)) return PRESUMED_LEASE_MS;
  return PRESUMED_LEASE_MS;
}

/** Transports an address can be reached over. Open on purpose: new ones appear. */
export const TRANSPORTS = ["lan", "tailscale", "tinc", "relay", "other"];

/**
 * @typedef {{
 *   transport: string,
 *   value: string,
 *   lastOk: number | null,
 *   learnedAt: number | null,
 *   stability?: "dynamic" | "stable",
 * }} PeerAddress
 */
/**
 * @typedef {{
 *   name: string,
 *   publicKey: string | null,
 *   sealPublicKey?: string,
 *   addresses: PeerAddress[],
 *   lastSeen: number | null,
 *   note?: string,
 *   v?: number,
 * }} PeerRecord
 */

/** @param {unknown} value @returns {value is string} */
const isPlainString = (value) => typeof value === "string" && value.trim().length > 0;

/**
 * Build a record, dropping anything malformed rather than guessing at it.
 *
 * Deliberately lossy: a half-understood record from a peer running a different
 * version should lose its unreadable parts, not poison the directory or fail
 * the exchange.
 *
 * @param {any} input untrusted: from disk, or from a peer running another version
 * @returns {PeerRecord | null}
 */
export function makePeerRecord(input) {
  if (!input || !isPlainString(input.name)) return null;
  const sealPublicKey = normalizeKey(input.sealPublicKey);
  return {
    name: input.name.trim(),
    // The identity. A name is a label; this is what signed something.
    publicKey: normalizeKey(input.publicKey),
    // The X25519 key peers seal content to for this machine (docs/sealing.md). It
    // rides the signed record, so a peer that admitted this identity's signing key
    // can trust the sealing key too — a relay cannot substitute it.
    ...(sealPublicKey ? { sealPublicKey } : {}),
    addresses: normalizeAddresses(input.addresses),
    lastSeen: Number.isFinite(input.lastSeen) ? input.lastSeen : null,
    ...(isPlainString(input.note) ? { note: input.note.trim() } : {}),
    // The sender's hail-format version, if it stated one. Untrusted like every
    // other field here, and used only to *raise* what we believe about that
    // peer's support (monotone) — never to lower it.
    ...(Number.isInteger(input.v) && input.v > 0 ? { v: input.v } : {}),
  };
}

/**
 * Addresses, most recently successful first, deduped by transport and value.
 *
 * @param {any} addresses
 * @returns {PeerAddress[]}
 */
/**
 * An address as something that can actually be dialled.
 *
 * A stored value is used as a URL base — `${value}/hail` — so `10.0.0.2:7645`
 * throws `Invalid URL` and arrives as "unreachable", which reads like the peer
 * is down rather than like the address was never usable. People type host:port,
 * so accept it and say what it means: plaintext HTTP, which is what the hello
 * protocol rides today.
 *
 * @param {string} value
 */
export function normalizeAddressValue(value) {
  const trimmed = String(value ?? "").trim().replace(/\/$/, "");
  if (!trimmed) return "";
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return trimmed;
  // A bare `host:port` or `host`. Not a scheme — `10.0.0.2:7645` looks like one
  // to a naive check, so the test above requires the `//`.
  return `http://${trimmed}`;
}

/**
 * Addresses, most recently successful first, deduped by transport and value.
 *
 * @param {any} addresses
 * @returns {PeerAddress[]}
 */
export function normalizeAddresses(addresses) {
  if (!Array.isArray(addresses)) return [];
  const seen = new Set();
  const kept = [];
  for (const entry of addresses) {
    if (!entry || !isPlainString(entry.value)) continue;
    const transport = isPlainString(entry.transport) ? entry.transport.trim() : "other";
    const value = normalizeAddressValue(entry.value);
    if (!value) continue;
    const key = `${transport} ${value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    kept.push({
      transport,
      value,
      lastOk: Number.isFinite(entry.lastOk) ? entry.lastOk : null,
      ...(entry.stability === "dynamic" || entry.stability === "stable"
        ? { stability: entry.stability }
        : {}),
      // When we were told about it. A route a peer reported an hour ago is a
      // better guess than one that worked a fortnight back, and without this
      // there is no way to tell those apart.
      learnedAt: Number.isFinite(entry.learnedAt) ? entry.learnedAt : null,
    });
  }
  // Stored in **eviction** order, which is not the order to dial in. What has
  // ever worked outranks what never has, always — otherwise a burst of freshly
  // reported addresses evicts the one route known to reach this peer, which is
  // a worse mistake than trying a dead address first. Dialing order is a
  // separate question, answered by orderForDialing.
  const ranked = kept.sort((left, right) => {
    const worked = (/** @type {PeerAddress} */ address) => (typeof address.lastOk === "number" ? 0 : 1);
    const byWorked = worked(left) - worked(right);
    if (byWorked !== 0) return byWorked;
    return (
      Math.max(right.lastOk ?? -1, right.learnedAt ?? -1) -
      Math.max(left.lastOk ?? -1, left.learnedAt ?? -1)
    );
  });

  /** @type {Map<string, number>} */
  const perTransport = new Map();
  const trimmed = [];
  for (const address of ranked) {
    const held = perTransport.get(address.transport) ?? 0;
    // Bounded per transport, so one busy network cannot crowd out the overlay
    // address that is the only way to reach this peer from elsewhere.
    if (held >= MAX_ADDRESSES_PER_TRANSPORT) continue;
    perTransport.set(address.transport, held + 1);
    trimmed.push(address);
    if (trimmed.length >= MAX_ADDRESSES) break;
  }
  return trimmed;
}

/**
 * Fold what we just heard into what we already knew.
 *
 * Ours wins on anything we verified ourselves, because we were there and the
 * other peer was not. Theirs contributes addresses we have never tried, which
 * is the whole reason for asking. A peer cannot talk us out of a route we have
 * seen work, and cannot age our record backwards.
 *
 * @param {PeerRecord | null} mine what we believe, having seen it ourselves
 * @param {any} theirs what a peer just told us
 * @returns {PeerRecord | null}
 */
export function mergePeerRecord(mine, theirs) {
  if (!mine) return makePeerRecord(theirs);
  if (!theirs) return mine;

  /** @type {Map<string, PeerAddress>} */
  const merged = new Map();
  for (const address of mine.addresses) {
    merged.set(`${address.transport} ${address.value}`, address);
  }
  for (const address of normalizeAddresses(theirs.addresses)) {
    const key = `${address.transport} ${address.value}`;
    const known = merged.get(key);
    if (!known) {
      // Never seen it work here, whatever they claim: it is a lead, not a fact.
      // Stamped with when we heard it, which is what makes a fresh report
      // outrank a success old enough for the lease to have turned over.
      merged.set(key, { ...address, lastOk: null, learnedAt: address.learnedAt ?? Date.now() });
    }
  }

  return {
    name: mine.name,
    // A key we hold is never replaced by one arriving over the wire. Rotation
    // is a deliberate act, not something a peer can perform on our directory by
    // introducing itself differently tomorrow.
    publicKey: mine.publicKey ?? normalizeKey(theirs.publicKey),
    addresses: normalizeAddresses([...merged.values()]),
    lastSeen: Math.max(mine.lastSeen ?? 0, theirs.lastSeen ?? 0) || null,
    ...(mine.note ? { note: mine.note } : theirs.note ? { note: theirs.note } : {}),
    // The advertised version rides the merge by `max`, so a gossip merge does
    // not erase it and stop this machine from propagating the peer's support to
    // the rest of the fleet. Monotone, like every read of this signal.
    ...(mergedVersion(mine.v, theirs.v) > 0 ? { v: mergedVersion(mine.v, theirs.v) } : {}),
  };
}

/**
 * The higher of two advertised versions, or 0 if neither is a positive integer.
 *
 * @param {unknown} mineV
 * @param {unknown} theirsV
 * @returns {number}
 */
function mergedVersion(mineV, theirsV) {
  const a = Number.isInteger(mineV) && /** @type {number} */ (mineV) > 0 ? /** @type {number} */ (mineV) : 0;
  const b = Number.isInteger(theirsV) && /** @type {number} */ (theirsV) > 0 ? /** @type {number} */ (theirsV) : 0;
  return Math.max(a, b);
}

/**
 * Strip a record to what is safe to hand another peer.
 *
 * The guard for the no-credentials rule. Anything not in this shape is dropped
 * on the way out, so a field added carelessly somewhere else cannot reach the
 * wire without passing here first.
 *
 * @param {any} record
 * @returns {{name: string, publicKey: string | null, addresses: {transport: string, value: string}[], lastSeen: number | null, note?: string, v?: number} | null}
 */
export function publicRecord(record) {
  const safe = makePeerRecord(record);
  if (!safe) return null;
  return {
    name: safe.name,
    // A public key is public: sharing it is how another machine can check that
    // a claim about this one came from it.
    publicKey: safe.publicKey,
    ...(safe.sealPublicKey ? { sealPublicKey: safe.sealPublicKey } : {}),
    addresses: safe.addresses.map(({ transport, value }) => ({ transport, value })),
    lastSeen: safe.lastSeen,
    ...(safe.note ? { note: safe.note } : {}),
    // The version travels with the record, signed along with it, so a peer
    // learns our support from bytes a relay cannot alter without breaking the
    // signature. Passed through for a peer we are gossiping (their `v`), stamped
    // fresh for ourselves by the directory when it describes itself.
    ...(typeof safe.v === "number" && safe.v > 0 ? { v: safe.v } : {}),
  };
}

/**
 * Wrap a record with a signature over its contents.
 *
 * What travels is `{ record, signature }`: the receiver checks the signature
 * against the key it already holds for that name, so addresses cannot be
 * rewritten in transit or invented by whoever relayed them.
 *
 * @param {PeerRecord} record
 * @param {string} privateKey
 * @returns {{record: object, signature: string} | null}
 */
export function signRecord(record, privateKey) {
  const body = publicRecord(record);
  if (!body) return null;
  return { record: body, signature: signPayload(body, privateKey) };
}

/**
 * Check a signed record against the key we expect it to be signed by.
 *
 * `expectedKey` is what this machine already believes about that name. Passing
 * null means we hold no key yet — first contact — and the record's own key is
 * used, which is trust on first use and no stronger than that. Once a key is
 * bound to a name, a record signed by any other key is rejected outright: that
 * is the case worth catching, since it is what impersonation looks like.
 *
 * @param {any} envelope
 * @param {string | null} expectedKey
 * @returns {{ok: true, record: PeerRecord, key: string}
 *   | {ok: false, error: string, presentedKey?: string}}
 */
export function verifyRecord(envelope, expectedKey) {
  const record = makePeerRecord(envelope?.record);
  if (!record) return { ok: false, error: "not a usable record" };

  const key = normalizeKey(expectedKey) ?? record.publicKey;
  if (!key) return { ok: false, error: `no key to check ${record.name} against` };
  if (expectedKey && record.publicKey && !sameKey(record.publicKey, expectedKey)) {
    // Somebody answered as this peer holding a key we do not have for it. That
    // is either a machine whose key changed or a machine that is not this peer,
    // and nothing on the wire can tell those apart — so the key is reported
    // rather than accepted, and only when they signed with the key they
    // present. Signing proves they hold it; without that, anyone could make us
    // record any key they liked against any name.
    const holdsWhatTheyClaim = verifyPayload(envelope?.record, envelope?.signature, record.publicKey);
    return {
      ok: false,
      error: `${record.name} presented a different key`,
      ...(holdsWhatTheyClaim ? { presentedKey: record.publicKey } : {}),
    };
  }
  if (!verifyPayload(envelope?.record, envelope?.signature, key)) {
    return { ok: false, error: `signature for ${record.name} did not verify` };
  }
  return { ok: true, record, key };
}

/**
 * The order to actually try a peer's routes in.
 *
 * Different from the order they are stored in, and deliberately so. Storage
 * protects a route known to work; dialing wants whatever is most likely to
 * answer *now*, which after a machine moves is the address somebody reported
 * this morning rather than the one that worked last week.
 *
 * Three bands: still within its presumed lifetime and known to work; reported
 * more recently than our last success; then everything else. Getting this wrong
 * costs a timeout, which is why a guess about lease lengths is allowed to
 * decide it.
 *
 * @param {PeerAddress[]} addresses
 * @param {number} [at]
 * @returns {PeerAddress[]}
 */
export function orderForDialing(addresses, at = Date.now()) {
  const band = (/** @type {PeerAddress} */ address) => {
    const lifetime = presumedLifetime(address);
    if (typeof address.lastOk === "number" && at - address.lastOk < lifetime) return 0;
    if (typeof address.learnedAt === "number" && at - address.learnedAt < lifetime) return 1;
    return 2;
  };
  return [...addresses].sort((left, right) => {
    const byBand = band(left) - band(right);
    if (byBand !== 0) return byBand;
    return (
      Math.max(right.lastOk ?? -1, right.learnedAt ?? -1) -
      Math.max(left.lastOk ?? -1, left.learnedAt ?? -1)
    );
  });
}
