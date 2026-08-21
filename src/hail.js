/**
 * The hello protocol: ask a peer who else it knows, then ask those.
 *
 * One question, asked outward. A peer answers with itself and the peers it has
 * admitted; the caller merges what it recognises, files the rest as candidates,
 * and repeats. No registry, no broadcast, and no new transport — the exchange
 * rides whatever route already reaches each peer.
 *
 * Nothing here admits anyone. A walk returns leads for a person to decide on,
 * which is the difference between discovering a machine and trusting it.
 *
 * Reachability is settled by connecting, not by asking. A peer's opinion of a
 * third machine is as old as their last exchange, so this treats every address
 * as a lead to try and every success as the only fact worth recording.
 *
 * @module hail
 */
import { signPayload } from "./identity.js";
import { makePeerRecord, verifyRecord } from "./peerRecord.js";

/**
 * What a hail says about itself.
 *
 * Signed, because the receiver decides what to answer based on who is asking —
 * an unsigned name is a claim anyone could make. The timestamp bounds how long
 * a captured request stays useful.
 *
 * @param {{name: string, privateKey: string} | undefined} as
 */
function hailBody(as) {
  if (!as) return {};
  const from = { name: as.name, at: Date.now() };
  return { from, signature: signPayload(from, as.privateKey) };
}

/** Long enough for a sleepy box, short enough that a dead one does not hold a walk. */
const DEFAULT_TIMEOUT_MS = 5_000;

/**
 * Hail one peer over the first address that answers.
 *
 * Addresses are tried in order — most recently successful first — because the
 * route that worked last time is the one most likely to work now.
 *
 * @param {any} record
 * @param {{fetchImpl?: typeof fetch, timeoutMs?: number, as?: {name: string, privateKey: string}}} [options]
 * @returns {Promise<{ok: true, address: import("./peerRecord.js").PeerAddress, response: any} | {ok: false, error: string}>}
 */
export async function hailPeer(record, { fetchImpl = fetch, timeoutMs = DEFAULT_TIMEOUT_MS, as } = {}) {
  const peer = makePeerRecord(record);
  if (!peer) return { ok: false, error: "not a usable peer record" };
  if (peer.addresses.length === 0) return { ok: false, error: `no known address for ${peer.name}` };

  /** @type {string[]} */
  const failures = [];
  for (const address of peer.addresses) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(`${address.value.replace(/\/$/, "")}/hail`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(hailBody(as)),
        signal: controller.signal,
      });
      if (!response.ok) {
        failures.push(`${address.value}: HTTP ${response.status}`);
        continue;
      }
      return { ok: true, address, response: await response.json() };
    } catch (cause) {
      // A refusal and a timeout are both just "not here"; the next address may be.
      failures.push(`${address.value}: ${cause instanceof Error ? cause.message : String(cause)}`);
    } finally {
      clearTimeout(timer);
    }
  }
  return { ok: false, error: `no address answered — ${failures.join("; ")}` };
}

/**
 * Hail every admitted peer, once, and collect what they know.
 *
 * One pass, deliberately. There is no second hop to take: a peer's answer can
 * only introduce candidates, and a candidate is never hailed — admitting one is
 * a person's decision, so following an introduction automatically is exactly
 * the behaviour this design refuses. A depth limit here would be a knob that
 * bounds nothing.
 *
 * Records are re-read as the pass proceeds, because an earlier peer may have
 * supplied the address that makes a later one reachable — the case where a
 * machine moved and someone else noticed first.
 *
 * @param {ReturnType<typeof import("./directory.js").createDirectory>} directory
 * @param {{fetchImpl?: typeof fetch, timeoutMs?: number}} [options]
 */
export async function walk(directory, options = {}) {
  /** @type {{name: string, via: any}[]} */
  const reached = [];
  /** @type {{name: string, error: string}[]} */
  const unreachable = [];

  for (const stale of directory.listAdmitted()) {
    if (stale.name === directory.self.name) continue;

    const peer = directory.get(stale.name) ?? stale;
    const result = await hailPeer(peer, options);
    if (!result.ok) {
      unreachable.push({ name: peer.name, error: result.error });
      continue;
    }

    // Something answered; that is not the same as the peer answering. An
    // address outlives its lease, and the machine holding it next is a
    // stranger — one who would otherwise be marked reachable as this peer and
    // have its directory merged into ours. The reply is signed, so check it.
    const proof = verifyRecord(result.response?.signed, peer.publicKey ?? null);
    if (!proof.ok) {
      unreachable.push({ name: peer.name, error: `answered by someone else: ${proof.error}` });
      continue;
    }

    directory.markReachable(peer.name, result.address);
    reached.push({ name: peer.name, via: result.address });
    directory.learnFrom(
      peer.name,
      Array.isArray(result.response?.peers) ? result.response.peers : [],
    );
  }

  return { reached, unreachable, candidates: directory.listCandidates() };
}
