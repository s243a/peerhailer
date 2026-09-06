/**
 * The routing-owned discovery record: a destination's signed **key-only** self-record,
 * optionally advertising its confidentiality floor.
 *
 * The signed body is exactly what `signRecord` would sign (`publicRecord` of the key-only
 * self), plus one routing-namespaced field, `routed`, when — and only when — the floor is on.
 * The signature is the same `signPayload` over the whole object, so:
 *
 *  - A floor-**off** destination emits bytes identical to today's `signRecord(keyOnly)`
 *    (Ed25519 is deterministic, so even the signature matches): back-compat is a no-op.
 *  - A floor-**on** record still verifies unchanged through `verifyRecord`. That function
 *    verifies the signature over the RAW `envelope.record` (via `canonicalize`, which sorts
 *    and covers every present key) but returns the `makePeerRecord`-stripped typed view — so
 *    the `routed` field is authenticated yet invisible to old readers. A relay cannot add,
 *    strip, or flip it without breaking the signature.
 *
 * One home for "sign the routed self-record" and "read the routed policy off a verified
 * envelope", so `routePlugin.js` and `routedKeyStore.js` cannot drift on the field name or the
 * leniency rule.
 *
 * @module routedDiscoveryRecord
 */
import { signPayload } from "./identity.js";
import { publicRecord, verifyRecord } from "./peerRecord.js";

/** The routing-owned namespace inside the signed discovery record. */
export const ROUTED_POLICY_FIELD = "routed";

/**
 * Sign this machine's KEY-ONLY self-record for routed discovery, optionally advertising its
 * confidentiality floor. Output is byte-identical to `signRecord(keyOnly)` when `requireSealed`
 * is false. Returns null when the self-record is unusable (as `signRecord` does).
 * @param {{ self: any, requireSealed?: boolean, privateKey: string }} input
 * @returns {{ record: object, signature: string } | null}
 */
export function signDiscoveryRecord({ self, requireSealed = false, privateKey }) {
  const body = publicRecord({ name: self?.name, publicKey: self?.publicKey, sealPublicKey: self?.sealPublicKey, addresses: [], lastSeen: null });
  if (!body) return null;
  const record = requireSealed === true ? { ...body, [ROUTED_POLICY_FIELD]: { requireSealed: true } } : body;
  return { record, signature: signPayload(record, privateKey) };
}

/**
 * Verify a discovery envelope exactly as `verifyRecord(envelope, null)` does, and additionally
 * surface the routed policy the destination signed. `floor` is read from the RAW record after
 * verification — the signature covers every field (`canonicalize` sorts and includes all keys),
 * while the typed `record` has already dropped it. A relay cannot add, strip, or flip `routed`
 * without breaking the signature. Lenient like `makePeerRecord`: anything but a plain object with
 * `requireSealed: true` reads as "no floor advertised".
 * @param {any} envelope
 * @returns {{ ok: true, record: import("./peerRecord.js").PeerRecord, key: string, floor: boolean } | { ok: false, error: string }}
 */
export function verifyDiscoveryRecord(envelope) {
  const rec = verifyRecord(envelope, null);
  if (!rec.ok) return rec;
  // Read the floor only AFTER verification: before it, `envelope.record` is relay-controlled bytes.
  const policy = envelope?.record?.[ROUTED_POLICY_FIELD];
  const floor = policy !== null && typeof policy === "object" && !Array.isArray(policy) && policy.requireSealed === true;
  return { ...rec, floor };
}
