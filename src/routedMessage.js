/**
 * The routed-message wrapper — the integration half of milestone M1
 * (`docs/routing-security-roadmap.md`): it ties the authenticated manifest, the
 * attached origin record, the payload-digest binding, the destination self-check,
 * and the replay guard into one origin-side `wrap` and one destination-side `open`.
 *
 * It rides *inside* the routing payload, opaque to the pure engine and to every
 * relay — a relay cannot forge the origin, redirect the message, or swap the body
 * (all of that is under the manifest signature) without the destination refusing it.
 * At M1 the body is **cleartext** (signed, not private): relays still read it, and
 * `open` refuses any manifest whose `payloadMode` is not `"clear"`. Confidentiality
 * (a sealed body under `payloadMode:"sealed"`) is M3; multi-block reassembly is later.
 *
 * Two limits worth stating precisely:
 *  - **The attached origin record is bound only by its *key*, not by this message.**
 *    The manifest commits to `originKeyId`, so a relay cannot substitute a record for
 *    a *different* key — but it could substitute an older self-signed record of the
 *    *same* origin (stale addresses, an older sealing key). `open` therefore exposes
 *    only `body` and `originKeyId`; a caller must not read address/seal fields out of
 *    the wrapper as if they were message-fresh.
 *  - **The body must be JSON-representable.** `wrap` serialises with `JSON.stringify`,
 *    so `-0`, `NaN`, `Date`, `undefined` properties, etc. are lost the usual way; the
 *    destination always receives the parse of exactly the bytes the origin signed.
 *
 * Trust note: `open` recovers the origin's key from the *self-certifying* attached
 * record (trust-on-first-use for its self-consistency) and binds it to the manifest.
 * That authenticates *which key* produced the message — not *which name* — so a
 * caller must treat an unknown origin as unknown-profile, never as admitted, and must
 * never bind a routed key to a name. Authenticated ≠ admitted.
 *
 * @module routedMessage
 */
import { buildManifest, keyId, payloadDigest, signManifest, verifyManifest } from "./routeManifest.js";
import { signRecord, verifyRecord } from "./peerRecord.js";

/**
 * Serialise a body to the exact bytes the manifest commits to. Done once at the origin.
 * Throws on a value JSON cannot represent — an origin-side programming error, not
 * network input, so it fails loudly rather than silently sending something else.
 */
const bodyToBytes = (body) => {
  const json = JSON.stringify(body ?? null);
  if (typeof json !== "string") throw new Error("routed body is not JSON-serialisable");
  return Buffer.from(json, "utf8");
};

/**
 * Origin side: build the signed, self-describing wrapper for `body` addressed to the
 * destination key `destinationKeyId` (`keyId(destPublicKey)`). Single-block only at M1.
 *
 * @param {{
 *   self: any,               // this machine's own record ({name, publicKey, ...})
 *   privateKey: string,      // its Ed25519 private key (PEM)
 *   destinationKeyId: string,
 *   body: any,               // must be JSON-representable
 *   messageId: string,       // >= 128 random bits, base64url
 *   now: number,
 *   validityMs: number,
 * }} input
 * @returns {{ manifest: any, manifestSignature: string, originRecord: any, payload: string }}
 */
export function wrapRoutedMessage({ self, privateKey, destinationKeyId, body, messageId, now, validityMs }) {
  const originRecord = signRecord(self, privateKey);
  if (!originRecord) throw new Error("cannot sign the origin record");
  const bytes = bodyToBytes(body);
  const manifest = buildManifest({
    originKeyId: keyId(self.publicKey),
    destinationKeyId,
    messageId,
    issuedAt: now,
    expiresAt: now + validityMs,
    payloadMode: "clear",
    payloadDigest: payloadDigest(bytes),
  });
  return {
    manifest,
    manifestSignature: signManifest(manifest, privateKey),
    originRecord,
    payload: bytes.toString("base64"),
  };
}

/**
 * Destination side: verify a wrapper end to end and, if it is fresh, return the body.
 *
 * In order (each a fail-closed gate): recover and self-verify the origin record →
 * bind its key to the manifest's origin → verify the manifest signature → confirm the
 * message is addressed to *this* destination → confirm it is a cleartext single block
 * → confirm the payload matches its signed digest → parse it → clear the replay guard.
 * The guard is cleared last, and only after the body parses, so nothing an attacker
 * can force to fail leaves a reservation behind. Any failure returns
 * `{ ok: false, reason }`; a malformed wrapper is a refusal, never a throw.
 *
 * @param {any} wrapper the `{ manifest, manifestSignature, originRecord, payload }` shape
 * @param {{
 *   selfKeyId: string,       // keyId(this machine's public key)
 *   guard: { admit: (m: any) => { ok: true } | { ok: false, reason: string } },
 * }} deps
 * @returns {{ ok: true, body: any, originKeyId: string }
 *   | { ok: false, reason: string }}
 */
export function openRoutedMessage(wrapper, { selfKeyId, guard }) {
  if (!wrapper || typeof wrapper !== "object") return { ok: false, reason: "malformed" };
  const { manifest, manifestSignature, originRecord, payload } = wrapper;

  // 1. Recover the origin's key from the self-certifying record (TOFU: its own key).
  const rec = verifyRecord(originRecord, null);
  if (!rec.ok) return { ok: false, reason: "origin-record" };

  // 2. Bind that key to the manifest's named origin.
  let recKeyId;
  try {
    recKeyId = keyId(rec.key);
  } catch {
    return { ok: false, reason: "origin-record" };
  }
  if (typeof manifest?.originKeyId !== "string" || recKeyId !== manifest.originKeyId) {
    return { ok: false, reason: "origin-mismatch" };
  }

  // 3. The manifest is signed by that key (verifyManifest re-checks the binding too).
  if (!verifyManifest(manifest, manifestSignature, rec.key)) return { ok: false, reason: "manifest" };

  // 4. Addressed to us.
  if (manifest.destinationKeyId !== selfKeyId) return { ok: false, reason: "not-for-me" };

  // 4b. A signed field, so refusing an unknown mode here is not a downgrade a relay can
  // force: a "sealed" (or future) payload must be opened by the milestone that knows it,
  // never reinterpreted as the cleartext this function returns.
  if (manifest.payloadMode !== "clear") return { ok: false, reason: "unsupported-mode" };
  // 4c. M1 delivers whole messages; a fragment must not be handed up as a full body.
  if (manifest.blockCount !== 1) return { ok: false, reason: "multi-block" };

  // 5. The payload is the exact bytes the manifest committed to. `payload` is checked
  // to be a string first: Buffer.from(number, "base64") would allocate, not decode.
  if (typeof payload !== "string") return { ok: false, reason: "payload" };
  const bytes = Buffer.from(payload, "base64"); // lenient decode; the digest binds the result
  if (payloadDigest(bytes) !== manifest.payloadDigest) return { ok: false, reason: "payload-digest" };

  // Parse before reserving: parsing is side-effect-free, so a body that fails to parse
  // costs the attacker nothing and must not burn a replay reservation (the guard
  // promises "on refusal nothing is reserved" — keep that true from the caller's side).
  let body;
  try {
    body = JSON.parse(bytes.toString("utf8"));
  } catch {
    return { ok: false, reason: "body" };
  }

  // 6. Not a replay, and in-window.
  const admitted = guard.admit(manifest);
  if (!admitted.ok) return { ok: false, reason: `replay:${admitted.reason}` };

  return { ok: true, body, originKeyId: manifest.originKeyId };
}
