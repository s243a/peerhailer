/**
 * Permission you make when it is needed, rather than one you keep.
 *
 * The directory deliberately holds no credentials: a record says a machine
 * exists and where it answered, and nothing in it opens a door. That leaves a
 * gap this fills. Sometimes a peer must prove to a *third* machine that it is
 * allowed something — that `luna` may relay through `mars`, on `sol`'s say-so —
 * and the third machine has never heard of it.
 *
 * A grant is a short-lived signed assertion, minted for one subject and one set
 * of capabilities. It is not stored, not replicated, and worthless once it
 * expires, which is what makes it safe to hand over a channel a directory entry
 * could never travel.
 *
 * Three rules, and each closes a way this becomes a bearer token by accident:
 *
 * **A grant names its subject by key.** It authorises *that* machine, not
 * whoever holds the bytes. Intercepting one gains nothing without the private
 * key it was minted for.
 *
 * **A grant cannot widen.** An issuer may only delegate capabilities it holds,
 * and re-minting from a grant may only narrow. Otherwise delegation is
 * escalation with extra steps.
 *
 * **A grant expires, and briefly.** Minutes, not months. Anything long-lived is
 * a credential in all but name, and a credential is the thing this design keeps
 * refusing to store.
 *
 * @module grants
 */
import { canonicalize, normalizeKey, sameKey, signPayload, verifyPayload } from "./identity.js";

/** Long enough to use, short enough that a copy is not worth keeping. */
export const DEFAULT_TTL_MS = 5 * 60_000;
/** Nobody needs a grant that outlives the conversation it was minted for. */
export const MAX_TTL_MS = 60 * 60_000;

/**
 * @typedef {{
 *   issuer: string,
 *   issuerKey: string,
 *   subjectKey: string,
 *   capabilities: string[],
 *   notBefore: number,
 *   expires: number,
 *   nonce: string,
 * }} GrantBody
 */

/**
 * Mint a grant for one peer, for one set of capabilities, for a short while.
 *
 * `allowed` is what the issuer may actually delegate — usually what its own
 * profile grants at the machine that will check this. Anything asked for beyond
 * it is dropped rather than refused, so a caller asking for more than it can
 * have still gets what it can.
 *
 * @param {{
 *   issuer: string,
 *   issuerKey: string,
 *   privateKey: string,
 *   subjectKey: string,
 *   capabilities: string[],
 *   allowed?: string[],
 *   ttlMs?: number,
 *   now?: number,
 *   nonce?: string,
 * }} input
 * @returns {{grant: GrantBody, signature: string} | null}
 */
export function mintGrant({
  issuer,
  issuerKey,
  privateKey,
  subjectKey,
  capabilities,
  allowed,
  ttlMs = DEFAULT_TTL_MS,
  now = Date.now(),
  nonce,
}) {
  const subject = normalizeKey(subjectKey);
  const key = normalizeKey(issuerKey);
  if (!subject || !key || typeof issuer !== "string" || issuer.length === 0) return null;

  const asked = [...new Set((capabilities ?? []).filter((c) => typeof c === "string" && c))];
  // Narrowing, never widening: an issuer hands on a subset of what it holds.
  const granted = allowed ? asked.filter((capability) => allowed.includes(capability)) : asked;
  if (granted.length === 0) return null;

  const body = {
    issuer,
    issuerKey: key,
    subjectKey: subject,
    capabilities: granted.sort(),
    notBefore: now,
    expires: now + Math.min(Math.max(Number(ttlMs) || 0, 1_000), MAX_TTL_MS),
    // Not for replay prevention — the expiry bounds that — but so two grants
    // minted in the same millisecond are distinguishable in a log.
    nonce: nonce ?? Math.random().toString(36).slice(2, 12),
  };
  return { grant: body, signature: signPayload(body, privateKey) };
}

/**
 * Check a grant, and say precisely why not.
 *
 * `presenterKey` is the key the caller actually authenticated with. A grant is
 * for a machine, so a grant presented by anyone else is refused however valid
 * its signature — that check is the whole difference between this and a bearer
 * token.
 *
 * @param {any} envelope
 * @param {{
 *   presenterKey?: string | null,
 *   issuerKey?: string | null,
 *   capability?: string,
 *   now?: number,
 * }} [expectations]
 * @returns {{ok: true, grant: GrantBody} | {ok: false, error: string}}
 */
export function verifyGrant(envelope, { presenterKey, issuerKey, capability, now = Date.now() } = {}) {
  const grant = envelope?.grant;
  if (!grant || typeof grant !== "object") return { ok: false, error: "no grant" };
  if (!Array.isArray(grant.capabilities) || grant.capabilities.length === 0) {
    return { ok: false, error: "grant carries no capabilities" };
  }
  if (!verifyPayload(grant, envelope?.signature, grant.issuerKey ?? "")) {
    return { ok: false, error: "grant signature did not verify" };
  }
  if (issuerKey && !sameKey(grant.issuerKey, issuerKey)) {
    return { ok: false, error: "grant was issued by a different key than expected" };
  }
  if (presenterKey && !sameKey(grant.subjectKey, presenterKey)) {
    // The rule that stops a grant being a bearer token: it names its holder.
    return { ok: false, error: "grant was minted for another machine" };
  }
  if (Number(grant.notBefore) > now) return { ok: false, error: "grant is not valid yet" };
  if (Number(grant.expires) <= now) return { ok: false, error: "grant has expired" };
  if (capability && !grant.capabilities.includes(capability)) {
    return { ok: false, error: `grant does not carry ${capability}` };
  }
  return { ok: true, grant };
}

/**
 * Re-mint a grant for someone else, no wider than the original.
 *
 * The subject of a grant may pass a piece of it on — a peer told it may relay
 * can tell a third machine so — and the piece is never larger than what it
 * holds, nor longer-lived.
 *
 * @param {{grant: GrantBody, signature: string}} envelope
 * @param {{
 *   issuer: string,
 *   issuerKey: string,
 *   privateKey: string,
 *   subjectKey: string,
 *   capabilities?: string[],
 *   ttlMs?: number,
 *   now?: number,
 * }} input
 */
export function attenuate(envelope, input) {
  const now = input.now ?? Date.now();
  const checked = verifyGrant(envelope, { presenterKey: input.issuerKey, now });
  if (!checked.ok) return null;

  const asked = input.capabilities ?? checked.grant.capabilities;
  const remaining = Math.max(0, checked.grant.expires - now);
  return mintGrant({
    ...input,
    capabilities: asked,
    // Bounded by what the parent still has, so a chain of grants cannot
    // outlive the one it descends from.
    allowed: checked.grant.capabilities,
    ttlMs: Math.min(input.ttlMs ?? remaining, remaining),
  });
}

/**
 * A stable one-line form, for logs and for humans comparing two of them.
 *
 * @param {any} grant
 */
export function describeGrant(grant) {
  const when = new Date(grant?.expires ?? 0).toISOString();
  return `${grant?.issuer} → ${String(grant?.subjectKey ?? "").slice(27, 39)}… [${(grant?.capabilities ?? []).join(", ")}] until ${when}`;
}

export { canonicalize };
