# Identity security (design)

**Status: design / threat model, not built.** This records how peerhailer stores a
node's identity today, what an attacker gains by stealing or faking it, and the
protections worth building — with an honest account of what each one does and does
*not* stop. The concrete work items live in `docs/backlog.md` under "Identity
persistence + encryption at rest"; this is the reasoning behind them.

## What the identity is

A peerhailer node **is** its Ed25519 identity key (`src/identity.js`). The name is a
label; the key is what signs, and a key either signed something or it did not. The
private key, plus an X25519 **sealing** key beside it, lives at
`<statedir>/identity.json` — JSON, written atomically, `mode 0o600`.

The identity key is the root of every trust decision on the wire:

- **TLS impersonation.** The TLS cert key is a *disposable subkey* the identity
  **vouches** for: the daemon generates a fresh Ed25519 cert key and has the identity
  sign `{k: cert-key, u: until}`, carried as a `subjectAltName` (`src/cert.js`,
  `docs/tls.md`). A peer pins by checking that vouch against the identity key it holds.
  So whoever holds the identity key can mint a vouch for *any* cert key and pass the
  pin — full impersonation at the transport layer. The subkey indirection means an
  OpenSSL bug leaks only a throwaway cert key, but it does nothing to protect the
  identity key *at rest*, which is the crown jewel.
- **Signed directory records.** The identity signs a node's own record — its
  addresses and metadata — so peers accept "find me here" as a claim only the key
  holder could make (`src/peerRecord.js`).
- **Routing.** The origin signs the route manifest and self-record; receipts are
  signed (`src/routeManifest.js`, `src/routeReceipt.js`). Faking the identity forges
  origin attribution across the fabric.
- **Sealing relationship.** The identity anchors which sealing key is "mine," so
  stealing it undermines confidential delivery too.

One stolen file, therefore, is not "a key" — it is the node. Every pin, grant, seal
marker and route attribution other machines hold for it becomes forgeable.

## Current state, and its two gaps

1. **Plaintext at rest.** `identity.json` is unencrypted, protected only by `mode
   600` — and that is weak exactly where it is relied on: on Windows the NTFS ACL is
   inherited, not set by `chmod` (noted in `src/identity.js`'s own header). A file
   people are invited to `cat`, back up, and paste is a poor place for the one secret
   that is the node.
2. **Silent regeneration.** `loadIdentity` mints a *brand-new* identity on a missing
   file (ENOENT) with only a stderr log line — no warning, no refusal. A fresh, moved,
   cleaned, or wrong-`--home` state dir therefore silently becomes a *different node*,
   and every peer that pinned the old key rejects it with `TLS pin failed`. We hit this
   live: a Puppy node's key rotated `BvXN7…` → `z7R3j…` across a rebuild and broke the
   caller's pin. (Credit where due: the non-ENOENT read-error path already fails safe —
   it throws rather than overwrite a key it merely failed to read — so the gap is
   narrowly the ENOENT→generate branch.)

These are one feature, not two: any encryption-at-rest scheme that can *fail to
decrypt* (moved dir, missing keyring entry) must fail **loud**, never by minting a new
identity. Otherwise it trades the plaintext-secret footgun for the silent-rotation
footgun.

## Threat model

Enumerate the adversary, and the boundary each one runs into.

| Adversary | What they want | What actually stops them |
| --- | --- | --- |
| **Network MITM** | Impersonate a peer on the wire | The pin/vouch (`docs/tls.md`). *Out of scope here* — already handled, and the reason the at-rest key matters so much. |
| **Offline theft** — a backup, a disk image, a powered-off stolen device | Read `identity.json` later | Encryption at rest (any wrap), or full-disk encryption while powered off. |
| **Other OS users** on a shared box | Read the file / ptrace the daemon | `mode 600` + a **dedicated uid** for the daemon. |
| **Same-uid live process** — malware running as the daemon's own user | Read the decrypted key from memory, or read the plaintext file | The hard case. Neither file mode nor an at-rest passphrase helps once the daemon is running: to sign, the key is decrypted in memory, and a same-uid process can read it (`/proc/pid/mem`, ptrace) or capture the passphrase. Only **process isolation** or a **keystore that signs without exposing the key** helps. |
| **Other apps on Android** | Read Termux's files | Android's per-**app** sandbox already isolates them — a *different* uid per app, enforced by the kernel and SELinux. Strong, and free, *as long as the key stays in Termux's private app data*. |

The uncomfortable row is **same-uid live process**. A passphrase answers *offline*
theft — a narrower threat than the one usually meant by "a malicious process could
fake my identity." Say so plainly rather than let an encrypted file imply a
protection it does not give.

## What each mitigation buys

- **Encryption at rest (passphrase or keystore-wrapped).** Stops offline theft and a
  casual same-uid *file* read (the bytes are ciphertext). Does **not** stop a same-uid
  process reading the running daemon's memory, nor a keylogged passphrase. Real, but
  bounded.
- **Dedicated uid.** Makes `mode 600` mean something: other users can neither read the
  file nor ptrace the process. The cheapest genuine win on a multi-user OS — **and
  unavailable on a non-rooted Android phone** (see below).
- **A keystore that signs without exposing the key** — TPM, Secure Enclave, Android
  Keystore (TEE/StrongBox), or a PKCS#11 token. The private key never becomes
  app-readable bytes; a compromise can *request* signatures while it has access but can
  never exfiltrate the identity, and the key survives a wipe of the box. This is the
  real answer to impersonation. Honest residual: a *live* compromise can still ask it
  to sign during its window — bounding that is a grants / short-lived-credential
  question, separate from protecting the long-term key.

## The Android / Termux case

A non-rooted Termux node is the sharpest instance of the same-uid problem, and worth
spelling out because the usual "dedicated uid" advice does not apply.

- **No separate uids.** Without root you cannot run the daemon under its own user.
  Termux is a single Android app with a single uid (e.g. `u0_a352`), and *every*
  Termux process shares it and the same SELinux domain.
- **The file is the soft target.** `identity.json` sits in Termux's private app data.
  Other **apps** cannot read it — the Android sandbox is a real, kernel-enforced
  boundary between apps. But every **Termux process** can: same uid, same domain, same
  app-data directory. A hostile script you run inside Termux reads the key directly,
  no exploit required.
- **Memory: assume readable.** In principle Yama `ptrace_scope` and SELinux restrict
  cross-process `ptrace`/`/proc/pid/mem` even at the same uid. In practice ptrace works
  *within* Termux (debuggers like `gdb` run there), so treat a same-uid process as able
  to read the daemon's decrypted key in the worst case. **The user's assumption — "if
  it's not rooted we can't have different users, so the memory is readable" — is the
  correct conservative posture.** The file is merely the *easier* target; encrypting it
  does not close the memory path.

What this leaves for a phone:

- **Android Keystore is the right fix** — hardware-backed (TEE/StrongBox), the key
  never enters app-readable space, and it signs on request. It defeats even a hostile
  same-uid Termux process, which is exactly the gap. **But reaching it from Termux Node
  is a feasibility problem:** there is no Node binding, and Termux's `termux-api` does
  not expose the keystore. It would take a companion mechanism — a small helper APK, a
  JNI/`am`-invoked shim, or an upstream `termux-api` addition — to have the phone sign
  through Keystore rather than with an in-process key. Document the gap; do not assume
  the ideal is reachable for free.
- **Interim honest posture.** Until a Keystore path exists, a Termux node's practical
  protections are: the Android app sandbox (against other apps), full-disk encryption
  (against powered-off theft), and treating **Termux itself as a trust boundary you
  own** — only run inside it what you would trust with the identity. Optionally
  passphrase-wrap the file: it turns a same-uid *file* read into ciphertext and covers
  offline theft, at the cost of unattended boot (a headless phone daemon cannot type a
  passphrase). It does **not** protect the running key in memory. That trade is the
  operator's to make, stated as such.

## Target posture: encrypted by default, passwordless by default

The design we want, once the pieces exist:

- **Never plaintext by default.** The wrapping key comes from the strongest
  *passwordless* mechanism a platform offers — an OS keystore (macOS Keychain, Windows
  DPAPI, libsecret, Android Keystore), unlocked by the login session. Encrypted at rest
  **and** nothing to remember. This is the actual resolution of "I hate passwords":
  don't build around one.
- **A passphrase is the exception, not the mechanism** — reserved for the portable
  **export/backup** path and for a keystore-less machine where the operator explicitly
  wants at-rest protection.
- **Two conditions keep default-on honest.** (1) It MUST fail *loud* when it cannot
  decrypt and never silently mint a new identity — the same fix as the regeneration
  gap. (2) A headless node cannot default to a typed passphrase (it breaks unattended
  boot), so where there is no keystore, "by default" degrades to a machine-bound wrap
  **labeled as weak** against a same-uid/live process, or plaintext + `600` +
  dedicated-uid with a warning — never *unlabeled* encryption theater. A wrap whose key
  sits readable beside it protects nothing.

## Per-platform recommendation

| Node | At-rest protection | Password? | Notes |
| --- | --- | --- | --- |
| Interactive workstation | OS keychain (login-unlocked), or passphrase via an agent | none / once per boot | Dedicated uid is the cheap immediate win. |
| Headless relay (e.g. Puppy) | TPM, or FDE + dedicated uid | none, or one at boot via an agent | No interactive prompt at boot; lean on hardware or isolation. |
| **Android / Termux (non-rooted)** | Android Keystore *(feasibility-gated)*; interim: app-sandbox + FDE | none | **No separate uid possible**; same-uid processes can read the key file, and memory in the worst case. Keystore is the real fix but not yet reachable from Termux Node. |
| Portable backup / moving a node | passphrase-wrapped export | one, rarely | The one place a remembered password earns its keep. |

## Staging (respecting zero-runtime-dep)

Real keyring integration means shelling out to platform CLIs (`security`,
`secret-tool`, DPAPI via PowerShell, an Android keystore helper) rather than adding an
npm dependency — per platform. So default-on is the end state, not the first step.

1. **Now, cheap:** dedicated-uid operator guidance, and the **loud
   no-silent-regeneration** refusal (`--refuse-new-identity` / a warning on the ENOENT
   branch). Plus identity **export/import** so a node keeps its key across a rebuild or
   move — the rotation-safety half.
2. **Next:** opt-in encryption — an OS-keyring or passphrase wrap of the Ed25519 (and
   the X25519 seal key), with a migration path for existing plaintext identities.
3. **Last:** make it the default, with the honest headless fallback above.

## Open questions

- Does the X25519 sealing key share the wrap, or get its own?
- Migration for existing plaintext `identity.json` — silent upgrade on next start, or
  an explicit `hail identity encrypt`?
- An ssh-agent-style holder for keystore-less interactive nodes (type once per boot)?
- The Termux → Android Keystore bridge: helper APK vs. JNI shim vs. upstream
  `termux-api` — scoped separately; it gates the phone's strong path.

## Non-goals

- Network-layer impersonation — handled by the pin/vouch (`docs/tls.md`).
- Protecting a *live, already-compromised* host from being asked to sign during the
  compromise window — a grants / short-lived-credential concern, not an at-rest one.
- Hand-rolled cryptography — the project's one crypto operation is a signature; any
  wrap must use a vetted KDF + AEAD from Node's `crypto`, no invented schemes.

## Prior art in-repo

- `src/identity.js` — `loadIdentity` / `saveIdentity` / `defaultIdentityPath`, the
  ENOENT regeneration, the `mode 600` caveat.
- `src/cert.js`, `docs/tls.md` — the vouch/subkey model the identity anchors.
- `src/gate.js` — `hashPassword` and the session model, the closest existing password
  UX to borrow from.
- `docs/backlog.md` — the tracked work items and their sequencing.
