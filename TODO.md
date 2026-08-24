# TODO

Small, deferred items. Nothing here blocks anything; captured so they aren't lost.

_Nothing pending._

## Done

- [x] **Add `PREFIX` to `scrubEnv`'s allowlist** — a plain `SAFE_ENV_KEYS` entry
      in `src/builtin/shellPlugin.js`, so a Termux shell's `$PREFIX` is no longer
      empty. It is a benign path (nothing in libc interprets it) whose value
      comes from the daemon's own env, so it needs no value check.

- [x] **WSL caller: resolve MagicDNS natively** — documented as its own section
      in [docs/shell.md](docs/shell.md#driving-a-shell-from-wsl-or-any-caller-that-cannot-resolve-magicdns).
      A caller-side DNS fix (`tailscale set --accept-dns` preferred), which
      removes the per-command preload. No code change: resolution is the caller's
      OS concern, not peerhailer's.
