# TODO

Small, deferred items. Nothing here blocks anything; captured so they aren't lost.

## Shell plugin on Termux

- [ ] **Add `PREFIX` to `scrubEnv`'s allowlist** (`src/builtin/shellPlugin.js`).
      A Termux session's `$PREFIX` currently comes back empty, so scripts that
      read it break (plain commands are fine via `PATH`). `PREFIX` is a benign
      path, not a secret — same shape as the `libtermux-exec.so` shim entry.

- [ ] **WSL caller: resolve MagicDNS natively.** Driving a shell from WSL into a
      `.ts.net` peer needs a per-command DNS preload today, because WSL doesn't
      wire Tailscale's resolver. Fix on the caller: `tailscale set --accept-dns`
      in WSL, or point `/etc/resolv.conf` at `100.100.100.100`. Then the preload
      goes away.
