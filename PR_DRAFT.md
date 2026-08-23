# docs: document Android userspace Tailscale peers

## Summary

- Add Android phone guidance for running Termux as a full peer with userspace `tailscaled`.
- Document the separate Android app node vs. Termux userspace node topology.
- Include the tailnet-only `tailscale serve` setup and the Node HTTP proxy command for outbound `hail walk` without the Android VPN app.

## Verification

- `npm test`
- `npx -y -p typescript@5.9.3 tsc --noEmit`
- `npm run typecheck` was attempted, but the repo's TypeScript 7 package cannot resolve `@typescript/typescript-android-arm64` on Play Store Termux because that package is not published.
