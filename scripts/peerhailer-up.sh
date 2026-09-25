#!/bin/sh
# Bring a peerhailer node up after a boot, on a machine with no service manager
# (e.g. a non-systemd Puppy Linux with kernel-mode Tailscale). Idempotent: it
# skips whatever is already running, so it is safe to re-run.
#
#   sh scripts/peerhailer-up.sh        relay/destination role only
#   sh scripts/peerhailer-up.sh ui     also serve --ui (the control API and page)
#
# Environment (all optional):
#   EXPECT_ID  start of this node's fingerprint; warns if the identity reverted
#   PORT       daemon port (default 7645)
#   REPO       peerhailer checkout (default: the one this script lives in)
#
# See docs/deploy-minimal-linux.md, "No service manager".

REPO=${REPO:-$(cd "$(dirname "$0")/.." && pwd)}
PORT=${PORT:-7645}
EXPECT_ID=${EXPECT_ID:-}
HAIL="node $REPO/bin/hail.js"
UI=""; [ "$1" = "ui" ] && UI="--ui"

# 1. tailscaled, if not already up; then wait until tailscale0 has an address,
#    so the daemon's bind below does not fail with "no address to bind".
if ! tailscale status >/dev/null 2>&1; then
  mkdir -p /var/lib/tailscale /var/run/tailscale
  setsid tailscaled --state=/var/lib/tailscale/tailscaled.state \
    --socket=/var/run/tailscale/tailscaled.sock >/var/log/tailscaled.log 2>&1 </dev/null &
  sleep 2
fi
tailscale up >/dev/null 2>&1 || true
i=0; while [ -z "$(ip -4 -o addr show tailscale0 2>/dev/null)" ] && [ "$i" -lt 30 ]; do sleep 1; i=$((i+1)); done
echo "[up] tailscale: $(tailscale ip -4 2>/dev/null || echo DOWN)"

# 2. Identity check: did the last save keep the key peers pin? A save-file
#    Puppy that rebooted uncleanly can come back with a freshly generated one.
ID=$($HAIL status 2>/dev/null | sed -n 's/^key:[[:space:]]*//p')
echo "[up] identity: $ID"
if [ -n "$EXPECT_ID" ]; then
  case "$ID" in
    "$EXPECT_ID"*) echo "[up]   ok: peers still pin this key" ;;
    *) echo "[up]   WARNING: expected $EXPECT_ID...; the identity reverted, re-pin it on peers" ;;
  esac
fi

# 3. The daemon, unless something already holds the port.
if ss -H -ltn 2>/dev/null | grep -q ":$PORT "; then
  echo "[up] daemon: already listening on :$PORT"
else
  setsid sh -c "exec $HAIL daemon --hail-on-tls tailscale0 --port $PORT --route $UI \
    >\$HOME/hail-daemon.log 2>&1 </dev/null" &
  sleep 2
fi
tail -n 4 "$HOME/hail-daemon.log"
echo "[up] peers:"; $HAIL peers
