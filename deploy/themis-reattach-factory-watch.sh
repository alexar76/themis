#!/usr/bin/env bash
# factory-vps: keep THEMIS reachable from the live modelmarket-hub (see themis-reattach.py).
# Reconciles at start, then after every hub 'start' event (create-start, docker start and
# docker restart all emit it). themis-reattach-check.timer covers missed events.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HUB="${HUB:-modelmarket-hub}"
echo "[themis-reattach] watcher starting; hub=$HUB"
python3 "$DIR/themis-reattach.py" || true
# No --format: event template fields differ across Docker versions (09-08 restart loop).
docker events --filter "container=${HUB}" --filter 'event=start' \
| while read -r line; do
    echo "[themis-reattach] hub event: ${line:0:160}"
    sleep 5   # let the hub settle before checking its namespace
    python3 "$DIR/themis-reattach.py" || true
  done
echo "[themis-reattach] docker events stream ended; systemd restarts this unit"
