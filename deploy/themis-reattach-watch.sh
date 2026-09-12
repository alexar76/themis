#!/usr/bin/env bash
# Keep THEMIS attached to the live hub, whatever recreates the hub.
#
# Reconciles once at start (covers a boot, a missed event, or a crashed watcher),
# then again on every modelmarket-hub 'start' event. 'start' fires on create-start,
# `docker start` and `docker restart`, so any deploy path is covered — including a
# bare `docker run` that knows nothing about THEMIS.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REATTACH="${DIR}/themis-reattach.sh"
HUB="${HUB:-modelmarket-hub}"

echo "[themis-reattach] watcher starting; hub=$HUB reattach=$REATTACH"
"$REATTACH" || true

# No --format on purpose: the event template fields differ across Docker versions
# ({{.Status}} does not exist on newer *events.Message and makes `docker events`
# exit immediately, which silently turns this watcher into a restart loop). The
# raw line is perfectly good for a log. The filter matches the hub by NAME, so it
# also matches the NEW container after a recreate under the same name.
docker events --filter "container=${HUB}" --filter 'event=start' \
| while read -r line; do
    echo "[themis-reattach] hub event: $line"
    sleep 2   # let the hub settle before borrowing its netns
    "$REATTACH" || true
  done

echo "[themis-reattach] docker events stream ended; systemd will restart this unit"
