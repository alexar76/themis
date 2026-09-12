#!/usr/bin/env bash
# Reconcile the THEMIS auditor sidecar into the CURRENT modelmarket-hub netns.
#
# THEMIS has no network namespace of its own: it joins the hub's via
#   --network container:modelmarket-hub
# because the hub's SSRF guard exempts only loopback (it calls the auditor at
# http://127.0.0.1:8080/invoke). A hub *recreate* therefore strands THEMIS in the
# deleted container's dead netns — reachable by nothing, yet still "healthy"
# (its healthcheck runs inside that dead netns). That is the 2026-09-08 502.
#
# This script re-creates THEMIS attached to whatever hub container is live now,
# binding the right interface for the hub's current network mode. It is idempotent:
# if THEMIS is already attached to the live hub it does nothing (unless FORCE=1).
#
# Env knobs: HUB, THEMIS_BASE_ENV, THEMIS_VOL, IMG (pin an image), FORCE=1 (always
# recreate — used by a deliberate image deploy).
set -uo pipefail

HUB="${HUB:-modelmarket-hub}"
BASE_ENV="${THEMIS_BASE_ENV:-/root/themis.env}"   # supplies AIMARKET_PROVIDER_IDENTITY_FILE etc.
VOL="${THEMIS_VOL:-themis_data}"
IMG="${IMG:-}"
FORCE="${FORCE:-0}"
log() { echo "[themis-reattach] $(date -u +%FT%TZ) $*"; }

hubid=$(docker inspect -f '{{.Id}}' "$HUB" 2>/dev/null || true)
if [ -z "$hubid" ]; then log "hub '$HUB' not running; leaving THEMIS as-is"; exit 0; fi

trun=$(docker inspect -f '{{.State.Running}}' themis 2>/dev/null || echo false)
tnet=$(docker inspect -f '{{.HostConfig.NetworkMode}}' themis 2>/dev/null || echo none)
if [ "$trun" = "true" ] && [ "$tnet" = "container:$hubid" ] && [ "$FORCE" != "1" ]; then
  log "already attached to live hub ${hubid:0:12}; ok"; exit 0
fi

# Pick the image: an explicit IMG wins; else keep THEMIS's current image if we can
# still see it; else themis:prod; else the newest themis:* image on the host.
img="$IMG"
[ -z "$img" ] && img=$(docker inspect -f '{{.Config.Image}}' themis 2>/dev/null || true)
if [ -z "$img" ]; then
  if docker image inspect themis:prod >/dev/null 2>&1; then
    img=themis:prod
  else
    img=$(docker images --format '{{.Repository}}:{{.Tag}} {{.CreatedAt}}' | awk '$1 ~ /^themis:/{print $1; exit}')
  fi
fi
if [ -z "$img" ]; then log "no themis image available; cannot attach"; exit 1; fi

# Bind interface follows the hub's network mode:
#   host-net hub  -> 127.0.0.1  (nginx and the hub both reach it on the host loopback;
#                                 NOT exposed to the internet)
#   bridge hub    -> 0.0.0.0    (so the hub's own -p 127.0.0.1:9460:8080 can reach it)
hubmode=$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$HUB" 2>/dev/null || echo host)
if [ "$hubmode" = "host" ]; then bindhost=127.0.0.1; else bindhost=0.0.0.0; fi

envfile=$(mktemp /run/themis.env.XXXXXX)
[ -f "$BASE_ENV" ] && grep -vE '^HOST=' "$BASE_ENV" > "$envfile"
echo "HOST=$bindhost" >> "$envfile"
chmod 600 "$envfile"

log "attaching THEMIS img=$img into hub ${hubid:0:12} mode=$hubmode bind=$bindhost"
docker rm -f themis >/dev/null 2>&1 || true
docker run -d --name themis --restart unless-stopped \
  --network "container:$hubid" \
  -v "$VOL":/data --env-file "$envfile" \
  "$img" >/dev/null
rc=$?
rm -f "$envfile"
if [ $rc -ne 0 ]; then log "docker run failed rc=$rc"; exit $rc; fi

sleep 4
health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' themis 2>/dev/null || echo unknown)
log "attached; health=$health"
