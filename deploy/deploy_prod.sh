#!/usr/bin/env bash
# Deploy THEMIS beside the production Hub and wire the admission gate.
#
#   ./deploy_prod.sh advisory   # first run: record verdicts, block nothing
#   ./deploy_prod.sh enforce    # only after a real verdict has been observed
#   ./deploy_prod.sh rollback   # restore the previous hub image and env
#
# The production Hub is not managed by compose: it is a plain `docker run`
# container. It is therefore recreated from the env captured off the running
# container, so no secret ever has to leave the server or pass through a
# deploy pipeline. The previous image tag and env are kept for rollback.
#
# The Hub database is SQLite in the `modelmarket_hub_data` volume; it is copied
# before anything else runs. Migration 021 is additive (ADD COLUMN / CREATE
# TABLE), so the previous image also starts fine against the migrated file —
# that is what makes the rollback path real rather than theoretical.
#
# TOPOLOGY: the auditor runs inside the Hub's own network namespace
# (--network container:modelmarket-hub) and is reached on 127.0.0.1:8080. That is
# not a shortcut — the Hub's SSRF guard only exempts loopback, so a private
# docker-network address is refused by design, and this way the auditor is never
# exposed off-host at all.
#
# ORDERING CONSEQUENCE, and the reason `enforce` is a separate decision: the
# auditor's netns belongs to the Hub container. Recreate the Hub and the auditor
# must be started again after it; on a daemon restart Docker does not guarantee
# that order, so `--restart unless-stopped` can leave the auditor down. In
# `advisory` that costs a recorded verdict. In `enforce` it fails closed and
# blocks every publish. Give the auditor its own HTTPS ingress, or encode the
# ordering in a compose unit, before living in `enforce`.
set -euo pipefail

HOST="${THEMIS_PROD_HOST:-my-vps}"
REMOTE="${THEMIS_PROD_PATH:-/root/claudecode/aicom}"
MODE="${1:-advisory}"
STAMP="$(date +%Y%m%d-%H%M%S)"
NET="aicom_aicom_net"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

case "$MODE" in
  advisory | enforce | off | rollback) ;;
  *)
    echo "usage: $0 [advisory|enforce|off|rollback]" >&2
    exit 2
    ;;
esac

if [ "$MODE" = "rollback" ]; then
  ssh "$HOST" "set -e
    cd $REMOTE
    previous=\$(cat deploy-admission/previous-image.txt)
    echo \"restoring \$previous\"
    docker rm -f modelmarket-hub
    docker run -d --name modelmarket-hub --restart unless-stopped \
      --network $NET -p 127.0.0.1:9083:9083 \
      -v modelmarket_hub_data:/app/data \
      -v $REMOTE/data:/factory_data:ro \
      --env-file deploy-admission/hub.env.previous \
      \"\$previous\"
    sleep 6
    docker ps --filter name=modelmarket-hub --format '{{.Status}}'"
  exit 0
fi

echo "── 1/6 sync source"
rsync -az --exclude '.venv' --exclude '__pycache__' --exclude '.pytest_cache' \
  --exclude '.git' --exclude 'docs/landing' --exclude 'docs/screenshots' \
  --exclude '.aimarket' "$ROOT/themis/" "$HOST:$REMOTE/themis/"
rsync -az --exclude '.venv' --exclude '__pycache__' --exclude '.pytest_cache' \
  --exclude '*.db' "$ROOT/aimarket-hub/" "$HOST:$REMOTE/aimarket-hub/"

echo "── 2/6 back up the hub database, capture its env once"
ssh "$HOST" "set -e
  cd $REMOTE && mkdir -p deploy-admission
  docker run --rm -v modelmarket_hub_data:/data -v $REMOTE/deploy-admission:/backup alpine \
    cp /data/hub.db /backup/hub.db.bak-$STAMP
  if [ ! -f deploy-admission/hub.env.previous ]; then
    docker inspect modelmarket-hub --format '{{range .Config.Env}}{{println .}}{{end}}' \
      | grep -vE '^(PATH|PYTHON|LANG|GPG_KEY)=' | grep -v '^\$' > deploy-admission/hub.env.previous
    chmod 600 deploy-admission/hub.env.previous
    docker inspect modelmarket-hub --format '{{.Config.Image}}' > deploy-admission/previous-image.txt
  fi
  echo \"backup: hub.db.bak-$STAMP, rollback image: \$(cat deploy-admission/previous-image.txt)\""

echo "── 3/6 build the auditor and read its pinned key"
# The key lives in the themis_data volume, so it survives every redeploy and can
# be read from a throwaway container before the long-lived one exists.
ssh "$HOST" "set -e
  cd $REMOTE/themis
  docker build -q -t themis:prod-$STAMP -t themis:prod . >/dev/null
  docker run --rm -v themis_data:/data themis:prod-$STAMP \
    python -c \"from provider_signing import ProviderSigner; print(ProviderSigner().public_key_b64)\" > /tmp/themis.pubkey
  echo \"auditor key \$(cut -c1-12 /tmp/themis.pubkey)…\""

echo "── 4/6 pin the auditor into the hub env (mode: $MODE)"
# Loopback, because the Hub's SSRF guard exempts nothing else: a docker-network
# name resolves to an RFC1918 address and is refused, and ALLOW_INSECURE only
# relaxes the HTTPS rule. Loopback also needs no TLS and no exposed port.
ssh "$HOST" "set -e
  cd $REMOTE
  key=\$(cat /tmp/themis.pubkey)
  grep -vE '^AIMARKET_SUPPLY_CHAIN_' deploy-admission/hub.env.previous > deploy-admission/hub.env
  {
    echo \"AIMARKET_SUPPLY_CHAIN_ADMISSION_MODE=$MODE\"
    echo 'AIMARKET_SUPPLY_CHAIN_AUDITOR_URL=http://127.0.0.1:8080/invoke'
    echo \"AIMARKET_SUPPLY_CHAIN_AUDITOR_PUBKEY=\$key\"
  } >> deploy-admission/hub.env
  chmod 600 deploy-admission/hub.env"

echo "── 5/6 rebuild the hub, then attach the auditor to its namespace"
# Built from the repository ROOT: the hub Dockerfile copies aimarket-hub/… paths.
# The auditor must start AFTER the hub, since it borrows the hub's netns.
ssh "$HOST" "set -e
  cd $REMOTE
  docker build -q -f aimarket-hub/Dockerfile -t modelmarket-hub:prod-$STAMP-admission . >/dev/null
  docker rm -f themis >/dev/null 2>&1 || true
  docker rm -f modelmarket-hub >/dev/null
  docker run -d --name modelmarket-hub --restart unless-stopped \
    --network $NET -p 127.0.0.1:9083:9083 \
    -v modelmarket_hub_data:/app/data \
    -v $REMOTE/data:/factory_data:ro \
    --env-file deploy-admission/hub.env \
    modelmarket-hub:prod-$STAMP-admission >/dev/null
  sleep 8
  docker run -d --name themis --restart unless-stopped \
    --network container:modelmarket-hub \
    -v themis_data:/data themis:prod-$STAMP >/dev/null
  sleep 6"

echo "── 6/6 verify"
ssh "$HOST" "set -e
  docker ps --filter name=themis --filter name=modelmarket-hub --format '{{.Names}}\t{{.Status}}'
  echo '--- migrations'
  docker logs modelmarket-hub 2>&1 | grep -iE 'migrat|021' | tail -5 || true
  echo '--- admission summary'
  curl -fsS http://127.0.0.1:9083/ai-market/v2/supply/audits \
    | python3 -c 'import json,sys;d=json.load(sys.stdin)[\"summary\"];print(json.dumps({k:d[k] for k in (\"mode\",\"configured\",\"enforce_readiness\") if k in d},indent=1))'
  echo '--- hub log tail'
  docker logs --tail 12 modelmarket-hub 2>&1 | tail -12"

echo
echo "done (mode: $MODE)."
echo "Read enforce_readiness above. When ready_for_enforce is true: $0 enforce"
echo "If anything looks wrong: $0 rollback"
