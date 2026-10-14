#!/usr/bin/env bash
# Nightly backup of a MedSeal production stack (run from deploy/, e.g. from cron):
#   ./backup.sh                 # -> deploy/backups/medseal-<UTC timestamp>/
#   KEEP_DAYS=30 ./backup.sh    # retention (default 14 days)
#
# What it contains:
#   db.dump        pg_dump (custom format)    restore: pg_restore -d medseal --clean db.dump
#   anchors.tgz    external ledger anchors    (evidence: must survive with the database)
#   keys.tgz       encrypted key files, root.pub
#   storage.tgz    encrypted sealed images
# What it deliberately does NOT contain: MEDSEAL_DATA_KEY and the HSM. Without the data key the
# keys and images in this backup are unreadable - keep the key offline, in a different place.
set -euo pipefail
cd "$(dirname "$0")"
COMPOSE=(docker compose -f docker-compose.prod.yml --env-file .env.prod)
out="backups/medseal-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out" && chmod 700 backups "$out"

"${COMPOSE[@]}" exec -T db pg_dump -U medseal -d medseal -Fc > "$out/db.dump"
for vol in anchors keys storage; do
  "${COMPOSE[@]}" run --rm --no-deps -T --entrypoint tar worker -czf - -C "/data/$vol" . > "$out/$vol.tgz"
done
( cd "$out" && sha256sum ./* > SHA256SUMS )
find backups -maxdepth 1 -name 'medseal-*' -mtime +"${KEEP_DAYS:-14}" -exec rm -rf {} +
echo "backup written to $out"
