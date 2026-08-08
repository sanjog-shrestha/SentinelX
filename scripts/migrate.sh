#!/bin/sh
# Applies every migration in migrations/ in filename order.
#
# Safe to re-run: every migration uses CREATE TABLE IF NOT EXISTS /
# ADD COLUMN IF NOT EXISTS, so re-applying is a no-op. This is why
# idempotent migrations matter — you can always just run them all.
#
# ON_ERROR_STOP=1 makes psql exit on the first failure instead of
# plowing ahead and leaving the schema half-applied.
set -e
for f in migrations/*.sql; do
  echo "applying $f"
  docker compose exec -T postgres psql -v ON_ERROR_STOP=1 \
    -U "${POSTGRES_USER:-sentinelx}" \
    -d "${POSTGRES_DB:-sentinelx}" < "$f"
done
echo "migrations complete"