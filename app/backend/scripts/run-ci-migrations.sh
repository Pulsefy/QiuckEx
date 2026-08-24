#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# run-ci-migrations.sh
#
# Runs every Supabase SQL migration file against a PostgreSQL database in
# alphabetical (timestamp) order.  Used by CI to validate that migrations
# are syntactically correct and produce the expected schema.
#
# Required environment variables:
#   DATABASE_URL  – Postgres connection string, e.g.
#                   postgresql://user:pass@localhost:5432/quickex_test
#
# Optional:
#   MIGRATIONS_DIR – Override the default migrations directory
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

MIGRATIONS_DIR="${MIGRATIONS_DIR:-$(dirname "$0")/../supabase/migrations}"

if [ -z "${DATABASE_URL:-}" ]; then
  echo "❌ DATABASE_URL is not set.  Cannot run migrations." >&2
  exit 1
fi

echo "📂 Migrations directory: $MIGRATIONS_DIR"
echo "🗄️  Target database: $(echo "$DATABASE_URL" | sed 's|://[^@]*@|://***@|')"  # mask password

# Collect migration files sorted by name (timestamps ensure order).
mapfile -t MIGRATION_FILES < <(find "$MIGRATIONS_DIR" -maxdepth 1 -name '*.sql' | sort)

if [ ${#MIGRATION_FILES[@]} -eq 0 ]; then
  echo "❌ No .sql files found in $MIGRATIONS_DIR" >&2
  exit 1
fi

echo "📋 Found ${#MIGRATION_FILES[@]} migration file(s)."

FAILED=0
for file in "${MIGRATION_FILES[@]}"; do
  basename="$(basename "$file")"
  echo -n "  ⏳ $basename ... "
  if psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$file" > /dev/null 2>&1; then
    echo "✅"
  else
    echo "❌ FAILED"
    echo "    ── Re-running with visible output ──"
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$file" || true
    FAILED=$((FAILED + 1))
  fi
done

echo ""
if [ "$FAILED" -gt 0 ]; then
  echo "❌ $FAILED migration(s) failed."
  exit 1
fi

echo "✅ All ${#MIGRATION_FILES[@]} migrations applied successfully."
