#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# run-ci-migrations.sh
#
# Runs every Supabase SQL migration file against a PostgreSQL database in
# alphabetical (timestamp) order.  Used by CI to validate that migrations
# are syntactically correct and produce the expected schema.
#
# This script scans the main supabase/migrations/ directory as well as any
# per-module migration directories (src/*/migrations/) to ensure all
# scattered migrations are applied.
#
# Required environment variables:
#   DATABASE_URL  – Postgres connection string, e.g.
#                   postgresql://user:pass@localhost:5432/quickex_test
#
# Optional:
#   MIGRATIONS_DIR – Override the default migrations directory
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$(dirname "$SCRIPT_DIR")"
MAIN_MIGRATIONS_DIR="${MIGRATIONS_DIR:-$BACKEND_DIR/supabase/migrations}"

if [ -z "${DATABASE_URL:-}" ]; then
  echo "❌ DATABASE_URL is not set.  Cannot run migrations." >&2
  exit 1

fi

echo "🗄️  Target database: $(echo "$DATABASE_URL" | sed 's|://[^@]*@|://***@|')"

# ── Collect migration files from all sources ──────────────────────────────────
# 1. Main supabase/migrations/ directory
# 2. Per-module src/*/migrations/ directories (for backward compatibility)

ALL_MIGRATION_FILES=()

# Main migrations directory
if [ -d "$MAIN_MIGRATIONS_DIR" ]; then
  while IFS= read -r -d '' file; do
    ALL_MIGRATION_FILES+=("$file")
  done < <(find "$MAIN_MIGRATIONS_DIR" -maxdepth 1 -name '*.sql' -print0 | sort -z)
fi

# Per-module migration directories (backward compatibility during transition)
MODULE_MIGRATIONS_DIR="$BACKEND_DIR/src"
if [ -d "$MODULE_MIGRATIONS_DIR" ]; then
  while IFS= read -r -d '' dir; do
    while IFS= read -r -d '' file; do
      ALL_MIGRATION_FILES+=("$file")
    done < <(find "$dir" -maxdepth 1 -name '*.sql' -print0 | sort -z)
  done < <(find "$MODULE_MIGRATIONS_DIR" -mindepth 2 -maxdepth 2 -type d -name 'migrations' -print0)
fi

if [ ${#ALL_MIGRATION_FILES[@]} -eq 0 ]; then
  echo "❌ No .sql migration files found" >&2
  exit 1
fi

echo "📂 Main migrations: $MAIN_MIGRATIONS_DIR"
echo "📋 Found ${#ALL_MIGRATION_FILES[@]} total migration file(s)."

# ── Apply migrations ─────────────────────────────────────────────────────────
FAILED=0
APPLIED=0
for file in "${ALL_MIGRATION_FILES[@]}"; do
  basename="$(basename "$file")"
  echo -n "  ⏳ $basename ... "
  if psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$file" > /dev/null 2>&1; then
    echo "✅"
    APPLIED=$((APPLIED + 1))
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

echo "✅ All $APPLIED migrations applied successfully."
