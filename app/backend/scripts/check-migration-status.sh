#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# check-migration-status.sh
#
# Reports whether a database is fully migrated by comparing the number of
# applied migrations (from schema_migrations) against the number of
# available migration files.  Exits non-zero if the database is behind.
#
# Required environment variables:
#   DATABASE_URL  – Postgres connection string
#
# Optional:
#   MIGRATIONS_DIR – Override the default migrations directory
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$(dirname "$SCRIPT_DIR")"
MAIN_MIGRATIONS_DIR="${MIGRATIONS_DIR:-$BACKEND_DIR/supabase/migrations}"

if [ -z "${DATABASE_URL:-}" ]; then
  echo "❌ DATABASE_URL is not set." >&2
  exit 1
fi

# ── Count available migration files ──────────────────────────────────────────
AVAILABLE=0

if [ -d "$MAIN_MIGRATIONS_DIR" ]; then
  AVAILABLE=$(find "$MAIN_MIGRATIONS_DIR" -maxdepth 1 -name '*.sql' | wc -l | tr -d ' ')
fi

# Per-module migration directories
MODULE_MIGRATIONS_DIR="$BACKEND_DIR/src"
if [ -d "$MODULE_MIGRATIONS_DIR" ]; then
  MODULE_COUNT=$(find "$MODULE_MIGRATIONS_DIR" -mindepth 2 -maxdepth 2 -type d -name 'migrations' -exec find {} -name '*.sql' \; | wc -l | tr -d ' ')
  AVAILABLE=$((AVAILABLE + MODULE_COUNT))
fi

# ── Count applied migrations ─────────────────────────────────────────────────
# Supabase tracks applied migrations in the schema_migrations table.
APPLIED=$(psql "$DATABASE_URL" -tAc "SELECT COUNT(*) FROM schema_migrations;" 2>/dev/null || echo "0")
APPLIED=$(echo "$APPLIED" | tr -d ' ')

echo "📊 Migration Status"
echo "   Available: $AVAILABLE"
echo "   Applied:   $APPLIED"

if [ "$APPLIED" -ge "$AVAILABLE" ]; then
  echo "✅ Database is fully migrated."
  exit 0
elif [ "$APPLIED" -eq 0 ] && [ "$AVAILABLE" -gt 0 ]; then
  echo "⚠️  No migrations applied. Database may be uninitialized."
  exit 1
else
  BEHIND=$((AVAILABLE - APPLIED))
  echo "❌ Database is behind by $BEHIND migration(s)."
  exit 1
fi
