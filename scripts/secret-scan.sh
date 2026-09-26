#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# secret-scan.sh – Local secret scanning helper
# ─────────────────────────────────────────────────────────────────────────────
# Usage:
#   ./scripts/secret-scan.sh              # Full scan, generate/update baseline
#   ./scripts/secret-scan.sh --verify     # Verify no new secrets vs baseline
#   ./scripts/secret-scan.sh --audit      # Interactive audit of baseline entries
#
# Prerequisites:
#   pip install detect-secrets
#   brew install gitleaks   (optional, for gitleaks scan)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE="$REPO_ROOT/.secrets.baseline"

EXCLUDE_FILES='(pnpm-lock\.yaml|package-lock\.json|.*\.lock|node_modules/.*|dist/.*|coverage/.*|.turbo/.*)'

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
  echo "Usage: $0 [--verify|--audit|--full]"
  echo ""
  echo "  (no args)  Generate or update the .secrets.baseline file"
  echo "  --verify   Check for new secrets against existing baseline"
  echo "  --audit    Interactively audit baseline entries"
  echo "  --full     Run both detect-secrets AND gitleaks"
  exit 0
}

check_deps() {
  if ! command -v detect-secrets &>/dev/null; then
    echo -e "${RED}detect-secrets not found.${NC}"
    echo "Install it with: pip install detect-secrets"
    exit 1
  fi
}

scan_generate_baseline() {
  echo -e "${YELLOW}Generating secret baseline...${NC}"
  detect-secrets scan \
    --exclude-files "$EXCLUDE_FILES" \
    "$REPO_ROOT" > "$BASELINE"

  # Count findings
  COUNT=$(python3 -c "
import json, sys
d = json.load(open('$BASELINE'))
total = sum(len(v) for v in d.get('results', {}).values())
print(total)
" 2>/dev/null || echo "0")

  if [ "$COUNT" -gt 0 ]; then
    echo -e "${YELLOW}Found $COUNT potential secret(s).${NC}"
    echo "Run '$0 --audit' to review them, then commit the baseline."
  else
    echo -e "${GREEN}No potential secrets found. Baseline is clean.${NC}"
  fi
}

scan_verify() {
  if [ ! -f "$BASELINE" ]; then
    echo -e "${RED}No baseline found. Run '$0' first to generate one.${NC}"
    exit 1
  fi

  echo -e "${YELLOW}Verifying against baseline...${NC}"
  detect-secrets scan \
    --baseline "$BASELINE" \
    --exclude-files "$EXCLUDE_FILES" \
    "$REPO_ROOT"

  echo -e "${GREEN}Verification complete. No new secrets detected.${NC}"
}

scan_audit() {
  if [ ! -f "$BASELINE" ]; then
    echo -e "${RED}No baseline found. Run '$0' first to generate one.${NC}"
    exit 1
  fi

  echo -e "${YELLOW}Starting interactive audit...${NC}"
  detect-secrets audit "$BASELINE"
}

scan_gitleaks() {
  if ! command -v gitleaks &>/dev/null; then
    echo -e "${YELLOW}gitleaks not found. Install with: brew install gitleaks${NC}"
    return
  fi

  echo -e "${YELLOW}Running gitleaks scan...${NC}"
  cd "$REPO_ROOT"
  gitleaks detect --source . --config gitleaks.toml --verbose --no-git || true
}

# ── Main ─────────────────────────────────────────────────────────────────────
check_deps

case "${1:-}" in
  --verify)
    scan_verify
    ;;
  --audit)
    scan_audit
    ;;
  --full)
    scan_generate_baseline
    scan_gitleaks
    ;;
  --help|-h)
    usage
    ;;
  "")
    scan_generate_baseline
    ;;
  *)
    echo "Unknown option: $1"
    usage
    ;;
esac
