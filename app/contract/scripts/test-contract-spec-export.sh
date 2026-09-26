#!/usr/bin/env bash
# Verifies that the exported contract spec (export-contract-spec.sh) is
# stable across repeat builds and contains the required version metadata.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Export run 1 (with build)"
OUT_PATH="$WORK_DIR/spec-1.json" "$ROOT_DIR/scripts/export-contract-spec.sh"

echo "==> Export run 2 (reusing artifact)"
OUT_PATH="$WORK_DIR/spec-2.json" SKIP_BUILD=1 "$ROOT_DIR/scripts/export-contract-spec.sh"

echo "==> Checking stability across repeat exports"
if ! diff -u "$WORK_DIR/spec-1.json" "$WORK_DIR/spec-2.json"; then
  echo "FAIL: exported spec is not stable across repeat builds" >&2
  exit 1
fi

echo "==> Checking completeness of required spec fields"
python3 - "$WORK_DIR/spec-1.json" <<'PY'
import json, sys

spec = json.load(open(sys.argv[1]))

required = ["kind", "contract_version", "event_schema_version", "wasm_sha256", "functions", "interface"]
missing = [field for field in required if field not in spec]
if missing:
    sys.exit(f"FAIL: missing required spec fields: {missing}")

if not isinstance(spec["contract_version"], int) or not isinstance(spec["event_schema_version"], int):
    sys.exit("FAIL: contract_version/event_schema_version must be present and integers")

if not isinstance(spec["functions"], list) or not spec["functions"]:
    sys.exit("FAIL: functions list must be a non-empty list")

print(
    f"OK: {len(spec['functions'])} functions, "
    f"contract_version={spec['contract_version']}, "
    f"event_schema_version={spec['event_schema_version']}"
)
PY

echo "Contract spec export is stable and complete."
