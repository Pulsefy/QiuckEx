#!/usr/bin/env bash
# Exports the QuickEx contract's canonical smoke scenarios as a machine-readable
# JSON artifact, so backend deploy tooling, CI, and contributors all validate
# contract behavior against the same expected outcomes.
#
# The canonical source of truth is `contracts/quickex/smoke-scenarios.json`.
# This script validates that file and publishes a copy to docs/smoke-scenarios/.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_PATH="$ROOT_DIR/contracts/quickex/smoke-scenarios.json"
SCHEMA_PATH="$ROOT_DIR/contracts/quickex/smoke-scenarios.schema.json"
OUT_PATH="${OUT_PATH:-$ROOT_DIR/docs/smoke-scenarios/smoke-scenarios.json}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }
need python3

if [[ ! -f "$SOURCE_PATH" ]]; then
  echo "smoke scenarios artifact not found at $SOURCE_PATH" >&2
  exit 1
fi

if [[ ! -f "$SCHEMA_PATH" ]]; then
  echo "smoke scenarios schema not found at $SCHEMA_PATH" >&2
  exit 1
fi

echo "==> Validating $SOURCE_PATH"
python3 - "$SOURCE_PATH" <<'PY'
import json, sys

path = sys.argv[1]
with open(path) as f:
    artifact = json.load(f)

assert artifact["kind"] == "quickex-smoke-scenarios-v1", "artifact kind mismatch"
assert artifact["contract"] == "quickex", "artifact must target the quickex contract"
assert isinstance(artifact["version"], str) and artifact["version"].count(".") == 2, "invalid version"

scenarios = artifact["scenarios"]
assert isinstance(scenarios, list) and scenarios, "artifact must declare at least one scenario"

seen_ids = set()
for s in scenarios:
    sid = s["id"]
    assert len(sid) == 9 and sid.startswith("SMOKE-") and sid[6:].isdigit(), f"invalid id {sid}"
    assert sid not in seen_ids, f"duplicate scenario id {sid}"
    seen_ids.add(sid)
    assert s["name"], f"{sid} missing name"
    assert s["entry_point"], f"{sid} missing entry_point"
    assert s["expected_outcome"] in ("success", "rejection"), f"{sid} invalid expected_outcome"
    if s["expected_outcome"] == "rejection":
        assert s["expected_error"] and s["expected_error"]["name"], f"{sid} missing expected_error"

print(f"validated {len(scenarios)} scenarios")
PY

echo "==> Publishing to $OUT_PATH"
mkdir -p "$(dirname "$OUT_PATH")"
cp "$SOURCE_PATH" "$OUT_PATH"

echo "Smoke scenarios exported to $OUT_PATH"
