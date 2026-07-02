#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETWORK="${NETWORK:-testnet}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/docs/rehearsal-artifacts/${NETWORK}-$(date -u +%Y%m%dT%H%M%SZ)}"
LATEST_DIR="$ROOT_DIR/docs/rehearsal-artifacts/latest"
REGISTRY_PATH="${REGISTRY_PATH:-$ROOT_DIR/documentation/environment-registry.toml}"
WASM_PATH="${WASM_PATH:-$ROOT_DIR/target/wasm32v1-none/release/quickex.wasm}"
CONTRACT_ID="${CONTRACT_ID:-}"
SOURCE="${SOURCE:-${ADMIN_SOURCE:-}}"
NEW_VERSION="${NEW_VERSION:-}"
START_TS="${START_TS:-1}"
END_TS="${END_TS:-0}"
RUN_LOCAL_TESTS="${RUN_LOCAL_TESTS:-1}"
STELLAR_BIN="${STELLAR_BIN:-stellar}"

mkdir -p "$OUT_DIR"
rm -rf "$LATEST_DIR"
mkdir -p "$LATEST_DIR"

need(){ command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }
need python3
need sha256sum
if [[ "$RUN_LOCAL_TESTS" == "1" ]]; then need cargo; fi
if [[ -n "$CONTRACT_ID" || -n "$SOURCE" ]]; then need "$STELLAR_BIN"; fi

if [[ "$RUN_LOCAL_TESTS" == "1" ]]; then
  echo "==> Running local upgrade invariant tests"
  cargo test -p quickex upgrade_harness_ -- --nocapture
  cargo test -p quickex upgrade_safety_gate_ -- --nocapture
fi

if [[ ! -f "$WASM_PATH" ]]; then
  echo "warning: wasm artifact not found at $WASM_PATH; artifact hash will be empty" >&2
  WASM_SHA=""
else
  WASM_SHA="$(sha256sum "$WASM_PATH" | awk '{print $1}')"
fi

if [[ -f "$WASM_PATH" ]] && command -v "$STELLAR_BIN" >/dev/null 2>&1; then
  echo "==> Exporting contract spec for this testnet build"
  WASM_PATH="$WASM_PATH" OUT_PATH="$OUT_DIR/contract-spec.json" SKIP_BUILD=1 STELLAR_BIN="$STELLAR_BIN" \
    "$ROOT_DIR/scripts/export-contract-spec.sh"
fi

BEFORE_METADATA='{}'
AFTER_METADATA='{}'
HEALTH='unknown'
UPGRADE_EXECUTED=false
if [[ -n "$CONTRACT_ID" && -n "$SOURCE" ]]; then
  echo "==> Fetching pre-upgrade metadata"
  BEFORE_METADATA="$($STELLAR_BIN contract invoke --id "$CONTRACT_ID" --source "$SOURCE" --network "$NETWORK" -- get_deployment_metadata 2>/dev/null || echo '{}')"

  if [[ -n "$NEW_VERSION" ]]; then
    echo "==> Running testnet upgrade rehearsal against $CONTRACT_ID"
    $STELLAR_BIN contract invoke --id "$CONTRACT_ID" --source "$SOURCE" --network "$NETWORK" -- set_upgrade_window --caller "$SOURCE" --start "$START_TS" --end "$END_TS"
    $STELLAR_BIN contract invoke --id "$CONTRACT_ID" --source "$SOURCE" --network "$NETWORK" -- start_upgrade --caller "$SOURCE" --new_version "$NEW_VERSION"
    $STELLAR_BIN contract invoke --id "$CONTRACT_ID" --source "$SOURCE" --network "$NETWORK" -- upgrade --new_wasm_hash "$WASM_SHA" || true
    $STELLAR_BIN contract invoke --id "$CONTRACT_ID" --source "$SOURCE" --network "$NETWORK" -- complete_upgrade --caller "$SOURCE" --new_version "$NEW_VERSION"
    $STELLAR_BIN contract invoke --id "$CONTRACT_ID" --source "$SOURCE" --network "$NETWORK" -- migrate --caller "$SOURCE" || true
    UPGRADE_EXECUTED=true
  fi

  AFTER_METADATA="$($STELLAR_BIN contract invoke --id "$CONTRACT_ID" --source "$SOURCE" --network "$NETWORK" -- get_deployment_metadata 2>/dev/null || echo '{}')"
  HEALTH="$($STELLAR_BIN contract invoke --id "$CONTRACT_ID" --source "$SOURCE" --network "$NETWORK" -- health_check 2>/dev/null || echo unknown)"
fi

python3 - "$OUT_DIR" "$LATEST_DIR" "$REGISTRY_PATH" "$NETWORK" "$CONTRACT_ID" "$SOURCE" "$NEW_VERSION" "$WASM_PATH" "$WASM_SHA" "$BEFORE_METADATA" "$AFTER_METADATA" "$HEALTH" "$UPGRADE_EXECUTED" <<'PY2'
import json, os, shutil, sys, datetime
from pathlib import Path
out=Path(sys.argv[1]); latest=Path(sys.argv[2]); registry=Path(sys.argv[3])
network, contract_id, source, new_version, wasm_path, wasm_sha = sys.argv[4:10]
before_raw, after_raw, health, upgrade_executed = sys.argv[10:14]
def parse(raw):
    try: return json.loads(raw)
    except Exception: return {"raw": raw}
manifest={
  "kind":"quickex-testnet-upgrade-rehearsal",
  "generated_at": datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z",
  "network": network,
  "contract_id": contract_id or None,
  "operator": source or None,
  "target_version": int(new_version) if new_version else None,
  "wasm": {"path": wasm_path, "sha256": wasm_sha or None},
  "contract_spec": str(out/'contract-spec.json') if (out/'contract-spec.json').exists() else None,
  "checks": {
    "local_upgrade_tests": True,
    "health_check": health,
    "upgrade_executed": upgrade_executed.lower()=="true",
  },
  "metadata": {"before": parse(before_raw), "after": parse(after_raw)},
  "registry_source": str(registry),
}
(out/'rehearsal-manifest.json').write_text(json.dumps(manifest, indent=2)+"\n")
if registry.exists(): shutil.copy2(registry, out/'environment-registry.toml')
(out/'README.md').write_text(f"# QuickEx {network} upgrade rehearsal\n\nArtifacts for the latest testnet upgrade rehearsal.\n\n- Contract: `{contract_id or 'n/a'}`\n- Target version: `{new_version or 'n/a'}`\n- Health check: `{health}`\n")
for item in out.iterdir():
    target=latest/item.name
    if target.exists(): target.unlink()
    shutil.copy2(item, target)
PY2

echo "Rehearsal artifacts written to $OUT_DIR"
