#!/usr/bin/env bash
set -euo pipefail

# QuickEx Contract Deploy Script
# ===============================
# Builds, deploys, and initialises a QuickEx Soroban contract on the target
# network, then emits a JSON manifest conforming to manifest-schema.json.
#
# Prerequisites: cargo (wasm32v1-none target), stellar CLI, sha256sum, python3
#
# Usage:
#   ./scripts/deploy.sh \
#     --network testnet \
#     --source quickex-testnet \
#     --admin GA5TBSBGERHVMEFBJGEM3KYMRLWO73Y2QRAV6P66GPEBOJ5ZMJUT7LLY \
#     --wasm target/wasm32v1-none/release/quickex.wasm \
#     [--rpc-url https://soroban-testnet.stellar.org] \
#     [--passphrase "Test SDF Network ; September 2015"] \
#     [--out-dir docs/deployment-artifacts]

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETWORK=""
SOURCE=""
ADMIN=""
WASM_PATH="${WASM_PATH:-$ROOT_DIR/target/wasm32v1-none/release/quickex.wasm}"
RPC_URL=""
PASSPHRASE=""
OUT_DIR="${OUT_DIR:-$ROOT_DIR/docs/deployment-artifacts}"
STELLAR_BIN="${STELLAR_BIN:-stellar}"
SKIP_BUILD="${SKIP_BUILD:-0}"
DRY_RUN="${DRY_RUN:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --network)    NETWORK="$2";   shift 2 ;;
    --source)     SOURCE="$2";    shift 2 ;;
    --admin)      ADMIN="$2";     shift 2 ;;
    --wasm)       WASM_PATH="$2"; shift 2 ;;
    --rpc-url)    RPC_URL="$2";   shift 2 ;;
    --passphrase) PASSPHRASE="$2"; shift 2 ;;
    --out-dir)    OUT_DIR="$2";   shift 2 ;;
    --skip-build) SKIP_BUILD=1;   shift ;;
    --dry-run)    DRY_RUN=1;      shift ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

# ── Validation ──────────────────────────────────────────────────────────────

need(){ command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }
need python3 need sha256sum need "$STELLAR_BIN"

if [[ -z "$NETWORK" ]]; then echo "error: --network is required" >&2; exit 1; fi
if [[ -z "$SOURCE" ]]; then echo "error: --source is required" >&2; exit 1; fi
if [[ -z "$ADMIN" ]]; then echo "error: --admin is required" >&2; exit 1; fi

# ── Resolve network defaults ────────────────────────────────────────────────

case "$NETWORK" in
  testnet)
    RPC_URL="${RPC_URL:-https://soroban-testnet.stellar.org}"
    PASSPHRASE="${PASSPHRASE:-Test SDF Network ; September 2015}"
    ;;
  mainnet)
    RPC_URL="${RPC_URL:-https://mainnet.stellar.org}"
    PASSPHRASE="${PASSPHRASE:-Public Global Stellar Network ; September 2015}"
    ;;
  *) echo "error: unknown network '$NETWORK' (use testnet or mainnet)" >&2; exit 1 ;;
esac

# ── Build ───────────────────────────────────────────────────────────────────

if [[ "$SKIP_BUILD" != "1" && "$DRY_RUN" != "1" ]]; then
  echo "==> Building WASM (release)"
  cargo build --target wasm32v1-none --release 2>&1
fi

if [[ ! -f "$WASM_PATH" ]]; then
  echo "error: WASM artifact not found at $WASM_PATH" >&2
  exit 1
fi

WASM_SHA="$(sha256sum "$WASM_PATH" | awk '{print $1}')"
echo "WASM SHA-256: 0x${WASM_SHA}"

if [[ "$DRY_RUN" == "1" ]]; then
  # Generate a dry-run manifest with placeholder values
  TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  mkdir -p "$OUT_DIR"

  python3 - "$OUT_DIR" <<PY
import json, os, sys
from pathlib import Path
out = Path(sys.argv[1])
manifest = {
    "manifest_version": 1,
    "application": "quickex",
    "generated_at": "$TIMESTAMP",
    "network": "$NETWORK",
    "network_passphrase": "$PASSPHRASE",
    "rpc_url": "$RPC_URL",
    "operator": "$SOURCE",
    "contracts": [
        {
            "name": "quickex",
            "contract_id": "DRY_RUN_NOT_DEPLOYED",
            "wasm_hash": "0x${WASM_SHA}",
            "contract_version": 1,
            "event_schema_version": 2,
            "admin_addresses": ["$ADMIN"],
            "init_params": {"admin": "$ADMIN"},
            "deployed_at": "$TIMESTAMP",
            "deployed_by": "$SOURCE",
            "notes": "DRY RUN — no on-chain transactions submitted",
        }
    ],
}
(out / "deployment-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
PY
  echo "Dry-run manifest written to $OUT_DIR/deployment-manifest.json"
  exit 0
fi

# ── Deploy ──────────────────────────────────────────────────────────────────

DEPLOY_DIR="${OUT_DIR}/${NETWORK}-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$DEPLOY_DIR"

echo "==> Installing WASM"
INSTALL_OUTPUT=$($STELLAR_BIN contract install \
  --wasm "$WASM_PATH" \
  --source "$SOURCE" \
  --network "$NETWORK" 2>&1)
echo "$INSTALL_OUTPUT"

echo "==> Deploying contract"
DEPLOY_OUTPUT=$($STELLAR_BIN contract deploy \
  --wasm-hash "$WASM_SHA" \
  --source "$SOURCE" \
  --network "$NETWORK" 2>&1)
echo "$DEPLOY_OUTPUT"

# Extract contract ID from deploy output (last line is typically the ID)
CONTRACT_ID=$(echo "$DEPLOY_OUTPUT" | tail -1 | xargs)
if [[ -z "$CONTRACT_ID" || "$CONTRACT_ID" != C* ]]; then
  echo "error: could not parse contract ID from deploy output" >&2
  exit 1
fi
echo "Contract ID: $CONTRACT_ID"

echo "==> Initialising contract"
INIT_OUTPUT=$($STELLAR_BIN contract invoke \
  --id "$CONTRACT_ID" \
  --source "$SOURCE" \
  --network "$NETWORK" \
  -- \
  initialize \
  --admin "$ADMIN" 2>&1)
echo "$INIT_OUTPUT"

echo "==> Fetching deployment metadata"
METADATA=$($STELLAR_BIN contract invoke \
  --id "$CONTRACT_ID" \
  --source "$SOURCE" \
  --network "$NETWORK" \
  -- \
  get_deployment_metadata 2>&1)
echo "$METADATA"

echo "==> Health check"
HEALTH=$($STELLAR_BIN contract invoke \
  --id "$CONTRACT_ID" \
  --source "$SOURCE" \
  --network "$NETWORK" \
  -- \
  health_check 2>&1)
echo "Health: $HEALTH"

# ── Generate manifest ───────────────────────────────────────────────────────

TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

python3 - "$DEPLOY_DIR" "$METADATA" "$CONTRACT_ID" "$WASM_SHA" "$TIMESTAMP" <<'PY'
import json, os, sys
from pathlib import Path

deploy_dir = Path(sys.argv[1])
metadata_raw = sys.argv[2]
contract_id = sys.argv[3]
wasm_sha = sys.argv[4]
timestamp = sys.argv[5]
admin = os.environ.get('ADMIN', '')
source = os.environ.get('SOURCE', '')
network = os.environ.get('NETWORK', '')
passphrase = os.environ.get('PASSPHRASE', '')
rpc_url = os.environ.get('RPC_URL', '')

# Parse on-chain metadata (Soroban CLI returns JSON with string-encoded values)
try:
    meta = json.loads(metadata_raw)
except (json.JSONDecodeError, TypeError):
    meta = {"raw": metadata_raw}

contract_version = meta.get("contract_version", 1)
event_schema_version = meta.get("event_schema_version", 2)

# Build manifest with sorted keys for stable output
manifest = {
    "manifest_version": 1,
    "application": "quickex",
    "generated_at": timestamp,
    "network": network,
    "network_passphrase": passphrase,
    "rpc_url": rpc_url,
    "operator": source,
    "contracts": [
        {
            "name": "quickex",
            "contract_id": contract_id,
            "wasm_hash": "0x" + wasm_sha if not wasm_sha.startswith("0x") else wasm_sha,
            "contract_version": contract_version,
            "event_schema_version": event_schema_version,
            "admin_addresses": [admin],
            "init_params": {"admin": admin},
            "deployed_at": timestamp,
            "deployed_by": source,
        }
    ],
}

manifest_path = deploy_dir / "deployment-manifest.json"
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print(f"Manifest written to {manifest_path}")

# Also write latest symlink copy
latest_dir = deploy_dir.parent / "latest"
latest_dir.mkdir(parents=True, exist_ok=True)
latest_path = latest_dir / "deployment-manifest.json"
latest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print(f"Latest manifest symlink: {latest_path}")
PY

echo ""
echo "=== Deployment Complete ==="
echo "Network:       $NETWORK"
echo "Contract ID:   $CONTRACT_ID"
echo "WASM Hash:     0x${WASM_SHA}"
echo "Admin:         $ADMIN"
echo "Operator:      $SOURCE"
echo "Manifest:      $DEPLOY_DIR/deployment-manifest.json"
