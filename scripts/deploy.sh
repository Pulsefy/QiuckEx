#!/usr/bin/env bash
set -euo pipefail

# Configuration and Flags
NETWORK="${NETWORK:-testnet}"
SOURCE_ACCOUNT="${SOURCE_ACCOUNT:-alice}"
STATE_FILE="${STATE_FILE:-.deploy-state.${NETWORK}.json}"
DRY_RUN=false

for arg in "$@"; do
  case $arg in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
  esac
done

# Step 1: Build & calculate WASM Hash
echo "==> Building contract WASM..."
stellar contract build

WASM_PATH="target/wasm32v1-none/release/quickex.wasm"
if [ ! -f "$WASM_PATH" ]; then
  WASM_PATH=$(find target/wasm32v1-none/release/ -name "*.wasm" | head -n 1)
fi

WASM_HASH=$(stellar contract install --wasm "$WASM_PATH" --network "$NETWORK" --source "$SOURCE_ACCOUNT" --ignore-checks 2>/dev/null || true)
if [ -z "$WASM_HASH" ]; then
  WASM_HASH=$(sha256sum "$WASM_PATH" | awk '{print $1}')
fi

echo "Network:   $NETWORK"
echo "WASM Hash: $WASM_HASH"

# Load local deployment state if available
CONTRACT_ID=""
IS_INITIALIZED=false

if [ -f "$STATE_FILE" ]; then
  RECORDED_HASH=$(jq -r '.wasm_hash // empty' "$STATE_FILE")
  if [ "$RECORDED_HASH" == "$WASM_HASH" ]; then
    CONTRACT_ID=$(jq -r '.contract_id // empty' "$STATE_FILE")
    IS_INITIALIZED=$(jq -r '.initialized // false' "$STATE_FILE")
  fi
fi

# Step 2: Idempotent Deployment
if [ -n "$CONTRACT_ID" ]; then
  echo "==> Reusing existing deployment for WASM Hash."
else
  if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Would deploy new contract instance for WASM Hash: $WASM_HASH"
    CONTRACT_ID="C_DRY_RUN_CONTRACT_ID"
  else
    echo "==> Deploying new contract instance..."
    CONTRACT_ID=$(stellar contract deploy \
      --wasm-hash "$WASM_HASH" \
      --network "$NETWORK" \
      --source "$SOURCE_ACCOUNT")
    
    # Immediately record deployment state atomically
    jq -n --arg net "$NETWORK" --arg hash "$WASM_HASH" --arg cid "$CONTRACT_ID" --argjson init false \
      '{network: $net, wasm_hash: $hash, contract_id: $cid, initialized: $init}' > "$STATE_FILE"
  fi
fi

echo "Contract ID: $CONTRACT_ID"

# Step 3: Idempotent Initialization
if [ "$IS_INITIALIZED" = true ]; then
  echo "==> Skipping initialization: Contract already marked as initialized."
else
  if [ "$DRY_RUN" = true ]; then
    echo "[DRY-RUN] Would invoke contract initialization."
  else
    echo "==> Checking on-chain status and initializing contract..."
    # Attempt initialization; skip if re-initialization fails on-chain
    if stellar contract invoke \
      --id "$CONTRACT_ID" \
      --network "$NETWORK" \
      --source "$SOURCE_ACCOUNT" \
      -- initialize 2>/dev/null; then
      
      echo "==> Initialization completed successfully."
      jq --argjson init true '.initialized = $init' "$STATE_FILE" > "${STATE_FILE}.tmp" && mv "${STATE_FILE}.tmp" "$STATE_FILE"
    else
      echo "==> Contract appears to be initialized already on-chain. Updating local state record."
      jq --argjson init true '.initialized = $init' "$STATE_FILE" > "${STATE_FILE}.tmp" && mv "${STATE_FILE}.tmp" "$STATE_FILE"
    fi
  fi
fi

# Final Output Summary
echo "=========================================="
echo "DEPLOYMENT SUMMARY"
echo "Network:     $NETWORK"
echo "WASM Hash:   $WASM_HASH"
echo "Contract ID: $CONTRACT_ID"
echo "Dry Run:     $DRY_RUN"
echo "=========================================="
