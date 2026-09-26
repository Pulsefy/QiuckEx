#!/usr/bin/env bash
# Exports the QuickEx contract's method/argument spec (and version metadata)
# as a stable JSON artifact, so tooling and contributors can introspect the
# contract without needing to read the Rust source.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WASM_PATH="${WASM_PATH:-$ROOT_DIR/target/wasm32v1-none/release/quickex.wasm}"
OUT_PATH="${OUT_PATH:-$ROOT_DIR/docs/contract-spec/contract-spec.json}"
STELLAR_BIN="${STELLAR_BIN:-stellar}"
SKIP_BUILD="${SKIP_BUILD:-0}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }
need python3
need sha256sum

if command -v "$STELLAR_BIN" >/dev/null 2>&1; then
  STELLAR_CMD="$STELLAR_BIN"
elif command -v soroban >/dev/null 2>&1; then
  STELLAR_CMD="soroban"
else
  echo "missing required command: $STELLAR_BIN (or soroban)" >&2
  exit 1
fi

if [[ "$SKIP_BUILD" != "1" ]]; then
  echo "==> Building contract wasm"
  (cd "$ROOT_DIR" && cargo build -p quickex --target wasm32v1-none --release)
fi

if [[ ! -f "$WASM_PATH" ]]; then
  echo "wasm artifact not found at $WASM_PATH" >&2
  exit 1
fi

echo "==> Extracting contract interface from $WASM_PATH"
INTERFACE_FILE="$(mktemp)"
trap 'rm -f "$INTERFACE_FILE"' EXIT
"$STELLAR_CMD" contract info interface --wasm "$WASM_PATH" --output json-formatted >"$INTERFACE_FILE"

WASM_SHA="$(sha256sum "$WASM_PATH" | awk '{print $1}')"
CONTRACT_VERSION="$(grep -oE 'pub const CURRENT_CONTRACT_VERSION: u32 = [0-9]+' "$ROOT_DIR/contracts/quickex/src/storage.rs" | grep -oE '[0-9]+$')"
EVENT_SCHEMA_VERSION="$(grep -oE 'pub const EVENT_SCHEMA_VERSION: u32 = [0-9]+' "$ROOT_DIR/contracts/quickex/src/events.rs" | grep -oE '[0-9]+$')"

mkdir -p "$(dirname "$OUT_PATH")"

python3 - "$OUT_PATH" "$CONTRACT_VERSION" "$EVENT_SCHEMA_VERSION" "$WASM_SHA" "$INTERFACE_FILE" <<'PY'
import json, sys

out_path, contract_version, event_schema_version, wasm_sha, interface_file = sys.argv[1:6]

with open(interface_file) as f:
    interface = json.load(f)

functions = sorted(
    entry["function_v0"]["name"] for entry in interface if "function_v0" in entry
)

spec = {
    "kind": "quickex-contract-spec-v1",
    "contract_version": int(contract_version),
    "event_schema_version": int(event_schema_version),
    "wasm_sha256": wasm_sha,
    "functions": functions,
    "interface": interface,
}

with open(out_path, "w") as f:
    json.dump(spec, f, indent=2, sort_keys=True)
    f.write("\n")

print(f"wrote {out_path} ({len(functions)} functions)")
PY

echo "Contract spec exported to $OUT_PATH"
