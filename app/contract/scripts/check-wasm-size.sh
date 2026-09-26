#!/usr/bin/env bash
# Measures the release WASM size for the quickex contract and fails if it
# grows beyond the tolerance recorded in wasm-size-baseline.json. Deployment
# cost scales with WASM size and there is an upper bound, so unnoticed
# growth becomes a deployment failure at the worst moment.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WASM_PATH="${WASM_PATH:-$ROOT_DIR/target/wasm32v1-none/release/quickex.wasm}"
BASELINE_PATH="${BASELINE_PATH:-$ROOT_DIR/wasm-size-baseline.json}"
SKIP_BUILD="${SKIP_BUILD:-0}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }; }
need python3

if [[ ! -f "$BASELINE_PATH" ]]; then
  echo "baseline file not found at $BASELINE_PATH" >&2
  exit 1
fi

if [[ "$SKIP_BUILD" != "1" ]]; then
  echo "==> Building release WASM"
  (cd "$ROOT_DIR" && cargo build -p quickex --target wasm32v1-none --release)
fi

if [[ ! -f "$WASM_PATH" ]]; then
  echo "wasm artifact not found at $WASM_PATH" >&2
  exit 1
fi

CURRENT_BYTES="$(stat -c%s "$WASM_PATH" 2>/dev/null || stat -f%z "$WASM_PATH")"

python3 - "$BASELINE_PATH" "$CURRENT_BYTES" "$WASM_PATH" <<'PY'
import json
import os
import sys

baseline_path, current_bytes, wasm_path = sys.argv[1], int(sys.argv[2]), sys.argv[3]

with open(baseline_path) as f:
    baseline = json.load(f)

baseline_bytes = int(baseline["baseline_bytes"])
tolerance_pct = float(baseline["tolerance_pct"])

max_allowed = baseline_bytes * (1 + tolerance_pct / 100)
delta_bytes = current_bytes - baseline_bytes
delta_pct = (delta_bytes / baseline_bytes * 100) if baseline_bytes else 0.0

passed = current_bytes <= max_allowed
status = "OK" if passed else "FAIL"

lines = [
    "==> WASM size report",
    f"    artifact:        {wasm_path}",
    f"    current size:    {current_bytes:,} bytes",
    f"    baseline size:   {baseline_bytes:,} bytes",
    f"    delta:           {delta_bytes:+,} bytes ({delta_pct:+.2f}%)",
    f"    tolerance:       {tolerance_pct:.2f}%",
    f"    max allowed:     {max_allowed:,.0f} bytes",
    f"    status:          {status}",
]
print("\n".join(lines))

summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
if summary_path:
    with open(summary_path, "a") as f:
        f.write("### WASM size gate\n\n")
        f.write("| metric | value |\n")
        f.write("| --- | --- |\n")
        f.write(f"| current size | {current_bytes:,} bytes |\n")
        f.write(f"| baseline size | {baseline_bytes:,} bytes |\n")
        f.write(f"| delta | {delta_bytes:+,} bytes ({delta_pct:+.2f}%) |\n")
        f.write(f"| tolerance | {tolerance_pct:.2f}% |\n")
        f.write(f"| max allowed | {max_allowed:,.0f} bytes |\n")
        f.write(f"| status | {status} |\n")

if not passed:
    print(
        f"\nFAIL: WASM size {current_bytes:,} bytes exceeds the allowed "
        f"{max_allowed:,.0f} bytes (baseline {baseline_bytes:,} + "
        f"{tolerance_pct:.2f}% tolerance).\n"
        "If this growth is intentional, raise `baseline_bytes` in "
        f"{baseline_path} in a dedicated, reviewable PR that explains why.",
        file=sys.stderr,
    )
    sys.exit(1)

print("\nOK: WASM size is within tolerance.")
PY
