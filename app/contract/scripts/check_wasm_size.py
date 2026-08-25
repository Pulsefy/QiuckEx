import os
import sys

def main():
    # Paths
    wasm_file = 'target/wasm32-unknown-unknown/release/quickex.wasm'
    baseline_file = 'wasm-size-baseline.txt'

    # Check if WASM exists
    if not os.path.exists(wasm_file):
        print(f"Error: WASM file not found at {wasm_file}")
        sys.exit(1)

    # Check if baseline exists
    if not os.path.exists(baseline_file):
        print(f"Error: Baseline file not found at {baseline_file}")
        sys.exit(1)

    # Get absolute size
    current_size = os.path.getsize(wasm_file)

    # Get baseline size
    with open(baseline_file, 'r') as f:
        try:
            baseline_size = int(f.read().strip())
        except ValueError:
            print("Error: Baseline file contains invalid data")
            sys.exit(1)

    # Calculate delta and percentage
    delta = current_size - baseline_size
    percent_change = (delta / baseline_size) * 100
    
    print(f"WASM Size Report:")
    print(f"  Baseline size: {baseline_size} bytes")
    print(f"  Current size:  {current_size} bytes")
    print(f"  Delta:         {delta:+} bytes ({percent_change:+.2f}%)")

    # Define tolerance (5%)
    TOLERANCE = 0.05
    max_allowed_size = baseline_size * (1 + TOLERANCE)

    if current_size > max_allowed_size:
        print(f"\nERROR: Current WASM size ({current_size} bytes) exceeds the maximum allowed size ({int(max_allowed_size)} bytes).")
        print(f"The size has grown beyond the documented tolerance of {TOLERANCE * 100}%.")
        print("If this growth is expected, please update the baseline in `wasm-size-baseline.txt`.")
        sys.exit(1)
    
    print(f"\nSUCCESS: WASM size is within the acceptable tolerance of {TOLERANCE * 100}%.")
    sys.exit(0)

if __name__ == '__main__':
    main()
