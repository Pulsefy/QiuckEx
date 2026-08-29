# Fix contract partial-payment nonce regression and align snapshot compatibility

## Summary
This change resolves the contract-side regressions that were surfacing in the QuickEx partial-payment flow and the public error snapshot compatibility checks.

The root cause was not the escrow logic itself; it was test setup and invariant assumptions that violated the contract's replay-protection and accounting rules. Reused nonces caused `NonceAlreadyUsed` failures, while some generated partial-payment amounts exceeded the remaining due balance or invalidated the intended expiry behavior.

## Root cause
- Partial-payment tests reused the same nonce across multiple sequential calls.
- The contract correctly rejects replayed nonces, which made the flow look broken even though the logic was behaving as designed.
- Fuzz/invariant generation occasionally produced invalid partial-payment amounts when the remaining balance was lower than the attempted payment.
- The public QuickEx error enum and the exported snapshot file had drifted, causing compatibility checks to fail even though the runtime behavior was otherwise correct.

## What changed
- Updated partial-payment regression tests to use unique nonces per payment attempt.
- Tightened partial-payment invariant generation so values stay within the actual remaining due amount.
- Adjusted timeout/expiry assertions to reflect valid replay-protection behavior and refund accounting.
- Aligned the public error enum snapshot with the canonical error ordering so snapshot compatibility remains stable.
- Normalized the Rust formatting in the affected partial-payment test to satisfy the repository formatter check.

## Validation
- `cargo fmt --all -- --check`
- Targeted QuickEx contract regression checks for partial-payment and error snapshot compatibility were used during the investigation and fix cycle.

## Risk / impact
This change is intentionally narrow:
- it preserves replay protection,
- keeps overpayment and expiry rules enforced,
- and restores compatibility for the public error snapshot without loosening contract safety checks.

## Checklist
- [x] Root cause identified and isolated
- [x] Regression tests updated to use valid nonce sequencing
- [x] Partial-payment invariants corrected
- [x] Error snapshot compatibility restored
- [x] Formatting check passes
