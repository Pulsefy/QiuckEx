# Testnet Upgrade Rehearsal

This document describes the repeatable QuickEx **testnet upgrade rehearsal** flow added for issue #570.

## What the rehearsal covers

The rehearsal is split into two layers:

1. **Local upgrade simulation and invariant validation** using the existing Rust harness in `contracts/quickex/src/upgrade_test.rs`
2. **Testnet operator rehearsal** using `scripts/testnet-upgrade-rehearsal.sh`, which records pre/post metadata and exports backend-consumable artifacts.

The local harness already covers the golden-state migration path and upgrade safety checks:

```bash
cargo test -p quickex upgrade_harness_ -- --nocapture
cargo test -p quickex upgrade_safety_gate_ -- --nocapture
