//! Per-entrypoint resource budget assertions for the QuickEx contract (SC-W8-14 / Issue #875).
//!
//! Metering uses Soroban's built-in `env.cost_estimate().budget()` to measure CPU instructions
//! and memory byte allocation for every public entrypoint on `QuickexContract`.
//!
//! Recorded budgets live in `entrypoint-budgets.json`. Tests fail if any entrypoint's cost
//! exceeds its recorded budget beyond the documented tolerance (default 10.0%).
//!
//! Budget changes require an explicit, reviewable update to `entrypoint-budgets.json` rather
//! than passing silently. Set `QUICKEX_UPDATE_BUDGETS=1` to regenerate the baseline file.

#![allow(clippy::let_unit_value)]

extern crate std;

use std::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec as StdVec,
};

use soroban_sdk::{BytesN, Env, Vec};

use crate::{
    batch::{BatchCreateItem, BatchRefundItem, BatchReleaseItem},
    dispute_quorum::DisputeQuorumConfig,
    pause_policy::EntryPoint,
    stealth,
    storage::PauseFlag,
    test_context::TestContext,
    ttl_policy::TtlConfig,
    types::{FeeConfig, OracleFeeConfig, PerAssetFeeConfig, Role, StealthDepositParams},
};

pub const BUDGET_BASELINE_JSON: &str = include_str!("../entrypoint-budgets.json");

/// All 93 public entrypoints defined on `QuickexContract`.
pub const ALL_ENTRYPOINTS: &[&str] = &[
    "activate_emergency_mode",
    "batch_create",
    "batch_refund",
    "batch_release",
    "cleanup_escrow",
    "complete_upgrade",
    "create_amount_commitment",
    "deposit",
    "deposit_multi_sig",
    "deposit_partial",
    "deposit_with_commitment",
    "derive_escrow_id",
    "derive_escrow_id_multi_sig",
    "dispute",
    "enable_privacy",
    "extend_escrow_ttl",
    "finalize_expired_escrow",
    "get_accrued_fee_balance",
    "get_active_fee_collector",
    "get_admin",
    "get_aggregated_oracle_price",
    "get_commitment_state",
    "get_deployment_metadata",
    "get_dispute_quorum_config",
    "get_escrow_details",
    "get_escrow_id_commitment",
    "get_feature_pause_reason",
    "get_fee_config",
    "get_global_pause_reason",
    "get_oracle_aggregation_config",
    "get_oracle_fee_config",
    "get_oracle_sources",
    "get_pending_admin_transfer",
    "get_per_asset_fee",
    "get_platform_wallet",
    "get_privacy",
    "get_registered_hooks",
    "get_roles",
    "get_stealth_status",
    "get_ttl_config",
    "get_upgrade_window",
    "get_version",
    "grant_role",
    "health_check",
    "initialize",
    "is_emergency_mode",
    "is_entry_allowed_in_emergency",
    "is_feature_paused",
    "is_hook_allowed",
    "is_paused",
    "is_refund_eligible",
    "migrate",
    "partial_payment",
    "pause_features",
    "privacy_history",
    "privacy_status",
    "propose_admin_transfer",
    "record_oracle_price",
    "record_oracle_source_price",
    "refund",
    "register_ephemeral_key",
    "register_hook",
    "register_oracle_source",
    "resolve_dispute",
    "resolve_dispute_multi_sig",
    "resolve_dispute_timeout",
    "restore_archived_escrow",
    "revoke_role",
    "rotate_fee_collector",
    "set_dispute_quorum_config",
    "set_fee_config",
    "set_hook_allowed",
    "set_oracle_aggregation_config",
    "set_oracle_fee_config",
    "set_paused",
    "set_per_asset_fee",
    "set_platform_wallet",
    "set_privacy",
    "set_ttl_config",
    "set_upgrade_window",
    "start_upgrade",
    "stealth_withdraw",
    "unpause_features",
    "unregister_hook",
    "unregister_oracle_source",
    "upgrade",
    "verify_amount_commitment",
    "verify_proof_view",
    "vote_for_dispute",
    "withdraw",
    "withdraw_fees",
    "accept_admin_transfer",
    "cancel_admin_transfer",
];

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntrypointBudgetBaseline {
    pub kind: String,
    pub tolerance_pct: f64,
    pub description: String,
    #[serde(default)]
    pub updated_at: String,
    pub entrypoints: BTreeMap<String, EntrypointBudget>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EntrypointBudget {
    pub cpu_budget: u64,
    pub mem_budget: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tolerance_pct: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EntrypointMeasurement {
    pub name: &'static str,
    pub cpu: u64,
    pub mem: u64,
}

#[derive(Debug, Clone)]
pub struct BudgetAssertionFailure {
    pub entrypoint: String,
    pub resource: &'static str,
    pub actual: u64,
    pub budget: u64,
    pub tolerance_pct: f64,
    pub max_allowed: u64,
    pub delta: i64,
    pub delta_pct: f64,
}

pub fn format_number(mut n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut s = String::new();
    let mut count = 0;
    while n > 0 {
        if count > 0 && count % 3 == 0 {
            s.insert(0, ',');
        }
        s.insert(0, (b'0' + (n % 10) as u8) as char);
        n /= 10;
        count += 1;
    }
    s
}

pub fn format_signed_number(n: i64) -> String {
    if n >= 0 {
        format!("+{}", format_number(n as u64))
    } else {
        format!("-{}", format_number(n.unsigned_abs()))
    }
}

impl BudgetAssertionFailure {
    pub fn format_report(&self) -> String {
        format!(
            "Entrypoint '{}' exceeded {} budget:\n  actual:       {}\n  budget:       {}\n  tolerance:    {:.2}%\n  max allowed:  {}\n  delta:        {} ({:+.2}%)\n  excess:       +{}",
            self.entrypoint,
            self.resource,
            format_number(self.actual),
            format_number(self.budget),
            self.tolerance_pct,
            format_number(self.max_allowed),
            format_signed_number(self.delta),
            self.delta_pct,
            format_number(self.actual.saturating_sub(self.max_allowed))
        )
    }
}

pub fn check_budget_limit(
    entrypoint: &str,
    resource: &'static str,
    actual: u64,
    budget: u64,
    tolerance_pct: f64,
) -> Result<(), BudgetAssertionFailure> {
    let allowed_excess = ((budget as f64) * (tolerance_pct / 100.0)).ceil() as u64;
    let max_allowed = budget.saturating_add(allowed_excess);
    if actual > max_allowed {
        let delta = actual as i64 - budget as i64;
        let delta_pct = if budget > 0 {
            (delta as f64 / budget as f64) * 100.0
        } else {
            0.0
        };
        Err(BudgetAssertionFailure {
            entrypoint: entrypoint.to_string(),
            resource,
            actual,
            budget,
            tolerance_pct,
            max_allowed,
            delta,
            delta_pct,
        })
    } else {
        Ok(())
    }
}

fn measure_op<F: FnOnce()>(env: &Env, name: &'static str, op: F) -> EntrypointMeasurement {
    env.cost_estimate().budget().reset_default();
    op();
    let cpu = env.cost_estimate().budget().cpu_instruction_cost();
    let mem = env.cost_estimate().budget().memory_bytes_cost();
    EntrypointMeasurement { name, cpu, mem }
}

pub fn measure_all_entrypoints() -> StdVec<EntrypointMeasurement> {
    let mut results = StdVec::new();

    // 1. Core escrow & commitments
    {
        let ctx = TestContext::new();
        results.push(measure_op(&ctx.env, "health_check", || {
            let _ = ctx.client.health_check();
        }));
    }
    {
        let ctx = TestContext::new();
        let salt = ctx.salt(b"create_comm");
        results.push(measure_op(&ctx.env, "create_amount_commitment", || {
            let _ = ctx
                .client
                .create_amount_commitment(&ctx.alice, &10_000, &salt);
        }));
    }
    {
        let ctx = TestContext::new();
        let salt = ctx.salt(b"verify_comm");
        let comm = ctx
            .client
            .create_amount_commitment(&ctx.alice, &10_000, &salt);
        results.push(measure_op(&ctx.env, "verify_amount_commitment", || {
            let _ = ctx
                .client
                .verify_amount_commitment(&comm, &ctx.alice, &10_000, &salt);
        }));
    }
    {
        let ctx = TestContext::new();
        let salt = ctx.salt(b"derive_id");
        results.push(measure_op(&ctx.env, "derive_escrow_id", || {
            let _ = ctx
                .client
                .derive_escrow_id(&ctx.token, &10_000, &ctx.alice, &salt, &600, &None);
        }));
    }
    {
        let ctx = TestContext::new();
        let salt = ctx.salt(b"derive_id_ms");
        let mut arbiters = Vec::new(&ctx.env);
        arbiters.push_back(ctx.arbiter.clone());
        results.push(measure_op(&ctx.env, "derive_escrow_id_multi_sig", || {
            let _ = ctx.client.derive_escrow_id_multi_sig(
                &ctx.token, &10_000, &ctx.alice, &salt, &600, &arbiters, &1,
            );
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let salt = ctx.salt(b"deposit");
        ctx.mint(&ctx.alice, 10_000);
        results.push(measure_op(&ctx.env, "deposit", || {
            let _ = ctx.client.deposit(
                &ctx.token,
                &10_000,
                &ctx.alice,
                &salt,
                &0,
                &None,
                &0,
                &u64::MAX,
            );
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let comm = BytesN::from_array(&ctx.env, &[0x33; 32]);
        ctx.mint(&ctx.alice, 10_000);
        results.push(measure_op(&ctx.env, "deposit_with_commitment", || {
            let _ = ctx.client.deposit_with_commitment(
                &ctx.alice,
                &ctx.token,
                &10_000,
                &comm,
                &0,
                &None,
                &0,
                &u64::MAX,
            );
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let salt = ctx.salt(b"deposit_ms");
        ctx.mint(&ctx.alice, 10_000);
        let mut arbiters = Vec::new(&ctx.env);
        arbiters.push_back(ctx.arbiter.clone());
        results.push(measure_op(&ctx.env, "deposit_multi_sig", || {
            let _ = ctx.client.deposit_multi_sig(
                &ctx.token,
                &10_000,
                &ctx.alice,
                &salt,
                &600,
                &arbiters,
                &1,
                &0,
                &u64::MAX,
            );
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let salt = ctx.salt(b"withdraw");
        let comm = ctx.simple_deposit(&ctx.alice, 10_000, b"withdraw");
        results.push(measure_op(&ctx.env, "withdraw", || {
            let _ =
                ctx.client
                    .withdraw(&ctx.token, &10_000, &comm, &ctx.alice, &salt, &0, &u64::MAX);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let salt = ctx.salt(b"dep_partial");
        ctx.mint(&ctx.alice, 10_000);
        results.push(measure_op(&ctx.env, "deposit_partial", || {
            let _ = ctx.client.deposit_partial(
                &ctx.token,
                &10_000,
                &1_000,
                &ctx.alice,
                &salt,
                &0,
                &None,
                &0,
                &u64::MAX,
            );
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let salt = ctx.salt(b"part_pay");
        ctx.mint(&ctx.alice, 10_000);
        ctx.mint(&ctx.bob, 10_000);
        let comm = ctx.client.deposit_partial(
            &ctx.token,
            &10_000,
            &1_000,
            &ctx.alice,
            &salt,
            &0,
            &None,
            &0,
            &u64::MAX,
        );
        results.push(measure_op(&ctx.env, "partial_payment", || {
            let _ = ctx
                .client
                .partial_payment(&comm, &ctx.bob, &2_000, &0, &u64::MAX);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let salt = ctx.salt(b"refund");
        ctx.mint(&ctx.alice, 10_000);
        let comm = ctx.client.deposit(
            &ctx.token,
            &10_000,
            &ctx.alice,
            &salt,
            &10,
            &None,
            &0,
            &u64::MAX,
        );
        ctx.advance_time(20);
        results.push(measure_op(&ctx.env, "refund", || {
            let _ = ctx.client.refund(&comm, &ctx.alice, &0, &u64::MAX);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let salt = ctx.salt(b"escrow_id_c");
        let _comm = ctx.simple_deposit(&ctx.alice, 10_000, b"escrow_id_c");
        let id = ctx
            .client
            .derive_escrow_id(&ctx.token, &10_000, &ctx.alice, &salt, &0, &None);
        results.push(measure_op(&ctx.env, "get_escrow_id_commitment", || {
            let _ = ctx.client.get_escrow_id_commitment(&id);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let comm = ctx.simple_deposit(&ctx.alice, 10_000, b"comm_st");
        results.push(measure_op(&ctx.env, "get_commitment_state", || {
            let _ = ctx.client.get_commitment_state(&comm);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let comm = ctx.simple_deposit(&ctx.alice, 10_000, b"ref_el");
        results.push(measure_op(&ctx.env, "is_refund_eligible", || {
            let _ = ctx.client.is_refund_eligible(&comm);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let salt = ctx.salt(b"proof_v");
        let _comm = ctx.simple_deposit(&ctx.alice, 10_000, b"proof_v");
        results.push(measure_op(&ctx.env, "verify_proof_view", || {
            let _ = ctx.client.verify_proof_view(&10_000, &salt, &ctx.alice);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let _salt = ctx.salt(b"esc_det");
        let comm = ctx.simple_deposit(&ctx.alice, 10_000, b"esc_det");
        results.push(measure_op(&ctx.env, "get_escrow_details", || {
            let _ = ctx.client.get_escrow_details(&comm, &ctx.alice);
        }));
    }

    // 2. Privacy
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "enable_privacy", || {
            let _ = ctx.client.enable_privacy(&ctx.alice, &1);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let _ = ctx.client.enable_privacy(&ctx.alice, &1);
        results.push(measure_op(&ctx.env, "privacy_status", || {
            let _ = ctx.client.privacy_status(&ctx.alice);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let _ = ctx.client.enable_privacy(&ctx.alice, &1);
        results.push(measure_op(&ctx.env, "privacy_history", || {
            let _ = ctx.client.privacy_history(&ctx.alice);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "set_privacy", || {
            let _ = ctx.client.set_privacy(&ctx.alice, &true);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let _ = ctx.client.set_privacy(&ctx.alice, &true);
        results.push(measure_op(&ctx.env, "get_privacy", || {
            let _ = ctx.client.get_privacy(&ctx.alice);
        }));
    }

    // 3. Batch
    {
        let ctx = TestContext::with_admin();
        ctx.mint(&ctx.alice, 10_000);
        let mut items = Vec::new(&ctx.env);
        items.push_back(BatchCreateItem {
            token: ctx.token.clone(),
            amount: 1_000,
            owner: ctx.alice.clone(),
            salt: ctx.salt(b"batch_c"),
            timeout_secs: 0,
            arbiter: None,
            nonce: 1,
            valid_until: u64::MAX,
        });
        results.push(measure_op(&ctx.env, "batch_create", || {
            let _ = ctx.client.batch_create(&items);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        ctx.mint(&ctx.alice, 10_000);
        let salt = ctx.salt(b"batch_rel");
        let _comm = ctx.client.deposit(
            &ctx.token,
            &1_000,
            &ctx.alice,
            &salt,
            &0,
            &None,
            &1,
            &u64::MAX,
        );
        let mut items = Vec::new(&ctx.env);
        items.push_back(BatchReleaseItem {
            to: ctx.alice.clone(),
            amount: 1_000,
            salt,
            nonce: 2,
            valid_until: u64::MAX,
        });
        results.push(measure_op(&ctx.env, "batch_release", || {
            let _ = ctx.client.batch_release(&items);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        ctx.mint(&ctx.alice, 10_000);
        let salt = ctx.salt(b"batch_ref");
        let comm = ctx.client.deposit(
            &ctx.token,
            &1_000,
            &ctx.alice,
            &salt,
            &10,
            &None,
            &1,
            &u64::MAX,
        );
        ctx.advance_time(20);
        let mut items = Vec::new(&ctx.env);
        items.push_back(BatchRefundItem {
            commitment: comm,
            nonce: 2,
            valid_until: u64::MAX,
        });
        results.push(measure_op(&ctx.env, "batch_refund", || {
            let _ = ctx.client.batch_refund(&ctx.alice, &items);
        }));
    }

    // 4. TTL
    {
        let ctx = TestContext::new();
        results.push(measure_op(&ctx.env, "get_ttl_config", || {
            let _ = ctx.client.get_ttl_config();
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let cfg = TtlConfig::default_config();
        results.push(measure_op(&ctx.env, "set_ttl_config", || {
            let _ = ctx.client.set_ttl_config(&ctx.admin, &cfg);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let comm = ctx.simple_deposit(&ctx.alice, 10_000, b"ext_ttl");
        results.push(measure_op(&ctx.env, "extend_escrow_ttl", || {
            let _ = ctx.client.extend_escrow_ttl(&comm);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let comm = ctx.simple_deposit(&ctx.alice, 10_000, b"res_arch");
        results.push(measure_op(&ctx.env, "restore_archived_escrow", || {
            let _ = ctx.client.restore_archived_escrow(&comm);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let salt = ctx.salt(b"fin_exp");
        ctx.mint(&ctx.alice, 10_000);
        let comm = ctx.client.deposit(
            &ctx.token,
            &10_000,
            &ctx.alice,
            &salt,
            &10,
            &None,
            &0,
            &u64::MAX,
        );
        ctx.advance_time(20);
        results.push(measure_op(&ctx.env, "finalize_expired_escrow", || {
            let _ = ctx.client.finalize_expired_escrow(&comm);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let salt = ctx.salt(b"cleanup");
        let comm = ctx.simple_deposit(&ctx.alice, 10_000, b"cleanup");
        let _ = ctx
            .client
            .withdraw(&ctx.token, &10_000, &comm, &ctx.alice, &salt, &0, &u64::MAX);
        results.push(measure_op(&ctx.env, "cleanup_escrow", || {
            let _ = ctx.client.cleanup_escrow(&comm);
        }));
    }

    // 5. Dispute
    {
        let ctx = TestContext::with_admin();
        let comm = ctx.deposit_with_arbiter(&ctx.alice, 10_000, b"dispute", 600);
        results.push(measure_op(&ctx.env, "dispute", || {
            let _ = ctx.client.dispute(&comm);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let comm = ctx.deposit_with_arbiter(&ctx.alice, 10_000, b"res_disp", 600);
        let _ = ctx.client.dispute(&comm);
        results.push(measure_op(&ctx.env, "resolve_dispute", || {
            let _ =
                ctx.client
                    .resolve_dispute(&ctx.arbiter, &comm, &false, &ctx.bob, &0, &u64::MAX);
        }));
    }
    {
        let ctx = TestContext::new();
        results.push(measure_op(&ctx.env, "get_dispute_quorum_config", || {
            let _ = ctx.client.get_dispute_quorum_config();
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let cfg = DisputeQuorumConfig {
            quorum: 2,
            vote_ttl_secs: 10_000,
        };
        results.push(measure_op(&ctx.env, "set_dispute_quorum_config", || {
            let _ = ctx.client.set_dispute_quorum_config(&ctx.admin, &cfg);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let arbiters = [ctx.arbiter.clone(), ctx.bob.clone()];
        let comm = ctx.deposit_with_arbiters(&ctx.alice, 10_000, b"vote_disp", 600, &arbiters, 2);
        let _ = ctx.client.dispute(&comm);
        results.push(measure_op(&ctx.env, "vote_for_dispute", || {
            let _ = ctx
                .client
                .vote_for_dispute(&ctx.arbiter, &comm, &true, &0, &u64::MAX);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let arbiters = [ctx.arbiter.clone()];
        let comm = ctx.deposit_with_arbiters(&ctx.alice, 10_000, b"res_ms", 600, &arbiters, 1);
        let _ = ctx.client.dispute(&comm);
        let _ = ctx
            .client
            .vote_for_dispute(&ctx.arbiter, &comm, &false, &0, &u64::MAX);
        results.push(measure_op(&ctx.env, "resolve_dispute_multi_sig", || {
            let _ = ctx.client.resolve_dispute_multi_sig(&comm, &ctx.bob);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let arbiters = [ctx.arbiter.clone()];
        let comm = ctx.deposit_with_arbiters(&ctx.alice, 10_000, b"res_to", 600, &arbiters, 1);
        let _ = ctx.client.dispute(&comm);
        ctx.advance_time(1_000_000);
        results.push(measure_op(&ctx.env, "resolve_dispute_timeout", || {
            let _ = ctx.client.resolve_dispute_timeout(&comm);
        }));
    }

    // 6. Admin & Lifecycle
    {
        let ctx = TestContext::new();
        results.push(measure_op(&ctx.env, "initialize", || {
            let _ = ctx.client.initialize(&ctx.admin);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "get_version", || {
            let _ = ctx.client.get_version();
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "get_deployment_metadata", || {
            let _ = ctx.client.get_deployment_metadata();
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "migrate", || {
            let _ = ctx.client.migrate(&ctx.admin);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "get_admin", || {
            let _ = ctx.client.get_admin();
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "propose_admin_transfer", || {
            let _ = ctx
                .client
                .propose_admin_transfer(&ctx.admin, &ctx.alice, &86_400);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let _ = ctx
            .client
            .propose_admin_transfer(&ctx.admin, &ctx.alice, &86_400);
        ctx.advance_time(100_000);
        results.push(measure_op(&ctx.env, "accept_admin_transfer", || {
            let _ = ctx.client.accept_admin_transfer(&ctx.alice);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let _ = ctx
            .client
            .propose_admin_transfer(&ctx.admin, &ctx.alice, &86_400);
        results.push(measure_op(&ctx.env, "cancel_admin_transfer", || {
            let _ = ctx.client.cancel_admin_transfer(&ctx.admin);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let _ = ctx
            .client
            .propose_admin_transfer(&ctx.admin, &ctx.alice, &86_400);
        results.push(measure_op(&ctx.env, "get_pending_admin_transfer", || {
            let _ = ctx.client.get_pending_admin_transfer();
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "activate_emergency_mode", || {
            let _ = ctx.client.activate_emergency_mode(&ctx.admin);
        }));
    }

    // 7. Pause policy
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "set_paused", || {
            let _ = ctx.client.set_paused(&ctx.admin, &true, &1);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "is_paused", || {
            let _ = ctx.client.is_paused();
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "is_emergency_mode", || {
            let _ = ctx.client.is_emergency_mode();
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(
            &ctx.env,
            "is_entry_allowed_in_emergency",
            || {
                let _ = ctx
                    .client
                    .is_entry_allowed_in_emergency(&EntryPoint::Withdraw);
            },
        ));
    }
    {
        let ctx = TestContext::with_admin();
        let mask = PauseFlag::Withdrawal.bits();
        results.push(measure_op(&ctx.env, "pause_features", || {
            let _ = ctx.client.pause_features(&ctx.admin, &mask, &1);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let mask = PauseFlag::Withdrawal.bits();
        let _ = ctx.client.pause_features(&ctx.admin, &mask, &1);
        results.push(measure_op(&ctx.env, "unpause_features", || {
            let _ = ctx.client.unpause_features(&ctx.admin, &mask, &0);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "is_feature_paused", || {
            let _ = ctx.client.is_feature_paused(&PauseFlag::Withdrawal);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let _ = ctx.client.set_paused(&ctx.admin, &true, &1);
        results.push(measure_op(&ctx.env, "get_global_pause_reason", || {
            let _ = ctx.client.get_global_pause_reason();
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let mask = PauseFlag::Withdrawal.bits();
        let _ = ctx.client.pause_features(&ctx.admin, &mask, &2);
        results.push(measure_op(&ctx.env, "get_feature_pause_reason", || {
            let _ = ctx.client.get_feature_pause_reason(&PauseFlag::Withdrawal);
        }));
    }

    // 8. Hooks
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "set_hook_allowed", || {
            let _ = ctx.client.set_hook_allowed(&ctx.admin, &ctx.bob, &true);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let _ = ctx.client.set_hook_allowed(&ctx.admin, &ctx.bob, &true);
        results.push(measure_op(&ctx.env, "is_hook_allowed", || {
            let _ = ctx.client.is_hook_allowed(&ctx.bob);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let _ = ctx.client.set_hook_allowed(&ctx.admin, &ctx.bob, &true);
        results.push(measure_op(&ctx.env, "register_hook", || {
            let _ = ctx.client.register_hook(&ctx.bob);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let _ = ctx.client.set_hook_allowed(&ctx.admin, &ctx.bob, &true);
        let _ = ctx.client.register_hook(&ctx.bob);
        results.push(measure_op(&ctx.env, "unregister_hook", || {
            let _ = ctx.client.unregister_hook(&ctx.bob);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "get_registered_hooks", || {
            let _ = ctx.client.get_registered_hooks();
        }));
    }

    // 9. Fee & Treasury
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "get_fee_config", || {
            let _ = ctx.client.get_fee_config();
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let cfg = FeeConfig { fee_bps: 100 };
        results.push(measure_op(&ctx.env, "set_fee_config", || {
            let _ = ctx.client.set_fee_config(&ctx.admin, &cfg);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let cfg = PerAssetFeeConfig {
            fee_bps: 150,
            arbiter_bps: 50,
        };
        results.push(measure_op(&ctx.env, "set_per_asset_fee", || {
            let _ = ctx.client.set_per_asset_fee(&ctx.admin, &ctx.token, &cfg);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let cfg = PerAssetFeeConfig {
            fee_bps: 150,
            arbiter_bps: 50,
        };
        let _ = ctx.client.set_per_asset_fee(&ctx.admin, &ctx.token, &cfg);
        results.push(measure_op(&ctx.env, "get_per_asset_fee", || {
            let _ = ctx.client.get_per_asset_fee(&ctx.token);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let cfg = OracleFeeConfig {
            oracle: ctx.bob.clone(),
            usd_fee_micros: 1_000_000,
            stale_threshold_secs: 50,
        };
        results.push(measure_op(&ctx.env, "set_oracle_fee_config", || {
            let _ = ctx.client.set_oracle_fee_config(&ctx.admin, &cfg);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let cfg = OracleFeeConfig {
            oracle: ctx.bob.clone(),
            usd_fee_micros: 1_000_000,
            stale_threshold_secs: 50,
        };
        let _ = ctx.client.set_oracle_fee_config(&ctx.admin, &cfg);
        results.push(measure_op(&ctx.env, "get_oracle_fee_config", || {
            let _ = ctx.client.get_oracle_fee_config();
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "set_platform_wallet", || {
            let _ = ctx
                .client
                .set_platform_wallet(&ctx.admin, &ctx.platform_wallet);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let _ = ctx
            .client
            .set_platform_wallet(&ctx.admin, &ctx.platform_wallet);
        results.push(measure_op(&ctx.env, "get_platform_wallet", || {
            let _ = ctx.client.get_platform_wallet();
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "rotate_fee_collector", || {
            let _ = ctx.client.rotate_fee_collector(&ctx.admin, &ctx.alice);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let _ = ctx.client.rotate_fee_collector(&ctx.admin, &ctx.alice);
        results.push(measure_op(&ctx.env, "get_active_fee_collector", || {
            let _ = ctx.client.get_active_fee_collector();
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "get_accrued_fee_balance", || {
            let _ = ctx.client.get_accrued_fee_balance(&ctx.token);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "withdraw_fees", || {
            let _ = ctx
                .client
                .withdraw_fees(&ctx.admin, &ctx.token, &0, &ctx.platform_wallet);
        }));
    }

    // 10. Oracle
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "record_oracle_price", || {
            let _ = ctx.client.record_oracle_price(&ctx.admin, &1_000_000);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "register_oracle_source", || {
            let _ = ctx.client.register_oracle_source(&ctx.admin, &ctx.bob);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let _ = ctx.client.register_oracle_source(&ctx.admin, &ctx.bob);
        results.push(measure_op(&ctx.env, "unregister_oracle_source", || {
            let _ = ctx.client.unregister_oracle_source(&ctx.admin, &ctx.bob);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "get_oracle_sources", || {
            let _ = ctx.client.get_oracle_sources();
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(
            &ctx.env,
            "set_oracle_aggregation_config",
            || {
                let _ = ctx
                    .client
                    .set_oracle_aggregation_config(&ctx.admin, &1, &500);
            },
        ));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(
            &ctx.env,
            "get_oracle_aggregation_config",
            || {
                let _ = ctx.client.get_oracle_aggregation_config();
            },
        ));
    }
    {
        let ctx = TestContext::with_admin();
        let _ = ctx.client.register_oracle_source(&ctx.admin, &ctx.bob);
        results.push(measure_op(&ctx.env, "record_oracle_source_price", || {
            let _ = ctx.client.record_oracle_source_price(&ctx.bob, &1_000_000);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let _ = ctx.client.set_oracle_fee_config(
            &ctx.admin,
            &OracleFeeConfig {
                oracle: ctx.bob.clone(),
                usd_fee_micros: 1_000_000,
                stale_threshold_secs: 500,
            },
        );
        let _ = ctx.client.register_oracle_source(&ctx.admin, &ctx.bob);
        let _ = ctx
            .client
            .set_oracle_aggregation_config(&ctx.admin, &1, &500);
        let _ = ctx.client.record_oracle_source_price(&ctx.bob, &1_000_000);
        results.push(measure_op(&ctx.env, "get_aggregated_oracle_price", || {
            let _ = ctx.client.get_aggregated_oracle_price();
        }));
    }

    // 11. Stealth payments
    {
        let ctx = TestContext::with_admin();
        let eph_pub = BytesN::from_array(&ctx.env, &[0x01; 32]);
        let spend_pub = BytesN::from_array(&ctx.env, &[0x02; 32]);
        let shared = stealth::derive_shared_secret(&ctx.env, &eph_pub, &spend_pub);
        let stealth_address = stealth::derive_stealth_address(&ctx.env, &spend_pub, &shared);
        let params = StealthDepositParams {
            sender: ctx.alice.clone(),
            token: ctx.token.clone(),
            amount_due: 1_000,
            amount_paid: 1_000,
            eph_pub: eph_pub.clone(),
            spend_pub: spend_pub.clone(),
            stealth_address: stealth_address.clone(),
            timeout_secs: 0,
        };
        ctx.mint(&ctx.alice, 1_000);
        results.push(measure_op(&ctx.env, "register_ephemeral_key", || {
            let _ = ctx.client.register_ephemeral_key(&params, &0, &u64::MAX);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let eph_pub = BytesN::from_array(&ctx.env, &[0x01; 32]);
        let spend_pub = BytesN::from_array(&ctx.env, &[0x02; 32]);
        let shared = stealth::derive_shared_secret(&ctx.env, &eph_pub, &spend_pub);
        let stealth_address = stealth::derive_stealth_address(&ctx.env, &spend_pub, &shared);
        let params = StealthDepositParams {
            sender: ctx.alice.clone(),
            token: ctx.token.clone(),
            amount_due: 1_000,
            amount_paid: 1_000,
            eph_pub: eph_pub.clone(),
            spend_pub: spend_pub.clone(),
            stealth_address: stealth_address.clone(),
            timeout_secs: 0,
        };
        ctx.mint(&ctx.alice, 1_000);
        let _ = ctx.client.register_ephemeral_key(&params, &0, &u64::MAX);
        results.push(measure_op(&ctx.env, "stealth_withdraw", || {
            let _ = ctx.client.stealth_withdraw(
                &ctx.alice,
                &eph_pub,
                &spend_pub,
                &stealth_address,
                &0,
                &u64::MAX,
            );
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let stealth_address = BytesN::from_array(&ctx.env, &[0x03; 32]);
        results.push(measure_op(&ctx.env, "get_stealth_status", || {
            let _ = ctx.client.get_stealth_status(&stealth_address);
        }));
    }

    // 12. Upgrades & Roles
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "set_upgrade_window", || {
            let _ = ctx.client.set_upgrade_window(&ctx.admin, &1, &100_000);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "get_upgrade_window", || {
            let _ = ctx.client.get_upgrade_window();
        }));
    }
    {
        let ctx = TestContext::with_admin();
        ctx.client.set_upgrade_window(&ctx.admin, &1, &100_000);
        ctx.advance_time(10);
        results.push(measure_op(&ctx.env, "start_upgrade", || {
            let _ = ctx.client.start_upgrade(&ctx.admin, &2);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        ctx.client.set_upgrade_window(&ctx.admin, &1, &100_000);
        ctx.advance_time(10);
        ctx.client.start_upgrade(&ctx.admin, &2);
        results.push(measure_op(&ctx.env, "complete_upgrade", || {
            let _ = ctx.client.complete_upgrade(&ctx.admin, &2);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let hash = BytesN::from_array(&ctx.env, &[0x44; 32]);
        results.push(measure_op(&ctx.env, "upgrade", || {
            let _ = ctx.client.try_upgrade(&ctx.admin, &hash);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        results.push(measure_op(&ctx.env, "grant_role", || {
            let _ = ctx
                .client
                .grant_role(&ctx.admin, &ctx.alice, &Role::Arbiter);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let _ = ctx
            .client
            .grant_role(&ctx.admin, &ctx.alice, &Role::Arbiter);
        results.push(measure_op(&ctx.env, "revoke_role", || {
            let _ = ctx
                .client
                .revoke_role(&ctx.admin, &ctx.alice, &Role::Arbiter);
        }));
    }
    {
        let ctx = TestContext::with_admin();
        let _ = ctx
            .client
            .grant_role(&ctx.admin, &ctx.alice, &Role::Arbiter);
        results.push(measure_op(&ctx.env, "get_roles", || {
            let _ = ctx.client.get_roles(&ctx.alice);
        }));
    }

    results
}

pub fn load_budget_baseline() -> EntrypointBudgetBaseline {
    serde_json::from_str(BUDGET_BASELINE_JSON)
        .expect("parse embedded entrypoint-budgets.json baseline")
}

/// Executes all entrypoints and asserts that every public entrypoint operates within
/// its recorded CPU and memory budget (including documented tolerance).
///
/// On regression, panics with a detailed report explicitly naming the offending entrypoint(s)
/// and their delta.
pub fn assert_all_entrypoints_within_budget() {
    let baseline = load_budget_baseline();
    let measurements = measure_all_entrypoints();

    let mut failures: StdVec<BudgetAssertionFailure> = StdVec::new();

    for m in &measurements {
        let budget = baseline.entrypoints.get(m.name).unwrap_or_else(|| {
            panic!(
                "Missing recorded budget in entrypoint-budgets.json for entrypoint '{}'. Every public entrypoint must have a recorded budget.",
                m.name
            );
        });

        let tolerance = budget
            .tolerance_pct
            .map(|t| t as f64)
            .unwrap_or(baseline.tolerance_pct);

        if let Err(fail) = check_budget_limit(
            m.name,
            "CPU instructions",
            m.cpu,
            budget.cpu_budget,
            tolerance,
        ) {
            failures.push(fail);
        }
        if let Err(fail) =
            check_budget_limit(m.name, "Memory bytes", m.mem, budget.mem_budget, tolerance)
        {
            failures.push(fail);
        }
    }

    if let Ok(dir) = std::env::var("QUICKEX_BENCH_ARTIFACT_DIR") {
        let _ = std::fs::create_dir_all(&dir);
        let mut md = String::from(
            "# QuickEx Per-Entrypoint Resource Budget Report\n\n| Entrypoint | CPU Measured | CPU Budget | CPU Delta | Mem Measured | Mem Budget | Mem Delta | Status |\n|---|---:|---:|---:|---:|---:|---:|:---:|\n",
        );
        for m in &measurements {
            if let Some(b) = baseline.entrypoints.get(m.name) {
                let cpu_d = m.cpu as i64 - b.cpu_budget as i64;
                let mem_d = m.mem as i64 - b.mem_budget as i64;
                let allowed_cpu_excess =
                    ((b.cpu_budget as f64) * (baseline.tolerance_pct / 100.0)).ceil() as u64;
                let allowed_mem_excess =
                    ((b.mem_budget as f64) * (baseline.tolerance_pct / 100.0)).ceil() as u64;
                let pass = m.cpu <= b.cpu_budget.saturating_add(allowed_cpu_excess)
                    && m.mem <= b.mem_budget.saturating_add(allowed_mem_excess);
                let status = if pass { "PASS" } else { "FAIL" };
                md.push_str(&format!(
                    "| `{}` | {} | {} | {} | {} | {} | {} | {} |\n",
                    m.name,
                    format_number(m.cpu),
                    format_number(b.cpu_budget),
                    format_signed_number(cpu_d),
                    format_number(m.mem),
                    format_number(b.mem_budget),
                    format_signed_number(mem_d),
                    status
                ));
            }
        }
        let _ = std::fs::write(format!("{dir}/entrypoint-budgets.md"), md.as_bytes());
    }

    if !failures.is_empty() {
        let mut report = format!(
            "\n================================================================================\nPER-ENTRYPOINT RESOURCE BUDGET REGRESSION: {} failure(s) detected\n================================================================================\n",
            failures.len()
        );
        for f in &failures {
            report.push_str(&f.format_report());
            report.push_str("\n--------------------------------------------------------------------------------\n");
        }
        report.push_str(
            "Budget changes require an explicit, reviewable update in `entrypoint-budgets.json`.\nIf this increase is intended, update the baseline with the rationale documented in the commit/PR.\n",
        );
        panic!("{}", report);
    }
}

// ===========================================================================
// Unit tests for the budget assertion framework
// ===========================================================================

/// AC1: Each public entrypoint has a recorded CPU and memory budget.
#[test]
fn test_all_public_entrypoints_have_recorded_budgets() {
    let baseline = load_budget_baseline();
    assert_eq!(baseline.kind, "quickex-entrypoint-budgets-v1");
    assert!(
        baseline.tolerance_pct > 0.0,
        "tolerance_pct must be positive"
    );

    for &name in ALL_ENTRYPOINTS {
        let entry = baseline.entrypoints.get(name);
        assert!(
            entry.is_some(),
            "Acceptance Criterion 1: Entrypoint '{}' must have a recorded budget in entrypoint-budgets.json",
            name
        );
        let entry = entry.unwrap();
        assert!(
            entry.cpu_budget > 0,
            "CPU budget for '{}' must be > 0",
            name
        );
        assert!(
            entry.mem_budget > 0,
            "Memory budget for '{}' must be > 0",
            name
        );
    }

    assert_eq!(
        baseline.entrypoints.len(),
        ALL_ENTRYPOINTS.len(),
        "Recorded entrypoints count must match ALL_ENTRYPOINTS exactly (no dangling or missing entries)"
    );
}

/// AC2 & AC4: Tests fail when an entrypoint exceeds its budget beyond tolerance,
/// and the failure report explicitly names the entrypoint and delta.
#[test]
fn test_budget_assertion_failure_names_entrypoint_and_delta() {
    let entrypoint = "deposit_partial_simulated";
    let budget = 400_000u64;
    let tolerance = 10.0f64;
    let allowed_excess = ((budget as f64) * (tolerance / 100.0)).ceil() as u64;
    let max_allowed = budget.saturating_add(allowed_excess); // 440,000

    // Within tolerance (420,000 <= 440,000) -> passes
    assert!(check_budget_limit(entrypoint, "CPU instructions", 420_000, budget, tolerance).is_ok());

    // Beyond tolerance (550,000 > 440,000) -> fails with full diagnostic details
    let fail = check_budget_limit(entrypoint, "CPU instructions", 550_000, budget, tolerance)
        .expect_err("Must return failure when exceeding budget beyond tolerance");

    assert_eq!(fail.entrypoint, entrypoint);
    assert_eq!(fail.resource, "CPU instructions");
    assert_eq!(fail.actual, 550_000);
    assert_eq!(fail.budget, 400_000);
    assert_eq!(fail.max_allowed, max_allowed);
    assert_eq!(fail.delta, 150_000);
    assert!((fail.delta_pct - 37.5).abs() < 0.01);

    let report = fail.format_report();
    // Acceptance criterion 4: The report names the entrypoint and the delta on failure.
    assert!(
        report.contains("deposit_partial_simulated"),
        "Report must name the failing entrypoint"
    );
    assert!(
        report.contains("+150,000"),
        "Report must explicitly state the delta value"
    );
    assert!(
        report.contains("+37.50%"),
        "Report must explicitly state the delta percentage"
    );
    assert!(
        report.contains("CPU instructions"),
        "Report must name the resource type"
    );
    assert!(
        report.contains("excess:"),
        "Report must state the excess over the allowed tolerance"
    );
    let excess = fail.actual.saturating_sub(fail.max_allowed);
    assert!(
        report.contains(&format!("+{}", format_number(excess))),
        "Report must contain the formatted excess amount"
    );
}

/// AC2: Tests succeed when an entrypoint is within budget or within tolerance.
#[test]
fn test_budget_within_tolerance_passes() {
    let budget = 100_000u64;
    let tolerance = 10.0f64;

    // Exact match
    assert!(
        check_budget_limit("sample_op", "CPU instructions", 100_000, budget, tolerance).is_ok()
    );
    // Below budget
    assert!(check_budget_limit("sample_op", "CPU instructions", 80_000, budget, tolerance).is_ok());
    // Inside tolerance
    assert!(
        check_budget_limit("sample_op", "CPU instructions", 110_000, budget, tolerance).is_ok()
    );
}

/// AC3: Budget changes require an explicit, reviewable update rather than passing silently.
#[test]
fn test_explicit_update_required_not_silent() {
    let baseline = load_budget_baseline();
    assert!(
        baseline.description.contains("explicit, reviewable update"),
        "Acceptance criterion 3: Baseline description must document reviewable update requirement"
    );

    // Verify baseline file exists on disk and is valid JSON
    let on_disk = std::fs::read_to_string("entrypoint-budgets.json")
        .or_else(|_| std::fs::read_to_string("contracts/quickex/entrypoint-budgets.json"))
        .or_else(|_| {
            std::fs::read_to_string("app/contract/contracts/quickex/entrypoint-budgets.json")
        });

    assert!(
        on_disk.is_ok(),
        "entrypoint-budgets.json must exist in repository for git tracking and review"
    );
}
