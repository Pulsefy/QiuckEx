//! Shared test scaffolding for QuickEx contract tests.
//!
//! Pick the constructor that matches what your test needs and you're ready to go:
//!
//! ```rust
//! // Just the contract, no admin yet
//! let ctx = TestContext::new();
//!
//! // Contract + admin initialized
//! let ctx = TestContext::with_admin();
//!
//! // Contract + admin + fee set (250 bps = 2.5%)
//! let ctx = TestContext::with_fees(250);
//! ```
//!
//! Every constructor gives you these pre-built fixtures:
//!
//! | Field             | Type      | What it is                                   |
//! |-------------------|-----------|----------------------------------------------|
//! | `env`             | `Env`     | Soroban test env (all auths mocked)          |
//! | `client`          | `…Client` | Deployed contract client                     |
//! | `admin`           | `Address` | Has admin privileges                         |
//! | `platform_wallet` | `Address` | Where fees land                              |
//! | `alice`           | `Address` | First test user                              |
//! | `bob`             | `Address` | Second test user                             |
//! | `arbiter`         | `Address` | Used in dispute tests                        |
//! | `token`           | `Address` | The test token                               |

use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env,
};

use crate::{types::FeeConfig, QuickexContract, QuickexContractClient};

/// Test harness for QuickEx contract tests.
///
/// See the module-level docs for usage examples.
#[allow(dead_code)]
pub struct TestContext<'a> {
    /// Soroban test env, all auths mocked.
    pub env: Env,
    /// Contract client pointing at the deployed instance.
    pub client: QuickexContractClient<'a>,
    pub admin: Address,
    pub platform_wallet: Address,
    /// First test user.
    pub alice: Address,
    /// Second test user.
    pub bob: Address,
    pub arbiter: Address,
    pub token: Address,
}

#[allow(dead_code)]
impl<'a> TestContext<'a> {
    // -- constructors -------------------------------------------------------

    /// Bare minimum — contract deployed and token registered, no admin set yet.
    pub fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(QuickexContract, ());
        let client = QuickexContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let platform_wallet = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let arbiter = Address::generate(&env);
        let token = env
            .register_stellar_asset_contract_v2(Address::generate(&env))
            .address();

        Self {
            env,
            client,
            admin,
            platform_wallet,
            alice,
            bob,
            arbiter,
            token,
        }
    }

    /// Same as `new()` but also calls `initialize` so the admin is set.
    pub fn with_admin() -> Self {
        let ctx = Self::new();
        ctx.client.initialize(&ctx.admin);
        ctx
    }

    /// `with_admin()` + a fee already set. `fee_bps` is in basis points (250 = 2.5%).
    pub fn with_fees(fee_bps: u32) -> Self {
        let ctx = Self::with_admin();
        ctx.client
            .set_fee_config(&ctx.admin, &FeeConfig { fee_bps });
        ctx.client
            .set_platform_wallet(&ctx.admin, &ctx.platform_wallet);
        ctx
    }

    // -- token helpers ------------------------------------------------------

    /// Give `recipient` some test tokens.
    pub fn mint(&self, recipient: &Address, amount: i128) {
        token::StellarAssetClient::new(&self.env, &self.token).mint(recipient, &amount);
    }

    /// Check the test token balance of `address`.
    pub fn balance(&self, address: &Address) -> i128 {
        token::Client::new(&self.env, &self.token).balance(address)
    }

    // -- commitment helpers -------------------------------------------------

    /// Off-chain commitment hash matching the on-chain formula, useful for building expected values in tests.
    #[allow(dead_code)]
    pub fn commitment(&self, owner: &Address, amount: i128, salt: &[u8]) -> BytesN<32> {
        let mut data = Bytes::new(&self.env);
        data.append(&owner.clone().to_xdr(&self.env));
        data.append(&Bytes::from_slice(&self.env, &amount.to_be_bytes()));
        data.append(&Bytes::from_slice(&self.env, salt));
        self.env.crypto().keccak256(&data).into()
    }

    /// Wrap a byte slice into the `Bytes` type the contract expects.
    pub fn salt(&self, s: &[u8]) -> Bytes {
        Bytes::from_slice(&self.env, s)
    }

    // -- escrow shortcuts ---------------------------------------------------

    /// Mint tokens then deposit — no arbiter, no timeout. Returns the commitment hash.
    pub fn simple_deposit(&self, owner: &Address, amount: i128, salt: &[u8]) -> BytesN<32> {
        self.mint(owner, amount);
        self.client
            .deposit(&self.token, &amount, owner, &self.salt(salt), &0, &None)
    }

    /// Like `simple_deposit` but wires in the arbiter and a timeout.
    pub fn deposit_with_arbiter(
        &self,
        owner: &Address,
        amount: i128,
        salt: &[u8],
        timeout_secs: u64,
    ) -> BytesN<32> {
        self.mint(owner, amount);
        self.client.deposit(
            &self.token,
            &amount,
            owner,
            &self.salt(salt),
            &timeout_secs,
            &Some(self.arbiter.clone()),
        )
    }

    // -- time helpers -------------------------------------------------------

    /// Push the ledger clock forward by `secs` seconds.
    pub fn advance_time(&self, secs: u64) {
        let now = self.env.ledger().timestamp();
        self.env.ledger().set_timestamp(now + secs);
    }
}
