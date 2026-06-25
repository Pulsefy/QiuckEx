//! QuickEx — Soroban contract (SC-W6-06: storage-compaction pass)
//!
//! # What changed and why
//!
//! ## Storage keys  (DataKey enum)
//! BEFORE: every variant carried a full `String` username which is heap-allocated
//!         and re-encoded as a Symbol+Bytes pair on every ledger access.
//! AFTER:  variants carry `soroban_sdk::Symbol` (≤ 32 chars, fits in one Val word)
//!         for the hot "username → owner" and "link" paths.  The cold "history"
//!         path uses a (Symbol, u32) tuple so the sequence number is packed
//!         inline rather than serialised as a separate Bytes field.
//!
//! ## PaymentLink record
//! BEFORE: { username: String, amount: i128, asset: String, memo: String,
//!           privacy: bool, created_at: u64, creator: Address }
//!         — two unbounded Strings (username + asset) duplicated on every link.
//! AFTER:  { amount: i128, asset: Symbol, memo: String,
//!           flags: u32, created_at: u64, creator: Address }
//!         — username dropped (it IS the key); asset promoted to Symbol;
//!           privacy bool packed into a `flags: u32` bitfield so future
//!           boolean fields cost zero extra bytes.
//!
//! ## UserRecord
//! BEFORE: { username: String, owner: Address, link_count: u64,
//!           total_received: i128, registered_at: u64 }
//! AFTER:  { owner: Address, link_count: u32, total_received: i128,
//!           registered_at: u64 }
//!         — username dropped (it IS the key); link_count narrowed u64→u32
//!           saving 4 bytes per record.

#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short,
    Address, Env, String, Symbol,
};

// ── Storage key schema ────────────────────────────────────────────────────────

/// Discriminated union of every storage key the contract uses.
///
/// Serialised size (XDR) per variant:
/// | Variant          | BEFORE (bytes) | AFTER (bytes) | Δ         |
/// |------------------|---------------|---------------|-----------|
/// | UsernameOwner    | 4 + len(name) | 4 + ≤8        | –variable |
/// | Link             | 4 + len(name) | 4 + ≤8 + 4    | –variable |
/// | TotalLinks (new) | n/a           | 4             | new       |
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Maps `username Symbol → UserRecord` (instance storage).
    UsernameOwner(Symbol),
    /// Maps `(username Symbol, link_id u32) → PaymentLink` (persistent storage).
    Link(Symbol, u32),
    /// Running count of all links ever created (instance storage).
    TotalLinks,
}

// ── Compacted data types ──────────────────────────────────────────────────────

/// Bit positions inside `PaymentLink::flags`.
pub mod flags {
    /// Set when X-Ray / ZK-privacy mode is enabled for this link.
    pub const PRIVACY_ENABLED: u32 = 1 << 0;
    /// Set when the link has been revoked by its creator.
    pub const REVOKED: u32 = 1 << 1;
}

/// A single payment-request link.
///
/// The username that owns this link is NOT stored here — it is the key under
/// which this record is stored, eliminating one redundant String per link.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct PaymentLink {
    /// Requested amount in stroops (0 = "any amount").
    pub amount: i128,
    /// Asset code as a Symbol (e.g. `USDC`, `XLM`) — fits in ≤ 32 chars.
    pub asset: Symbol,
    /// Optional human-readable memo (arbitrary length, stored verbatim).
    pub memo: String,
    /// Packed boolean flags — see the `flags` module.
    pub flags: u32,
    /// Ledger timestamp at creation.
    pub created_at: u64,
    /// Wallet address that created the link.
    pub creator: Address,
}

impl PaymentLink {
    pub fn privacy_enabled(&self) -> bool {
        self.flags & flags::PRIVACY_ENABLED != 0
    }
    pub fn is_revoked(&self) -> bool {
        self.flags & flags::REVOKED != 0
    }
}

/// Per-username ownership and stats record.
///
/// Stored under `DataKey::UsernameOwner(username)`.  Username itself dropped
/// from the value (it is already the key), saving 4 + len bytes per record.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct UserRecord {
    /// The wallet that claimed this username.
    pub owner: Address,
    /// Number of links ever created under this username.
    /// Narrowed from u64 → u32 (saves 4 bytes; 4 billion links is sufficient).
    pub link_count: u32,
    /// Lifetime USDC received through all links (in stroops).
    pub total_received: i128,
    /// Ledger timestamp when the username was claimed.
    pub registered_at: u64,
}

// ── Contract implementation ───────────────────────────────────────────────────

#[contract]
pub struct QuickExContract;

#[contractimpl]
impl QuickExContract {
    // ── Username registration ─────────────────────────────────────────────

    /// Claim a unique username.  Panics if already taken.
    pub fn register(env: Env, username: Symbol, owner: Address) {
        owner.require_auth();

        let key = DataKey::UsernameOwner(username.clone());
        if env.storage().instance().has(&key) {
            panic!("username already taken");
        }

        let record = UserRecord {
            owner,
            link_count: 0,
            total_received: 0,
            registered_at: env.ledger().timestamp(),
        };

        env.storage().instance().set(&key, &record);
    }

    /// Look up a username's owner record.
    pub fn get_user(env: Env, username: Symbol) -> Option<UserRecord> {
        env.storage()
            .instance()
            .get(&DataKey::UsernameOwner(username))
    }

    // ── Payment link CRUD ─────────────────────────────────────────────────

    /// Create a new payment link under `username`.
    /// Returns the numeric link-id assigned.
    pub fn create_link(
        env: Env,
        username: Symbol,
        amount: i128,
        asset: Symbol,
        memo: String,
        privacy: bool,
    ) -> u32 {
        let owner_key = DataKey::UsernameOwner(username.clone());
        let mut user_rec: UserRecord = env
            .storage()
            .instance()
            .get(&owner_key)
            .expect("username not found");

        user_rec.owner.require_auth();

        let link_id = user_rec.link_count;
        user_rec.link_count = link_id
            .checked_add(1)
            .expect("link_count overflow");

        let link = PaymentLink {
            amount,
            asset,
            memo,
            flags: if privacy { flags::PRIVACY_ENABLED } else { 0 },
            created_at: env.ledger().timestamp(),
            creator: user_rec.owner.clone(),
        };

        env.storage()
            .persistent()
            .set(&DataKey::Link(username.clone(), link_id), &link);

        env.storage().instance().set(&owner_key, &user_rec);

        let total: u32 = env
            .storage()
            .instance()
            .get(&DataKey::TotalLinks)
            .unwrap_or(0u32);
        env.storage()
            .instance()
            .set(&DataKey::TotalLinks, &(total + 1));

        link_id
    }

    /// Fetch a specific payment link.
    pub fn get_link(env: Env, username: Symbol, link_id: u32) -> Option<PaymentLink> {
        env.storage()
            .persistent()
            .get(&DataKey::Link(username, link_id))
    }

    /// Revoke a link (creator only).
    pub fn revoke_link(env: Env, username: Symbol, link_id: u32) {
        let owner_key = DataKey::UsernameOwner(username.clone());
        let user_rec: UserRecord = env
            .storage()
            .instance()
            .get(&owner_key)
            .expect("username not found");

        user_rec.owner.require_auth();

        let link_key = DataKey::Link(username, link_id);
        let mut link: PaymentLink = env
            .storage()
            .persistent()
            .get(&link_key)
            .expect("link not found");

        link.flags |= flags::REVOKED;
        env.storage().persistent().set(&link_key, &link);
    }

    /// Record an inbound payment (called by off-chain relayer after Horizon confirms).
    pub fn record_payment(env: Env, username: Symbol, amount_received: i128) {
        let key = DataKey::UsernameOwner(username);
        let mut rec: UserRecord = env
            .storage()
            .instance()
            .get(&key)
            .expect("username not found");

        rec.total_received = rec
            .total_received
            .checked_add(amount_received)
            .expect("total_received overflow");

        env.storage().instance().set(&key, &rec);
    }

    /// Global link count (testnet telemetry helper).
    pub fn total_links(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::TotalLinks)
            .unwrap_or(0)
    }
}

// ── Convenience symbol constructors ──────────────────────────────────────────

pub fn sym_usdc(env: &Env) -> Symbol {
    Symbol::new(env, "USDC")
}

pub fn sym_xlm(_env: &Env) -> Symbol {
    symbol_short!("XLM")
}