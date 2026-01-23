#![no_std]
use soroban_sdk::{
    Address, Bytes, BytesN, Env, Map, Symbol, Vec, contract, contracterror, contractevent,
    contractimpl, contracttype, token, xdr::ToXdr,
};

// NOTE: These should already exist from previous tasks
// Including here for completeness, but they may already be defined

/// Escrow entry status
#[contracttype]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EscrowStatus {
    Pending,
    Spent,
}

/// Escrow entry structure
#[contracttype]
#[derive(Clone)]
pub struct EscrowEntry {
    pub commitment: BytesN<32>,
    pub token: Address,
    pub amount: i128,
    pub status: EscrowStatus,
    pub depositor: Address,
}

#[contractevent]
pub struct WithdrawEvent {
    pub to: Address,
    pub commitment: BytesN<32>,
}

/// Contract errors
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    CommitmentNotFound = 1,
    AlreadySpent = 2,
    InvalidCommitment = 3,
    InvalidAmount = 4,
}

/// Main contract structure
#[contract]
pub struct QuickexContract;

#[contractimpl]
impl QuickexContract {
    /// Withdraw funds by proving commitment ownership

    pub fn withdraw(env: Env, to: Address, amount: i128, salt: Bytes) -> Result<bool, Error> {
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        to.require_auth();

        let commitment = Self::compute_commitment_hash(&env, &to, amount, &salt);

        let escrow_key = Symbol::new(&env, "escrow");
        let entry: EscrowEntry = env
            .storage()
            .persistent()
            .get(&(escrow_key.clone(), commitment.clone()))
            .ok_or(Error::CommitmentNotFound)?;

        if entry.status != EscrowStatus::Pending {
            return Err(Error::AlreadySpent);
        }

        if entry.amount != amount {
            return Err(Error::InvalidCommitment);
        }

        let mut updated_entry = entry.clone();
        updated_entry.status = EscrowStatus::Spent;
        env.storage()
            .persistent()
            .set(&(escrow_key, commitment.clone()), &updated_entry);

        let token_client = token::Client::new(&env, &entry.token);
        token_client.transfer(&env.current_contract_address(), &to, &amount);

        WithdrawEvent { to, commitment }.publish(&env);

        Ok(true)
    }

    /// Compute commitment hash - internal helper for withdraw function
    fn compute_commitment_hash(
        env: &Env,
        address: &Address,
        amount: i128,
        salt: &Bytes,
    ) -> BytesN<32> {
        let mut data = Bytes::new(env);

        let address_bytes: Bytes = address.to_xdr(&env);

        data.append(&address_bytes);

        data.append(&Bytes::from_slice(env, &amount.to_be_bytes()));

        data.append(salt);

        env.crypto().sha256(&data).into()
    }

    pub fn enable_privacy(env: Env, account: Address, privacy_level: u32) -> bool {
        let key = Symbol::new(&env, "privacy_level");
        env.storage()
            .persistent()
            .set(&(key, account.clone()), &privacy_level);

        let history_key = Symbol::new(&env, "privacy_history");
        let mut history: Vec<u32> = env
            .storage()
            .persistent()
            .get(&(history_key.clone(), account.clone()))
            .unwrap_or(Vec::new(&env));

        history.push_front(privacy_level);
        env.storage()
            .persistent()
            .set(&(history_key, account), &history);

        true
    }

    pub fn privacy_status(env: Env, account: Address) -> Option<u32> {
        let key = Symbol::new(&env, "privacy_level");
        env.storage().persistent().get(&(key, account))
    }

    pub fn privacy_history(env: Env, account: Address) -> Vec<u32> {
        let key = Symbol::new(&env, "privacy_history");
        env.storage()
            .persistent()
            .get(&(key, account))
            .unwrap_or(Vec::new(&env))
    }

    pub fn create_escrow(env: Env, from: Address, to: Address, _amount: u64) -> u64 {
        let counter_key = Symbol::new(&env, "escrow_counter");
        let mut count: u64 = env.storage().persistent().get(&counter_key).unwrap_or(0);
        count += 1;
        env.storage().persistent().set(&counter_key, &count);

        let escrow_id = count;
        let escrow_key = Symbol::new(&env, "escrow");
        let mut escrow_details = Map::<Symbol, Address>::new(&env);
        escrow_details.set(Symbol::new(&env, "from"), from);
        escrow_details.set(Symbol::new(&env, "to"), to);

        env.storage()
            .persistent()
            .set(&(escrow_key, escrow_id), &escrow_details);

        escrow_id
    }

    pub fn health_check() -> bool {
        true
    }
}

#[cfg(test)]
mod test;
