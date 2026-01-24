use crate::errors::QuickexError;
use soroban_sdk::{Address, Bytes, BytesN, Env, xdr::ToXdr};

pub fn create_amount_commitment(
    env: &Env,
    owner: Address,
    amount: i128,
    salt: Bytes,
) -> Result<BytesN<32>, QuickexError> {
    if amount < 0 {
        return Err(QuickexError::InvalidAmount);
    }

    // Cap salt length as a safeguard
    if salt.len() > 1024 {
        return Err(QuickexError::InvalidSalt);
    }

    let mut payload = Bytes::new(env);

    // Append owner (Address) - using XDR serialization for consistency
    payload.append(&owner.to_xdr(env));

    // Serialize amount (i128) to big-endian bytes
    let amount_bytes: [u8; 16] = amount.to_be_bytes();

    // Correct loop iteration over bytes
    for b in &amount_bytes {
        payload.push_back(*b);
    }

    // Append salt
    payload.append(&salt);

    // Return SHA256 hash
    Ok(env.crypto().sha256(&payload).into())
}

pub fn verify_amount_commitment(
    env: &Env,
    commitment: BytesN<32>,
    owner: Address,
    amount: i128,
    salt: Bytes,
) -> bool {
    match create_amount_commitment(env, owner, amount, salt) {
        Ok(hash) => hash == commitment,
        Err(_) => false,
    }
}
