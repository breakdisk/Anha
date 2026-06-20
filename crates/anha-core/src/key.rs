//! Deterministic record-key derivation.
//!
//! The DHT/storage key for a handle is `SHA256(handle_string)`. Keeping this in
//! one place means the resolver, storage engine, and DHT all agree on the key.

use crate::handle::Handle;
use sha2::{Digest, Sha256};

/// Derive the 32-byte record key for a handle.
pub fn record_key(handle: &Handle) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(handle.to_string().as_bytes());
    hasher.finalize().into()
}

/// Hex-encoded form of [`record_key`], convenient for cache keys and logs.
pub fn record_key_hex(handle: &Handle) -> String {
    hex::encode(record_key(handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_deterministic() {
        let h = Handle::parse("@reasoning.acme.ai").unwrap();
        assert_eq!(record_key(&h), record_key(&h));
    }

    #[test]
    fn different_handles_differ() {
        let a = Handle::parse("@reasoning.acme.ai").unwrap();
        let b = Handle::parse("@coding.acme.ai").unwrap();
        assert_ne!(record_key(&a), record_key(&b));
    }
}
