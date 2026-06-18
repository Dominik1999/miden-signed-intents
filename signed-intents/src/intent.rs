//! The transfer intent and its canonical, signable encoding.

use miden_client::crypto::Rpo256;
use miden_protocol::{Felt, Word};

/// Domain-separation tag — stops a signature for one action type being
/// replayed as another. See the cancel/withdraw tags in the perp repo.
pub const DOMAIN_TRANSFER: u64 = 1;

/// A user's authorization to move `amount` to a recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Intent {
    pub recipient_prefix: u64,
    pub recipient_suffix: u64,
    pub amount: u64,
    /// Per-account strictly-increasing replay guard.
    pub nonce: u64,
    /// Intent is invalid once the chain reaches this block height.
    pub expiry_block: u64,
}

impl Intent {
    /// The exact field elements that are hashed to the signed Word.
    /// MUST match the TypeScript `intentFelts` ordering byte-for-byte.
    pub fn canonical_felts(&self) -> Vec<u64> {
        vec![
            DOMAIN_TRANSFER,
            self.recipient_prefix,
            self.recipient_suffix,
            self.amount,
            self.nonce,
            self.expiry_block,
        ]
    }

    /// The Word the user signs.
    pub fn message_word(&self) -> Word {
        message_word(&self.canonical_felts())
    }
}

/// Hash a canonical felt vector to the signable Word.
pub fn message_word(felts: &[u64]) -> Word {
    let elements: Vec<Felt> = felts.iter().map(|&v| Felt::new(v)).collect();
    Rpo256::hash_elements(&elements)
}
