//! Builds a depositor account whose NATIVE authentication is an ecdsa_k256_keccak key we hold,
//! so the same key both controls the account and signs its intents (Plan 2 binding).
//!
//! We build the `AuthSingleSig` auth component directly from a key WE generate (one per `seed`),
//! rather than using `Auth::BasicAuth { EcdsaK256Keccak }` from miden-testing: that path's
//! `build_component()` uses a fixed zero RNG seed, so every account would get the SAME key.
//! Here each `seed` deterministically produces a DISTINCT key, which is load-bearing for Plan 2
//! (each depositor's intents are signed by, and verified against, its own key).
use miden_protocol::Word;
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey, PublicKeyCommitment};
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountStorageMode};
use miden_standards::account::auth::AuthSingleSig;
use miden_standards::account::wallets::BasicWallet;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// A depositor: a Miden account whose native auth key is one we hold and will also use to sign
/// the account's intents.
pub struct Depositor {
    pub account: Account,
    pub key: AuthSecretKey,
    /// Commitment to the account's auth public key — equals the value stored in the
    /// `AuthSingleSig` public-key slot, and the value intents will be verified against.
    pub commitment: Word,
}

/// Builds a depositor account whose native auth component is `AuthSingleSig` over an
/// `EcdsaK256Keccak` key derived deterministically from `seed`. Distinct seeds yield distinct keys.
pub fn new_depositor(seed: u64) -> Depositor {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let key = AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rng);
    let pkc: PublicKeyCommitment = key.public_key().to_commitment();
    let commitment: Word = pkc.into();

    // Account-build randomness is also derived from `seed` so the whole account is reproducible.
    let mut acct_rng = ChaCha20Rng::seed_from_u64(seed ^ 0x5eed_5eed_5eed_5eed);
    // The native auth component (AuthSingleSig) exports only the auth procedure, which does NOT
    // count toward an account's required non-auth procedures. A depositor is a wallet, so we add
    // the standard BasicWallet component (receive_asset / move_asset_to_note) to satisfy the
    // `MIN_NUM_PROCEDURES` requirement and to give the depositor a usable identity/vault.
    let account = AccountBuilder::new(rand::Rng::random::<[u8; 32]>(&mut acct_rng))
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(AuthSingleSig::new(pkc, AuthScheme::EcdsaK256Keccak))
        .with_component(BasicWallet)
        .build_existing()
        .expect("depositor account must build");

    Depositor { account, key, commitment }
}

/// The depositor's user-id word: `[id_prefix, id_suffix, 0, 0]`. This is the raw `StorageMap` key
/// under which the operator stores/looks up this depositor's pubkey commitment (Plan 2 Q1).
pub fn user_id_word(account_id: AccountId) -> Word {
    Word::from([
        account_id.prefix().as_felt(),
        account_id.suffix(),
        0u32.into(),
        0u32.into(),
    ])
}

/// Build a depositor account whose native auth component is `AuthSingleSig` over a GIVEN
/// `PublicKeyCommitment` (e.g. derived from a TypeScript-produced public key). No secret key is
/// held in Rust; the account is usable for verification tests where the private key lives in an
/// external SDK (TypeScript, hardware wallet, etc.).
///
/// This is the Plan 2 binding entry point for the TS→MASM flow: the caller deserialises the TS
/// public key via `PublicKey::read_from_bytes`, calls `pubkey.to_commitment()`, and passes the
/// result here. The returned `Account` has the TS key as its native auth key.
pub fn account_from_pubkey_commitment(pkc: PublicKeyCommitment) -> Account {
    AccountBuilder::new(rand::random::<[u8; 32]>())
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(AuthSingleSig::new(pkc, AuthScheme::EcdsaK256Keccak))
        .with_component(BasicWallet)
        .build_existing()
        .expect("account_from_pubkey_commitment: account must build")
}

/// Build a depositor account deterministically from a `PublicKeyCommitment`.
///
/// The `AccountBuilder` seed is derived from the commitment bytes, so the same commitment always
/// produces the same `AccountId`. This is required by the two-phase walkthrough flow where the
/// account id must be known (and passed to the TS signer) before the intent is signed.
///
/// Unlike `account_from_pubkey_commitment` (which uses `rand::random` and produces a different
/// account id on every call), this function is pure and side-effect-free: given the same
/// `PublicKeyCommitment`, it always returns the same `Account` with the same `AccountId`.
pub fn account_from_pubkey_commitment_seeded(pkc: PublicKeyCommitment) -> Account {
    // Derive a deterministic 32-byte seed from the commitment word.
    // The commitment is a `Word` ([Felt; 4]); we pack each felt's canonical u64 as
    // little-endian bytes into the seed so the mapping is injective.
    let comm_word: Word = pkc.into();
    let mut seed = [0u8; 32];
    for (i, felt) in comm_word.iter().enumerate() {
        let bytes = felt.as_canonical_u64().to_le_bytes();
        seed[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    AccountBuilder::new(seed)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(AuthSingleSig::new(pkc, AuthScheme::EcdsaK256Keccak))
        .with_component(BasicWallet)
        .build_existing()
        .expect("account_from_pubkey_commitment_seeded: account must build")
}

/// Reads the auth component's stored pubkey commitment from account storage.
///
/// `AuthSingleSig` stores the pubkey commitment as a value slot named
/// `miden::standards::auth::singlesig::pub_key` (see `AuthSingleSig::public_key_slot()` /
/// `impl From<AuthSingleSig> for AccountComponent`). The returned `Word` equals the depositor's
/// `commitment`, proving the held key controls the account.
pub fn stored_auth_commitment(account: &Account) -> Word {
    account
        .storage()
        .get_item(AuthSingleSig::public_key_slot())
        .expect("AuthSingleSig public-key slot must exist in a depositor account")
}
