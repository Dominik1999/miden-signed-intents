//! Adversarial tests: proves the relayer cannot forge, tamper, replay, or expire intents.
//!
//! Each test submits a cheating request to `relay_intent` and asserts the result is
//! `Err(RelayError::Rejected(_))`. The transaction is cryptographically unprovable in every
//! case, which is the payoff of the whole tutorial.

use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::utils::serde::Serializable as _; // brings to_bytes() into scope
use signed_intents::intent::Intent;
use signed_intents::relayer::{
    advance_blocks, deploy_operator, new_chain, relay_intent, RelayError,
};

fn key() -> AuthSecretKey {
    AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rand::rng())
}

fn make_intent(nonce: u64, expiry: u64) -> Intent {
    Intent {
        user_prefix: 0xAAAA,
        user_suffix: 0xBBBB,
        recipient_prefix: 0x1234,
        recipient_suffix: 0x5678,
        amount: 1000,
        nonce,
        expiry_block: expiry,
    }
}

/// Sign an intent; returns the hex-encoded serialised `Signature` bytes.
/// Matches the idiom in `happy_path.rs`: `hex::encode(signature.to_bytes())`.
fn sign(k: &AuthSecretKey, i: &Intent) -> String {
    let sig = k.sign(i.message_word());
    hex::encode(sig.to_bytes())
}

// ---------------------------------------------------------------------------
// 1. Tampered amount
// ---------------------------------------------------------------------------

/// Relayer edits the amount field after the user has signed. The on-chain Poseidon2
/// reconstruction produces a different MSG, so ECDSA recovery yields the wrong key
/// (or panics), and `relay_intent` maps it to `Rejected`.
#[test]
fn relayer_cannot_tamper_with_the_amount() {
    let k = key();
    let signed = make_intent(1, 100_000);
    let sig_hex = sign(&k, &signed);

    let mut chain = new_chain();
    let dep = deploy_operator(&mut chain, &k.public_key());

    // Relayer submits a DIFFERENT amount than was signed.
    let mut tampered = signed;
    tampered.amount = 9_999_999;

    let r = relay_intent(&mut chain, &dep, &tampered, &sig_hex);
    match r {
        Err(RelayError::Rejected(ref msg)) => {
            // The tamper is caught at the on-chain commitment check (recovered pubkey
            // differs from the stored commitment) OR via a caught ECDSA-recovery panic.
            // Either way the rejection message must be non-empty.
            assert!(!msg.is_empty(), "tampered amount: rejection message must not be empty");
        }
        other => panic!("tampered amount must be rejected; got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 2. Forged signature
// ---------------------------------------------------------------------------

/// An attacker signs the intent with their own key, but the account was deployed with the
/// owner's commitment. When `to_prepared_signature` runs it recovers the attacker's pubkey
/// instead of the owner's, so the on-chain commitment guard aborts.
#[test]
fn a_forged_signature_is_rejected() {
    let owner = key();
    let attacker = key();
    let i = make_intent(1, 100_000);

    // Attacker signs with their own key.
    let attacker_sig_hex = sign(&attacker, &i);

    let mut chain = new_chain();
    // Account is deployed with the OWNER's commitment in storage slot 0.
    let dep = deploy_operator(&mut chain, &owner.public_key());

    // Submit the attacker's signature against the owner's account.
    let r = relay_intent(&mut chain, &dep, &i, &attacker_sig_hex);
    match r {
        Err(RelayError::Rejected(ref msg)) => {
            assert!(
                msg.contains("invalid public key commitment"),
                "forged signature: unexpected rejection reason: {msg}"
            );
        }
        other => panic!("forged signature must be rejected; got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 3. Replayed nonce
// ---------------------------------------------------------------------------

/// The first relay SETTLES (assert Ok). Replaying the exact same (intent, signature) must
/// be rejected because the on-chain `last_nonce` is now >= the intent's nonce.
#[test]
fn a_replayed_nonce_is_rejected() {
    let k = key();
    let mut chain = new_chain();
    let dep = deploy_operator(&mut chain, &k.public_key());

    let first = make_intent(1, 100_000);
    let sig1 = sign(&k, &first);

    // First relay must succeed — proves the rejection in round 2 is due to replay, not setup.
    relay_intent(&mut chain, &dep, &first, &sig1).expect("first relay must settle");

    // Replay the same nonce.
    let r = relay_intent(&mut chain, &dep, &first, &sig1);
    match r {
        Err(RelayError::Rejected(ref msg)) => {
            assert!(
                msg.contains("intent nonce must exceed the stored last_nonce"),
                "replayed nonce: unexpected rejection reason: {msg}"
            );
        }
        other => panic!("replayed nonce must be rejected; got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 4. Expired intent
// ---------------------------------------------------------------------------

/// Advance the chain past the intent's `expiry_block`, then relay. The on-chain expiry
/// guard aborts the transaction.
#[test]
fn an_expired_intent_is_rejected() {
    let k = key();
    let mut chain = new_chain();
    let dep = deploy_operator(&mut chain, &k.public_key());

    // After deploy the chain is at block 1 (genesis = 0, builder adds 1). Set expiry = 1
    // so that after advancing 5 more blocks the chain is well past expiry.
    let i = make_intent(1, 1);
    let sig = sign(&k, &i);

    // Advance the chain forward so the current height exceeds the expiry.
    advance_blocks(&mut chain, 5);

    let r = relay_intent(&mut chain, &dep, &i, &sig);
    match r {
        Err(RelayError::Rejected(ref msg)) => {
            assert!(
                msg.contains("intent has expired"),
                "expired intent: unexpected rejection reason: {msg}"
            );
        }
        other => panic!("expired intent must be rejected; got: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 5. Wrong depositor (user_id binding)
// ---------------------------------------------------------------------------

/// A signature valid for depositor A is replayed against an intent that names
/// depositor B.  The on-chain Poseidon2 reconstruction hashes `user_prefix = B`
/// (and all other fields) into a different MSG, so ECDSA recovery returns the
/// wrong public key; the commitment guard rejects it.
#[test]
fn a_replayed_signature_for_a_different_depositor_is_rejected() {
    let k = key();
    let mut chain = new_chain();
    let dep = deploy_operator(&mut chain, &k.public_key());

    // Sign an intent for depositor A (user_prefix = 0xAAAA, the default).
    let signed_for_a = make_intent(1, 100_000);
    let sig_hex = sign(&k, &signed_for_a);

    // Construct an otherwise-identical intent but for a different depositor.
    let mut for_b = signed_for_a;
    for_b.user_prefix = 0xDEAD;

    // Relay depositor B's intent with depositor A's valid signature.
    let r = relay_intent(&mut chain, &dep, &for_b, &sig_hex);
    match r {
        Err(RelayError::Rejected(ref msg)) => {
            // The tamper is caught at the on-chain commitment check: the recovered
            // pubkey differs from the stored commitment because the hashed MSG
            // changed when user_prefix changed.
            assert!(!msg.is_empty(), "wrong depositor: rejection message must not be empty");
        }
        other => panic!("wrong-depositor intent must be rejected; got: {:?}", other),
    }
}
