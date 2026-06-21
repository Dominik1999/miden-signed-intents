//! Adversarial tests: proves the relayer cannot forge, tamper, replay, or expire intents.
//!
//! Each test submits a cheating request to `relay_intent` and asserts the result is
//! `Err(RelayError::Rejected(_))`. The transaction is cryptographically unprovable in every
//! case, which is the payoff of the whole tutorial.

use miden_protocol::utils::serde::Serializable as _; // brings to_bytes() into scope
use signed_intents::intent::Intent;
use signed_intents::relayer::{
    advance_blocks, deploy_operator, new_chain, relay_intent, RelayError,
};
use signed_intents::user_account::{new_depositor, user_id_word};

/// Build an intent that identifies `depositor` (seed=1) by its real account-id halves.
fn make_intent_for(id_prefix: u64, id_suffix: u64, nonce: u64, expiry: u64) -> Intent {
    Intent {
        user_prefix: id_prefix,
        user_suffix: id_suffix,
        recipient_prefix: 0x1234,
        recipient_suffix: 0x5678,
        amount: 1000,
        nonce,
        expiry_block: expiry,
    }
}

/// Sign an intent; returns the hex-encoded serialised `Signature` bytes.
fn sign_intent(d: &signed_intents::user_account::Depositor, i: &Intent) -> String {
    let sig = d.key.sign(i.message_word());
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
    let d = new_depositor(1);
    let uid = user_id_word(d.account.id());
    let id_prefix = d.account.id().prefix().as_felt().as_canonical_u64();
    let id_suffix = d.account.id().suffix().as_canonical_u64();

    let signed = make_intent_for(id_prefix, id_suffix, 1, 100_000);
    let sig_hex = sign_intent(&d, &signed);

    let mut chain = new_chain();
    let dep = deploy_operator(&mut chain, &[(uid, d.commitment)]);

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
    let owner = new_depositor(1);
    let attacker = new_depositor(2);

    let uid = user_id_word(owner.account.id());
    let id_prefix = owner.account.id().prefix().as_felt().as_canonical_u64();
    let id_suffix = owner.account.id().suffix().as_canonical_u64();

    let i = make_intent_for(id_prefix, id_suffix, 1, 100_000);

    // Attacker signs with their own key.
    let attacker_sig_hex = sign_intent(&attacker, &i);

    let mut chain = new_chain();
    // Account is deployed with the OWNER's commitment in the map.
    let dep = deploy_operator(&mut chain, &[(uid, owner.commitment)]);

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
    let d = new_depositor(1);
    let uid = user_id_word(d.account.id());
    let id_prefix = d.account.id().prefix().as_felt().as_canonical_u64();
    let id_suffix = d.account.id().suffix().as_canonical_u64();

    let mut chain = new_chain();
    let dep = deploy_operator(&mut chain, &[(uid, d.commitment)]);

    let first = make_intent_for(id_prefix, id_suffix, 1, 100_000);
    let sig1 = sign_intent(&d, &first);

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
    let d = new_depositor(1);
    let uid = user_id_word(d.account.id());
    let id_prefix = d.account.id().prefix().as_felt().as_canonical_u64();
    let id_suffix = d.account.id().suffix().as_canonical_u64();

    let mut chain = new_chain();
    let dep = deploy_operator(&mut chain, &[(uid, d.commitment)]);

    // After deploy the chain is at block 1 (genesis = 0, builder adds 1). Set expiry = 1
    // so that after advancing 5 more blocks the chain is well past expiry.
    let i = make_intent_for(id_prefix, id_suffix, 1, 1);
    let sig = sign_intent(&d, &i);

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
/// depositor B. The operator's map has no entry for depositor B, so `get_map_item`
/// returns a zero commitment; the on-chain commitment guard rejects the signature.
#[test]
fn a_replayed_signature_for_a_different_depositor_is_rejected() {
    // Depositor A — the one whose key and commitment we seed into the map.
    let a = new_depositor(1);
    let uid_a = user_id_word(a.account.id());
    let id_prefix_a = a.account.id().prefix().as_felt().as_canonical_u64();
    let id_suffix_a = a.account.id().suffix().as_canonical_u64();

    // Depositor B — a different depositor whose user_id is NOT in the map.
    let b = new_depositor(2);
    let id_prefix_b = b.account.id().prefix().as_felt().as_canonical_u64();
    let id_suffix_b = b.account.id().suffix().as_canonical_u64();

    let mut chain = new_chain();
    // Only depositor A is seeded in the operator map.
    let dep = deploy_operator(&mut chain, &[(uid_a, a.commitment)]);

    // Sign an intent for depositor A.
    let signed_for_a = make_intent_for(id_prefix_a, id_suffix_a, 1, 100_000);
    let sig_hex = sign_intent(&a, &signed_for_a);

    // Construct an otherwise-identical intent but naming depositor B.
    let for_b = make_intent_for(id_prefix_b, id_suffix_b, 1, 100_000);

    // Relay depositor B's intent with depositor A's valid signature.
    // The map lookup for B's user_id returns a zero commitment; the commitment
    // guard (or ECDSA recovery) therefore rejects.
    let r = relay_intent(&mut chain, &dep, &for_b, &sig_hex);
    match r {
        Err(RelayError::Rejected(ref msg)) => {
            // The map returns a zero/absent commitment for the unknown depositor B,
            // so the commitment check or ECDSA verify aborts.
            assert!(!msg.is_empty(), "wrong depositor: rejection message must not be empty");
        }
        other => panic!("wrong-depositor intent must be rejected; got: {:?}", other),
    }
}
