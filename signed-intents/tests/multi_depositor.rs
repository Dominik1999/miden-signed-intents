use miden_protocol::utils::serde::Serializable as _;
use signed_intents::intent::Intent;
use signed_intents::relayer::{deploy_operator, new_chain, read_last_nonce, relay_intent, RelayError};
use signed_intents::user_account::{new_depositor, user_id_word};

#[test]
fn depositor_account_auth_key_equals_its_signing_key() {
    let d = new_depositor(1);
    // The account's stored auth-key commitment must equal the commitment of the key we hold
    // (and will sign intents with). This is the "key belongs to the account" binding.
    let stored = signed_intents::user_account::stored_auth_commitment(&d.account);
    assert_eq!(stored, d.commitment);
    // user_id word is the account id as [prefix, suffix, 0, 0].
    let _ = user_id_word(d.account.id());

    // Distinct seeds must yield distinct keys/commitments — load-bearing for Plan 2
    // (each depositor has its own key mapped under its own user_id).
    assert_ne!(new_depositor(1).commitment, new_depositor(2).commitment);
}

#[test]
fn operator_map_is_seeded_with_each_depositor_commitment() {
    use signed_intents::relayer::{deploy_operator, new_chain, read_depositor_commitment};
    let a = new_depositor(1);
    let b = new_depositor(2);
    let mut chain = new_chain();
    let entries = [
        (user_id_word(a.account.id()), a.commitment),
        (user_id_word(b.account.id()), b.commitment),
    ];
    let dep = deploy_operator(&mut chain, &entries);
    assert_eq!(read_depositor_commitment(&chain, &dep, user_id_word(a.account.id())), a.commitment);
    assert_eq!(read_depositor_commitment(&chain, &dep, user_id_word(b.account.id())), b.commitment);
}

// ---------------------------------------------------------------------------
// Capstone: each depositor key authorises only its own user_id slot
// ---------------------------------------------------------------------------

/// Deploys ONE operator seeded with BOTH depositors and proves:
///   1. `a` relays its own intent (nonce 1) → accepted.
///   2. `b` relays its own intent (nonce 2) → accepted.
///      Note on nonce ordering: the operator uses a single global `last_nonce` slot
///      (Plan 1/2 does not have per-depositor nonce counters). After `a` sets it to 1,
///      `b` must use nonce 2 to satisfy the monotonic guard. The isolation property
///      being proven here is about KEY/user_id binding — that each depositor's key is
///      authoritative only for its own slot — not about separate nonce counters.
///   3. `a` signs an intent for its own user_id but the relayer substitutes `b`'s
///      user_id in the payload. The operator fetches `b`'s commitment from the map and
///      compares it against the recovered public key from `a`'s signature — they differ,
///      so the on-chain commitment guard rejects with "invalid public key commitment".
#[test]
fn depositors_are_isolated_each_authorizes_only_its_own_slot() {
    // Build two depositors with distinct seeds (→ distinct ECDSA keys and commitments).
    let a = new_depositor(1);
    let b = new_depositor(2);

    let uid_a = user_id_word(a.account.id());
    let uid_b = user_id_word(b.account.id());

    let id_prefix_a = a.account.id().prefix().as_felt().as_canonical_u64();
    let id_suffix_a = a.account.id().suffix().as_canonical_u64();
    let id_prefix_b = b.account.id().prefix().as_felt().as_canonical_u64();
    let id_suffix_b = b.account.id().suffix().as_canonical_u64();

    // Deploy ONE operator with BOTH depositors seeded in the map.
    let mut chain = new_chain();
    let dep = deploy_operator(
        &mut chain,
        &[(uid_a, a.commitment), (uid_b, b.commitment)],
    );

    // ------------------------------------------------------------------
    // Step 1 — depositor A authorises its own slot (nonce 1).
    // ------------------------------------------------------------------
    let intent_a = Intent {
        user_prefix: id_prefix_a,
        user_suffix: id_suffix_a,
        recipient_prefix: 0xAAAA,
        recipient_suffix: 0xBBBB,
        amount: 500,
        nonce: 1,
        expiry_block: 100_000,
    };
    let sig_a = a.key.sign(intent_a.message_word());
    let sig_a_hex = hex::encode(sig_a.to_bytes());

    relay_intent(&mut chain, &dep, &intent_a, &sig_a_hex)
        .expect("depositor A: own-slot intent must be accepted");

    assert_eq!(
        read_last_nonce(&chain, &dep),
        1,
        "after A's relay, last_nonce must be 1"
    );

    // ------------------------------------------------------------------
    // Step 2 — depositor B authorises its own slot (nonce 2, because the
    // global last_nonce is now 1 and must be strictly exceeded).
    // ------------------------------------------------------------------
    let intent_b = Intent {
        user_prefix: id_prefix_b,
        user_suffix: id_suffix_b,
        recipient_prefix: 0xCCCC,
        recipient_suffix: 0xDDDD,
        amount: 750,
        nonce: 2,
        expiry_block: 100_000,
    };
    let sig_b = b.key.sign(intent_b.message_word());
    let sig_b_hex = hex::encode(sig_b.to_bytes());

    relay_intent(&mut chain, &dep, &intent_b, &sig_b_hex)
        .expect("depositor B: own-slot intent must be accepted");

    assert_eq!(
        read_last_nonce(&chain, &dep),
        2,
        "after B's relay, last_nonce must be 2"
    );

    // ------------------------------------------------------------------
    // Step 3 — cross-use rejection: A signs an intent for A's user_id,
    // but the relayer substitutes B's user_id in the payload sent to the
    // operator. The operator fetches B's commitment from the map and
    // compares it against the pubkey recovered from A's signature —
    // they differ, so the commitment guard rejects.
    // ------------------------------------------------------------------
    let intent_a_signed = Intent {
        user_prefix: id_prefix_a,
        user_suffix: id_suffix_a,
        recipient_prefix: 0x1234,
        recipient_suffix: 0x5678,
        amount: 100,
        nonce: 3,
        expiry_block: 100_000,
    };
    // A signs over ITS OWN user_id.
    let sig_cross = a.key.sign(intent_a_signed.message_word());
    let sig_cross_hex = hex::encode(sig_cross.to_bytes());

    // Build the payload the relayer will actually submit — B's user_id swapped in.
    let intent_with_b_uid = Intent {
        user_prefix: id_prefix_b,
        user_suffix: id_suffix_b,
        ..intent_a_signed
    };

    let r = relay_intent(&mut chain, &dep, &intent_with_b_uid, &sig_cross_hex);
    match r {
        Err(RelayError::Rejected(ref msg)) => {
            // The operator fetches B's commitment; A's signature recovers A's pubkey,
            // which does not match B's commitment → same "invalid public key commitment"
            // error as a forged-signature attack.
            assert!(
                msg.contains("invalid public key commitment"),
                "cross-use: unexpected rejection reason: {msg}"
            );
        }
        other => panic!("cross-use of A's signature against B's slot must be rejected; got: {other:?}"),
    }
}
