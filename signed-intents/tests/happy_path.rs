//! Task 6 happy-path test: deploy the authorizer account on MockChain, relay a valid signed
//! intent, and assert the on-chain storage was updated correctly.

use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::utils::serde::Serializable;
use signed_intents::intent::Intent;
use signed_intents::relayer::{deploy_authorizer, new_chain, read_last_authorized, read_last_nonce, relay_intent};

fn sample_intent() -> Intent {
    Intent {
        recipient_prefix: 0x1234,
        recipient_suffix: 0x5678,
        amount: 1000,
        nonce: 1,
        expiry_block: 100_000,
    }
}

#[test]
fn valid_intent_is_authorized_and_recorded() {
    let mut rng = rand::rng();
    let key = AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rng);

    // User signs off-chain.
    let intent = sample_intent();
    let msg = intent.message_word();
    let signature = key.sign(msg);
    let sig_hex = hex::encode(signature.to_bytes());
    let pk_hex = hex::encode(key.public_key().to_bytes());

    // Relayer deploys + submits.
    let mut chain = new_chain();
    let deployed = deploy_authorizer(&mut chain, &key.public_key());
    relay_intent(&mut chain, &deployed, &intent, &sig_hex, &pk_hex)
        .expect("valid intent must settle");

    // Storage advanced: nonce must be 1.
    assert_eq!(
        read_last_nonce(&chain, &deployed),
        1,
        "last_nonce slot must be 1 after one valid intent"
    );

    // last_authorized slot layout (Rust Word array, where index 3 = TOP stack element):
    // Word([r_pre, r_suf, amount, nonce])
    //   word[0] = r_pre = 0x1234
    //   word[1] = r_suf = 0x5678
    //   word[2] = amount = 1000
    //   word[3] = nonce  = 1
    let last = read_last_authorized(&chain, &deployed);
    let amount = last[2].as_canonical_u64(); // amount is at word[2]
    assert_eq!(amount, 1000, "last_authorized slot must record amount=1000; got {amount}");
}
