//! Happy-path test: deploy the operator account on MockChain, relay a valid signed
//! intent, and assert the on-chain storage was updated correctly.

use signed_intents::intent::Intent;
use signed_intents::relayer::{
    deploy_operator, new_chain, read_last_authorized, read_last_nonce, relay_intent,
};
use signed_intents::user_account::{new_depositor, user_id_word};
use miden_protocol::utils::serde::Serializable as _;

#[test]
fn valid_intent_is_authorized_and_recorded() {
    // Build a real native-ECDSA depositor (seed=1 → deterministic key).
    let d = new_depositor(1);
    let uid = user_id_word(d.account.id());

    // Extract the depositor's account-id halves so the intent names the right user.
    let id_prefix = d.account.id().prefix().as_felt().as_canonical_u64();
    let id_suffix = d.account.id().suffix().as_canonical_u64();

    // Construct the intent whose user_prefix/user_suffix identify this depositor.
    let intent = Intent {
        user_prefix: id_prefix,
        user_suffix: id_suffix,
        recipient_prefix: 0x1234,
        recipient_suffix: 0x5678,
        amount: 1000,
        nonce: 1,
        expiry_block: 100_000,
    };

    // User signs off-chain.
    let msg = intent.message_word();
    let signature = d.key.sign(msg);
    let sig_hex = hex::encode(signature.to_bytes());

    // Relayer deploys the operator with this depositor seeded in the map, then submits.
    let mut chain = new_chain();
    let deployed = deploy_operator(&mut chain, &[(uid, d.commitment)]);
    relay_intent(&mut chain, &deployed, &intent, &sig_hex)
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
