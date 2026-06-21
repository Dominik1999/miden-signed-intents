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
