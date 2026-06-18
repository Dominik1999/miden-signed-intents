use signed_intents::intent::{Intent, DOMAIN_TRANSFER};

fn sample_intent() -> Intent {
    Intent {
        recipient_prefix: 0x1234,
        recipient_suffix: 0x5678,
        amount: 1_000,
        nonce: 1,
        expiry_block: 500,
    }
}

#[test]
fn canonical_felts_are_in_the_agreed_order() {
    let i = sample_intent();
    assert_eq!(
        i.canonical_felts(),
        vec![DOMAIN_TRANSFER, 0x1234, 0x5678, 1_000, 1, 500]
    );
}

#[test]
fn message_word_matches_the_golden_vector() {
    // GOLDEN (Poseidon2). The intent message is hashed with Poseidon2 — the protocol's
    // canonical `Hasher` and the ONLY algebraic hash the Miden VM can reconstruct on-chain
    // (the native `hperm` instruction is Poseidon2; there is no RPO permutation instruction in
    // this toolchain). Task 5's authorizer rebuilds this exact Word inside the transaction and
    // the verify-as-oracle test proves the match against `Poseidon2::hash_elements`.
    //
    // NOTE: this supersedes the earlier RPO golden
    // (ead149459c102c63dffeadd553e3bd50ae48d32af53267ad42eb49c0382a3136), which the VM cannot
    // reproduce. The Task 4 TS signer must hash with Poseidon2 and assert THIS hex.
    const GOLDEN_WORD_HEX: &str =
        "51dca2817b795ff469c66a03bbe4a5c2145458b6e1df4d257eb47e835f309622";
    let i = sample_intent();
    assert_eq!(hex::encode(i.message_word().as_bytes()), GOLDEN_WORD_HEX);
}
