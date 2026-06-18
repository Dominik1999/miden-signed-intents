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
    // GOLDEN: copied from the first run of this test (Step 4), then frozen.
    // The TS signer (Task 4) asserts the identical hex.
    const GOLDEN_WORD_HEX: &str = "ead149459c102c63dffeadd553e3bd50ae48d32af53267ad42eb49c0382a3136";
    let i = sample_intent();
    assert_eq!(hex::encode(i.message_word().as_bytes()), GOLDEN_WORD_HEX);
}
