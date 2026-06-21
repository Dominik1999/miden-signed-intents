//! Task 5: the authorizer account component.
//!
//! Two tests:
//!  1. `authorizer_assembles` — the MASM compiles into an `AccountComponentCode`.
//!  2. `verify_as_oracle_accepts_a_valid_intent` — the VERIFY-AS-ORACLE: the on-chain
//!     MSG reconstruction in `execute_intent` must produce the SAME Word as Rust
//!     `Poseidon2::hash_elements`. We prove this indirectly but rigorously: we put the
//!     signer's pubkey commitment in slot 0, sign the 8 canonical felts, and run a
//!     transaction that calls `execute_intent`. The ECDSA `verify` proc aborts unless
//!     `to_commitment(pk) == storage slot 0` AND the signature verifies against the
//!     reconstructed MSG. So a PASSING transaction proves the MASM hash is byte-correct.

const AUTHORIZER_MASM: &str = include_str!("../masm/operator.masm");

#[test]
fn authorizer_assembles() {
    use miden_client::assembly::CodeBuilder;

    let result = CodeBuilder::default()
        .compile_component_code("signed_intents::operator", AUTHORIZER_MASM);

    assert!(
        result.is_ok(),
        "operator.masm must assemble as an account component: {:?}",
        result.err()
    );
}

#[test]
fn verify_as_oracle_accepts_a_valid_intent() {
    use miden_protocol::account::auth::AuthSecretKey;
    use signed_intents::intent::Intent;

    let mut rng = rand::rng();
    let key = AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rng);

    // The sample intent. Its Rust message Word is the on-chain MSG anchor.
    let intent = Intent {
        user_prefix: 0xabcd,
        user_suffix: 0xef01,
        recipient_prefix: 0x1234,
        recipient_suffix: 0x5678,
        amount: 1000,
        nonce: 1,
        expiry_block: 500,
    };
    let msg = intent.message_word();
    let signature = key.sign(msg);
    let pk_comm = key.public_key();

    let outcome = oracle::run_execute_intent(&intent, &pk_comm, &signature);
    assert!(
        outcome.is_ok(),
        "valid signed intent must pass on-chain verify (proves the MASM MSG reconstruction \
         matches Rust Poseidon2::hash_elements byte-for-byte). Error: {:?}",
        outcome.err()
    );

    // Negative control: tamper one intent felt so the reconstructed MSG differs from the
    // signed message. `to_prepared_signature` then recovers a different pubkey -> the slot-0
    // commitment guard aborts. This confirms the check is real, not vacuously passing.
    let tampered = Intent { amount: 9999, ..intent };
    let outcome_bad = oracle::run_execute_intent(&tampered, &pk_comm, &signature);
    assert!(
        outcome_bad.is_err(),
        "a tampered intent must be rejected by the on-chain commitment/signature guard"
    );
}

/// The transaction harness: build an account carrying the operator component (slot 0 =
/// owner pubkey commitment), then run a tx script that pushes the 8 intent felts and the
/// prepared signature (PK||SIG) on the advice stack and `call`s `execute_intent`.
mod oracle {
    use miden_protocol::account::auth::{PublicKey, Signature};
    use signed_intents::intent::Intent;

    const AUTHORIZER_MASM: &str = include_str!("../masm/operator.masm");

    // Slot names MUST match the `word("...")` constants in operator.masm.
    const OWNER_PK_SLOT: &str = "signed_intents::operator::owner_pubkey_commitment";
    const LAST_NONCE_SLOT: &str = "signed_intents::operator::last_nonce";
    const LAST_AUTH_SLOT: &str = "signed_intents::operator::last_authorized";

    pub fn run_execute_intent(
        intent: &Intent,
        pk_comm: &PublicKey,
        signature: &Signature,
    ) -> anyhow::Result<()> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");
        rt.block_on(run_inner(intent, pk_comm, signature))
    }

    async fn run_inner(
        intent: &Intent,
        pk_comm: &PublicKey,
        signature: &Signature,
    ) -> anyhow::Result<()> {
        use miden_client::assembly::CodeBuilder;
        use miden_protocol::Felt;
        use miden_protocol::Word;
        use miden_protocol::account::component::AccountComponentMetadata;
        use miden_protocol::account::{
            AccountBuilder, AccountComponent, StorageSlot, StorageSlotName,
        };
        use miden_protocol::vm::AdviceInputs;
        use miden_testing::{Auth, TransactionContextBuilder};

        // --- Assemble the authorizer component library. ---
        let library = CodeBuilder::default()
            .compile_component_code("signed_intents::operator", AUTHORIZER_MASM)?;

        // --- Build the account with the component + its three named storage slots. ---
        let owner_slot = StorageSlotName::new(OWNER_PK_SLOT)?;
        let nonce_slot = StorageSlotName::new(LAST_NONCE_SLOT)?;
        let auth_slot = StorageSlotName::new(LAST_AUTH_SLOT)?;

        let pk_comm_word: Word = pk_comm.to_commitment().into();

        let component = AccountComponent::new(
            library.clone(),
            vec![
                StorageSlot::with_value(owner_slot, pk_comm_word),
                StorageSlot::with_value(nonce_slot, Word::from([0u32, 0, 0, 0])),
                StorageSlot::with_value(auth_slot, Word::from([0u32, 0, 0, 0])),
            ],
            AccountComponentMetadata::mock("signed_intents::operator"),
        )?;

        let account = AccountBuilder::new(rand::random())
            .with_auth_component(Auth::IncrNonce)
            .with_component(component)
            .build_existing()?;

        // --- Transaction script: push 8 intent felts, then call execute_intent. ---
        // Canonical order (top->down once pushed):
        //   [domain, user_pre, user_suf, r_pre, r_suf, amount, nonce, expiry]
        // `push` puts its last operand on top, so we list them deepest-first (expiry) to
        // top-most (domain).
        let felts = intent.canonical_felts();
        let tx_script_code = format!(
            r#"
            use signed_intents::operator->operator
            use miden::core::sys

            begin
                push.{expiry}.{nonce}.{amount}.{r_suf}.{r_pre}.{user_suf}.{user_pre}.{domain}
                # => [domain, user_pre, user_suf, r_pre, r_suf, amount, nonce, expiry, pad...]
                call.operator::execute_intent
                # The call frame leaves the script stack deeper than 16; truncate before the
                # program returns so the kernel's depth-16 exit invariant holds.
                exec.sys::truncate_stack
            end
            "#,
            domain = felts[0],
            user_pre = felts[1],
            user_suf = felts[2],
            r_pre = felts[3],
            r_suf = felts[4],
            amount = felts[5],
            nonce = felts[6],
            expiry = felts[7],
        );

        let tx_script = CodeBuilder::default()
            .with_dynamically_linked_library(&library)?
            .compile_tx_script(tx_script_code)?;

        // --- Advice stack: the prepared signature [PK[9], SIG[17]] that `verify` consumes. ---
        let prepared: Vec<Felt> = signature.to_prepared_signature(intent.message_word());
        let advice_inputs = AdviceInputs::default().with_stack(prepared);

        let tx_context = TransactionContextBuilder::new(account)
            .tx_script(tx_script)
            .extend_advice_inputs(advice_inputs)
            .build()?;

        tx_context.execute().await?;
        Ok(())
    }
}

#[test]
fn verify_as_oracle_negative_hits_the_commitment_guard() {
    use miden_protocol::account::auth::AuthSecretKey;
    use signed_intents::intent::Intent;
    let mut rng = rand::rng();
    let key = AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rng);
    let intent = Intent { user_prefix: 0xabcd, user_suffix: 0xef01, recipient_prefix: 0x1234, recipient_suffix: 0x5678, amount: 1000, nonce: 1, expiry_block: 500 };
    let sig = key.sign(intent.message_word());
    let tampered = Intent { amount: 9999, ..intent };
    let err = oracle::run_execute_intent(&tampered, &key.public_key(), &sig).unwrap_err();
    let msg = format!("{err:?}");
    // The reconstructed MSG for the tampered intent differs; to_prepared_signature recovers a
    // different pubkey -> the slot-0 commitment guard (or the signature check) aborts. Either
    // way it must be an ECDSA-layer rejection, not an earlier domain/nonce/expiry assert.
    assert!(
        msg.contains("public key commitment") || msg.contains("ECDSA signature"),
        "tampered intent must be rejected at the ECDSA layer, got: {msg}"
    );
}
