//! Task 5 / Plan 2 Task 3: the operator account component, verified as an oracle.
//!
//! Two tests:
//!  1. `authorizer_assembles` — the MASM compiles into an `AccountComponentCode`.
//!  2. `verify_as_oracle_accepts_a_valid_intent` — the VERIFY-AS-ORACLE: the on-chain
//!     MSG reconstruction in `execute_intent` must produce the SAME Word as Rust
//!     `Poseidon2::hash_elements`. We prove this indirectly but rigorously: we seed the
//!     operator's `depositor_keys` StorageMap with `(user_id_word -> pubkey commitment)` for
//!     the test depositor, sign the 8 canonical felts, and run a transaction that calls
//!     `execute_intent`. The MASM fetches the key from the map by the intent's own
//!     `user_prefix`/`user_suffix`, then the ECDSA `verify` proc aborts unless
//!     `to_commitment(pk) == map[user_id]` AND the signature verifies against the
//!     reconstructed MSG. So a PASSING transaction proves the MASM hash is byte-correct AND
//!     the per-depositor map lookup returns the right key.

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
    use signed_intents::intent::Intent;
    use signed_intents::user_account::{new_depositor, user_id_word};

    // A real depositor: the key that signs the intent IS the key whose commitment we seed
    // under this depositor's user_id in the operator's map.
    let depositor = new_depositor(1);
    let user_id = user_id_word(depositor.account.id());
    let id_prefix = depositor.account.id().prefix().as_felt().as_canonical_u64();
    let id_suffix = depositor.account.id().suffix().as_canonical_u64();

    // The sample intent. Its user_prefix/user_suffix ARE the depositor account id, so the
    // on-chain map lookup selects this depositor's seeded key.
    let intent = Intent {
        user_prefix: id_prefix,
        user_suffix: id_suffix,
        recipient_prefix: 0x1234,
        recipient_suffix: 0x5678,
        amount: 1000,
        nonce: 1,
        expiry_block: 500,
    };
    let msg = intent.message_word();
    let signature = depositor.key.sign(msg);

    let outcome = oracle::run_execute_intent(&intent, user_id, depositor.commitment, &signature);
    assert!(
        outcome.is_ok(),
        "valid signed intent must pass on-chain verify (proves the MASM MSG reconstruction \
         matches Rust Poseidon2::hash_elements byte-for-byte AND the map lookup returns the \
         depositor's key). Error: {:?}",
        outcome.err()
    );

    // Negative control: tamper one intent felt so the reconstructed MSG differs from the
    // signed message. `to_prepared_signature` then recovers a different pubkey -> the map
    // commitment guard aborts. This confirms the check is real, not vacuously passing.
    let tampered = Intent { amount: 9999, ..intent };
    let outcome_bad =
        oracle::run_execute_intent(&tampered, user_id, depositor.commitment, &signature);
    assert!(
        outcome_bad.is_err(),
        "a tampered intent must be rejected by the on-chain commitment/signature guard"
    );
}

/// The transaction harness: build an account carrying the operator component (slot 0 = a
/// one-entry `depositor_keys` StorageMap), then run a tx script that pushes the 8 intent felts
/// and the prepared signature (PK||SIG) on the advice stack and `call`s `execute_intent`.
mod oracle {
    use miden_protocol::Word;
    use miden_protocol::account::auth::Signature;
    use signed_intents::intent::Intent;

    const AUTHORIZER_MASM: &str = include_str!("../masm/operator.masm");

    // Slot names MUST match the `word("...")` constants in operator.masm.
    const DEPOSITOR_KEYS_SLOT: &str = "signed_intents::operator::depositor_keys";
    const LAST_NONCE_SLOT: &str = "signed_intents::operator::last_nonce";
    const LAST_AUTH_SLOT: &str = "signed_intents::operator::last_authorized";

    pub fn run_execute_intent(
        intent: &Intent,
        user_id: Word,
        pk_comm_word: Word,
        signature: &Signature,
    ) -> anyhow::Result<()> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");
        rt.block_on(run_inner(intent, user_id, pk_comm_word, signature))
    }

    async fn run_inner(
        intent: &Intent,
        user_id: Word,
        pk_comm_word: Word,
        signature: &Signature,
    ) -> anyhow::Result<()> {
        use miden_client::assembly::CodeBuilder;
        use miden_protocol::Felt;
        use miden_protocol::account::component::AccountComponentMetadata;
        use miden_protocol::account::{
            AccountBuilder, AccountComponent, StorageMap, StorageMapKey, StorageSlot,
            StorageSlotName,
        };
        use miden_protocol::vm::AdviceInputs;
        use miden_testing::{Auth, TransactionContextBuilder};

        // --- Assemble the authorizer component library. ---
        let library = CodeBuilder::default()
            .compile_component_code("signed_intents::operator", AUTHORIZER_MASM)?;

        // --- Build the account with the component + its three named storage slots. ---
        // Slot 0 is the depositor_keys StorageMap, seeded with one entry for this depositor:
        // (user_id -> pubkey commitment). The MASM fetches this by the intent's user id.
        let keys_slot = StorageSlotName::new(DEPOSITOR_KEYS_SLOT)?;
        let nonce_slot = StorageSlotName::new(LAST_NONCE_SLOT)?;
        let auth_slot = StorageSlotName::new(LAST_AUTH_SLOT)?;

        let map = StorageMap::with_entries([(StorageMapKey::new(user_id), pk_comm_word)])?;

        let component = AccountComponent::new(
            library.clone(),
            vec![
                StorageSlot::with_map(keys_slot, map),
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
    use signed_intents::intent::Intent;
    use signed_intents::user_account::{new_depositor, user_id_word};

    let depositor = new_depositor(2);
    let user_id = user_id_word(depositor.account.id());
    let id_prefix = depositor.account.id().prefix().as_felt().as_canonical_u64();
    let id_suffix = depositor.account.id().suffix().as_canonical_u64();

    let intent = Intent {
        user_prefix: id_prefix,
        user_suffix: id_suffix,
        recipient_prefix: 0x1234,
        recipient_suffix: 0x5678,
        amount: 1000,
        nonce: 1,
        expiry_block: 500,
    };
    let sig = depositor.key.sign(intent.message_word());
    let tampered = Intent { amount: 9999, ..intent };
    let err =
        oracle::run_execute_intent(&tampered, user_id, depositor.commitment, &sig).unwrap_err();
    let msg = format!("{err:?}");
    // The reconstructed MSG for the tampered intent differs; to_prepared_signature recovers a
    // different pubkey -> the map commitment guard (or the signature check) aborts. Either
    // way it must be an ECDSA-layer rejection, not an earlier domain/nonce/expiry assert.
    assert!(
        msg.contains("public key commitment") || msg.contains("ECDSA signature"),
        "tampered intent must be rejected at the ECDSA layer, got: {msg}"
    );
}
