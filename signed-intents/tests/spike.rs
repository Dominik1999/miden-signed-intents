//! Task 2 spike: prove on-chain ECDSA-K256-Keccak `verify` works inside a Miden
//! 0.14 MockChain transaction, and PIN the exact operand/advice ABI that the later
//! authorizer (Task 5) depends on.
//!
//! See `masm/ecdsa_spike.masm` for the verified ABI documentation.

use miden_protocol::Felt;
use miden_protocol::Word;
use miden_protocol::account::auth::AuthSecretKey;

/// Helper: a fixed message Word to sign and verify.
fn sample_message() -> Word {
    Word::from([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)])
}

#[test]
fn on_chain_ecdsa_verify_accepts_a_valid_signature() {
    let mut rng = rand::rng();
    let key = AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rng);
    let msg = sample_message();
    let signature = key.sign(msg);
    let public_key = key.public_key();

    let ok = signed_intents_spike::run_verify(&public_key, msg, &signature);

    assert!(ok, "valid signature must verify on-chain");
}

#[test]
fn on_chain_ecdsa_verify_rejects_a_tampered_message() {
    let mut rng = rand::rng();
    let key = AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rng);
    let signed = sample_message();
    let signature = key.sign(signed);

    // Verify against a DIFFERENT message than was signed.
    let tampered = Word::from([Felt::new(9), Felt::new(9), Felt::new(9), Felt::new(9)]);
    let ok = signed_intents_spike::run_verify(&key.public_key(), tampered, &signature);

    assert!(!ok, "verification must fail for a message the key did not sign");
}

/// The transaction/VM execution harness. This module is where the 0.14 MockChain
/// advice-injection and tx-script API is pinned.
mod signed_intents_spike {
    use miden_client::assembly::CodeBuilder;
    use miden_client::testing::{Auth, MockChain};
    use miden_protocol::Felt;
    use miden_protocol::Word;
    use miden_protocol::account::auth::{PublicKey, Signature};
    use miden_protocol::vm::AdviceInputs;

    /// The spike MASM, embedded at compile time (tests run from the crate root).
    const SPIKE_MASM: &str = include_str!("../masm/ecdsa_spike.masm");

    /// Builds a throwaway no-auth wallet, assembles `ecdsa_spike.masm` as a transaction
    /// script, injects `[MSG, PK_COMM, PK[9], SIG[17]]` on the advice stack, executes the
    /// transaction, and reports whether `ecdsa_k256_keccak::verify` accepted the signature.
    ///
    /// A clean transaction == valid signature (`true`). The `verify` procedure aborts the
    /// transaction on an invalid commitment or signature; we catch that and map it to `false`.
    pub fn run_verify(public_key: &PublicKey, msg: Word, signature: &Signature) -> bool {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");
        rt.block_on(run_verify_inner(public_key, msg, signature))
    }

    async fn run_verify_inner(public_key: &PublicKey, msg: Word, signature: &Signature) -> bool {
        // ---- Minimal MockChain with a no-auth wallet to host the tx script. ----
        let mut builder = MockChain::builder();
        // IncrNonce auth bumps the account nonce on auth, giving the transaction a state
        // change so it is not rejected as a no-op (Noop auth would leave the tx empty).
        let account = builder
            .add_existing_wallet(Auth::IncrNonce)
            .expect("failed to add wallet");
        let mock_chain = builder.build().expect("failed to build mock chain");

        // ---- Assemble the spike MASM into a transaction script. ----
        // The default CodeBuilder links the tx kernel + core libs, so the
        // `use miden::core::crypto::dsa::ecdsa_k256_keccak` import resolves.
        let tx_script = CodeBuilder::default()
            .compile_tx_script(SPIKE_MASM)
            .expect("failed to assemble ecdsa_spike.masm");

        // ---- Build the advice stack the script expects (top-first): MSG, PK_COMM, PK, SIG.
        // PK[9] || SIG[17] is exactly Signature::to_prepared_signature(msg).
        let pk_comm: Word = public_key.to_commitment().into();
        let prepared: Vec<Felt> = signature.to_prepared_signature(msg); // [PK[9], SIG[17]]

        let mut advice_stack: Vec<Felt> = Vec::with_capacity(8 + prepared.len());
        advice_stack.extend_from_slice(msg.as_elements()); // MSG (4) — consumed first
        advice_stack.extend_from_slice(pk_comm.as_elements()); // PK_COMM (4)
        advice_stack.extend_from_slice(&prepared); // PK[9], SIG[17]

        // `AdviceInputs::with_stack(iter)` stores the iterator order verbatim and the VM pops
        // from the FRONT, so the FIRST element of `advice_stack` is the TOP of the advice stack
        // (first consumed). Our vector is already in top-first order; no reversal needed.
        let advice_inputs = AdviceInputs::default().with_stack(advice_stack);

        // ---- Execute the transaction; a clean run means verify accepted. ----
        let tx_context = mock_chain
            .build_tx_context(account.clone(), &[], &[])
            .expect("failed to build tx context")
            .tx_script(tx_script)
            .extend_advice_inputs(advice_inputs)
            .build()
            .expect("failed to build tx context");

        // A clean execution means `ecdsa_k256_keccak::verify` returned without aborting, i.e.
        // both the public-key commitment matched and the signature verified. Any execution
        // error (invalid commitment for a tampered message, or a failed signature check) is
        // surfaced as a rejected signature.
        tx_context.execute().await.is_ok()
    }
}
