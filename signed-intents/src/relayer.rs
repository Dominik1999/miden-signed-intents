//! Deploys the authorizer account and relays signed intents against MockChain.
//!
//! # Auth scheme
//! The authorizer account uses `Auth::IncrNonce` (a mock auth component that simply increments
//! the nonce). This gives each transaction a state delta so the kernel does not reject it as a
//! no-op. Security is provided entirely by `execute_intent` itself — the ECDSA commitment check
//! inside the MASM is the real authorization boundary. This matches the approach proven working
//! in `tests/authorizer.rs` (Task 5).
//!
//! # Panic / error mapping in `relay_intent`
//! `Signature::to_prepared_signature` calls `PublicKey::recover_from(msg, sig)` which panics
//! (not returns Err) if ECDSA recovery fails. For tampered intents the recovered pubkey may
//! also be valid but differ from the stored commitment, so the on-chain VM will abort.
//! `relay_intent` wraps the prepared-signature construction in `std::panic::catch_unwind` and
//! maps both panics and execution errors to `RelayError::Rejected`.

use std::panic;

use miden_client::assembly::CodeBuilder;
use miden_protocol::Felt;
use miden_protocol::account::auth::{PublicKey, Signature};
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountBuilder, AccountComponent, AccountId, AccountStorageMode, StorageSlot, StorageSlotName,
};
use miden_protocol::utils::serde::Deserializable;
use miden_protocol::vm::AdviceInputs;
use miden_protocol::Word;
use miden_testing::{Auth, MockChain};

use crate::intent::Intent;

const AUTHORIZER_MASM: &str = include_str!("../masm/authorizer.masm");

const OWNER_PK_SLOT: &str = "signed_intents::authorizer::owner_pubkey_commitment";
const LAST_NONCE_SLOT: &str = "signed_intents::authorizer::last_nonce";
const LAST_AUTH_SLOT: &str = "signed_intents::authorizer::last_authorized";

/// Handle returned by `deploy_authorizer`, consumed by the other relayer functions.
pub struct DeployedAuthorizer {
    pub account_id: AccountId,
}

/// Errors that can arise when relaying an intent.
#[derive(Debug)]
pub enum RelayError {
    /// The transaction failed — bad signature, replay, expiry, or tampered field.
    Rejected(String),
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::Rejected(msg) => write!(f, "RelayError::Rejected({msg})"),
        }
    }
}

/// Create a fresh `MockChain` with a single genesis block.
///
/// The returned chain is empty; call `deploy_authorizer` to populate it with the
/// authorizer account before calling `relay_intent`.
pub fn new_chain() -> MockChain {
    MockChain::new()
}

/// Build the authorizer account and register it in the genesis state of `chain`.
///
/// Because `MockChain` does not support adding accounts after genesis, this function rebuilds
/// the chain from scratch with the authorizer account included. Any previous state in `chain`
/// is replaced.
///
/// Slot 0 = `owner.to_commitment()`; slots 1 and 2 are zeroed (last_nonce, last_authorized).
pub fn deploy_authorizer(chain: &mut MockChain, owner: &PublicKey) -> DeployedAuthorizer {
    let library = CodeBuilder::default()
        .compile_component_code("signed_intents::authorizer", AUTHORIZER_MASM)
        .expect("authorizer.masm must assemble");

    let owner_slot = StorageSlotName::new(OWNER_PK_SLOT).expect("slot name must parse");
    let nonce_slot = StorageSlotName::new(LAST_NONCE_SLOT).expect("slot name must parse");
    let auth_slot = StorageSlotName::new(LAST_AUTH_SLOT).expect("slot name must parse");

    let pk_comm_word: Word = owner.to_commitment().into();

    let component = AccountComponent::new(
        library,
        vec![
            StorageSlot::with_value(owner_slot, pk_comm_word),
            StorageSlot::with_value(nonce_slot, Word::from([0u32, 0, 0, 0])),
            StorageSlot::with_value(auth_slot, Word::from([0u32, 0, 0, 0])),
        ],
        AccountComponentMetadata::mock("signed_intents::authorizer"),
    )
    .expect("authorizer component must build");

    // Build the account via MockChainBuilder using Auth::IncrNonce, which gives each
    // transaction a nonce delta so the kernel does not reject it as a no-op.
    // We pre-build the Account with IncrNonce auth component.
    let account = {
        let (auth_component, _authenticator) = Auth::IncrNonce.build_component();
        AccountBuilder::new(rand::random())
            .storage_mode(AccountStorageMode::Public)
            .with_auth_component(auth_component)
            .with_component(component)
            .build_existing()
            .expect("authorizer account must build")
    };

    let account_id = account.id();

    // Rebuild the chain with the authorizer account in genesis state.
    let mut builder = MockChain::builder();
    builder.add_account(account).expect("add account to builder must succeed");
    *chain = builder.build().expect("chain must build with authorizer account");

    DeployedAuthorizer { account_id }
}

/// Build and execute the transaction that calls `execute_intent` on the authorizer account.
///
/// On success the transaction is committed to the chain (pending tx + prove_next_block) so
/// subsequent storage reads via `read_last_nonce` / `read_last_authorized` reflect the new state.
///
/// # Error mapping
/// Both a panic from `to_prepared_signature` (ECDSA recovery failure on a tampered intent)
/// and a VM execution error are mapped to `RelayError::Rejected`.
pub fn relay_intent(
    chain: &mut MockChain,
    deployed: &DeployedAuthorizer,
    intent: &Intent,
    signature_hex: &str,
    _public_key_hex: &str,
) -> Result<(), RelayError> {
    // Decode the hex-encoded serialised `Signature` bytes and deserialise.
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| RelayError::Rejected(format!("bad signature hex: {e}")))?;
    let signature = Signature::read_from_bytes(&sig_bytes)
        .map_err(|e| RelayError::Rejected(format!("cannot deserialise signature: {e}")))?;

    let msg = intent.message_word();

    // Guard against a panic from ECDSA recovery inside `to_prepared_signature`.
    // For tampered intents the MASM-reconstructed MSG differs from the signed MSG, so
    // `PublicKey::recover_from(tampered_msg, sig)` panics rather than returning Err.
    let prepared: Vec<Felt> = {
        let prev_hook = panic::take_hook();
        panic::set_hook(Box::new(|_| {})); // suppress panic output in tests
        let result = panic::catch_unwind(|| signature.to_prepared_signature(msg));
        panic::set_hook(prev_hook);
        result.map_err(|e| {
            let reason = e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_else(|| "ECDSA recovery panic".to_string());
            RelayError::Rejected(format!("to_prepared_signature panicked: {reason}"))
        })?
    };

    // Assemble the tx script that calls `execute_intent` with the 6 canonical intent felts.
    let library = CodeBuilder::default()
        .compile_component_code("signed_intents::authorizer", AUTHORIZER_MASM)
        .expect("authorizer.masm must assemble");

    let felts = intent.canonical_felts();
    let tx_script_code = format!(
        r#"
        use signed_intents::authorizer->authorizer
        use miden::core::sys

        begin
            push.{expiry}.{nonce}.{amount}.{r_suf}.{r_pre}.{domain}
            # => [DOMAIN, r_pre, r_suf, amount, nonce, expiry, pad...]
            call.authorizer::execute_intent
            # The call leaves the script stack deeper than 16; truncate so the kernel's
            # depth-16 exit invariant holds.
            exec.sys::truncate_stack
        end
        "#,
        domain = felts[0],
        r_pre = felts[1],
        r_suf = felts[2],
        amount = felts[3],
        nonce = felts[4],
        expiry = felts[5],
    );

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_library(&library)
        .map_err(|e| RelayError::Rejected(format!("library link failed: {e}")))?
        .compile_tx_script(tx_script_code)
        .map_err(|e| RelayError::Rejected(format!("tx script compile failed: {e}")))?;

    let advice_inputs = AdviceInputs::default().with_stack(prepared);

    // Execute via a blocking tokio runtime (execute() is async).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| RelayError::Rejected(format!("tokio runtime error: {e}")))?;

    let tx_result = rt.block_on(async {
        chain
            .build_tx_context(deployed.account_id, &[], &[])
            .map_err(|e| RelayError::Rejected(format!("build_tx_context failed: {e}")))?
            .tx_script(tx_script)
            .extend_advice_inputs(advice_inputs)
            .build()
            .map_err(|e| RelayError::Rejected(format!("tx context build failed: {e}")))?
            .execute()
            .await
            .map_err(|e| RelayError::Rejected(format!("tx execution failed: {e}")))
    })?;

    // Commit to the chain so storage reads reflect the new state.
    chain
        .add_pending_executed_transaction(&tx_result)
        .map_err(|e| RelayError::Rejected(format!("add_pending_tx failed: {e}")))?;
    chain
        .prove_next_block()
        .map_err(|e| RelayError::Rejected(format!("prove_next_block failed: {e}")))?;

    Ok(())
}

/// Read the `last_nonce` from slot 1 of the committed account state.
///
/// The MASM stores the nonce as the deepest element in the `[0, 0, 0, nonce]` stack word
/// (three zeros pushed on top), which maps to `word[3]` in the Rust `Word` array (where
/// `word[0]` = TOP of stack element = 0, `word[3]` = deepest = nonce).
pub fn read_last_nonce(chain: &MockChain, d: &DeployedAuthorizer) -> u64 {
    let slot_name = StorageSlotName::new(LAST_NONCE_SLOT).expect("slot name must parse");
    let account = chain.committed_account(d.account_id).expect("account must be committed");
    let word = account.storage().get_item(&slot_name).expect("last_nonce slot must exist");
    // Stored as [0, 0, 0, nonce] (0=TOP), so word[3]=nonce in Rust.
    // Verified empirically: nonce=1 produces Word([0, 0, 0, 1]).
    word[3].as_canonical_u64()
}

/// Read the `last_authorized` word (slot 2) from the committed account state.
///
/// The MASM stashes `[r_pre, r_suf, amount, nonce]` (r_pre = TOP) into local memory at addr 0
/// via `loc_storew_le.0`, then loads it back reversed as `[nonce, amount, r_suf, r_pre]`
/// (nonce = TOP) via `loc_loadw_le.0` before calling `set_item`.
///
/// In Rust `Word` representation, TOP stack element becomes `word[3]` and deepest becomes
/// `word[0]`:
/// - `word[3]` = nonce
/// - `word[2]` = amount
/// - `word[1]` = recipient_suffix
/// - `word[0]` = recipient_prefix
pub fn read_last_authorized(chain: &MockChain, d: &DeployedAuthorizer) -> Word {
    let slot_name = StorageSlotName::new(LAST_AUTH_SLOT).expect("slot name must parse");
    let account = chain.committed_account(d.account_id).expect("account must be committed");
    account.storage().get_item(&slot_name).expect("last_authorized slot must exist")
}
