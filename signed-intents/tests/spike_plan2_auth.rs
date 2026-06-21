//! FEASIBILITY SPIKE — Plan 2. Not production.
//!
//! Q2 (GATING): prove a User Account whose NATIVE authentication IS an `ecdsa_k256_keccak` key
//! can be built in `MockChain` and authorize a real, state-changing transaction. The
//! BasicAuthenticator (holding the ECDSA secret key) signs the tx summary and the tx executes.
//!
//! GREEN = Q2 PASS.
//!
//! HOW SIGNING IS WIRED (the load-bearing finding for Plan 2):
//!   1. `MockChainBuilder::add_account_from_builder(Auth::BasicAuth { auth_scheme }, ..)` calls
//!      `auth_method.build_component()`, which for `BasicAuth` returns
//!      `(AuthSingleSig component, Some(BasicAuthenticator))`. The component holds the pubkey
//!      commitment in storage; the `BasicAuthenticator` holds the ECDSA SECRET key.
//!   2. The builder stores that authenticator in `MockChain.account_authenticators[account_id]`.
//!   3. `MockChain::build_tx_context(input)` (-> `build_tx_context_at`) looks up
//!      `account_authenticators.get(&input.id())` and calls
//!      `TransactionContextBuilder::new(account).authenticator(authenticator)` for you.
//!   4. At `execute()`, the tx kernel runs the account's `auth__` procedure, which asks the
//!      authenticator to sign the transaction summary with the ECDSA key. The signature is
//!      supplied to the VM automatically — NO manual `to_prepared_signature` / advice injection,
//!      unlike Plan 1's operator (which verifies a signature it gets via the advice stack).
//!
//! => For Plan 2, a User Account with native ECDSA auth "just works" inside MockChain; the
//!    relayer does not hand-craft the user-account auth signature. (A relayer-submitted tx on
//!    behalf of the user would still need the user's authenticator registered, OR the design
//!    keeps the verify-the-signed-intent pattern from Plan 1 on the OPERATOR account. This spike
//!    only proves the native-ECDSA-auth account itself authorizes a tx.)

use miden_protocol::account::auth::AuthScheme;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::{ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET, ACCOUNT_ID_SENDER};
use miden_testing::{Auth, MockChain, TxContextInput};

#[tokio::test]
async fn native_ecdsa_auth_account_authorizes_a_state_changing_tx() -> anyhow::Result<()> {
    let faucet_id = ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET.try_into()?;

    // --- Build a User Account (BasicWallet) whose native auth IS the ecdsa_k256_keccak key. ---
    // `create_new_wallet` builds a public BasicWallet account, attaches the BasicAuth component,
    // and registers the ECDSA authenticator in the chain — exactly the User Account shape Plan 2
    // wants. (Equivalent to add_account_from_builder(BasicAuth, AccountBuilder.with(BasicWallet)).)
    let mut builder = MockChain::builder();
    let auth_scheme = AuthScheme::EcdsaK256Keccak;
    let account = builder.create_new_wallet(Auth::BasicAuth { auth_scheme })?;
    let account_id = account.id();
    assert_eq!(account.nonce().as_canonical_u64(), 0, "fresh account starts at nonce 0");

    // A P2ID note targeting the user account. Consuming it is the state change that forces the
    // native auth path (output/input notes => the account's auth__ proc must sign).
    let note = builder.add_p2id_note(
        ACCOUNT_ID_SENDER.try_into().unwrap(),
        account_id,
        &[Asset::Fungible(FungibleAsset::new(faucet_id, 1000u64).unwrap())],
        NoteType::Public,
    )?;

    let mut chain = builder.build()?;
    chain.prove_next_block()?;

    // --- Execute the tx. build_tx_context auto-attaches the ECDSA authenticator (see module doc).
    // No advice signature is injected here — the authenticator signs the tx summary internally.
    let tx = chain
        .build_tx_context(TxContextInput::Account(account), &[], &[note])?
        .build()?
        .execute()
        .await?;

    chain.add_pending_executed_transaction(&tx)?;
    chain.prove_next_block()?;

    // --- The nonce advanced => the native ECDSA auth proc ran and authorized the tx. ---
    assert!(
        tx.final_account().nonce().as_canonical_u64() > 0,
        "native ECDSA auth must increment the nonce, proving the signed tx executed"
    );
    assert_eq!(
        tx.final_account().to_commitment(),
        chain.committed_account(account_id)?.to_commitment(),
        "committed account state must match the executed tx's final account"
    );

    Ok(())
}
