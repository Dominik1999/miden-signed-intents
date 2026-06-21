//! FEASIBILITY SPIKE — Plan 2. Not production.
//!
//! Q1 (GATING): prove an account can hold a per-depositor `StorageMap` seeded with one entry
//! `(user_id_word -> pubkey_commitment_word)`, and that a MASM proc can READ that value by key
//! and expose it. We expose it by copying the looked-up VALUE into a plain `readback` value slot,
//! then assert (from the executed tx's final account storage) that it equals the seeded commitment.
//!
//! GREEN = Q1 PASS.
//!
//! Key 0.14 ABI findings pinned here:
//!   Rust:  StorageMap::with_entries([(StorageMapKey::new(word), value_word)])
//!          StorageSlot::with_map(slot_name, map)
//!   MASM:  miden::protocol::active_account::get_map_item
//!            [slot_prefix, slot_suffix, KEY, ...] -> [VALUE, ...]
//!   GOTCHA: the map key is HASHED by both sides. Rust `StorageMapKey::hash` =
//!           `Hasher::hash_elements(key)`, and the kernel's get_map_item hashes the raw KEY
//!           the same way. So Rust seeds with the RAW user-id word and MASM passes the RAW word;
//!           neither side pre-hashes.

use miden_protocol::Word;
use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountBuilder, AccountComponent, StorageMap, StorageMapKey, StorageSlot, StorageSlotName,
};
use miden_client::assembly::CodeBuilder;
use miden_testing::{Auth, TransactionContextBuilder};

const SPIKE_MASM: &str = include_str!("../masm/spike_plan2.masm");

const KEYS_MAP_SLOT: &str = "signed_intents::spike::depositor_keys";
const READBACK_SLOT: &str = "signed_intents::spike::readback";

#[test]
fn storage_map_read_in_masm_returns_seeded_commitment() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(run());
}

async fn run() {
    // The depositor's raw account-id word (user_pre, user_suf, 0, 0) used as the map key,
    // and the pubkey commitment value we seed it with.
    let user_id: Word = Word::from([0xabcdu32, 0xef01, 0, 0]);
    let pubkey_commitment: Word = Word::from([1111u32, 2222, 3333, 4444]);

    // --- Assemble the spike component library. ---
    let library = CodeBuilder::default()
        .compile_component_code("signed_intents::spike", SPIKE_MASM)
        .expect("spike_plan2.masm must assemble as a component");

    // --- Seed the StorageMap with one entry (raw user_id -> pubkey commitment). ---
    let map = StorageMap::with_entries([(StorageMapKey::new(user_id), pubkey_commitment)])
        .expect("storage map with one entry must build");

    let keys_slot = StorageSlotName::new(KEYS_MAP_SLOT).unwrap();
    let readback_slot = StorageSlotName::new(READBACK_SLOT).unwrap();

    let component = AccountComponent::new(
        library.clone(),
        vec![
            StorageSlot::with_map(keys_slot, map),
            StorageSlot::with_value(readback_slot, Word::from([0u32, 0, 0, 0])),
        ],
        AccountComponentMetadata::mock("signed_intents::spike"),
    )
    .expect("spike component must build with a map slot + a value slot");

    let account = AccountBuilder::new(rand::random())
        .with_auth_component(Auth::IncrNonce)
        .with_component(component)
        .build_existing()
        .expect("spike account must build");

    // --- Tx script: push the raw user_id word, call read_depositor_key. ---
    // push lists last-operand-on-top; we want [user_pre, user_suf, 0, 0] with user_pre on top.
    let tx_script_code = format!(
        r#"
        use signed_intents::spike->spike
        use miden::core::sys

        begin
            push.0.0.{user_suf}.{user_pre}
            # => [user_pre, user_suf, 0, 0, pad...]
            call.spike::read_depositor_key
            exec.sys::truncate_stack
        end
        "#,
        user_pre = user_id.as_elements()[0].as_canonical_u64(),
        user_suf = user_id.as_elements()[1].as_canonical_u64(),
    );

    let tx_script = CodeBuilder::default()
        .with_dynamically_linked_library(&library)
        .unwrap()
        .compile_tx_script(tx_script_code)
        .expect("spike tx script must compile");

    let tx = TransactionContextBuilder::new(account)
        .tx_script(tx_script)
        .build()
        .unwrap()
        .execute()
        .await
        .expect("spike tx must execute (map read + set_item must succeed)");

    // --- Assert: the readback value slot was written with the seeded commitment. ---
    // `final_account()` only exposes an AccountHeader (no storage items), so we read the new
    // value out of the transaction's storage delta instead.
    let readback_name = StorageSlotName::new(READBACK_SLOT).unwrap();
    let written = tx
        .account_delta()
        .storage()
        .values()
        .find(|(name, _)| **name == readback_name)
        .map(|(_, word)| *word)
        .expect("readback value slot must appear in the storage delta (set_item ran)");

    assert_eq!(
        written, pubkey_commitment,
        "MASM get_map_item must return the seeded pubkey commitment for the user_id key"
    );
}
