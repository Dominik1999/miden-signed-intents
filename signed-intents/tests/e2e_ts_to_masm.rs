//! Proves a TypeScript-produced ECDSA signature over the 8-felt intent is accepted
//! by the operator MASM through the Rust relayer. This is the cross-SDK link: TS
//! serializes the pubkey + signature, Rust deserializes them, and the VM verifies.
//!
//! The fixture has fixed `user_prefix`/`user_suffix` (e.g. 0xAAAA/0xBBBB) chosen by the
//! TypeScript key-generation script. We seed the operator's depositor map with the word
//! `[user_prefix, user_suffix, 0, 0]` → `ts_pubkey.to_commitment()`, matching what the
//! MASM looks up by the intent's user_id. No real Miden AccountId is needed here — the
//! e2e test proves cross-SDK signature verification through the map path.

use std::fs;

use miden_protocol::Felt;
use miden_protocol::account::auth::PublicKey;
use miden_protocol::utils::serde::Deserializable;
use miden_protocol::Word;
use serde_json::Value;
use signed_intents::intent::Intent;
use signed_intents::relayer::{deploy_operator, new_chain, read_last_nonce, relay_intent};

/// Parses a fixture JSON value that is either a hex string ("0xAAAA") or a decimal number.
fn hex_u64(v: &Value) -> u64 {
    match v {
        Value::String(s) => u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap(),
        Value::Number(n) => n.as_u64().unwrap(),
        _ => panic!("unexpected json type"),
    }
}

#[test]
fn ts_signed_intent_is_accepted_by_the_operator_masm() {
    let raw = fs::read_to_string("tests/fixtures/intent_signed.json")
        .expect("run `cd ts && npm run gen-fixture` first");
    let v: Value = serde_json::from_str(&raw).unwrap();

    let i = &v["intent"];
    let intent = Intent {
        user_prefix: hex_u64(&i["user_prefix"]),
        user_suffix: hex_u64(&i["user_suffix"]),
        recipient_prefix: hex_u64(&i["recipient_prefix"]),
        recipient_suffix: hex_u64(&i["recipient_suffix"]),
        amount: hex_u64(&i["amount"]),
        nonce: hex_u64(&i["nonce"]),
        expiry_block: hex_u64(&i["expiry_block"]),
    };

    let pk_bytes = hex::decode(v["publicKeyHex"].as_str().unwrap()).unwrap();
    let pubkey = PublicKey::read_from_bytes(&pk_bytes)
        .expect("TS-serialized pubkey must deserialize in Rust");
    let signature_hex = v["signatureHex"].as_str().unwrap();

    // Build the depositor-map key from the fixture's user_prefix/user_suffix.
    // The MASM looks up `[user_prefix, user_suffix, 0, 0]` in the StorageMap, so we seed
    // exactly that key → the TS pubkey's commitment word.
    let user_id_word: Word = Word::from([
        Felt::new(intent.user_prefix),
        Felt::new(intent.user_suffix),
        Felt::new(0u64),
        Felt::new(0u64),
    ]);
    let commitment: Word = pubkey.to_commitment().into();

    let mut chain = new_chain();
    let deployed = deploy_operator(&mut chain, &[(user_id_word, commitment)]);

    relay_intent(&mut chain, &deployed, &intent, signature_hex)
        .expect("TS-signed intent must be accepted by the operator MASM");

    assert_eq!(read_last_nonce(&chain, &deployed), 1);
}
