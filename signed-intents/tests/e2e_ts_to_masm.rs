//! Proves a TypeScript-produced ECDSA signature over the 8-felt intent is accepted
//! by the operator MASM through the Rust relayer. This is the cross-SDK link: TS
//! serializes the pubkey + signature, Rust deserializes them, and the VM verifies.

use std::fs;

use miden_protocol::account::auth::PublicKey;
use miden_protocol::utils::serde::Deserializable;
use serde_json::Value;
use signed_intents::intent::Intent;
use signed_intents::relayer::{deploy_operator, new_chain, read_last_nonce, relay_intent};

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

    let mut chain = new_chain();
    let deployed = deploy_operator(&mut chain, &pubkey);

    relay_intent(&mut chain, &deployed, &intent, signature_hex)
        .expect("TS-signed intent must be accepted by the operator MASM");

    assert_eq!(read_last_nonce(&chain, &deployed), 1);
}
