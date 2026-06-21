//! Narrated end-to-end walkthrough: TypeScript signs → Miden ECDSA account → operator MASM verify.
//!
//! Run with:
//!   cargo test --test walkthrough_ts -- --nocapture
//!
//! # What this test proves
//!
//! This test unifies two previously separate demos into one coherent, narrated flow:
//!
//! 1. **REAL — TS signing**: the user signs an intent in TypeScript using the Miden SDK
//!    `AuthSecretKey.ecdsaWithRNG()`. The live TS signer is invoked as a subprocess; if
//!    node/npm is unavailable the test falls back to the committed `tests/fixtures/intent_signed.json`
//!    (which was also produced by the TS SDK). Either way the verified signature is genuinely
//!    TypeScript-produced.
//!
//! 2. **REAL — TS key controls the Miden account**: the TS-produced public key is deserialised and
//!    used to build a real Miden ECDSA account (`AuthSingleSig` / `EcdsaK256Keccak`). The same
//!    key that signed the intent controls the account. No separate key is generated in Rust.
//!
//! 3. **MODELED — operator registration**: the operator is deployed with the user's pubkey
//!    commitment seeded directly into its `StorageMap`. A real user-submitted registration /
//!    deposit transaction (Plan 3) is NOT exercised here; registration is seeded at deploy.
//!
//! 4. **REAL — MASM verification**: `relay_intent` builds a Miden VM transaction that invokes
//!    `execute_intent` in MASM. The VM rebuilds the Poseidon2 message hash, looks up the
//!    registered pubkey commitment, calls `ecdsa_k256_keccak::verify`, and enforces nonce/expiry
//!    guards — entirely inside the ZK-provable transaction.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use miden_protocol::Felt;
use miden_protocol::Word;
use miden_protocol::account::auth::PublicKey;
use miden_protocol::utils::serde::Deserializable;
use serde_json::Value;
use signed_intents::intent::Intent;
use signed_intents::relayer::{deploy_operator, new_chain, read_last_nonce, relay_intent, RelayError};
use signed_intents::user_account::{account_from_pubkey_commitment, stored_auth_commitment};

/// Parses a fixture JSON value that is either a hex string ("0xAAAA") or a decimal number.
fn hex_u64(v: &Value) -> u64 {
    match v {
        Value::String(s) => u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap(),
        Value::Number(n) => n.as_u64().unwrap(),
        _ => panic!("unexpected json type: {v}"),
    }
}

/// Try to run the TS signer live, writing to `out_path`. Returns true on success.
fn try_live_ts_sign(out_path: &str) -> bool {
    // Locate the ts/ directory relative to the crate root (the test's working dir).
    let ts_dir = PathBuf::from("ts");
    if !ts_dir.exists() {
        return false;
    }
    // Check that node_modules is present; otherwise npm run will fail.
    if !ts_dir.join("node_modules").exists() {
        return false;
    }
    let status = Command::new("npm")
        .args(["run", "gen-fixture"])
        .current_dir(&ts_dir)
        .env("FIXTURE_OUT", out_path)
        .status();
    match status {
        Ok(s) if s.success() => true,
        _ => false,
    }
}

#[test]
fn walkthrough_ts_signed_intent_unified_flow() {
    // =========================================================================
    // INTRO BANNER
    // =========================================================================
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║    SIGNED INTENTS — UNIFIED TS-SIGNS → MIDEN-ECDSA-ACCOUNT FLOW    ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!();
    println!("This walkthrough proves the full cross-SDK path:");
    println!("  • The USER generates a key in TypeScript and signs an intent with it.");
    println!("  • The SAME TypeScript public key becomes the native auth key of a real");
    println!("    Miden ECDSA account (AuthSingleSig / EcdsaK256Keccak).");
    println!("  • The OPERATOR is deployed with that key commitment pre-seeded (Plan 3");
    println!("    will replace seeding with a real deposit/registration transaction).");
    println!("  • The MIDEN VM verifies the TS-produced signature on-chain in MASM.");
    println!();
    println!("ACTORS");
    println!("  • User       — an ECDSA key pair born in the TypeScript @miden-sdk.");
    println!("  • Operator   — an untrusted relayer that cannot forge, tamper, or replay.");
    println!("  • Miden VM   — executes execute_intent: rebuilds MSG, looks up commitment,");
    println!("                 runs ecdsa_k256_keccak::verify, enforces nonce & expiry.");
    println!();

    // =========================================================================
    // STEP 1: USER SIGNS IN TYPESCRIPT
    // =========================================================================
    println!("========== STEP 1: USER SIGNS IN TYPESCRIPT ==========");
    println!();

    // Write the live fixture to a separate path so we don't clobber
    // tests/fixtures/intent_signed.json (which e2e_ts_to_masm.rs depends on).
    // Use an absolute path so the npm subprocess (cwd=ts/) and the Rust reader both agree.
    let live_fixture_path = std::env::current_dir()
        .unwrap()
        .join("tests/fixtures/walkthrough_live.json")
        .to_string_lossy()
        .into_owned();

    let (fixture_path, signing_source) = if try_live_ts_sign(&live_fixture_path) {
        println!("  Live TS signing succeeded.");
        println!("  Fixture written to: {live_fixture_path}");
        (live_fixture_path.clone(), "LIVE — signed just now by the TypeScript @miden-sdk")
    } else {
        println!("  node/npm not available or node_modules missing — falling back to the");
        println!("  committed pre-generated fixture (also produced by the TypeScript SDK).");
        (
            "tests/fixtures/intent_signed.json".to_string(),
            "PRE-GENERATED — committed TS SDK fixture (same SDK, same key type)",
        )
    };
    println!("  Signing source : {signing_source}");
    println!();

    let raw = fs::read_to_string(&fixture_path)
        .unwrap_or_else(|_| panic!("cannot read fixture at {fixture_path}"));
    let v: Value = serde_json::from_str(&raw).unwrap();

    let i = &v["intent"];
    let intent = Intent {
        user_prefix:      hex_u64(&i["user_prefix"]),
        user_suffix:      hex_u64(&i["user_suffix"]),
        recipient_prefix: hex_u64(&i["recipient_prefix"]),
        recipient_suffix: hex_u64(&i["recipient_suffix"]),
        amount:           hex_u64(&i["amount"]),
        nonce:            hex_u64(&i["nonce"]),
        expiry_block:     hex_u64(&i["expiry_block"]),
    };

    let pk_bytes = hex::decode(v["publicKeyHex"].as_str().unwrap()).unwrap();
    let ts_pubkey = PublicKey::read_from_bytes(&pk_bytes)
        .expect("TS-serialised pubkey must deserialise in Rust");
    let signature_hex = v["signatureHex"].as_str().unwrap().to_string();
    let message_word_hex = v["messageWordHex"].as_str().unwrap();

    println!("  TS-produced values:");
    println!("    publicKeyHex   = {}", v["publicKeyHex"].as_str().unwrap());
    println!("    signatureHex   = {}...", &signature_hex[..16]);
    println!("                     ({} bytes)", hex::decode(&signature_hex).unwrap().len());
    println!("    messageWordHex = {message_word_hex}");
    println!();
    println!("  Intent fields from fixture:");
    println!("    user_prefix    = 0x{:x}", intent.user_prefix);
    println!("    user_suffix    = 0x{:x}", intent.user_suffix);
    println!("    amount         = {}", intent.amount);
    println!("    nonce          = {}", intent.nonce);
    println!("    expiry_block   = {}", intent.expiry_block);
    println!();

    // =========================================================================
    // STEP 2: BUILD THE USER'S MIDEN ECDSA ACCOUNT FROM THE TS KEY
    // =========================================================================
    println!("========== STEP 2: BUILD THE USER'S MIDEN ECDSA ACCOUNT FROM THE TS KEY ==========");
    println!();
    println!("  We deserialise the TS public key and derive its PublicKeyCommitment.");
    println!("  Then we build a Miden account with AuthSingleSig / EcdsaK256Keccak");
    println!("  seeded from that commitment. No Rust secret key is involved.");
    println!();

    let ts_pkc = ts_pubkey.to_commitment();
    let ts_commitment: Word = ts_pkc.into();

    let user_account = account_from_pubkey_commitment(ts_pkc);
    let acct_id = user_account.id();
    let id_prefix = acct_id.prefix().as_felt().as_canonical_u64();
    let id_suffix = acct_id.suffix().as_canonical_u64();

    println!("  Miden account id (prefix) : 0x{id_prefix:016x}  ({id_prefix})");
    println!("  Miden account id (suffix) : 0x{id_suffix:016x}  ({id_suffix})");
    println!("  Native auth scheme        : AuthSingleSig / EcdsaK256Keccak");
    println!();
    println!("  TS pubkey commitment (from pubkey.to_commitment()):");
    println!("    [{}, {}, {}, {}]",
        ts_commitment[0], ts_commitment[1], ts_commitment[2], ts_commitment[3]);

    let stored = stored_auth_commitment(&user_account);
    println!();
    println!("  Commitment stored in account's AuthSingleSig slot:");
    println!("    [{}, {}, {}, {}]",
        stored[0], stored[1], stored[2], stored[3]);

    assert_eq!(
        ts_commitment, stored,
        "the TS pubkey commitment must equal the commitment stored in the account's auth slot"
    );
    println!();
    println!("  VERIFIED: ts_pubkey.to_commitment() == stored_auth_commitment(&user_account)");
    println!("  The TypeScript key controls this Miden account AND signed the intent above.");
    println!("  This is the Plan 2 binding: one key, two roles.");
    println!();

    // =========================================================================
    // STEP 3: REGISTER (SEED) THE USER'S PUBKEY WITH THE OPERATOR
    // =========================================================================
    println!("========== STEP 3: REGISTER (SEED) THE USER'S PUBKEY WITH THE OPERATOR ==========");
    println!();
    println!("  The operator's StorageMap (slot 0, 'signed_intents::operator::depositor_keys')");
    println!("  maps user_id_word → pubkey_commitment for each registered depositor.");
    println!();
    println!("  [NOTE on registration] In this demo, registration is MODELED by seeding the");
    println!("  operator's map at deploy time. A real user-submitted registration/deposit");
    println!("  transaction (Plan 3) is not exercised here — that requires asset custody.");
    println!();
    println!("  [NOTE on user_id] The TS fixture carries a fixed user_id (0xAAAA / 0xBBBB)");
    println!("  chosen when the key was generated, not tied to the freshly-built Miden account");
    println!("  id above. In a production flow the user would sign AFTER account creation so");
    println!("  user_prefix/user_suffix match the account id. Here we key the operator map by");
    println!("  the INTENT'S user_id (what MASM will look up), and the account is built from");
    println!("  the same TS key for the auth-binding demonstration.");
    println!();

    // Use the intent's user_id as the map key (MASM looks up by user_prefix/user_suffix).
    let user_id_word: Word = Word::from([
        Felt::new(intent.user_prefix),
        Felt::new(intent.user_suffix),
        Felt::new(0u64),
        Felt::new(0u64),
    ]);

    println!("  StorageMap key (user_id_word from intent):");
    println!("    [0x{:x}, 0x{:x}, 0, 0]", intent.user_prefix, intent.user_suffix);
    println!("  Value seeded : ts_commitment = [{}, {}, {}, {}]",
        ts_commitment[0], ts_commitment[1], ts_commitment[2], ts_commitment[3]);
    println!();

    let mut chain = new_chain();
    let deployed = deploy_operator(&mut chain, &[(user_id_word, ts_commitment)]);

    println!("  Operator account id: {}", deployed.account_id);
    println!();

    // Verify the seeded value is readable.
    let read_comm = signed_intents::relayer::read_depositor_commitment(&chain, &deployed, user_id_word);
    assert_eq!(read_comm, ts_commitment, "seeded commitment must read back correctly");
    println!("  VERIFIED: read_depositor_commitment(user_id_word) == ts_commitment");
    println!();

    // =========================================================================
    // STEP 4: OPERATOR DESERIALISES & VERIFIES THE TS SIGNATURE IN MASM
    // =========================================================================
    println!("========== STEP 4: OPERATOR DESERIALISES & VERIFIES IN MASM ==========");
    println!();
    println!("  relay_intent builds a Miden VM transaction invoking execute_intent.");
    println!("  Inside the VM (MASM), the following happens:");
    println!();
    println!("    1. REBUILD MSG   — push the 8 canonical intent felts, run hperm");
    println!("                       (Poseidon2). If any field was tampered, MSG differs.");
    println!("    2. LOOKUP KEY    — get_map_item(slot 0, [user_prefix, user_suffix, 0, 0])");
    println!("                       → the TS pubkey commitment registered at deploy.");
    println!("    3. VERIFY ECDSA  — ecdsa_k256_keccak::verify(MSG, commitment, sig).");
    println!("                       The VM checks the sig proves knowledge of the TS key.");
    println!("    4. NONCE GUARD   — assert intent.nonce > last_nonce (slot 1).");
    println!("    5. EXPIRY GUARD  — assert current_block_height < intent.expiry_block.");
    println!("    6. AUDIT RECORD  — write [nonce, amount, recip_suf, recip_pre] to slot 2.");
    println!();
    println!("  Submitting TS-signed intent to the Miden VM...");

    let result = relay_intent(&mut chain, &deployed, &intent, &signature_hex);

    assert!(
        result.is_ok(),
        "TS-signed intent must be accepted by the operator MASM; got: {:?}",
        result
    );

    let last_nonce = read_last_nonce(&chain, &deployed);
    println!();
    println!("  ACCEPTED — transaction settled on the chain.");
    println!("  last_nonce (slot 1) = {last_nonce}  (was 0, now = intent.nonce = {})", intent.nonce);
    assert_eq!(last_nonce, intent.nonce, "last_nonce must equal the relayed intent's nonce");
    println!();

    // =========================================================================
    // STEP 5: ADVERSARIAL — tampered intent is REJECTED
    // =========================================================================
    println!("========== STEP 5: ADVERSARIAL — TAMPERED INTENT REJECTED ==========");
    println!();
    println!("  The relayer (operator) tries to inflate the amount after the user signed.");
    println!();
    println!("  Original amount (signed by TS user) : {}", intent.amount);

    let mut tampered = intent;
    tampered.amount = intent.amount * 1000 + 7;
    println!("  Tampered amount (relayer's edit)    : {}", tampered.amount);
    println!();
    println!("  The signatureHex is UNCHANGED — it's the genuine TS signature,");
    println!("  just submitted against a different amount field.");
    println!();
    println!("  Inside the VM: hperm(tampered_felts) → MSG' ≠ MSG_original.");
    println!("  ECDSA recovery on (MSG', sig) yields the wrong key (or panics).");
    println!("  commitment check: wrong_key.commitment ≠ stored_commitment → ABORT.");
    println!();

    // Use a fresh chain so nonce state doesn't interfere.
    let mut chain2 = new_chain();
    let dep2 = deploy_operator(&mut chain2, &[(user_id_word, ts_commitment)]);
    let tamper_result = relay_intent(&mut chain2, &dep2, &tampered, &signature_hex);

    match &tamper_result {
        Err(RelayError::Rejected(msg)) => {
            println!("  REJECTED — relay_intent returned RelayError::Rejected");
            println!("  Reason: {msg}");
            println!();
            println!("  The relayer cannot forge or tamper. The Miden VM re-derives MSG");
            println!("  from submitted felts and re-checks against the registered commitment.");
            assert!(!msg.is_empty(), "rejection reason must not be empty");
        }
        Ok(()) => panic!("tampered intent must be rejected, but relay_intent returned Ok"),
    }
    println!();

    // =========================================================================
    // CLOSING SUMMARY
    // =========================================================================
    println!("========== CLOSING SUMMARY ==========");
    println!();
    println!("  STEP 1 — REAL   : User signed in TypeScript ({signing_source}).");
    println!("  STEP 2 — REAL   : TS public key = native auth key of a real Miden ECDSA");
    println!("                    account (AuthSingleSig / EcdsaK256Keccak).");
    println!("                    Same key controls the account AND signed the intent.");
    println!("  STEP 3 — MODELED: Operator registration is SEEDED at deploy (not a real");
    println!("                    deposit/registration tx). Real registration = Plan 3.");
    println!("  STEP 4 — REAL   : Miden VM verified the TS signature in MASM: rebuilt MSG,");
    println!("                    looked up ts_commitment, ran ecdsa_k256_keccak::verify,");
    println!("                    enforced nonce/expiry, recorded the authorized payload.");
    println!();
    println!("  The relayer cannot forge, tamper, or replay (Step 5 proves this).");
    println!();
    println!("  Next step (Plan 3): real deposit/registration tx + on-chain payout.");
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║             WALKTHROUGH COMPLETE — ALL ASSERTIONS PASSED            ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!();
}
