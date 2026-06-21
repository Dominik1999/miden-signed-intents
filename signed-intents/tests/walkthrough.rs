//! Narrated, end-to-end walkthrough of the signed-intent flow (run with --nocapture).
//!
//! Run with:
//!   cargo test --test walkthrough -- --nocapture
//!
//! The test narrates each stage of the signed-intent lifecycle in printed sections so a
//! developer new to the codebase can follow exactly what happens — from key registration
//! through on-chain MASM verification to adversarial rejection.

use std::fs;

use miden_protocol::account::auth::PublicKey;
use miden_protocol::utils::serde::{Deserializable, Serializable as _};
use serde_json::Value;
use signed_intents::intent::Intent;
use signed_intents::relayer::{
    deploy_operator, new_chain, read_depositor_commitment, read_last_authorized, read_last_nonce,
    relay_intent, RelayError,
};
use signed_intents::user_account::{new_depositor, stored_auth_commitment, user_id_word};

fn hex_u64(v: &Value) -> u64 {
    match v {
        Value::String(s) => u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap(),
        Value::Number(n) => n.as_u64().unwrap(),
        _ => panic!("unexpected json type"),
    }
}

#[test]
fn walkthrough_signed_intent_flow() {
    // =========================================================================
    // INTRO BANNER
    // =========================================================================
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║          SIGNED INTENTS ON MIDEN — END-TO-END WALKTHROUGH           ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!();
    println!("A SIGNED INTENT is a user's off-chain authorisation to move funds.");
    println!("The user signs a compact, domain-separated message (8 Miden field elements");
    println!("hashed to a single 256-bit Word via Poseidon2). The user's wallet holds");
    println!("an ECDSA-k256-keccak key pair; the same key both controls their Miden");
    println!("account (native auth) and signs their intents (the Plan 2 binding).");
    println!();
    println!("ACTORS");
    println!("  • User / Depositor — owns the ECDSA key, signs the intent off-chain");
    println!("    (in production: browser wallet via the TypeScript @miden-sdk).");
    println!("  • Operator / Relayer — an untrusted off-chain service that receives");
    println!("    the signed payload and submits it to the Miden VM. It cannot");
    println!("    forge, tamper, or replay because the VM re-verifies the signature.");
    println!("  • Miden VM — executes the operator's MASM procedure `execute_intent`");
    println!("    which rebuilds the message hash on-chain, looks up the depositor's");
    println!("    registered pubkey commitment, runs `ecdsa_k256_keccak::verify`, and");
    println!("    enforces replay / expiry guards — all inside a ZK-provable transaction.");
    println!();

    // =========================================================================
    // STEP 1: THE USER'S ACCOUNT
    // =========================================================================
    println!("========== STEP 1: THE USER'S ACCOUNT ==========");
    println!();
    println!("We build a depositor account with seed=1. Each seed deterministically");
    println!("produces a distinct ECDSA-k256-keccak key pair so tests are reproducible.");
    println!();

    let user = new_depositor(1);
    let id_prefix = user.account.id().prefix().as_felt().as_canonical_u64();
    let id_suffix = user.account.id().suffix().as_canonical_u64();

    println!("  Miden account id (prefix) : 0x{id_prefix:016x}  ({id_prefix})");
    println!("  Miden account id (suffix) : 0x{id_suffix:016x}  ({id_suffix})");
    println!();
    println!("  Native auth scheme : AuthSingleSig / EcdsaK256Keccak");
    println!("  This key CONTROLS the account AND will SIGN its intents (Plan 2 binding).");
    println!();
    println!("  Pubkey commitment (from Depositor struct):");
    println!("    [{}, {}, {}, {}]",
        user.commitment[0], user.commitment[1],
        user.commitment[2], user.commitment[3]);

    let stored = stored_auth_commitment(&user.account);
    println!();
    println!("  Stored auth commitment (AuthSingleSig storage slot in the account):");
    println!("    [{}, {}, {}, {}]",
        stored[0], stored[1], stored[2], stored[3]);

    assert_eq!(
        user.commitment, stored,
        "the held key commitment must match the commitment stored in the account"
    );
    println!();
    println!("  ✓ user.commitment == stored_auth_commitment(&user.account)");
    println!("    The key we hold IS the key that controls this account.");
    println!();

    // =========================================================================
    // STEP 2: REGISTRATION — the operator is deployed with the user's key
    // =========================================================================
    println!("========== STEP 2: REGISTRATION (KEY SEEDING) ==========");
    println!();
    println!("The operator account is deployed on MockChain. Its storage contains a");
    println!("StorageMap (slot 0, named `signed_intents::operator::depositor_keys`)");
    println!("that maps each depositor's user_id word to their pubkey commitment.");
    println!("This is the 'registry' step: the user's key is enrolled before any intent.");
    println!();

    let uid = user_id_word(user.account.id());
    println!("  StorageMap key (user_id_word) : [{}, {}, {}, {}]",
        uid[0], uid[1], uid[2], uid[3]);
    println!("    = [id_prefix, id_suffix, 0, 0]");
    println!();

    let mut chain = new_chain();
    let deployed = deploy_operator(&mut chain, &[(uid, user.commitment)]);

    println!("  Operator account id : {}", deployed.account_id);
    println!();
    println!("  Storage slot name  : signed_intents::operator::depositor_keys");
    println!("  Map key            : [id_prefix, id_suffix, 0, 0]");

    let stored_comm = read_depositor_commitment(&chain, &deployed, uid);
    println!("  Value read back    : [{}, {}, {}, {}]",
        stored_comm[0], stored_comm[1], stored_comm[2], stored_comm[3]);

    assert_eq!(stored_comm, user.commitment, "depositor commitment in map must match user.commitment");
    println!();
    println!("  ✓ read_depositor_commitment == user.commitment");
    println!();
    println!("  [NOTE] Asset custody (depositing funds into the operator vault) is Plan 3;");
    println!("         this walkthrough shows KEY REGISTRATION + AUTHORIZATION only.");
    println!("         No money has moved. The operator holds no tokens yet.");
    println!();

    // =========================================================================
    // STEP 3: USER SIGNS AN INTENT (THE WALLET STEP)
    // =========================================================================
    println!("========== STEP 3: USER SIGNS AN INTENT (WALLET STEP) ==========");
    println!();
    println!("The user (or their browser wallet) constructs an Intent struct and signs");
    println!("the Poseidon2 hash of its 8 canonical field elements.");
    println!();

    let intent = Intent {
        user_prefix: id_prefix,
        user_suffix: id_suffix,
        recipient_prefix: 0x0000_DEAD_BEEF_0001,
        recipient_suffix: 0x0000_CAFE_BABE_0002,
        amount: 42_000,
        nonce: 1,
        expiry_block: 100_000,
    };

    let felts = intent.canonical_felts();
    println!("  8 canonical field elements (domain-separated encoding):");
    println!("    [0] domain         = {}  (DOMAIN_TRANSFER = 1)", felts[0]);
    println!("    [1] user_prefix    = {}", felts[1]);
    println!("    [2] user_suffix    = {}", felts[2]);
    println!("    [3] recip_prefix   = {}", felts[3]);
    println!("    [4] recip_suffix   = {}", felts[4]);
    println!("    [5] amount         = {}", felts[5]);
    println!("    [6] nonce          = {}", felts[6]);
    println!("    [7] expiry_block   = {}", felts[7]);
    println!();

    let msg = intent.message_word();
    let msg_hex = msg.iter()
        .map(|f| format!("{:016x}", f.as_canonical_u64()))
        .collect::<Vec<_>>()
        .join("");
    println!("  Poseidon2 message word (MSG) = 0x{msg_hex}");
    println!("  This is the exact value the Miden VM reconstructs on-chain via `hperm`.");
    println!();

    let signature = user.key.sign(msg);
    let sig_bytes = signature.to_bytes();
    let sig_hex = hex::encode(&sig_bytes);

    println!("  Signature (hex, {} bytes) :", sig_bytes.len());
    println!("    {sig_hex}");
    println!();
    println!("  In production this signing happens in the user's browser wallet via the");
    println!("  TypeScript @miden-sdk (ecdsa_k256_keccak). Here we use the same ECDSA");
    println!("  primitive in Rust for a self-contained walkthrough.");
    println!();

    // TS fixture cross-reference
    println!("  --- TypeScript SDK cross-reference ---");
    println!("  The file tests/fixtures/intent_signed.json was produced by the TS SDK:");
    let raw = fs::read_to_string("tests/fixtures/intent_signed.json")
        .expect("tests/fixtures/intent_signed.json must exist");
    let v: Value = serde_json::from_str(&raw).unwrap();
    println!("    publicKeyHex  = {}", v["publicKeyHex"].as_str().unwrap());
    println!("    signatureHex  = {}", v["signatureHex"].as_str().unwrap());
    println!("    messageWord   = {}", v["messageWordHex"].as_str().unwrap());
    println!();
    println!("  The test `tests/e2e_ts_to_masm.rs::ts_signed_intent_is_accepted_by_the_operator_masm`");
    println!("  proves that a TS-produced signature verifies correctly in the same MASM.");
    println!("  (We do not relay the fixture here — step 4 uses our Rust-signed intent for");
    println!("   a coherent single-depositor flow.)");
    println!();

    // =========================================================================
    // STEP 4: TRANSPORT — the operator receives the payload
    // =========================================================================
    println!("========== STEP 4: TRANSPORT — THE OPERATOR RECEIVES THE PAYLOAD ==========");
    println!();
    println!("The user's wallet (or TS SDK) transmits an opaque JSON payload to the");
    println!("operator. The operator is UNTRUSTED — it cannot alter any field without");
    println!("invalidating the signature, and it cannot construct a new valid signature");
    println!("without the user's private key.");
    println!();
    println!("  Payload received by the operator:");
    println!("  {{");
    println!("    user_prefix    : 0x{:016x}", intent.user_prefix);
    println!("    user_suffix    : 0x{:016x}", intent.user_suffix);
    println!("    recipient_prefix: 0x{:016x}", intent.recipient_prefix);
    println!("    recipient_suffix: 0x{:016x}", intent.recipient_suffix);
    println!("    amount         : {}", intent.amount);
    println!("    nonce          : {}", intent.nonce);
    println!("    expiry_block   : {}", intent.expiry_block);
    println!("    signatureHex   : {}", &sig_hex[..32], );
    println!("                     {}...  ({} bytes total)", &sig_hex[32..64], sig_bytes.len());
    println!("  }}");
    println!();
    println!("  The relayer merely wraps this in a Miden transaction and submits.");
    println!("  It cannot peek inside the ECDSA signature to extract the private key.");
    println!();

    // =========================================================================
    // STEP 5: ON-CHAIN VERIFICATION IN MASM
    // =========================================================================
    println!("========== STEP 5: ON-CHAIN VERIFICATION IN MASM ==========");
    println!();
    println!("When `relay_intent` is called, it builds a Miden transaction that invokes");
    println!("`execute_intent` in the operator's MASM component. Inside the VM:");
    println!();
    println!("  1. REBUILD MSG   — push the 8 canonical felts from the tx-script stack,");
    println!("                     run one `hperm` (Poseidon2 permutation), read the hash");
    println!("                     from the rate lanes. If any field was tampered, MSG");
    println!("                     will be DIFFERENT from the signed MSG.");
    println!();
    println!("  2. LOOKUP KEY    — call `get_map_item` on slot 0 (depositor_keys) with");
    println!("                     key = [user_prefix, user_suffix, 0, 0] to fetch the");
    println!("                     pubkey commitment registered for THIS depositor.");
    println!();
    println!("  3. VERIFY ECDSA  — call `ecdsa_k256_keccak::verify` with (MSG, commitment,");
    println!("                     recovered_key_from_advice_stack). The VM checks the");
    println!("                     signature proves knowledge of the private key for the");
    println!("                     STORED commitment, not just any key.");
    println!();
    println!("  4. NONCE GUARD   — assert intent.nonce > last_nonce (slot 1). Replays");
    println!("                     always fail because last_nonce advances after each relay.");
    println!();
    println!("  5. EXPIRY GUARD  — assert current_block_height < intent.expiry_block.");
    println!("                     Stale intents cannot be submitted after their deadline.");
    println!();
    println!("  6. AUDIT RECORD  — write [nonce, amount, recip_suf, recip_pre] into slot 2");
    println!("                     (last_authorized) so the accepted payload is visible to");
    println!("                     the payout logic (Plan 3).");
    println!();
    println!("  Calling relay_intent now...");

    let result = relay_intent(&mut chain, &deployed, &intent, &sig_hex);
    assert!(result.is_ok(), "valid intent must be accepted; got: {:?}", result);

    println!();
    println!("  ✓ ACCEPTED — transaction settled and committed to the chain.");
    println!();

    let last_nonce = read_last_nonce(&chain, &deployed);
    println!("  last_nonce  (slot 1) = {last_nonce}  (was 0, now equals intent.nonce)");
    assert_eq!(last_nonce, 1, "last_nonce must be 1 after the first relay");

    // last_authorized layout: Word([r_pre, r_suf, amount, nonce]) where index 3 = TOP
    let last_auth = read_last_authorized(&chain, &deployed);
    println!("  last_authorized (slot 2) =");
    println!("    word[0] = recipient_prefix = 0x{:016x}  ({})",
        last_auth[0].as_canonical_u64(), last_auth[0].as_canonical_u64());
    println!("    word[1] = recipient_suffix = 0x{:016x}  ({})",
        last_auth[1].as_canonical_u64(), last_auth[1].as_canonical_u64());
    println!("    word[2] = amount           = {}",
        last_auth[2].as_canonical_u64());
    println!("    word[3] = nonce            = {}",
        last_auth[3].as_canonical_u64());

    assert_eq!(last_auth[2].as_canonical_u64(), 42_000, "amount must be recorded in last_authorized");
    assert_eq!(last_auth[3].as_canonical_u64(), 1, "nonce must be recorded in last_authorized");
    println!();

    // =========================================================================
    // STEP 6: ADVERSARIAL BONUS — tampered intent is REJECTED
    // =========================================================================
    println!("========== STEP 6: ADVERSARIAL BONUS — TAMPERED INTENT IS REJECTED ==========");
    println!();
    println!("Scenario: the operator (relayer) is malicious and tries to steal funds by");
    println!("inflating the amount from 42,000 to 9,999,999 AFTER the user has signed.");
    println!();
    println!("  Original amount (signed by user) : {}", intent.amount);

    let mut tampered = intent;
    tampered.amount = 9_999_999;
    println!("  Tampered amount (relayer's edit) : {}", tampered.amount);
    println!();
    println!("  The signature hex is UNCHANGED — this is the user's real signature,");
    println!("  just submitted against a different amount field.");
    println!();
    println!("  What happens inside the VM:");
    println!("    The MASM rebuilds MSG from the TAMPERED 8 felts -> MSG' != MSG_original.");
    println!("    ECDSA recovery on (MSG', sig) yields a WRONG public key (or panics).");
    println!("    The commitment check: wrong_key.commitment != stored_commitment -> ABORT.");
    println!();
    println!("  Calling relay_intent with tampered intent...");

    // Use a fresh chain so tamper test is independent (avoids nonce conflict with step 5).
    let mut chain2 = new_chain();
    let dep2 = deploy_operator(&mut chain2, &[(uid, user.commitment)]);
    let tamper_result = relay_intent(&mut chain2, &dep2, &tampered, &sig_hex);

    match &tamper_result {
        Err(RelayError::Rejected(msg)) => {
            println!();
            println!("  ✓ REJECTED — relay_intent returned RelayError::Rejected");
            println!("    Reason: {msg}");
            println!();
            println!("  The relayer cannot forge or tamper because the Miden VM re-derives");
            println!("  MSG from the submitted felts and re-checks the signature against");
            println!("  the commitment registered at deploy time. No valid proof exists.");
            assert!(!msg.is_empty(), "rejection reason must not be empty");
        }
        Ok(()) => panic!("tampered intent must be rejected, but relay_intent returned Ok"),
    }

    // =========================================================================
    // CLOSING SUMMARY
    // =========================================================================
    println!("========== CLOSING SUMMARY ==========");
    println!();
    println!("What just happened, end-to-end:");
    println!();
    println!("  1. The USER generated an ECDSA-k256-keccak key pair. The same key");
    println!("     controls their Miden account (Plan 2 binding) and signs intents.");
    println!();
    println!("  2. The OPERATOR was deployed with the user's pubkey COMMITMENT seeded");
    println!("     in a per-depositor StorageMap (slot 0, depositor_keys).");
    println!();
    println!("  3. The USER signed an intent off-chain: 8 felts -> Poseidon2 -> Word,");
    println!("     then ECDSA-k256-keccak sign(MSG). In production this happens in the");
    println!("     browser via the TypeScript @miden-sdk (same primitive, cross-verified");
    println!("     by tests/e2e_ts_to_masm.rs).");
    println!();
    println!("  4. The MIDEN VM verified the signature ON-CHAIN in MASM: rebuilt MSG,");
    println!("     looked up the depositor's commitment, ran ecdsa_k256_keccak::verify,");
    println!("     enforced nonce > last_nonce and block < expiry, and recorded the");
    println!("     authorized payload — all inside a ZK-provable transaction.");
    println!();
    println!("  5. A TAMPERED intent (inflated amount) was REJECTED, proving the relayer");
    println!("     cannot cheat even if it controls the submission pipeline.");
    println!();
    println!("  Next step (Plan 3): asset custody — the user deposits funds into the");
    println!("  operator vault, and approved intents trigger on-chain payout to the");
    println!("  recipient. See the design spec for the full roadmap.");
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║                     WALKTHROUGH COMPLETE — ALL ASSERTIONS PASSED    ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!();
}
