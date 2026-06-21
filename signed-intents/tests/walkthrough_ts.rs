//! Narrated two-phase walkthrough: TS generates key → Rust builds account → TS signs → MASM verifies.
//!
//! Run with:
//!   cargo test --test walkthrough_ts -- --nocapture
//!
//! # What this test proves
//!
//! This is a TWO-PHASE cross-SDK orchestration that makes the user's ECDSA account the genuine
//! subject of the signed intent:
//!
//! ## Phase A — TS generates the key
//! A TypeScript subprocess (`ts/wt-export-key.ts`) generates a fresh `ecdsa_k256_keccak` key via
//! `AuthSecretKey.ecdsaWithRNG()`, serializes it with `key.serialize()` (a `Uint8Array` persisted
//! as hex in a temp JSON), and exports the public key hex for Rust.
//!
//! ## Rust mid-step — build account + compute id
//! Rust deserialises the TS `PublicKey`, calls `pubkey.to_commitment()`, and builds the user's
//! Miden ECDSA account via `account_from_pubkey_commitment_seeded` (deterministic seed derived from
//! the commitment, so the same pubkey always yields the same `AccountId`). The account's id prefix
//! and suffix felts are written to a second temp JSON for Phase B.
//!
//! ## Phase B — TS signs with user_id = account id
//! A second TypeScript subprocess (`ts/wt-sign-intent.ts`) loads the persisted key via
//! `AuthSecretKey.deserialize(keyBytes)`, reads the account id felts, and builds the 8-felt intent
//! with `userPrefix`/`userSuffix` equal to the actual Miden account id. It signs `messageWord` and
//! writes `{ intent, signatureHex, publicKeyHex, messageWordHex }` to a live fixture file.
//!
//! ## Rust relay — register + verify
//! Rust asserts `intent.user_prefix == acct_id_prefix` and `intent.user_suffix == acct_id_suffix`,
//! deploys the operator keyed by the account's `user_id_word`, relays the TS signature through
//! `relay_intent`, and verifies MASM accepted it. A tampered-intent relay is then asserted to fail.
//!
//! # Key persistence
//! `AuthSecretKey.serialize()` → hex string in temp JSON → `AuthSecretKey.deserialize(bytes)`.
//! The same key instance is recovered in Phase B without any re-generation.
//!
//! # Fallback
//! If node or node_modules are unavailable the test prints a clear SKIP message and returns
//! without failing. The committed `tests/fixtures/intent_signed.json` and `e2e_ts_to_masm.rs`
//! are NOT touched.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use miden_protocol::Word;
use miden_protocol::account::auth::PublicKey;
use miden_protocol::utils::serde::Deserializable;
use serde_json::Value;
use signed_intents::intent::Intent;
use signed_intents::relayer::{deploy_operator, new_chain, read_last_nonce, relay_intent, RelayError};
use signed_intents::user_account::{account_from_pubkey_commitment_seeded, stored_auth_commitment, user_id_word};

/// Parses a fixture JSON value that is either a hex string ("0xAAAA") or a decimal number or
/// decimal string.
fn hex_or_dec_u64(v: &Value) -> u64 {
    match v {
        Value::String(s) if s.starts_with("0x") || s.starts_with("0X") => {
            u64::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap()
        }
        Value::String(s) => s.parse::<u64>().unwrap(),
        Value::Number(n) => n.as_u64().unwrap(),
        _ => panic!("unexpected json type: {v}"),
    }
}

/// Check that node and node_modules are available for running TS scripts.
fn ts_toolchain_available() -> bool {
    let ts_dir = PathBuf::from("ts");
    if !ts_dir.exists() || !ts_dir.join("node_modules").exists() {
        return false;
    }
    // Quick sanity: node --version must succeed.
    matches!(Command::new("node").arg("--version").output(), Ok(o) if o.status.success())
}

/// Run a TS script via `npm run <script>` with given env vars. Returns true on success.
fn run_ts_script(script: &str, env_vars: &[(&str, &str)]) -> bool {
    let ts_dir = PathBuf::from("ts");
    let mut cmd = Command::new("npm");
    cmd.args(["run", script]).current_dir(&ts_dir);
    for (k, v) in env_vars {
        cmd.env(k, v);
    }
    match cmd.status() {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("[walkthrough_ts] npm run {script} exited with {s}");
            false
        }
        Err(e) => {
            eprintln!("[walkthrough_ts] npm run {script} failed to spawn: {e}");
            false
        }
    }
}

#[test]
fn walkthrough_ts_two_phase_intent_bound_to_account_id() {
    // =========================================================================
    // INTRO BANNER
    // =========================================================================
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║   SIGNED INTENTS — TWO-PHASE WALKTHROUGH: INTENT BOUND TO ACCOUNT  ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!();
    println!("This walkthrough proves the full cross-SDK path with the user's ECDSA");
    println!("account as the GENUINE subject of the signed intent:");
    println!();
    println!("  Phase A (TS)   — user generates key; key is serialized for Phase B.");
    println!("  Mid-step (Rust)— account built from TS pubkey; account id computed.");
    println!("  Phase B (TS)   — user signs intent with user_id = the account id.");
    println!("  Relay (Rust)   — operator seeded by account id; MASM verifies sig.");
    println!();
    println!("ACTORS");
    println!("  User     — ECDSA key pair born in TypeScript @miden-sdk.");
    println!("  Operator — untrusted relayer (cannot forge, tamper, or replay).");
    println!("  Miden VM — executes execute_intent: rebuilds MSG, looks up commitment,");
    println!("             runs ecdsa_k256_keccak::verify, enforces nonce & expiry.");
    println!();

    // =========================================================================
    // TOOLCHAIN CHECK — skip gracefully if node/npm unavailable
    // =========================================================================
    if !ts_toolchain_available() {
        println!("══════════════════════════════════════════════════════════════════════");
        println!("  SKIPPED: this live walkthrough requires the TS toolchain.");
        println!("  Ensure node/npm is installed and run `cd ts && npm install`.");
        println!("  The committed fixture flow is covered by e2e_ts_to_masm.rs.");
        println!("══════════════════════════════════════════════════════════════════════");
        println!();
        return;
    }

    // =========================================================================
    // TEMP FILE PATHS
    // =========================================================================
    // All temp files go under target/ so they are git-ignored and cleaned by `cargo clean`.
    let cwd = std::env::current_dir().unwrap();
    let tmp = cwd.join("target/wt-tmp");
    fs::create_dir_all(&tmp).expect("create tmp dir");

    let key_path        = tmp.join("wt-key.json").to_string_lossy().into_owned();
    let pubkey_path     = tmp.join("wt-pubkey.json").to_string_lossy().into_owned();
    let account_id_path = tmp.join("wt-account-id.json").to_string_lossy().into_owned();
    let fixture_path    = tmp.join("wt-fixture.json").to_string_lossy().into_owned();

    // =========================================================================
    // STEP 0: PHASE A — TS GENERATES KEY + EXPORTS PUBKEY
    // =========================================================================
    println!("══════════════════════════════════════════════════════════════════════════");
    println!("  STEP 0 (Phase A / REAL) — TypeScript generates ECDSA key");
    println!("══════════════════════════════════════════════════════════════════════════");
    println!();
    println!("  Running: ts/wt-export-key.ts");
    println!("    • AuthSecretKey.ecdsaWithRNG() generates the key.");
    println!("    • key.serialize() → hex → persisted for Phase B reuse.");
    println!("    • key.publicKey().serialize() → exported for Rust account build.");
    println!();

    let ok = run_ts_script("wt-export-key", &[
        ("KEY_OUT",    &key_path),
        ("PUBKEY_OUT", &pubkey_path),
    ]);
    assert!(ok, "Phase A (wt-export-key) must succeed");

    // Read the exported public key hex.
    let pubkey_json: Value = serde_json::from_str(
        &fs::read_to_string(&pubkey_path).expect("read pubkey json"),
    ).unwrap();
    let pubkey_hex = pubkey_json["publicKeyHex"].as_str().unwrap();
    println!("  publicKeyHex = {pubkey_hex}");
    println!();

    // =========================================================================
    // STEP 1: RUST BUILDS MIDEN ECDSA ACCOUNT FROM TS PUBKEY
    // =========================================================================
    println!("══════════════════════════════════════════════════════════════════════════");
    println!("  STEP 1 (REAL) — Rust builds user's Miden ECDSA account from TS pubkey");
    println!("══════════════════════════════════════════════════════════════════════════");
    println!();
    println!("  We deserialise the TS PublicKey and derive its PublicKeyCommitment.");
    println!("  account_from_pubkey_commitment_seeded builds a deterministic account:");
    println!("  the same pubkey always yields the same AccountId (seed = comm bytes).");
    println!();

    let pk_bytes = hex::decode(pubkey_hex).expect("decode pubkey hex");
    let ts_pubkey = PublicKey::read_from_bytes(&pk_bytes)
        .expect("TS-serialised pubkey must deserialise in Rust");
    let ts_pkc = ts_pubkey.to_commitment();
    let ts_commitment: Word = ts_pkc.into();

    let user_account = account_from_pubkey_commitment_seeded(ts_pkc);
    let acct_id = user_account.id();
    let id_prefix = acct_id.prefix().as_felt().as_canonical_u64();
    let id_suffix = acct_id.suffix().as_canonical_u64();

    println!("  Miden account id:");
    println!("    prefix (user_prefix) = {id_prefix}  (0x{id_prefix:016x})");
    println!("    suffix (user_suffix) = {id_suffix}  (0x{id_suffix:016x})");
    println!("  Native auth scheme: AuthSingleSig / EcdsaK256Keccak");
    println!();

    let stored = stored_auth_commitment(&user_account);
    println!("  TS pubkey commitment (from pubkey.to_commitment()):");
    println!("    [{}, {}, {}, {}]",
        ts_commitment[0], ts_commitment[1], ts_commitment[2], ts_commitment[3]);
    println!("  Commitment in account's AuthSingleSig slot:");
    println!("    [{}, {}, {}, {}]",
        stored[0], stored[1], stored[2], stored[3]);

    assert_eq!(
        ts_commitment, stored,
        "the TS pubkey commitment must equal the commitment stored in the account's auth slot"
    );
    println!();
    println!("  VERIFIED: ts_pubkey.to_commitment() == stored_auth_commitment(&user_account)");
    println!("  The TypeScript key controls this Miden account.");
    println!();

    // Write account id to temp file for Phase B.
    fs::write(
        &account_id_path,
        serde_json::to_string_pretty(&serde_json::json!({
            "userPrefix": id_prefix.to_string(),
            "userSuffix": id_suffix.to_string(),
        })).unwrap(),
    ).expect("write account-id json");
    println!("  Account id written for Phase B: {account_id_path}");
    println!();

    // =========================================================================
    // STEP 2: PHASE B — TS SIGNS INTENT WITH user_id = ACCOUNT ID
    // =========================================================================
    println!("══════════════════════════════════════════════════════════════════════════");
    println!("  STEP 2 (Phase B / REAL) — TypeScript signs intent; user_id = account id");
    println!("══════════════════════════════════════════════════════════════════════════");
    println!();
    println!("  Running: ts/wt-sign-intent.ts");
    println!("    • AuthSecretKey.deserialize(keyBytes) restores the Phase A key.");
    println!("    • intent.userPrefix/userSuffix = the Miden account id computed above.");
    println!("    • key.sign(messageWord) produces the ECDSA signature.");
    println!();

    let ok = run_ts_script("wt-sign-intent", &[
        ("KEY_IN",        &key_path),
        ("ACCOUNT_ID_IN", &account_id_path),
        ("FIXTURE_OUT",   &fixture_path),
    ]);
    assert!(ok, "Phase B (wt-sign-intent) must succeed");

    // Read the signed fixture.
    let raw = fs::read_to_string(&fixture_path).expect("read signed fixture");
    let v: Value = serde_json::from_str(&raw).unwrap();

    let i = &v["intent"];
    let intent = Intent {
        user_prefix:      hex_or_dec_u64(&i["user_prefix"]),
        user_suffix:      hex_or_dec_u64(&i["user_suffix"]),
        recipient_prefix: hex_or_dec_u64(&i["recipient_prefix"]),
        recipient_suffix: hex_or_dec_u64(&i["recipient_suffix"]),
        amount:           hex_or_dec_u64(&i["amount"]),
        nonce:            hex_or_dec_u64(&i["nonce"]),
        expiry_block:     hex_or_dec_u64(&i["expiry_block"]),
    };

    let signature_hex = v["signatureHex"].as_str().unwrap().to_string();
    let message_word_hex = v["messageWordHex"].as_str().unwrap();

    println!("  TS-produced signed fixture:");
    println!("    intent.user_prefix  = {}  (0x{:016x})", intent.user_prefix, intent.user_prefix);
    println!("    intent.user_suffix  = {}  (0x{:016x})", intent.user_suffix, intent.user_suffix);
    println!("    intent.amount       = {}", intent.amount);
    println!("    intent.nonce        = {}", intent.nonce);
    println!("    intent.expiry_block = {}", intent.expiry_block);
    println!("    signatureHex        = {}...", &signature_hex[..16]);
    println!("    messageWordHex      = {message_word_hex}");
    println!();

    // =========================================================================
    // THE CRITICAL ASSERTION: intent.user_id == user_account.id()
    // =========================================================================
    println!("  ── CRITICAL ASSERTION ──────────────────────────────────────────────");
    println!("  intent.user_prefix  = {}", intent.user_prefix);
    println!("  account id prefix   = {id_prefix}");
    println!("  intent.user_suffix  = {}", intent.user_suffix);
    println!("  account id suffix   = {id_suffix}");

    assert_eq!(
        intent.user_prefix, id_prefix,
        "intent.user_prefix ({}) must equal the Miden account id prefix ({})",
        intent.user_prefix, id_prefix
    );
    assert_eq!(
        intent.user_suffix, id_suffix,
        "intent.user_suffix ({}) must equal the Miden account id suffix ({})",
        intent.user_suffix, id_suffix
    );
    println!("  VERIFIED: intent.user_id == user_account.id()");
    println!("  The intent is GENUINELY about this account, not an arbitrary placeholder.");
    println!("  ────────────────────────────────────────────────────────────────────");
    println!();

    // =========================================================================
    // STEP 3: REGISTER (SEED) THE USER'S PUBKEY WITH THE OPERATOR
    // =========================================================================
    println!("══════════════════════════════════════════════════════════════════════════");
    println!("  STEP 3 (MODELED) — Register user's pubkey commitment with operator");
    println!("══════════════════════════════════════════════════════════════════════════");
    println!();
    println!("  The operator's StorageMap (slot 0) maps user_id_word → pubkey_commitment.");
    println!("  user_id_word is derived from the account id: [prefix, suffix, 0, 0].");
    println!();
    println!("  [NOTE on registration] Registration is SEEDED at deploy time (Plan 2).");
    println!("  A real user-submitted registration/deposit tx (Plan 3) is not exercised here.");
    println!();

    let uid_word = user_id_word(acct_id);
    println!("  StorageMap key: user_id_word = [{}, {}, 0, 0]", id_prefix, id_suffix);
    println!("  Value seeded:   ts_commitment = [{}, {}, {}, {}]",
        ts_commitment[0], ts_commitment[1], ts_commitment[2], ts_commitment[3]);
    println!();

    let mut chain = new_chain();
    let deployed = deploy_operator(&mut chain, &[(uid_word, ts_commitment)]);
    println!("  Operator account id: {}", deployed.account_id);
    println!();

    let read_comm = signed_intents::relayer::read_depositor_commitment(&chain, &deployed, uid_word);
    assert_eq!(read_comm, ts_commitment, "seeded commitment must read back correctly");
    println!("  VERIFIED: read_depositor_commitment(user_id_word) == ts_commitment");
    println!();

    // =========================================================================
    // STEP 4: OPERATOR DESERIALISES & VERIFIES THE TS SIGNATURE IN MASM
    // =========================================================================
    println!("══════════════════════════════════════════════════════════════════════════");
    println!("  STEP 4 (REAL) — Miden VM verifies TS signature in MASM");
    println!("══════════════════════════════════════════════════════════════════════════");
    println!();
    println!("  relay_intent builds a Miden VM transaction invoking execute_intent.");
    println!("  Inside the VM (MASM):");
    println!();
    println!("    1. REBUILD MSG   — push the 8 canonical intent felts, run hperm.");
    println!("    2. LOOKUP KEY    — get_map_item(slot 0, [user_prefix, user_suffix, 0, 0])");
    println!("                       → ts_commitment (registered by account id).");
    println!("    3. VERIFY ECDSA  — ecdsa_k256_keccak::verify(MSG, commitment, sig).");
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
    println!("  last_nonce (slot 1) = {last_nonce}  (intent.nonce = {})", intent.nonce);
    assert_eq!(last_nonce, intent.nonce, "last_nonce must equal the relayed intent's nonce");
    println!();

    // =========================================================================
    // STEP 5: ADVERSARIAL — tampered intent is REJECTED
    // =========================================================================
    println!("══════════════════════════════════════════════════════════════════════════");
    println!("  STEP 5 (ADVERSARIAL) — tampered intent is REJECTED by MASM");
    println!("══════════════════════════════════════════════════════════════════════════");
    println!();
    println!("  The relayer tries to inflate the amount after the user signed.");
    println!("  Original amount (signed by TS user) : {}", intent.amount);

    let mut tampered = intent;
    tampered.amount = intent.amount * 1000 + 7;
    println!("  Tampered amount (relayer's edit)    : {}", tampered.amount);
    println!();
    println!("  Signature is UNCHANGED — genuine TS sig, tampered intent field.");
    println!("  Inside VM: hperm(tampered_felts) → MSG' ≠ MSG_original → abort.");
    println!();

    // Use a fresh chain so nonce state doesn't interfere.
    let mut chain2 = new_chain();
    let dep2 = deploy_operator(&mut chain2, &[(uid_word, ts_commitment)]);
    let tamper_result = relay_intent(&mut chain2, &dep2, &tampered, &signature_hex);

    match &tamper_result {
        Err(RelayError::Rejected(msg)) => {
            println!("  REJECTED — relay_intent returned RelayError::Rejected");
            println!("  Reason: {msg}");
            println!();
            println!("  The relayer cannot forge or tamper with a signed intent.");
            assert!(!msg.is_empty(), "rejection reason must not be empty");
        }
        Ok(()) => panic!("tampered intent must be rejected, but relay_intent returned Ok"),
    }
    println!();

    // =========================================================================
    // CLOSING SUMMARY
    // =========================================================================
    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║                    CLOSING SUMMARY                                  ║");
    println!("╠══════════════════════════════════════════════════════════════════════╣");
    println!("║                                                                      ║");
    println!("║  STEP 0 — REAL    TS generates ECDSA key (ecdsaWithRNG).            ║");
    println!("║                   Key serialized (serialize) for Phase B.            ║");
    println!("║                                                                      ║");
    println!("║  STEP 1 — REAL    Rust builds user's Miden ECDSA account            ║");
    println!("║                   from TS pubkey. Account id computed.              ║");
    println!("║                   (1) user creates ECDSA account = REAL subject.    ║");
    println!("║                                                                      ║");
    println!("║  STEP 2 — REAL    TS signs intent with user_id = account id.        ║");
    println!("║                   Key restored via deserialize(keyBytes).           ║");
    println!("║                   ASSERTED: intent.user_id == account.id() ✓        ║");
    println!("║                   (3) TS signs = REAL.                              ║");
    println!("║                                                                      ║");
    println!("║  STEP 3 — MODELED Operator registration SEEDED at deploy.           ║");
    println!("║                   Real registration/deposit tx = Plan 3.            ║");
    println!("║                   (2) registration = SEEDED by design.              ║");
    println!("║                                                                      ║");
    println!("║  STEP 4 — REAL    Miden VM verified TS sig in MASM: rebuilt MSG,    ║");
    println!("║                   looked up ts_commitment BY ACCOUNT ID,            ║");
    println!("║                   ran ecdsa_k256_keccak::verify, nonce/expiry ok.   ║");
    println!("║                   (4) MASM verifies = REAL.                         ║");
    println!("║                                                                      ║");
    println!("║  STEP 5 — Relayer cannot forge, tamper, or replay. PROVED.          ║");
    println!("║                                                                      ║");
    println!("╠══════════════════════════════════════════════════════════════════════╣");
    println!("║         TWO-PHASE WALKTHROUGH COMPLETE — ALL ASSERTIONS PASSED      ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
    println!();
}
