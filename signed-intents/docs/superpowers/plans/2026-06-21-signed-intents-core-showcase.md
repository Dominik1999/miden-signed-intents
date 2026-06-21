# Signed Intents — Core Showcase Implementation Plan (Plan 1 of N)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reshape the existing (proven) ECDSA-intent verifier into the *operator account* framing with a `user_id`-bound 8-felt intent, and deliver the currently-missing end-to-end test that proves a **TypeScript-produced** signature verifies **inside MASM** through the Rust relayer.

**Architecture:** The existing `authorizer.masm` already verifies an ECDSA-K256-Keccak intent on-chain against a stored pubkey, reconstructs the Poseidon2 message hash with one `hperm`, and runs nonce/expiry guards. Plan 1 keeps that proven core, renames it to the *operator* role, extends the signed message to bind the depositor's account id (`user_id`), rewrites the MASM hashing section in the clearer style the team requested, and adds the TS→Rust→MASM e2e test. Deposit flow, per-depositor storage map, payout P2ID note, and the full tutorial rewrite are deferred to Plans 2–4 (see end).

**Tech Stack:** Rust (miden-protocol 0.14.5, miden-testing 0.14.6, miden-client 0.14), MASM (miden-assembly 0.22.4, Poseidon2 via native `hperm`), TypeScript (@miden-sdk/miden-sdk 0.14, vitest).

## Global Constraints

- **Toolchain pinned:** miden-protocol 0.14.x, miden-core-lib 0.22.4, miden-assembly 0.22.4. Do not bump.
- **Hash:** Poseidon2 only (the VM's `hperm` is Poseidon2; there is no RPO permutation instruction in this toolchain). The off-chain hash MUST be `Poseidon2::hash_elements`.
- **Signed message size:** 8 felts (≤ RATE_WIDTH 8) so the MASM reconstruction stays a **single** `hperm`. `faucet_id` is NOT part of the signed message in Plan 1 (operator config); revisit in Plan 2 only if needed.
- **Cross-language ordering is normative:** Rust `Intent::canonical_felts` and TS `intentFelts` MUST produce byte-identical felt vectors; a golden Poseidon2 digest hex is asserted on both sides.
- **No silent placeholders in MASM:** the MSG-reconstruction task carries an oracle test that asserts the in-VM digest equals `Poseidon2::hash_elements`. If it fails, fix the sponge construction before proceeding — do not adjust the golden to match a wrong digest.
- **Commit message style:** Conventional Commits; no `Co-Authored-By`, no "Generated with" attribution. Never `git push` (user pushes).

## Canonical 8-felt intent (normative)

```
index  field               notes
0      DOMAIN_TRANSFER=1   domain separation tag
1      user_prefix         depositor User Account ID, high word
2      user_suffix         depositor User Account ID, low word
3      recipient_prefix    payout recipient account ID, high word
4      recipient_suffix    payout recipient account ID, low word
5      amount              asset amount
6      nonce               strictly increasing per depositor
7      expiry_block        intent invalid once chain height >= this
```

## File Structure

- `src/intent.rs` — **modify**: 8-felt `Intent` with `user_prefix`/`user_suffix`; `canonical_felts`/`message_word` unchanged in shape.
- `ts/signIntent.ts` — **modify**: 8-felt `IntentInput` + `intentFelts`.
- `masm/operator.masm` — **rename+modify** from `masm/authorizer.masm`: operator framing, 8-felt MSG reconstruction in the clearer style, `extract_digest_from_hashing_output` helper.
- `src/relayer.rs` — **modify**: operator naming; push 8 intent felts; expose the TS-pubkey deploy path.
- `tests/golden.rs` — **modify**: 8-felt sample + new golden hex.
- `ts/signIntent.test.ts` — **modify**: 8-felt sample + new golden hex.
- `tests/e2e_ts_to_masm.rs` — **create**: the new end-to-end test.
- `ts/gen-fixture.ts` — **create**: writes a TS-signed intent fixture for the e2e test.
- `tests/fixtures/` — **create**: holds the generated fixture JSON (git-ignored or committed; see Task 6).

---

### Task 1: Extend the Rust `Intent` to 8 felts with `user_id`

**Files:**
- Modify: `src/intent.rs:10-40`
- Test: `tests/golden.rs:1-37`

**Interfaces:**
- Produces: `Intent { user_prefix: u64, user_suffix: u64, recipient_prefix: u64, recipient_suffix: u64, amount: u64, nonce: u64, expiry_block: u64 }`; `Intent::canonical_felts() -> Vec<u64>` (8 elems, order per the normative table); `Intent::message_word() -> Word`.

- [ ] **Step 1: Update the golden test to the 8-felt sample (will fail to compile)**

In `tests/golden.rs`, replace `sample_intent` and the order assertion:

```rust
fn sample_intent() -> Intent {
    Intent {
        user_prefix: 0xAAAA,
        user_suffix: 0xBBBB,
        recipient_prefix: 0x1234,
        recipient_suffix: 0x5678,
        amount: 1_000,
        nonce: 1,
        expiry_block: 500,
    }
}

#[test]
fn canonical_felts_are_in_the_agreed_order() {
    let i = sample_intent();
    assert_eq!(
        i.canonical_felts(),
        vec![DOMAIN_TRANSFER, 0xAAAA, 0xBBBB, 0x1234, 0x5678, 1_000, 1, 500]
    );
}
```

- [ ] **Step 2: Run it to confirm it fails to compile**

Run: `cargo test --test golden 2>&1 | head -20`
Expected: compile error — `Intent` has no field `user_prefix`.

- [ ] **Step 3: Implement the 8-felt `Intent`**

In `src/intent.rs`, replace the struct and `canonical_felts`:

```rust
/// A user's authorization to move `amount` to a recipient, bound to the
/// depositor's account id so the operator knows whose funds are moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Intent {
    /// Depositor (User Account) id, high word.
    pub user_prefix: u64,
    /// Depositor (User Account) id, low word.
    pub user_suffix: u64,
    pub recipient_prefix: u64,
    pub recipient_suffix: u64,
    pub amount: u64,
    /// Per-depositor strictly-increasing replay guard.
    pub nonce: u64,
    /// Intent is invalid once the chain reaches this block height.
    pub expiry_block: u64,
}

impl Intent {
    /// The exact field elements hashed to the signed Word.
    /// MUST match the TypeScript `intentFelts` ordering byte-for-byte.
    pub fn canonical_felts(&self) -> Vec<u64> {
        vec![
            DOMAIN_TRANSFER,
            self.user_prefix,
            self.user_suffix,
            self.recipient_prefix,
            self.recipient_suffix,
            self.amount,
            self.nonce,
            self.expiry_block,
        ]
    }

    /// The Word the user signs.
    pub fn message_word(&self) -> Word {
        message_word(&self.canonical_felts())
    }
}
```

- [ ] **Step 4: Run the order test (golden hex test still wrong — expected)**

Run: `cargo test --test golden canonical_felts_are_in_the_agreed_order 2>&1 | tail -5`
Expected: PASS for the order test.

- [ ] **Step 5: Capture the new golden hex and pin it**

Temporarily make the golden test print the hex, then freeze it:

Run: `cargo test --test golden message_word_matches_the_golden_vector -- --nocapture 2>&1 | grep -i 'left\|0x\|[0-9a-f]\{64\}' | head`
(The assertion will fail and print the actual hex.) Copy the 64-char `left` hex into `GOLDEN_WORD_HEX` in `tests/golden.rs`, replacing the old value. Re-run:

Run: `cargo test --test golden 2>&1 | tail -5`
Expected: PASS (both tests).

- [ ] **Step 6: Commit**

```bash
git add src/intent.rs tests/golden.rs
git commit -m "feat: bind depositor user_id into the 8-felt signed intent"
```

---

### Task 2: Mirror the 8-felt intent in the TypeScript signer

**Files:**
- Modify: `ts/signIntent.ts:10-33`
- Test: `ts/signIntent.test.ts:6-37`

**Interfaces:**
- Consumes: golden hex from Task 1 (Rust is the source of truth).
- Produces: `IntentInput { userPrefix, userSuffix, recipientPrefix, recipientSuffix, amount, nonce, expiryBlock }` (all `bigint`); `intentFelts(i) -> bigint[]` (8 elems); `signIntent(key, i) -> { signatureHex, publicKeyHex, messageWordHex }` (unchanged shape).

- [ ] **Step 1: Update the test sample + golden to match Task 1 (will fail)**

In `ts/signIntent.test.ts`, replace `SAMPLE`, `GOLDEN_WORD_HEX`, and the order assertion:

```ts
const SAMPLE = {
  userPrefix: 0xAAAAn,
  userSuffix: 0xBBBBn,
  recipientPrefix: 0x1234n,
  recipientSuffix: 0x5678n,
  amount: 1000n,
  nonce: 1n,
  expiryBlock: 500n,
};

// Frozen from the Rust golden run in Task 1 (Poseidon2). Paste the SAME hex.
const GOLDEN_WORD_HEX = "<PASTE_THE_TASK_1_GOLDEN_HEX>";
```

And the order test body:

```ts
expect(intentFelts(SAMPLE)).toEqual([1n, 0xAAAAn, 0xBBBBn, 0x1234n, 0x5678n, 1000n, 1n, 500n]);
```

- [ ] **Step 2: Run it to confirm it fails (type error on new fields)**

Run: `cd ts && npm test 2>&1 | tail -20`
Expected: FAIL — `IntentInput` lacks `userPrefix`, etc.

- [ ] **Step 3: Implement the 8-felt `IntentInput` + `intentFelts`**

In `ts/signIntent.ts`:

```ts
export interface IntentInput {
  userPrefix: bigint;
  userSuffix: bigint;
  recipientPrefix: bigint;
  recipientSuffix: bigint;
  amount: bigint;
  nonce: bigint;
  expiryBlock: bigint;
}

/** Canonical felt vector — MUST match Rust `Intent::canonical_felts`.
 *  Order: [DOMAIN_TRANSFER, userPrefix, userSuffix, recipientPrefix,
 *          recipientSuffix, amount, nonce, expiryBlock]
 */
export function intentFelts(i: IntentInput): bigint[] {
  return [
    DOMAIN_TRANSFER,
    i.userPrefix,
    i.userSuffix,
    i.recipientPrefix,
    i.recipientSuffix,
    i.amount,
    i.nonce,
    i.expiryBlock,
  ];
}
```

- [ ] **Step 4: Run the test to verify cross-language agreement**

Run: `cd ts && npm test 2>&1 | tail -10`
Expected: PASS (all 3) — proving TS Poseidon2 of the 8 felts equals the Rust golden hex.

- [ ] **Step 5: Commit**

```bash
git add ts/signIntent.ts ts/signIntent.test.ts
git commit -m "feat: mirror the 8-felt user_id intent in the TypeScript signer"
```

---

### Task 3: Rename authorizer → operator MASM and rewrite the hashing section in the clearer style

**Files:**
- Rename: `masm/authorizer.masm` → `masm/operator.masm` (via `git mv`)
- Modify: the MSG-reconstruction section to absorb 8 felts (single `hperm`) and use a named digest-extract helper.
- Test: `tests/authorizer.rs` (the existing oracle/assemble test) — update the include path + 8-felt push.

**Interfaces:**
- Consumes: 8 operand felts in canonical order, pushed by the tx script (Task 4).
- Produces: `operator.masm` exporting `execute_intent` with operand input `[DOMAIN, user_pre, user_suf, r_pre, r_suf, amount, nonce, expiry, pad(8)]`, advice `[PK[9], SIG[17]]`. Verifies vs the stored operator key slot; nonce/expiry guards; records the authorized payload.

- [ ] **Step 1: Rename the file and update includes**

```bash
git mv masm/authorizer.masm masm/operator.masm
```
In `src/relayer.rs` and `tests/authorizer.rs`, change `include_str!("../masm/authorizer.masm")` → `include_str!("../masm/operator.masm")` and the component path string `"signed_intents::authorizer"` → `"signed_intents::operator"` (keep both sides consistent; grep to confirm none missed).

Run: `grep -rn "authorizer.masm\|signed_intents::authorizer" src tests`
Expected: no remaining references after the edits.

- [ ] **Step 2: Update the oracle test to push 8 felts (will fail / not assemble)**

In `tests/authorizer.rs`, find where the test pushes the canonical felts into the tx script and extend it to the 8-felt order: `push.{expiry}.{nonce}.{amount}.{r_suf}.{r_pre}.{user_suf}.{user_pre}.{domain}` and supply `user_pre`/`user_suf` from the sample intent. (Exact lines depend on the current test body; mirror Task 4's tx-script format string.)

Run: `cargo test --test authorizer 2>&1 | tail -20`
Expected: FAIL — MASM still builds a 6-element sponge / wrong digest.

- [ ] **Step 3: Rewrite the MSG-reconstruction + digest extraction in the clearer style**

In `masm/operator.masm`, replace the `HASH_CAP_6` const and Phase-1 block with the 8-felt version using the team's requested style. Header const:

```
# Sponge capacity initializer for an 8-element input: 8 % RATE_WIDTH(8) = 0.
const NUMBER_OF_HASHED_ELEMENTS_CAP = 0
```

Stash + reconstruct (operand stack in: `[domain, user_pre, user_suf, r_pre, r_suf, amount, nonce, expiry, pad...]`):

```
    # --- 1. Rebuild MSG = Poseidon2::hash_elements(intent_felts[0..8]). ---
    # The 8 operand felts exactly fill the sponge rate (RATE_WIDTH = 8), so this is a
    # single permutation. Build the 12-element state (top->down):
    #   [m0,m1,m2,m3, m4,m5,m6,m7, cap,0,0,0]   where cap = 8 % 8 = 0.
    push.0 push.0 push.0 push.NUMBER_OF_HASHED_ELEMENTS_CAP
    # => [cap,0,0,0, m0..m7, pad...]   (capacity word currently on top)
    movdnw.2
    # => [m0,m1,m2,m3, m4,m5,m6,m7, cap,0,0,0, pad...]
    hperm
    # => [R0, R1, C, pad...]
    exec.extract_digest_from_hashing_output
    # => [MSG(4), pad...]
```

Replace `squeeze_rate0` with the clearer-named helper at the bottom of the file:

```
#! Returns the rate-0 word (the 4-element digest) of a Poseidon2 sponge state.
#! Inputs: [R0, R1, C, ...]   Outputs: [R0, ...]   Invocation: exec
proc extract_digest_from_hashing_output
    swapw.2 dropw dropw
    # => [R0, ...]
end
```

**Note (stashing):** the values needed after hashing (recipient, amount, nonce, expiry) must still be stashed to locals BEFORE `hperm` consumes the operand felts, exactly as the current file does — extend the existing `loc_storew_le` stash to carry `user_pre/user_suf` if a later step needs them (Plan 1 records recipient/amount/nonce only, so the existing stash layout may be reused; keep `@locals(8)`). Document each local slot with a one-line comment per the team's style.

- [ ] **Step 4: Run the oracle test — the in-VM digest must equal Rust Poseidon2**

Run: `cargo test --test authorizer 2>&1 | tail -20`
Expected: PASS. The oracle test reconstructs MSG in-VM and the ECDSA verify only succeeds if it equals the signed `Poseidon2::hash_elements`. If it FAILS: the sponge construction is wrong (likely the capacity or the full-block padding for len==8). Fix the MASM — do NOT change the golden. If len==8 turns out to require a second permutation (empty padding block), add the second `hperm` over a zeroed rate and re-extract; re-run.

- [ ] **Step 5: Commit**

```bash
git add masm/operator.masm src/relayer.rs tests/authorizer.rs
git commit -m "refactor: operator MASM verifier with 8-felt single-hperm hashing, clearer style"
```

---

### Task 4: Update the relayer to push 8 intent felts under the operator framing

**Files:**
- Modify: `src/relayer.rs:33-37` (slot/const names), `:74-117` (`deploy_authorizer` → `deploy_operator`), `:135-231` (`relay_intent` tx-script felts).

**Interfaces:**
- Consumes: `Intent` (8-felt, Task 1); a TS or Rust `PublicKey`.
- Produces: `deploy_operator(chain, owner_pubkey) -> DeployedOperator { account_id }`; `relay_intent(chain, &DeployedOperator, &Intent, signature_hex) -> Result<(), RelayError>`; `read_last_nonce`, `read_last_authorized` unchanged in behavior.

- [ ] **Step 1: Rename consts + deploy fn + handle struct**

Rename `OWNER_PK_SLOT`→`OPERATOR_KEY_SLOT` value `"signed_intents::operator::owner_pubkey_commitment"`, and the two others to `signed_intents::operator::last_nonce` / `::last_authorized`. Rename `DeployedAuthorizer`→`DeployedOperator`, `deploy_authorizer`→`deploy_operator`. Update `tests/*` references accordingly (grep).

- [ ] **Step 2: Extend the tx-script felt push to 8 fields (will fail to compile)**

In `relay_intent`, replace the `push` line and format args:

```rust
let felts = intent.canonical_felts(); // 8 elements
let tx_script_code = format!(
    r#"
    use signed_intents::operator->operator
    use miden::core::sys

    begin
        push.{expiry}.{nonce}.{amount}.{r_suf}.{r_pre}.{user_suf}.{user_pre}.{domain}
        # => [domain, user_pre, user_suf, r_pre, r_suf, amount, nonce, expiry, pad...]
        call.operator::execute_intent
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
```

- [ ] **Step 3: Build the crate**

Run: `cargo build 2>&1 | tail -20`
Expected: PASS (no unresolved names; the format string references all 8 felts).

- [ ] **Step 4: Run the existing happy-path + adversarial suites against the reshaped relayer**

Run: `cargo test 2>&1 | tail -30`
Expected: the suites referencing the old 6-felt sample now use the 8-felt `Intent`; fix each test's `Intent { .. }` literal to include `user_prefix`/`user_suffix` until green. (These literal updates are mechanical; do them as the compiler points them out.)

- [ ] **Step 5: Commit**

```bash
git add src/relayer.rs tests/happy_path.rs tests/adversarial.rs
git commit -m "refactor: relay 8-felt operator intents (user_id-bound)"
```

---

### Task 5: End-to-end test — a TypeScript-signed intent verifies inside MASM

**Files:**
- Create: `ts/gen-fixture.ts`
- Create: `tests/e2e_ts_to_masm.rs`
- Create: `tests/fixtures/.gitkeep`
- Modify: `ts/package.json` (add a `gen-fixture` script)

**Interfaces:**
- Consumes: `deploy_operator`, `relay_intent`, `read_last_nonce` (Task 4); `signIntent` (Task 2).
- Produces: a committed proof that a TS-produced `{publicKeyHex, signatureHex}` for the 8-felt intent is accepted by the operator MASM via the Rust relayer (cross-SDK serialization + cross-language hash agreement, end to end).

- [ ] **Step 1: Write the TS fixture generator**

`ts/gen-fixture.ts`:

```ts
import { writeFileSync, mkdirSync } from "node:fs";
import { AuthSecretKey } from "@miden-sdk/miden-sdk";
import { signIntent, type IntentInput } from "./signIntent.js";

const intent: IntentInput = {
  userPrefix: 0xAAAAn,
  userSuffix: 0xBBBBn,
  recipientPrefix: 0x1234n,
  recipientSuffix: 0x5678n,
  amount: 1000n,
  nonce: 1n,
  expiryBlock: 500n,
};

const key = AuthSecretKey.ecdsaWithRNG();
const { signatureHex, publicKeyHex, messageWordHex } = signIntent(key, intent);

mkdirSync("../tests/fixtures", { recursive: true });
writeFileSync(
  "../tests/fixtures/intent_signed.json",
  JSON.stringify(
    {
      intent: {
        user_prefix: "0xAAAA", user_suffix: "0xBBBB",
        recipient_prefix: "0x1234", recipient_suffix: "0x5678",
        amount: 1000, nonce: 1, expiry_block: 500,
      },
      signatureHex, publicKeyHex, messageWordHex,
    },
    null, 2,
  ),
);
console.log("wrote tests/fixtures/intent_signed.json");
```

Add to `ts/package.json` scripts: `"gen-fixture": "tsx gen-fixture.ts"`.

- [ ] **Step 2: Generate the fixture**

Run: `cd ts && npm run gen-fixture && cat ../tests/fixtures/intent_signed.json | head`
Expected: file written; `messageWordHex` equals the Task 1 golden hex.

- [ ] **Step 3: Write the failing e2e test**

`tests/e2e_ts_to_masm.rs`:

```rust
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
```

Add `serde_json` to `[dev-dependencies]` in `Cargo.toml` if absent.

- [ ] **Step 4: Run it to verify it fails first (fixture-then-pass)**

Run: `rm -f tests/fixtures/intent_signed.json && cargo test --test e2e_ts_to_masm 2>&1 | tail -10`
Expected: FAIL with the "run gen-fixture first" message — proving the test actually depends on the TS output.

- [ ] **Step 5: Generate the fixture and run the test green**

Run: `cd ts && npm run gen-fixture && cd .. && cargo test --test e2e_ts_to_masm 2>&1 | tail -10`
Expected: PASS — a TS signature verified inside MASM end to end.

- [ ] **Step 6: Commit**

```bash
git add ts/gen-fixture.ts ts/package.json tests/e2e_ts_to_masm.rs tests/fixtures/.gitkeep Cargo.toml
git commit -m "test: end-to-end TS-signed intent verified inside the operator MASM"
```

---

### Task 6: Add a wrong-depositor adversarial case + full-suite green

**Files:**
- Modify: `tests/adversarial.rs`

**Interfaces:**
- Consumes: Task 4's `deploy_operator`/`relay_intent`.

- [ ] **Step 1: Write the wrong-depositor test (signature valid, but for a different user_id)**

Append to `tests/adversarial.rs` a test that signs an intent with `user_prefix = X`, then relays the SAME signature with an intent whose `user_prefix = Y != X`; assert `relay_intent` returns `RelayError::Rejected` (the reconstructed MSG differs, so ECDSA verify aborts). Mirror the structure of the existing `relayer_cannot_tamper_with_the_amount` test, changing the mutated field to `user_prefix`.

- [ ] **Step 2: Run the full suite**

Run: `cargo test 2>&1 | tail -20 && cd ts && npm test 2>&1 | tail -6`
Expected: ALL Rust tests + all TS tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/adversarial.rs
git commit -m "test: reject an intent replayed against a different depositor (user_id binding)"
```

---

## Self-Review (completed during authoring)

- **Spec coverage:** §4 message/serialization → Tasks 1–2 (8-felt, golden vector). §6 Phase D in-MASM verification → Task 3 (the core showcase). §7 who-verifies-what → Tasks 4–5. §10 NEW TS→MASM e2e test → Task 5. §10 wrong-depositor adversarial → Task 6. §9 tamper/forge/replay/expire → preserved via Task 4 step 4. **Deferred (own plans, see below):** §3/§6 deposit + User Account native ECDSA auth; §3 per-depositor storage *map*; §6 payout P2ID note; §11 spike for those; §9 over-withdrawal; §11 tutorial rewrite.
- **Placeholder scan:** one intentional fill-in — `GOLDEN_WORD_HEX` in Task 2 is pasted from the Task 1 run (computed value, not inventable offline). The TS fixture↔Rust field names are consistent (`user_prefix`, etc.).
- **Type consistency:** `deploy_operator`/`DeployedOperator`/`relay_intent`/`Intent` field names match across Tasks 1, 4, 5.

## Follow-on plans (not in scope here)

- **Plan 2 — Deposit & accounts:** User Account built with `Auth::BasicAuth { EcdsaK256Keccak }`; a deposit tx authorized by that native auth; per-depositor storage **map** keyed by `user_id` (replaces the single key slot). Carries the §11 feasibility spike (storage map read in MASM; user-account ECDSA-auth deposit).
- **Plan 3 — Payout action:** replace record-to-storage with emitting a **P2ID note** derived from the verified felts; over-withdrawal guard against the tracked balance. Spike: note creation from within the operator tx on 0.14.
- **Plan 4 — Tutorial rewrite:** restructure `TUTORIAL.md` around the operator/deposit flow in the clearer MASM style, with the security section (what's signed, replay, message uniqueness, account binding, common mistakes).

## Execution Handoff

See the message accompanying this plan for execution options.
