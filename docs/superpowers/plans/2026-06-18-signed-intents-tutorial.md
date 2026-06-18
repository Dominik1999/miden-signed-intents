# Signed Intents on Miden — Tutorial Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone, runnable tutorial showing how a user signs an intent off-chain in TypeScript (ECDSA-K256-Keccak) and an account verifies that signature **on-chain in MASM** before acting — so the relaying receiver cannot forge, alter, or replay it.

**Architecture:** A custom MASM account component (`authorizer.masm`) with `NoAuth` at the protocol level exposes one procedure, `execute_intent`. It rebuilds the signed message `Word` from intent fields, verifies the ECDSA signature via the native `ecdsa_k256_keccak::verify` precompile (pubkey + signature supplied through the advice provider by the relayer), enforces a monotonic nonce and a block-height expiry, then records the authorized payload to storage. A Rust relayer (built on MockChain) deploys the account and submits intents; a TypeScript module produces the signed intents. The whole thing is proven by MockChain tests, including adversarial cases.

**Tech Stack:** Rust (`miden-client` / `miden-protocol` 0.14, MockChain test harness), hand-written Miden Assembly (core-lib namespace `miden::core::...`), TypeScript (`@miden-sdk/miden-sdk` 0.14), Markdown (docs recipe template).

## Global Constraints

- **Crate versions:** `miden-client` 0.14, `miden-protocol` 0.14, `miden-client-sqlite-store` not required (MockChain only). Copy exact versions into `Cargo.toml`.
- **TS package:** `@miden-sdk/miden-sdk` 0.14.
- **Signature scheme:** ECDSA-K256-Keccak (`AuthScheme::EcdsaK256Keccak`, scheme id `1`). Produced in TS via `AuthSecretKey.ecdsaWithRNG()`; verified on-chain via `miden::core::crypto::dsa::ecdsa_k256_keccak::verify`.
- **Account protocol auth:** `NoAuth`. All authorization comes from `execute_intent`.
- **Verification location:** on-chain in MASM. Off-chain Rust verification is explicitly NOT the security boundary here.
- **Canonical intent felt order (signed by both sides, byte-exact):**
  `[DOMAIN_TRANSFER, recipient_prefix, recipient_suffix, amount, nonce, expiry_block]`,
  with `DOMAIN_TRANSFER = 1`. Hashed with `Rpo256::hash_elements` → the signed `Word`.
- **On-chain action:** write the authorized payload to a storage slot (`last_authorized`). NOT an asset transfer (kept out to stay focused on verification).
- **Testing:** MockChain only. No live node. No SQLite store.
- **Project location:** new directory `signed-intents/` at repo root. Does not modify `agentic-template/`.

---

## File Structure

```
signed-intents/
├── Cargo.toml                  # single crate, edition 2021, miden deps + dev-deps
├── masm/
│   ├── ecdsa_spike.masm        # Task 2: minimal program pinning the verify ABI
│   └── authorizer.masm         # Task 5: the account component (execute_intent)
├── src/
│   ├── lib.rs                  # re-exports
│   ├── intent.rs               # Intent type + canonical_felts() + intent_word()
│   └── relayer.rs              # build account, build & run the intent transaction
├── tests/
│   ├── spike.rs                # Task 2: on-chain ECDSA verify works
│   ├── golden.rs               # Task 3: canonical word matches the TS golden vector
│   ├── happy_path.rs           # Task 6: valid intent settles, storage advances
│   └── adversarial.rs          # Task 7: tamper / forge / replay / expire => unprovable
├── ts/
│   ├── package.json
│   ├── tsconfig.json
│   ├── signIntent.ts           # Task 4: build felts, hash, ECDSA sign, export hex
│   ├── signIntent.test.ts      # Task 4: determinism + golden vector
│   └── demo.ts                 # Task 4: prints a signed intent for the Rust side
└── TUTORIAL.md                 # Task 8: the recipe-template tutorial
```

**Decision — hand-written MASM, not the Rust `#[account_component]` macro:** the tutorial's whole point is to *show the MASM*, so the account component is authored as `authorizer.masm` and loaded via `AccountComponent::compile(...)`. (The perp repo uses the Rust macro for its contracts; we deliberately diverge here for pedagogy.)

---

## Task 1: Project scaffold

**Files:**
- Create: `signed-intents/Cargo.toml`
- Create: `signed-intents/src/lib.rs`
- Create: `signed-intents/tests/spike.rs` (placeholder smoke test only)

**Interfaces:**
- Produces: a compiling crate named `signed_intents` with the miden dependency set wired, so every later task can `cargo test`.

- [ ] **Step 1: Write `Cargo.toml`**

```toml
[package]
name = "signed-intents"
version = "0.1.0"
edition = "2021"

[lib]
name = "signed_intents"
path = "src/lib.rs"

[dependencies]
miden-protocol = { version = "0.14" }
miden-client = { version = "0.14", features = ["testing"] }
hex = "0.4"
rand = "0.9"

[dev-dependencies]
# MockChain harness lives behind the miden-client `testing` feature in 0.14.
# Task 2 confirms the exact import path during the spike and adjusts if needed.
tokio = { version = "1.46", features = ["rt-multi-thread", "macros"] }
```

- [ ] **Step 2: Write a minimal `src/lib.rs`**

```rust
//! Signed Intents on Miden — tutorial support crate.
//!
//! A user signs a transfer intent off-chain (ECDSA-K256-Keccak); an account
//! verifies that signature on-chain in MASM before recording it.

pub mod intent;
pub mod relayer;
```

> Note: `intent` and `relayer` modules are created in Tasks 3 and 6. For Task 1 only, comment both `pub mod` lines out so the crate compiles, with a `// added in Task 3 / Task 6` marker. Uncomment each as its module lands.

For Task 1, `src/lib.rs` is therefore:

```rust
//! Signed Intents on Miden — tutorial support crate.

// pub mod intent;   // added in Task 3
// pub mod relayer;  // added in Task 6
```

- [ ] **Step 3: Write a placeholder smoke test `tests/spike.rs`**

```rust
#[test]
fn crate_compiles() {
    assert_eq!(2 + 2, 4);
}
```

- [ ] **Step 4: Run it**

Run: `cd signed-intents && cargo test --test spike crate_compiles`
Expected: PASS (and the miden dependencies resolve/download).

- [ ] **Step 5: Commit**

```bash
git add signed-intents/Cargo.toml signed-intents/src/lib.rs signed-intents/tests/spike.rs
git commit -m "chore: scaffold signed-intents tutorial crate"
```

> If `signed-intents/` is not inside a git repo, initialize one first: `git -C signed-intents init` is wrong (it must include the docs). Run `git init` at the location the user designates. Confirm with the user before initializing if unsure.

---

## Task 2: ECDSA verify spike — pin the on-chain ABI

This is the load-bearing discovery task. It proves on-chain ECDSA verification works on 0.14 **and** pins the exact operand-stack/advice layout that `authorizer.masm` (Task 5) depends on. Treat the code below as the research-grounded starting point; if the spike fails to assemble or run, adjust to the real 0.14 ABI **and record the correct ABI in a comment block at the top of `masm/ecdsa_spike.masm`** so Task 5 consumes the verified shape.

**Files:**
- Create: `signed-intents/masm/ecdsa_spike.masm`
- Modify: `signed-intents/tests/spike.rs`

**Interfaces:**
- Produces (documented at the top of `ecdsa_spike.masm` as the verified ABI):
  - the import path for the verify procedure (research value: `miden::core::crypto::dsa::ecdsa_k256_keccak`),
  - operand-stack layout for `verify` (research value: `[PK_COMMITMENT, MSG, ...]`),
  - advice-provider layout (research value: public key = 9 felts, signature = 17 felts),
  - the Rust-side calls that generate a matching key/signature and inject the advice.

- [ ] **Step 1: Write the spike test (failing) `tests/spike.rs`**

Replace the placeholder with a test that: generates an ECDSA-K256-Keccak key in Rust, signs a known `Word`, runs a tiny MASM program that calls `verify`, and asserts the program executes successfully (verify aborts on failure, so a clean run == valid).

```rust
use miden_protocol::Word;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::Felt;

/// Helper: a fixed message Word to sign and verify.
fn sample_message() -> Word {
    Word::from([Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)])
}

#[test]
fn on_chain_ecdsa_verify_accepts_a_valid_signature() {
    // 1. Generate an ECDSA-K256-Keccak key and sign the message.
    let mut rng = rand::rng();
    let key = AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rng);
    let msg = sample_message();
    let signature = key.sign(msg);
    let public_key = key.public_key();

    // 2. Assemble masm/ecdsa_spike.masm, inject pubkey + signature as advice,
    //    push [PK_COMMITMENT, MSG] on the operand stack, execute.
    //    The exact host/advice plumbing is confirmed against the 0.14
    //    MockChain / TransactionExecutor API in this step — see helper below.
    let ok = signed_intents_spike::run_verify(&public_key, msg, &signature);

    assert!(ok, "valid signature must verify on-chain");
}
```

> The `signed_intents_spike::run_verify` helper is written inline in `tests/spike.rs` (a `mod signed_intents_spike { ... }`) during this task. Its body is where the 0.14 transaction/VM execution API is pinned. Use the MockChain transaction path: build a throwaway account whose code is `ecdsa_spike.masm`, build a transaction that calls the spike proc, and provide the signature via the advice inputs. The exact constructor names (`MockChain::new`, `TransactionExecutor`, advice map/stack injection) are confirmed by reading the 0.14 `miden-client` testing module before writing the body. Do NOT guess silently — open the installed crate source (`cargo doc --open` or the `~/.cargo/registry` source) and copy the real signatures.

- [ ] **Step 2: Write `masm/ecdsa_spike.masm`**

```
# ECDSA-K256-Keccak on-chain verify — ABI spike.
#
# VERIFIED ABI (fill in/confirm during this task):
#   import : use miden::core::crypto::dsa::ecdsa_k256_keccak
#   operand: [PK_COMMITMENT, MSG, ...]
#   advice : public key = 9 felts, signature = 17 felts
#   result : no return value; the procedure aborts the tx if invalid.

use miden::core::crypto::dsa::ecdsa_k256_keccak

# Verifies the signature for MSG under the committed public key.
# Inputs (operand stack): [PK_COMMITMENT, MSG]
# Advice: [PK[9], SIG[17]]
export.verify_intent_sig
    exec.ecdsa_k256_keccak::verify
    # => []  (aborts if the signature is invalid)
end
```

- [ ] **Step 3: Run the spike test — expect it to fail first**

Run: `cd signed-intents && cargo test --test spike on_chain_ecdsa_verify_accepts_a_valid_signature -- --nocapture`
Expected initially: FAIL (helper unimplemented / ABI mismatch). Iterate on the helper and the masm until it PASSES. Record any ABI corrections in the masm header comment.

- [ ] **Step 4: Add the negative spike assertion**

Append to `tests/spike.rs`:

```rust
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
```

- [ ] **Step 5: Run both spike tests**

Run: `cd signed-intents && cargo test --test spike`
Expected: both PASS. The negative test confirms `run_verify` surfaces an aborted transaction as `false` (catch the execution error and map it to `false`).

- [ ] **Step 6: Commit**

```bash
git add signed-intents/masm/ecdsa_spike.masm signed-intents/tests/spike.rs
git commit -m "test: pin on-chain ECDSA-K256-Keccak verify ABI with a MockChain spike"
```

---

## Task 3: The canonical intent and its signed Word (Rust side)

**Files:**
- Create: `signed-intents/src/intent.rs`
- Modify: `signed-intents/src/lib.rs` (uncomment `pub mod intent;`)
- Create: `signed-intents/tests/golden.rs`

**Interfaces:**
- Produces:
  - `pub const DOMAIN_TRANSFER: u64 = 1;`
  - `pub struct Intent { pub recipient_prefix: u64, pub recipient_suffix: u64, pub amount: u64, pub nonce: u64, pub expiry_block: u64 }`
  - `impl Intent { pub fn canonical_felts(&self) -> Vec<u64>; pub fn message_word(&self) -> Word; }`
  - free fn `pub fn message_word(felts: &[u64]) -> Word` (hashes via `Rpo256::hash_elements`).

- [ ] **Step 1: Write the failing golden test `tests/golden.rs`**

The golden hex is a placeholder until Step 4 fills it from the first run; this is intentional and is the standard golden-vector bootstrap.

```rust
use signed_intents::intent::{Intent, DOMAIN_TRANSFER};

fn sample_intent() -> Intent {
    Intent {
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
        vec![DOMAIN_TRANSFER, 0x1234, 0x5678, 1_000, 1, 500]
    );
}

#[test]
fn message_word_matches_the_golden_vector() {
    // GOLDEN: copied from the first run of this test (Step 4), then frozen.
    // The TS signer (Task 4) asserts the identical hex.
    const GOLDEN_WORD_HEX: &str = "<FILL FROM FIRST RUN>";
    let i = sample_intent();
    assert_eq!(hex::encode(i.message_word().as_bytes()), GOLDEN_WORD_HEX);
}
```

- [ ] **Step 2: Run it — expect failure**

Run: `cd signed-intents && cargo test --test golden`
Expected: FAIL (module `intent` does not exist).

- [ ] **Step 3: Write `src/intent.rs`**

```rust
//! The transfer intent and its canonical, signable encoding.

use miden_protocol::{Felt, Word, Rpo256};

/// Domain-separation tag — stops a signature for one action type being
/// replayed as another. See the cancel/withdraw tags in the perp repo.
pub const DOMAIN_TRANSFER: u64 = 1;

/// A user's authorization to move `amount` to a recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Intent {
    pub recipient_prefix: u64,
    pub recipient_suffix: u64,
    pub amount: u64,
    /// Per-account strictly-increasing replay guard.
    pub nonce: u64,
    /// Intent is invalid once the chain reaches this block height.
    pub expiry_block: u64,
}

impl Intent {
    /// The exact field elements that are hashed to the signed Word.
    /// MUST match the TypeScript `intentFelts` ordering byte-for-byte.
    pub fn canonical_felts(&self) -> Vec<u64> {
        vec![
            DOMAIN_TRANSFER,
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

/// Hash a canonical felt vector to the signable Word.
pub fn message_word(felts: &[u64]) -> Word {
    let elements: Vec<Felt> = felts.iter().map(|&v| Felt::new(v)).collect();
    Rpo256::hash_elements(&elements).into()
}
```

> Confirm `Rpo256` and `as_bytes()` exact paths against 0.14 (`miden_protocol::Rpo256` per research; if `hash_elements` returns a `Digest`, use `.into()` to `Word` and `Word::as_bytes()` / `to_bytes()` for the hex). Adjust the golden test's serializer to whatever 0.14 exposes (`as_bytes`, `to_bytes`, or `to_hex`).

- [ ] **Step 4: Uncomment the module and capture the golden**

In `src/lib.rs`, change `// pub mod intent;` to `pub mod intent;`. Run the golden test once, read the actual hex from the failure output, paste it into `GOLDEN_WORD_HEX`.

- [ ] **Step 5: Run the tests**

Run: `cd signed-intents && cargo test --test golden`
Expected: both PASS.

- [ ] **Step 6: Commit**

```bash
git add signed-intents/src/intent.rs signed-intents/src/lib.rs signed-intents/tests/golden.rs
git commit -m "feat: canonical transfer intent and signable Word with golden vector"
```

---

## Task 4: TypeScript signer (the user)

**Files:**
- Create: `signed-intents/ts/package.json`
- Create: `signed-intents/ts/tsconfig.json`
- Create: `signed-intents/ts/signIntent.ts`
- Create: `signed-intents/ts/signIntent.test.ts`
- Create: `signed-intents/ts/demo.ts`

**Interfaces:**
- Produces:
  - `export interface IntentInput { recipientPrefix: bigint; recipientSuffix: bigint; amount: bigint; nonce: bigint; expiryBlock: bigint }`
  - `export function intentFelts(i: IntentInput): bigint[]`
  - `export function messageWord(felts: bigint[]): Word`
  - `export function signIntent(key: AuthSecretKey, i: IntentInput): { signatureHex: string; publicKeyHex: string; messageWordHex: string }`
- Consumes: the **same golden word hex** frozen in Task 3 — the TS test asserts it, proving cross-language agreement.

- [ ] **Step 1: Write `package.json`**

```json
{
  "name": "signed-intents-signer",
  "private": true,
  "type": "module",
  "scripts": {
    "test": "vitest run",
    "demo": "tsx demo.ts"
  },
  "dependencies": {
    "@miden-sdk/miden-sdk": "0.14"
  },
  "devDependencies": {
    "tsx": "^4",
    "typescript": "^5",
    "vitest": "^2"
  }
}
```

- [ ] **Step 2: Write `tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ES2022",
    "moduleResolution": "bundler",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  }
}
```

- [ ] **Step 3: Write the failing test `signIntent.test.ts`**

```ts
import { describe, it, expect } from "vitest";
import { intentFelts, messageWord, signIntent } from "./signIntent";
import { AuthSecretKey, PublicKey, Signature } from "@miden-sdk/miden-sdk";

const SAMPLE = {
  recipientPrefix: 0x1234n,
  recipientSuffix: 0x5678n,
  amount: 1000n,
  nonce: 1n,
  expiryBlock: 500n,
};

// Frozen in Task 3 from the Rust golden run. Cross-language agreement check.
const GOLDEN_WORD_HEX = "<SAME HEX AS RUST GOLDEN>";

describe("signed intent", () => {
  it("encodes canonical felts in the agreed order", () => {
    expect(intentFelts(SAMPLE)).toEqual([1n, 0x1234n, 0x5678n, 1000n, 1n, 500n]);
  });

  it("hashes to the same Word as the Rust side", () => {
    const word = messageWord(intentFelts(SAMPLE));
    expect(bytesToHex(word.toBytes())).toBe(GOLDEN_WORD_HEX);
  });

  it("produces a signature that verifies under its own public key", () => {
    const key = AuthSecretKey.ecdsaWithRNG();
    const { signatureHex, publicKeyHex, messageWordHex } = signIntent(key, SAMPLE);
    expect(messageWordHex).toBe(GOLDEN_WORD_HEX);
    const pk = PublicKey.deserialize(hexToBytes(publicKeyHex));
    const sig = Signature.deserialize(hexToBytes(signatureHex));
    expect(pk.verify(messageWord(intentFelts(SAMPLE)), sig)).toBe(true);
  });
});

function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(h: string): Uint8Array {
  const s = h.startsWith("0x") ? h.slice(2) : h;
  return new Uint8Array(s.match(/.{1,2}/g)!.map((x) => parseInt(x, 16)));
}
```

- [ ] **Step 4: Run it — expect failure**

Run: `cd signed-intents/ts && npm install && npm test`
Expected: FAIL (`./signIntent` not found).

- [ ] **Step 5: Write `signIntent.ts`**

```ts
import {
  AuthSecretKey,
  Felt,
  FeltArray,
  Rpo256,
  Signature,
  type Word,
} from "@miden-sdk/miden-sdk";

const DOMAIN_TRANSFER = 1n;

export interface IntentInput {
  recipientPrefix: bigint;
  recipientSuffix: bigint;
  amount: bigint;
  nonce: bigint;
  expiryBlock: bigint;
}

/** Canonical felt vector — MUST match Rust `Intent::canonical_felts`. */
export function intentFelts(i: IntentInput): bigint[] {
  return [
    DOMAIN_TRANSFER,
    i.recipientPrefix,
    i.recipientSuffix,
    i.amount,
    i.nonce,
    i.expiryBlock,
  ];
}

/** Hash the canonical felts to the signable Word. */
export function messageWord(felts: bigint[]): Word {
  const elements = felts.map((v) => new Felt(v));
  return Rpo256.hashElements(new FeltArray(elements));
}

export interface SignResult {
  signatureHex: string;
  publicKeyHex: string;
  messageWordHex: string;
}

/** Sign a transfer intent with an ECDSA-K256-Keccak key. */
export function signIntent(key: AuthSecretKey, i: IntentInput): SignResult {
  const word = messageWord(intentFelts(i));
  const signature: Signature = key.sign(word);
  return {
    signatureHex: bytesToHex(signature.serialize()),
    publicKeyHex: bytesToHex(key.publicKey().serialize()),
    messageWordHex: bytesToHex(word.toBytes()),
  };
}

function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}
```

> Confirm `Word.toBytes()` exists in the 0.14 `.d.ts`; the perp repo uses `signature.serialize()` / `publicKey().serialize()` which are confirmed. If `Word` lacks `toBytes`, derive the hex via `Rpo256.hashElements(...).toHex()` or the SDK's Word serializer and use that same form in the Rust golden test.

- [ ] **Step 6: Run the tests**

Run: `cd signed-intents/ts && npm test`
Expected: all PASS. The Word-hex test is the proof TS and Rust agree.

- [ ] **Step 7: Write `demo.ts`**

```ts
import { AuthSecretKey } from "@miden-sdk/miden-sdk";
import { signIntent, IntentInput } from "./signIntent";

const intent: IntentInput = {
  recipientPrefix: 0x1234n,
  recipientSuffix: 0x5678n,
  amount: 1000n,
  nonce: 1n,
  expiryBlock: 500n,
};

const key = AuthSecretKey.ecdsaWithRNG();
const signed = signIntent(key, intent);

console.log(JSON.stringify({ intent: serializeIntent(intent), ...signed }, null, 2));

function serializeIntent(i: IntentInput) {
  return Object.fromEntries(Object.entries(i).map(([k, v]) => [k, v.toString()]));
}
```

- [ ] **Step 8: Commit**

```bash
git add signed-intents/ts
git commit -m "feat: TypeScript ECDSA signer for transfer intents with cross-language golden check"
```

---

## Task 5: The authorizer account component (MASM)

**Files:**
- Create: `signed-intents/masm/authorizer.masm`

**Interfaces:**
- Consumes: the verified ECDSA verify ABI pinned in `masm/ecdsa_spike.masm` (Task 2).
- Produces: a MASM account component exporting `execute_intent`, with this contract used by the Rust relayer (Task 6):
  - **Operand-stack inputs:** the 6 canonical intent felts in order `[DOMAIN_TRANSFER, recipient_prefix, recipient_suffix, amount, nonce, expiry_block]`.
  - **Advice inputs:** public key (9 felts) + signature (17 felts), pushed by the relayer.
  - **Storage layout:** slot 0 = `owner_pubkey_commitment` (Word), slot 1 = `last_nonce` (Felt in a Word), slot 2 = `last_authorized` (Word = `[recipient_prefix, recipient_suffix, amount, nonce]`).

- [ ] **Step 1: Write `masm/authorizer.masm`**

Use the verified ABI from Task 2 for the hashing, storage, and block-height procedures. The procedure names below (`hash_elements`, storage get/set, `get_block_number`) are research-grounded; confirm exact 0.14 core-lib paths while writing and correct inline. There is no separate unit test for this file — Tasks 6 and 7 exercise it end-to-end.

```
# Authorizer account component.
#
# Verifies a user's ECDSA-K256-Keccak transfer intent ON-CHAIN, then records
# the authorized payload to storage. NoAuth at the protocol level: this
# procedure is the entire authorization boundary.
#
# Operand inputs : [DOMAIN_TRANSFER, recipient_prefix, recipient_suffix,
#                   amount, nonce, expiry_block]
# Advice inputs  : [PK[9], SIG[17]]
# Storage        : slot0 owner_pubkey_commitment (Word)
#                  slot1 last_nonce (Word; nonce in element 0)
#                  slot2 last_authorized (Word)

use miden::core::crypto::dsa::ecdsa_k256_keccak
use miden::core::crypto::hashes::rpo            # confirm path for hash_elements
use miden::core::account                        # storage get/set
use miden::core::tx                             # block number

const.SLOT_OWNER_PK = 0
const.SLOT_LAST_NONCE = 1
const.SLOT_LAST_AUTH = 2
const.DOMAIN_TRANSFER = 1

export.execute_intent
    # Operand: [DOMAIN, r_pre, r_suf, amount, nonce, expiry]
    # --- 0. Sanity: the domain tag must be DOMAIN_TRANSFER ---
    dup
    push.DOMAIN_TRANSFER assert_eq
    # (domain stays on stack as part of the message preimage)

    # --- 1. Rebuild MSG = hash_elements([DOMAIN, r_pre, r_suf, amount, nonce, expiry]) ---
    # Duplicate the 6 inputs into memory / hasher input, then hash.
    # Exact hasher invocation confirmed against 0.14 core lib (Rpo256
    # hash_elements over 6 elements). Result: [MSG (4 felts)] on stack.
    # ... (assemble per the verified hashing ABI) ...
    # => [MSG, DOMAIN, r_pre, r_suf, amount, nonce, expiry]

    # --- 2. Load committed pubkey from storage, verify signature ---
    push.SLOT_OWNER_PK exec.account::get_item   # => [PK_COMMITMENT, MSG, ...]
    exec.ecdsa_k256_keccak::verify              # aborts if invalid => []

    # --- 3. Replay guard: nonce must exceed stored last_nonce ---
    # load nonce (input) and last_nonce (slot1), assert nonce > last
    push.SLOT_LAST_NONCE exec.account::get_item # => [LAST_NONCE_WORD, ...]
    # extract element 0, compare with the intent nonce, assert greater
    # ... gt assertion ...
    # write the new nonce back to slot1
    push.SLOT_LAST_NONCE exec.account::set_item

    # --- 4. Expiry: current block height must be < expiry_block ---
    exec.tx::get_block_number                   # => [block_num, ...]
    # assert block_num < expiry  (lt assertion)

    # --- 5. Record authorized payload to slot2 ---
    # build Word [r_pre, r_suf, amount, nonce] and store it
    push.SLOT_LAST_AUTH exec.account::set_item
    # => []
end
```

> The arithmetic/stack-shuffling between the marked steps is filled in concretely while writing, against the verified core-lib procedure signatures. Do not leave `...` in the committed file — every line must be real MASM that assembles. The comments document intent; the code must be complete. Lean on the existing "How to Use Mappings in Miden Assembly" and "Create Notes in MASM" recipes for storage/stack idioms.

- [ ] **Step 2: Assemble-check the component**

There is no standalone test; assembly is verified when Task 6's account build compiles it. To fail fast, add a temporary Rust check in `tests/spike.rs` that calls `AccountComponent::compile("masm/authorizer.masm" contents, assembler, storage_slots)` and asserts it returns `Ok`. Remove or keep as a smoke test.

Run: `cd signed-intents && cargo test --test spike authorizer_assembles`
Expected: PASS (component assembles).

- [ ] **Step 3: Commit**

```bash
git add signed-intents/masm/authorizer.masm signed-intents/tests/spike.rs
git commit -m "feat: authorizer account component verifies ECDSA intents on-chain in MASM"
```

---

## Task 6: Rust relayer + happy-path test

**Files:**
- Create: `signed-intents/src/relayer.rs`
- Modify: `signed-intents/src/lib.rs` (uncomment `pub mod relayer;`)
- Create: `signed-intents/tests/happy_path.rs`

**Interfaces:**
- Consumes: `Intent` (Task 3), `authorizer.masm` (Task 5), the verify advice layout (Task 2).
- Produces:
  - `pub struct DeployedAuthorizer { /* account id, MockChain handle */ }`
  - `pub fn deploy_authorizer(chain, owner_pubkey: &PublicKey) -> DeployedAuthorizer`
  - `pub fn relay_intent(chain, &DeployedAuthorizer, intent: &Intent, signature_hex: &str, public_key_hex: &str) -> Result<ExecutedTx, RelayError>` — builds the tx that calls `execute_intent`, pushing the 6 intent felts as inputs and decoding `public_key_hex` (9 felts) + `signature_hex` (17 felts) into the advice provider.
  - `pub fn read_last_authorized(chain, &DeployedAuthorizer) -> Word`
  - `pub fn read_last_nonce(chain, &DeployedAuthorizer) -> u64`

- [ ] **Step 1: Write the failing happy-path test `tests/happy_path.rs`**

```rust
use signed_intents::intent::Intent;
use signed_intents::relayer::{deploy_authorizer, relay_intent, read_last_nonce, read_last_authorized};
use miden_protocol::account::auth::AuthSecretKey;

fn sample_intent() -> Intent {
    Intent { recipient_prefix: 0x1234, recipient_suffix: 0x5678, amount: 1000, nonce: 1, expiry_block: 100_000 }
}

#[test]
fn valid_intent_is_authorized_and_recorded() {
    let mut rng = rand::rng();
    let key = AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rng);

    // User signs off-chain.
    let intent = sample_intent();
    let signature = key.sign(intent.message_word());
    let sig_hex = hex::encode(signature.to_bytes());
    let pk_hex = hex::encode(key.public_key().to_bytes());

    // Relayer deploys + submits.
    let mut chain = signed_intents::relayer::new_chain();
    let deployed = deploy_authorizer(&mut chain, &key.public_key());
    relay_intent(&mut chain, &deployed, &intent, &sig_hex, &pk_hex)
        .expect("valid intent must settle");

    // Storage advanced.
    assert_eq!(read_last_nonce(&chain, &deployed), 1);
    let last = read_last_authorized(&chain, &deployed);
    // last == [recipient_prefix, recipient_suffix, amount, nonce]
    assert_eq!(last_authorized_amount(last), 1000);
}

fn last_authorized_amount(w: miden_protocol::Word) -> u64 {
    w[2].as_int() // element 2 = amount; confirm Word indexing in 0.14
}
```

- [ ] **Step 2: Run it — expect failure**

Run: `cd signed-intents && cargo test --test happy_path`
Expected: FAIL (`relayer` module missing).

- [ ] **Step 3: Write `src/relayer.rs`**

Implement against the 0.14 MockChain API confirmed in Task 2's spike helper (reuse that exact plumbing — the spike already pinned how to build an account from MASM, push operand inputs, and inject advice). Structure:

```rust
//! Deploys the authorizer account and relays signed intents against MockChain.

use miden_protocol::{Word, Felt};
use miden_protocol::account::{Account, AccountId};
use miden_protocol::account::auth::PublicKey;
use crate::intent::Intent;

pub struct DeployedAuthorizer {
    pub account_id: AccountId,
    // plus whatever handle the MockChain build returns
}

#[derive(Debug)]
pub enum RelayError {
    /// The transaction failed to prove — i.e. on-chain verification rejected
    /// the intent (bad sig, replay, expiry, tampered field).
    Rejected(String),
}

/// Create a fresh MockChain (confirm constructor name in 0.14).
pub fn new_chain() -> /* MockChain */ { unimplemented!("Task 6: from spike helper") }

/// Build the authorizer account: NoAuth + the authorizer.masm component,
/// with slot0 = owner pubkey commitment, slots 1/2 zeroed.
pub fn deploy_authorizer(chain: &mut /* MockChain */, owner: &PublicKey) -> DeployedAuthorizer {
    // 1. Assemble masm/authorizer.masm into an AccountComponent with 3 storage slots.
    // 2. owner commitment = owner.to_commitment() into slot0.
    // 3. Build account with NoAuth, add to chain.
    unimplemented!("Task 6")
}

/// Build + execute the transaction that calls execute_intent.
pub fn relay_intent(
    chain: &mut /* MockChain */,
    deployed: &DeployedAuthorizer,
    intent: &Intent,
    signature_hex: &str,
    public_key_hex: &str,
) -> Result<(), RelayError> {
    // 1. operand inputs = intent.canonical_felts() as Felts.
    // 2. advice = decode public_key_hex (9 felts) + signature_hex (17 felts),
    //    laid out exactly as the spike proved.
    // 3. build a tx script that `call`s execute_intent on the account.
    // 4. execute against MockChain; map any prove/exec error to RelayError::Rejected.
    unimplemented!("Task 6")
}

pub fn read_last_nonce(chain: &/* MockChain */, d: &DeployedAuthorizer) -> u64 {
    // read slot1 element 0
    unimplemented!("Task 6")
}

pub fn read_last_authorized(chain: &/* MockChain */, d: &DeployedAuthorizer) -> Word {
    // read slot2
    unimplemented!("Task 6")
}
```

> The `unimplemented!` markers above are a skeleton for the executor to fill using the spike's verified API — they MUST be replaced with real code before the test passes. Do not commit `unimplemented!`. The decode of pubkey/sig hex into the advice felt layout is the same decode the spike used; factor it into a shared helper if convenient.

- [ ] **Step 4: Uncomment the module**

In `src/lib.rs`, change `// pub mod relayer;` to `pub mod relayer;`.

- [ ] **Step 5: Run the test**

Run: `cd signed-intents && cargo test --test happy_path`
Expected: PASS. Storage shows nonce=1 and amount=1000.

- [ ] **Step 6: Commit**

```bash
git add signed-intents/src/relayer.rs signed-intents/src/lib.rs signed-intents/tests/happy_path.rs
git commit -m "feat: relayer deploys authorizer and settles valid signed intents on MockChain"
```

---

## Task 7: Adversarial tests (the anti-cheat proof)

**Files:**
- Create: `signed-intents/tests/adversarial.rs`

**Interfaces:**
- Consumes: everything from Task 6 (`deploy_authorizer`, `relay_intent`, `new_chain`).

- [ ] **Step 1: Write the four failing-by-design tests `tests/adversarial.rs`**

Each asserts that a cheating relayer cannot get an invalid intent accepted — `relay_intent` returns `Err(RelayError::Rejected)` (the transaction is unprovable).

```rust
use signed_intents::intent::Intent;
use signed_intents::relayer::{deploy_authorizer, relay_intent, new_chain, RelayError};
use miden_protocol::account::auth::AuthSecretKey;

fn key() -> AuthSecretKey {
    AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rand::rng())
}
fn intent(nonce: u64, expiry: u64) -> Intent {
    Intent { recipient_prefix: 0x1234, recipient_suffix: 0x5678, amount: 1000, nonce, expiry_block: expiry }
}
fn sign(k: &AuthSecretKey, i: &Intent) -> (String, String) {
    let s = k.sign(i.message_word());
    (hex::encode(s.to_bytes()), hex::encode(k.public_key().to_bytes()))
}

#[test]
fn relayer_cannot_tamper_with_the_amount() {
    let k = key();
    let signed = intent(1, 100_000);
    let (sig, pk) = sign(&k, &signed);

    let mut chain = new_chain();
    let dep = deploy_authorizer(&mut chain, &k.public_key());

    // Relayer submits a DIFFERENT amount than was signed.
    let mut tampered = signed;
    tampered.amount = 9_999_999;
    let r = relay_intent(&mut chain, &dep, &tampered, &sig, &pk);
    assert!(matches!(r, Err(RelayError::Rejected(_))), "tampered amount must be rejected");
}

#[test]
fn a_forged_signature_is_rejected() {
    let owner = key();
    let attacker = key();
    let i = intent(1, 100_000);
    let (sig, _) = sign(&attacker, &i);           // signed by the wrong key
    let pk = hex::encode(owner.public_key().to_bytes()); // claims owner's pubkey

    let mut chain = new_chain();
    let dep = deploy_authorizer(&mut chain, &owner.public_key());
    let r = relay_intent(&mut chain, &dep, &i, &sig, &pk);
    assert!(matches!(r, Err(RelayError::Rejected(_))), "forged signature must be rejected");
}

#[test]
fn a_replayed_nonce_is_rejected() {
    let k = key();
    let mut chain = new_chain();
    let dep = deploy_authorizer(&mut chain, &k.public_key());

    let first = intent(1, 100_000);
    let (sig1, pk1) = sign(&k, &first);
    relay_intent(&mut chain, &dep, &first, &sig1, &pk1).expect("first settles");

    // Replay the same nonce (a validly-signed but stale intent).
    let r = relay_intent(&mut chain, &dep, &first, &sig1, &pk1);
    assert!(matches!(r, Err(RelayError::Rejected(_))), "replayed nonce must be rejected");
}

#[test]
fn an_expired_intent_is_rejected() {
    let k = key();
    let mut chain = new_chain();
    let dep = deploy_authorizer(&mut chain, &k.public_key());

    // Expiry in the past relative to the chain's current height.
    let i = intent(1, 1); // expiry_block = 1
    let (sig, pk) = sign(&k, &i);
    // advance the chain past block 1 before relaying (confirm MockChain
    // block-advance API in 0.14).
    signed_intents::relayer::advance_blocks(&mut chain, 5);
    let r = relay_intent(&mut chain, &dep, &i, &sig, &pk);
    assert!(matches!(r, Err(RelayError::Rejected(_))), "expired intent must be rejected");
}
```

- [ ] **Step 2: Add `advance_blocks` to the relayer**

Add to `src/relayer.rs`:

```rust
/// Advance the MockChain by `n` blocks (confirm exact API in 0.14).
pub fn advance_blocks(chain: &mut /* MockChain */, n: u32) {
    unimplemented!("Task 7: MockChain block advance")
}
```

(Replace `unimplemented!` with the real 0.14 call.)

- [ ] **Step 3: Run the tests**

Run: `cd signed-intents && cargo test --test adversarial`
Expected: all four PASS (each cheating attempt is rejected).

- [ ] **Step 4: Run the whole suite**

Run: `cd signed-intents && cargo test`
Expected: spike + golden + happy_path + adversarial all PASS.

- [ ] **Step 5: Commit**

```bash
git add signed-intents/tests/adversarial.rs signed-intents/src/relayer.rs
git commit -m "test: prove the relayer cannot forge, tamper, replay, or expire intents"
```

---

## Task 8: The tutorial document

**Files:**
- Create: `signed-intents/TUTORIAL.md`

**Interfaces:**
- Consumes: the finished code in `signed-intents/` (every snippet is quoted from real, tested files).

- [ ] **Step 1: Write `TUTORIAL.md` following the docs recipe template**

Sections, in order, with real code pulled from the implemented files:

1. **Overview** — one paragraph: what a signed intent is; the user signs off-chain, the account verifies on-chain in MASM; why that bounds the receiver ("the operator can't cheat"). Contrast with off-chain verification.
2. **What we'll cover** — bullets: signed intents; ECDSA-K256-Keccak; on-chain signature verification in an account component; canonical message hashing across TS and MASM; replay (nonce) and expiry (block height); the relayer/advice-provider plumbing.
3. **Prerequisites** — basic MASM and accounts/notes; Rust + the TS SDK installed; links to the Counter, "Create Notes in MASM", and account-component recipes; the stack versions (0.14).
4. **Step 1 — Define the intent** — the canonical felt vector (`src/intent.rs`), why domain tag + nonce + block-height expiry.
5. **Step 2 — Verify it on-chain (MASM)** — walk through `authorizer.masm` (`execute_intent`): rebuild MSG, `ecdsa_k256_keccak::verify`, nonce, expiry, record. Emphasize advice-provider inputs.
6. **Step 3 — Sign the intent (TypeScript)** — `signIntent.ts`; note it's the same ECDSA scheme the perp session keys use; the cross-language golden Word.
7. **Step 4 — Relay and settle (Rust)** — `deploy_authorizer` + `relay_intent`; how pubkey/sig are decoded into advice; reading storage back.
8. **Step 5 — Break it on purpose** — the four adversarial tests; this is the section that demonstrates the security property.
9. **Running the example** — `cd signed-intents && cargo test`; `cd ts && npm test && npm run demo`.
10. **Continue learning** — the perp repo (off-chain operator verification, the trade-off) and miden-x402 (Falcon voucher in a note) as real-world variants; note Falcon512 is the cheaper native alternative when EVM-key compatibility isn't required.

- [ ] **Step 2: Verify every code snippet matches the real files**

Run: `cd signed-intents && cargo test && cd ts && npm test`
Expected: all green. Re-quote any snippet that drifted from the source.

- [ ] **Step 3: Commit**

```bash
git add signed-intents/TUTORIAL.md
git commit -m "docs: signed intents on Miden tutorial (recipe)"
```

---

## Self-Review

**Spec coverage:**
- Off-chain TS ECDSA signing → Task 4. ✓
- On-chain MASM verification in an account → Tasks 2 (ABI) + 5 (component). ✓
- ECDSA-K256-Keccak scheme → constraints + Tasks 2/4/6. ✓
- NoAuth + intent-as-authorization → Task 5/6. ✓
- Canonical intent schema (domain/nonce/expiry, storage-flag action) → Task 3 (Rust) + Task 4 (TS) + Task 5 (MASM record). ✓
- Replay + block-height expiry → Task 5 (MASM) proven in Task 7. ✓
- Happy-path + adversarial tests → Tasks 6 + 7. ✓
- MockChain-only, no live node → constraints + all test tasks. ✓
- Standalone runnable project + recipe markdown → file structure + Task 8. ✓
- Storage-flag action (not P2ID) → Task 5 step 5, Task 6 assertions. ✓

**Placeholder scan:** The plan contains deliberate, clearly-marked discovery points (the Task 2 ABI pinning, the `unimplemented!` skeletons in Task 6/7, the `<FILL FROM FIRST RUN>` golden). These are *executable* gates with explicit instructions to replace before committing — not silent TODOs. Each is paired with a run command that fails until filled. Acceptable because the 0.14 MASM/MockChain ABI genuinely must be confirmed empirically; the plan front-loads that into Task 2 so downstream tasks build on verified shapes rather than guesses.

**Type consistency:** `Intent` fields, `canonical_felts` ordering, `message_word`/`messageWord`, `signIntent` return shape, `relay_intent`/`deploy_authorizer`/`read_last_*` signatures, and `RelayError::Rejected` are used consistently across Rust, TS, and the tests. The 6-felt canonical order is identical in `intent.rs`, `signIntent.ts`, and `authorizer.masm`.

**Known residual risk (flagged, not a gap):** exact 0.14 names for core-lib MASM procs (`hash_elements`, storage get/set, block number), the MockChain constructor/advice-injection API, and `Word`/`Digest` byte-serialization. All are confined to Task 2's spike and reused thereafter; if any differs from the research value, the spike fails loudly and is corrected in one place.
