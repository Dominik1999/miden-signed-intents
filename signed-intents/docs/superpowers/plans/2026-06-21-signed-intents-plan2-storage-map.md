# Signed Intents — Per-Depositor Map + Native-ECDSA User Account (Plan 2 of N)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the operator account's single hardcoded key slot with a per-depositor `StorageMap` (keyed by the depositor's account id), look the depositor's key up in MASM via `get_map_item`, and make each depositor a *real* native-ECDSA-auth account whose auth key provably equals the key that signs its intents — so the system supports multiple depositors and the "key belongs to the account" binding is concrete.

**Architecture:** Builds directly on Plan 1's operator verifier (commits up to `dcd91b7`). The 8-felt intent already carries the depositor's account id (`user_prefix`/`user_suffix`) — Plan 1 added it precisely so Plan 2 can route by it. The operator's verify path changes from "load the one stored key (`get_item`)" to "look up *this depositor's* key in a map (`get_map_item`) by the intent's `user_id`". Registration is **modeled simply** (the operator's map is seeded at deploy with each depositor's pubkey commitment); the binding is real because each depositor account's native auth component (`AuthSingleSig` over `EcdsaK256Keccak`) commits to the *same* key we seed and sign with. The relayer still drives the **operator** account (NoAuth/IncrNonce); native ECDSA auth only ever signs a user's *own* txs, which Plan 2 does not execute (deferred to Plan 3's real deposit). All of this is proven feasible by the Plan 2 spike (commit `2caafaf`, report `.git/sdd/plan2-spike-report.md`).

**Tech Stack:** Rust (miden-protocol 0.14.5, miden-testing 0.14.6, **miden-standards 0.14.5** — newly added for `AuthSingleSig`), MASM (miden-assembly 0.22.4), TypeScript (unchanged from Plan 1).

## Global Constraints

- **Toolchain pinned:** miden-protocol 0.14.x, miden-testing 0.14.6, miden-assembly 0.22.4, miden-core-lib 0.22.4, miden-standards 0.14.5. Do not bump.
- **New dependency:** add `miden-standards = { version = "0.14" }` to `[dependencies]` (or `[dev-dependencies]` if only tests use it). Needed for `AuthSingleSig::new(pub_key_commitment, AuthScheme)`. This is the canonical 0.14 component crate.
- **Map key is the RAW user-id word, hashed by neither side.** Seed with `StorageMapKey::new([user_prefix, user_suffix, 0, 0])`; in MASM pass the raw `[user_prefix, user_suffix, 0, 0]` word to `get_map_item`. The kernel hashes internally (`hash_elements`). Do NOT pre-hash on either side. (Spike Q1 gotcha.)
- **`user_id` is the depositor's real account id.** `intent.user_prefix`/`user_suffix` MUST equal the depositor account's `AccountId` prefix/suffix felts, so the map key and the binding line up.
- **Intent shape is unchanged from Plan 1** (8 felts, same Poseidon2 golden). The MASM hashing/verify/nonce/expiry logic is preserved; only the *key source* changes (single slot → map lookup) plus stashing `user_id` across the hash.
- **The relayer still drives the operator account; the user account runs no tx in Plan 2.** Do not attempt to make a relayer author a tx as the user account (it would need the user's secret key). Native-auth user txs are Plan 3.
- **Verification:** every MASM change is guarded by the existing oracle/verify-as-tx tests; never tune a golden to a wrong digest.
- **Commit style:** Conventional Commits; no `Co-Authored-By`/attribution; never `git push` (user decides).

## File Structure

- `Cargo.toml` — **modify**: add `miden-standards` dependency.
- `src/user_account.rs` — **create**: helper to build a native-ECDSA-auth depositor account from a held `AuthSecretKey`, exposing `(Account, AuthSecretKey, pubkey_commitment)`; plus a binding assertion helper.
- `src/lib.rs` — **modify**: `pub mod user_account;`
- `src/relayer.rs` — **modify**: operator account gets a `StorageMap` slot (seeded per depositor) instead of the single key slot; `deploy_operator` takes a list of `(user_id_word, pubkey_commitment)`.
- `masm/operator.masm` — **modify**: stash `user_id` across the hash; replace the single-key `get_item` load with a `get_map_item` lookup keyed by the intent's `user_id`.
- `tests/multi_depositor.rs` — **create**: two distinct depositors; each authorizes only its own `user_id`; cross-use rejected; binding asserted.

---

### Task 1: Native-ECDSA depositor account from a held key + binding assertion

**Files:**
- Modify: `Cargo.toml` (add `miden-standards`)
- Create: `src/user_account.rs`
- Modify: `src/lib.rs`
- Test: `tests/multi_depositor.rs` (first test only; file created here)

**Interfaces:**
- Produces: `pub struct Depositor { pub account: Account, pub key: AuthSecretKey, pub commitment: Word }` and `pub fn new_depositor(seed: u64) -> Depositor` — builds an account whose **native auth component is `AuthSingleSig` over an `EcdsaK256Keccak` key we generate and hold**, distinct per `seed`. `commitment == key.public_key().to_commitment().into()`.
- Produces: `pub fn user_id_word(account_id: AccountId) -> Word` → `[prefix, suffix, 0, 0]` (the map key / intent user_id).

- [ ] **Step 1: Add the dependency**

In `Cargo.toml` add under `[dependencies]`:
```toml
miden-standards = { version = "0.14" }
```
Run: `cargo build 2>&1 | tail -5` → expect success (downloads/links miden-standards).

- [ ] **Step 2: Write the failing binding test**

Create `tests/multi_depositor.rs`:
```rust
use signed_intents::user_account::{new_depositor, user_id_word};

#[test]
fn depositor_account_auth_key_equals_its_signing_key() {
    let d = new_depositor(1);
    // The account's stored auth-key commitment must equal the commitment of the key we hold
    // (and will sign intents with). This is the "key belongs to the account" binding.
    let stored = signed_intents::user_account::stored_auth_commitment(&d.account);
    assert_eq!(stored, d.commitment);
    // user_id word is the account id as [prefix, suffix, 0, 0].
    let _ = user_id_word(d.account.id());
}
```

- [ ] **Step 3: Run it — fails to compile (module missing)**

Run: `cargo test --test multi_depositor 2>&1 | tail -15`
Expected: unresolved `signed_intents::user_account`.

- [ ] **Step 4: Implement `src/user_account.rs`**

Discover-and-implement (the spike pinned the pieces; the exact `AuthSingleSig` import path and the "read stored auth-key commitment" accessor are confirmed here):
- `AuthSingleSig::new(pub_key: PublicKeyCommitment, auth_scheme: AuthScheme)` lives in `miden_standards::account::auth` (confirm exact path with `cargo doc`/grep of `~/.cargo/registry/src/.../miden-standards-0.14.5/src/account/auth/singlesig.rs:51`); `.into()` yields an `AccountComponent`.
- Generate the key: `AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rng)` (vary `rng` by `seed` so depositors differ) — see `miden-protocol-0.14.5/src/account/auth.rs:139`.
- `commitment: Word = key.public_key().to_commitment().into()`.
- Build the account: `AccountBuilder::new(<seeded rand>).storage_mode(AccountStorageMode::Public).with_auth_component(AuthSingleSig::new(commitment_as_pkc, AuthScheme::EcdsaK256Keccak).into()).build_existing()?`. (No app component needed — this is a passive identity in Plan 2.)
- `stored_auth_commitment(account: &Account) -> Word`: read the auth component's stored pubkey-commitment value slot from `account.storage()`. Determine the slot name from `AuthSingleSig` (its storage layout) — confirm via the singlesig component metadata; the value equals `commitment`.

```rust
//! Builds a depositor account whose NATIVE authentication is an ecdsa_k256_keccak key we hold,
//! so the same key both controls the account and signs its intents (Plan 2 binding).
use miden_protocol::account::auth::{AuthScheme, AuthSecretKey, PublicKeyCommitment};
use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountStorageMode};
use miden_protocol::Word;
use miden_standards::account::auth::AuthSingleSig; // confirm exact path in Step 4
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub struct Depositor {
    pub account: Account,
    pub key: AuthSecretKey,
    pub commitment: Word,
}

pub fn new_depositor(seed: u64) -> Depositor {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let key = AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rng);
    let pkc: PublicKeyCommitment = key.public_key().to_commitment();
    let commitment: Word = pkc.into();
    let account = AccountBuilder::new(rand::random())
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(AuthSingleSig::new(pkc, AuthScheme::EcdsaK256Keccak).into())
        .build_existing()
        .expect("depositor account must build");
    Depositor { account, key, commitment }
}

pub fn user_id_word(account_id: AccountId) -> Word {
    Word::from([account_id.prefix().as_felt(), account_id.suffix(), 0u32.into(), 0u32.into()])
}

/// Reads the auth component's stored pubkey commitment from the account storage.
pub fn stored_auth_commitment(account: &Account) -> Word {
    // Confirm the AuthSingleSig pubkey slot name in Step 4 and read it via account.storage().
    // The returned Word equals the depositor's `commitment`.
    todo!("read AuthSingleSig pubkey slot — pin slot name from miden-standards singlesig metadata")
}
```
Replace the `todo!` with the real slot read once the slot name is confirmed (grep `miden-standards-0.14.5/src/account/auth/singlesig.rs` for its storage slot name/`StorageSlotName`). If the account-id felt accessors differ (`prefix().as_felt()` / `suffix()`), adjust to the real `AccountId` API.

Add `pub mod user_account;` to `src/lib.rs`.

- [ ] **Step 5: Run the test green**

Run: `cargo test --test multi_depositor depositor_account_auth_key_equals_its_signing_key 2>&1 | tail -10`
Expected: PASS — the account's stored auth-key commitment equals the held key's commitment.

- [ ] **Step 6: Commit**
```bash
git add Cargo.toml Cargo.lock src/user_account.rs src/lib.rs tests/multi_depositor.rs
git commit -m "feat: native-ecdsa depositor account whose auth key equals its signing key"
```

---

### Task 2: Operator account holds a per-depositor StorageMap (seeded registration)

**Files:**
- Modify: `src/relayer.rs` (the operator account construction in `deploy_operator`)

**Interfaces:**
- Consumes: `user_id_word` (Task 1); `Depositor.commitment`.
- Produces: `deploy_operator(chain, depositors: &[(Word /*user_id_word*/, Word /*pubkey_commitment*/)]) -> DeployedOperator`. Internally builds a `StorageMap` slot `DEPOSITOR_KEYS` seeded with one entry per depositor; keeps the existing `last_nonce`/`last_authorized` value slots.

- [ ] **Step 1: Write the failing seed-and-read-back test**

Add to `tests/multi_depositor.rs`:
```rust
#[test]
fn operator_map_is_seeded_with_each_depositor_commitment() {
    use signed_intents::relayer::{new_chain, deploy_operator, read_depositor_commitment};
    let a = new_depositor(1);
    let b = new_depositor(2);
    let mut chain = new_chain();
    let entries = [
        (user_id_word(a.account.id()), a.commitment),
        (user_id_word(b.account.id()), b.commitment),
    ];
    let dep = deploy_operator(&mut chain, &entries);
    assert_eq!(read_depositor_commitment(&chain, &dep, user_id_word(a.account.id())), a.commitment);
    assert_eq!(read_depositor_commitment(&chain, &dep, user_id_word(b.account.id())), b.commitment);
}
```
(`read_depositor_commitment` reads the committed operator account's map slot by key — add it alongside `read_last_nonce`.)

- [ ] **Step 2: Run it — fails (signature mismatch / missing fn)**

Run: `cargo test --test multi_depositor operator_map_is_seeded 2>&1 | tail -15`
Expected: `deploy_operator` arity mismatch and `read_depositor_commitment` missing.

- [ ] **Step 3: Implement the map-backed operator**

In `src/relayer.rs`:
- Add `use miden_protocol::account::{StorageMap, StorageMapKey};`
- Replace `OPERATOR_KEY_SLOT` (single value slot) with `DEPOSITOR_KEYS_SLOT = "signed_intents::operator::depositor_keys"`.
- In `deploy_operator(chain, depositors: &[(Word, Word)])`:
```rust
let map = StorageMap::with_entries(
    depositors.iter().map(|(uid, comm)| (StorageMapKey::new(*uid), *comm)),
).expect("depositor map must build");
let keys_slot = StorageSlotName::new(DEPOSITOR_KEYS_SLOT).expect("slot name");
// component slots: [ StorageSlot::with_map(keys_slot, map),
//                    StorageSlot::with_value(nonce_slot, zero),
//                    StorageSlot::with_value(auth_slot, zero) ]
```
  Keep the `last_nonce`/`last_authorized` value slots and the `Auth::IncrNonce` operator auth exactly as before.
- Add:
```rust
pub fn read_depositor_commitment(chain: &MockChain, d: &DeployedOperator, user_id: Word) -> Word {
    let slot = StorageSlotName::new(DEPOSITOR_KEYS_SLOT).expect("slot name");
    let account = chain.committed_account(d.account_id).expect("committed account");
    account.storage().get_map_item(&slot, StorageMapKey::new(user_id)).expect("map item")
}
```
  (Confirm the Rust-side map read accessor name — `get_map_item` on the storage; grep `miden-protocol-0.14.5/src/account/storage` if needed.)

- [ ] **Step 4: Run the test green**

Run: `cargo test --test multi_depositor operator_map_is_seeded 2>&1 | tail -10`
Expected: PASS — both depositor commitments read back from the seeded map.

- [ ] **Step 5: Commit**
```bash
git add src/relayer.rs
git commit -m "feat: operator account holds a per-depositor StorageMap of pubkey commitments"
```

---

### Task 3: Operator MASM looks the depositor key up by user_id (get_map_item)

**Files:**
- Modify: `masm/operator.masm`
- Test: `tests/authorizer.rs` (the oracle test — now deploys with a seeded map)

**Interfaces:**
- Consumes: the 8 operand felts (unchanged), now using `user_prefix`/`user_suffix` as the map key.
- Produces: `execute_intent` verifies against the *depositor-specific* key fetched from the map.

- [ ] **Step 1: Stash `user_id`, then change the key load to a map lookup**

In `masm/operator.masm`:
- Bump locals to hold a third word: `@locals(12)`. Document the new slot: `# loc.8-11 : [user_prefix, user_suffix, 0, 0]  (map key, needed after the hash)`.
- In the stash section (before `hperm` consumes the operands), also stash `[user_prefix, user_suffix, 0, 0]` to `loc.8`. `user_prefix`/`user_suffix` are operand indices 1 and 2 at entry; capture them with the same `dup.N` idiom already used, then `loc_storew_le.8 dropw`. Document the derivation per the existing style.
- Replace Phase 2's single-key load:
```
# --- 2. Load THIS depositor's committed pubkey from the map and verify. ---
padw loc_loadw_le.8            # => [user_pre, user_suf, 0, 0, MSG, ...]  (raw map key word)
push.DEPOSITOR_KEYS_SLOT[0..2] # => [slot_prefix, slot_suffix, KEY, MSG, ...]
exec.active_account::get_map_item
# => [PK_COMM, MSG, ...]   (kernel hashes the key internally; pass the RAW word)
exec.ecdsa_k256_keccak::verify
```
  Replace the `const OPERATOR_KEY_SLOT` with `const DEPOSITOR_KEYS_SLOT = word("signed_intents::operator::depositor_keys")`.
  Confirm the loc_loadw_le round-trip leaves the key word as `[user_pre, user_suf, 0, 0]` in the order `get_map_item` expects (KEY just below `[slot_prefix, slot_suffix]`); adjust drops/order using the oracle test as the arbiter.

- [ ] **Step 2: Update the oracle test to deploy with a seeded map**

In `tests/authorizer.rs`, build the operator with a one-entry map for the test depositor (`user_id_word(account.id()) -> key.commitment`) and set the intent's `user_prefix`/`user_suffix` to that account id. Run:

Run: `cargo test --test authorizer 2>&1 | tail -15`
Expected: first RED (map lookup wiring), then iterate to GREEN — the in-VM verify now fetches the key from the map. The oracle property still holds: a wrong reconstructed MSG or wrong key aborts.

- [ ] **Step 3: Run map-path + golden tests**

Run: `cargo test --test authorizer --test golden 2>&1 | tail -10`
Expected: PASS.

- [ ] **Step 4: Commit**
```bash
git add masm/operator.masm tests/authorizer.rs
git commit -m "feat: operator MASM fetches the depositor key from the map by user_id"
```

---

### Task 4: Thread depositor identity through the relayer + reconcile existing suites

**Files:**
- Modify: `src/relayer.rs` (`relay_intent` already pushes `user_prefix`/`user_suffix` — confirm the intent's user id is the depositor's account id), `tests/happy_path.rs`, `tests/adversarial.rs`, `tests/e2e_ts_to_masm.rs`.

**Interfaces:**
- Consumes: `new_depositor` (Task 1), map-backed `deploy_operator` (Task 2).

- [ ] **Step 1: Update happy_path to use a native-ECDSA depositor**

Rewrite `tests/happy_path.rs` so it: builds `d = new_depositor(1)`; deploys the operator seeded with `[(user_id_word(d.account.id()), d.commitment)]`; constructs an `Intent` whose `user_prefix`/`user_suffix` = `d.account.id()` prefix/suffix; signs with `d.key`; relays; asserts acceptance + `read_last_nonce == 1`.

- [ ] **Step 2: Reconcile adversarial + e2e**

`tests/adversarial.rs` and `tests/e2e_ts_to_masm.rs`: update their operator deployment to the seeded-map form and set intents' `user_id` to the deploying depositor's account id. The tamper/forge/replay/expire/wrong-depositor assertions are unchanged in intent. For e2e, the fixture's `user_prefix`/`user_suffix` must equal the depositor account id the Rust test deploys — either regenerate the fixture from a known id or set the test's depositor id from the fixture (document which).

- [ ] **Step 3: Full suite green**

Run: `cargo test 2>&1 | grep -E "Running tests/|test result:"` and `cd ts && npm test 2>&1 | tail -6`
Expected: all Rust suites + TS green.

- [ ] **Step 4: Commit**
```bash
git add src/relayer.rs tests/happy_path.rs tests/adversarial.rs tests/e2e_ts_to_masm.rs
git commit -m "test: relay native-ecdsa depositor intents through the map-backed operator"
```

---

### Task 5: Multi-depositor isolation test

**Files:**
- Modify: `tests/multi_depositor.rs`

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the isolation test**

Add a test that: builds depositors `a = new_depositor(1)`, `b = new_depositor(2)`; deploys the operator seeded with BOTH; then:
- `a` signs an intent with `user_id = a.id` → relays → **accepted**.
- `b` signs an intent with `user_id = b.id` → relays → **accepted** (independent nonce).
- `a` signs an intent but it is relayed with `user_id = b.id` (or `b`'s key used against `a`'s slot) → **`RelayError::Rejected`** (the map fetches the *other* depositor's key, ECDSA verify fails).
- Assert each depositor's `read_last_nonce` advanced independently.

```rust
#[test]
fn depositors_are_isolated_each_authorizes_only_its_own_slot() {
    // build a, b; deploy operator with both; accepted-own, rejected-cross, independent nonces.
}
```

- [ ] **Step 2: Run green**

Run: `cargo test --test multi_depositor 2>&1 | tail -12`
Expected: PASS — own-slot accepted, cross-slot rejected, nonces independent.

- [ ] **Step 3: Full suite + commit**

Run: `cargo test 2>&1 | grep "test result:"` → all ok.
```bash
git add tests/multi_depositor.rs
git commit -m "test: depositors are isolated — each key authorizes only its own user_id slot"
```

---

## Self-Review (completed during authoring)

- **Spec coverage:** operator per-depositor map (spec §3/§6.2) → Tasks 2–3; native-ECDSA user account whose key == auth key (spec §3, the binding) → Task 1; registration modeled simply (spec §11) → Task 2 seeding; multi-depositor isolation → Task 5; relayer still drives operator (spike finding) → Task 4. **Deferred (Plan 3):** real note-based deposit/registration, asset custody + payout note, over-withdrawal guard.
- **Placeholder scan:** one intentional discover-then-fill in Task 1 (`stored_auth_commitment` slot-name read and the exact `AuthSingleSig` import path) — these are confirmed against installed `miden-standards-0.14.5` source during Step 4, not invented; the binding test gates correctness. `read_depositor_commitment`'s exact map accessor is confirmed against installed source in Task 2 Step 3.
- **Type consistency:** `Depositor`/`new_depositor`/`user_id_word`/`deploy_operator(&[(Word,Word)])`/`read_depositor_commitment` names align across Tasks 1–5.

## Risks & checkpoints

- **Lower risk than usual:** both hard primitives are spike-proven (`get_map_item` read, native ECDSA auth). The residual unknowns are small API-surface details (exact `AuthSingleSig` import path; how to read an account's stored auth-key commitment and the operator map item in Rust), all confirmable against installed source and gated by tests. If `stored_auth_commitment` cannot read the AuthSingleSig slot cleanly, fall back to asserting the binding via the seeded map (commitment we seed == `d.commitment`) and note the limitation — do not block.
- **MASM stash depth:** adding the `user_id` stash bumps `@locals` to 12 and adds operand juggling before `hperm`; the oracle test is the arbiter for stack correctness, same as Plan 1 Task 3.

## Follow-on (Plan 3+)
Real note-based deposit (User Account native-auth tx sends a registration/funding note; operator consumes it and writes its own map), asset custody, payout P2ID note from verified felts, over-withdrawal guard, then the Plan 4 tutorial rewrite.
